"""Regression tests for the RangeBatchReplayGuard / RegionBatchReplayGuard refactor.

The two batch replay guards now share their binding, claim and consume
lifecycle in the private ``_BatchReplayGuard`` base class. These tests pin,
through the public entry points (``bind_once`` / ``check`` /
``SQLiteReplayStore``), the behavior the refactor must preserve: return
values, exception types, binding bytes (recomputed here from the documented
F / U / S / E framing, independently of the package internals) and state
transitions — including retry after a failed verification and lease
takeover — for both the in-memory and the SQLite backends.
"""

import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest

from zkregion import (
    RangeBatchEntry,
    RangeBatchReplayGuard,
    RangeProof,
    Region,
    RegionBatchEntry,
    RegionBatchReplayGuard,
    RegionProof,
    ReplayBinding,
    SQLiteReplayStore,
    pedersen_commit,
    prove_range,
    prove_region,
    verify_range_batch,
    verify_region_batch,
)

SMALL_PRIME = 104729  # a small prime keeps the group arithmetic fast in tests
OTHER_PRIME = 104723


def counter_randbelow(start: int = 1):
    state = {"value": start}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


def frame(item: bytes) -> bytes:
    return len(item).to_bytes(4, "big") + item


def expected_batch_digest(domain, leaf, entries, session_id, expires_at):
    """SHA-256(F(D) || F(session_id) || S(entries, L) || F(E))."""
    expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
    material = frame(domain) + frame(session_id)
    material += frame(len(entries).to_bytes(8, "big"))
    for entry in entries:
        material += frame(leaf(entry))
    material += frame(expiry)
    return hashlib.sha256(material).digest()


def bound_range_leaf(entry):
    c = entry.commitment
    items = [b"zkregion/range-bound/v1"]
    items += [
        str(v).encode("ascii")
        for v in (c.element, c.lower, c.upper, c.prime, c.generator, c.h)
    ]
    items.append(entry.context)
    for seq in (entry.proof.t, entry.proof.e, entry.proof.s):
        items.append(str(len(seq)).encode("ascii"))
        items += [str(v).encode("ascii") for v in seq]
    return b"".join(frame(item) for item in items)


def bound_region_leaf(entry):
    items = [b"zkregion/region-bound/v1"]
    for c in (entry.x_commitment, entry.y_commitment):
        items += [
            str(v).encode("ascii")
            for v in (c.element, c.lower, c.upper, c.prime, c.generator, c.h)
        ]
    r = entry.region
    items += [
        str(v).encode("ascii") for v in (r.min_x, r.max_x, r.min_y, r.max_y)
    ]
    items.append(entry.context)
    for sub in (entry.proof.x_proof, entry.proof.y_proof):
        for seq in (sub.t, sub.e, sub.s):
            items.append(str(len(seq)).encode("ascii"))
            items += [str(v).encode("ascii") for v in seq]
    return b"".join(frame(item) for item in items)


class BatchReplayGuardRegressionMixin:
    """Behavior shared by both batch guards, pinned against the refactor."""

    GUARD = None
    DOMAIN = None
    VERIFY = None
    LEAF = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "replay.db")
        self.entries = self.make_entries()

    def tearDown(self):
        self._tmp.cleanup()

    # ---- per-guard fixtures ---------------------------------------------------

    def make_entries(self):
        raise NotImplementedError

    def make_bool_field_entry(self):
        """A well-formed entry except for one bool masquerading as an int."""
        raise NotImplementedError

    def make_broken_proof_entries(self):
        """Well-typed entries whose proofs fail batch verification."""
        raise NotImplementedError

    def expected_digest(self, entries, session_id, expires_at=None):
        return expected_batch_digest(
            self.DOMAIN, self.LEAF, entries, session_id, expires_at
        )

    def make_store(self, *args, **kwargs):
        return SQLiteReplayStore(self.path, *args, **kwargs)

    # ---- binding bytes --------------------------------------------------------

    def test_binding_fields_and_bytes_match_documented_framing(self):
        guard = self.GUARD()
        binding = guard.bind_once(self.entries, b"session")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"session")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(binding.digest, self.expected_digest(self.entries, b"session"))
        expiring = guard.bind_once(self.entries, b"timed", expires_at=1000)
        self.assertEqual(expiring.expires_at, 1000)
        self.assertEqual(
            expiring.digest, self.expected_digest(self.entries, b"timed", 1000)
        )
        zero_expiry = guard.bind_once(self.entries, b"zero", expires_at=0)
        self.assertEqual(
            zero_expiry.digest, self.expected_digest(self.entries, b"zero", 0)
        )

    def test_binding_bytes_are_deterministic_across_instances_and_backends(self):
        first = self.GUARD().bind_once(self.entries, b"s", expires_at=7)
        second = self.GUARD().bind_once(list(self.entries), b"s", expires_at=7)
        self.assertEqual(first, second)
        store = self.make_store()
        stored = self.GUARD(store=store).bind_once(tuple(self.entries), b"s", expires_at=7)
        self.assertEqual(first, stored)
        store.close()

    def test_batch_order_and_duplicates_still_change_the_binding(self):
        base = self.GUARD().bind_once(self.entries, b"s").digest

        def digest_of(batch):
            return self.GUARD().bind_once(batch, b"s").digest

        self.assertNotEqual(base, digest_of(self.entries[::-1]))
        self.assertNotEqual(base, digest_of(self.entries[:-1]))
        self.assertNotEqual(base, digest_of([self.entries[0], self.entries[0]]))
        self.assertEqual(base, digest_of(list(self.entries)))

    # ---- bind_once exceptions ---------------------------------------------------

    def test_bind_once_value_errors(self):
        guard = self.GUARD()
        with self.assertRaises(ValueError):  # empty batch
            guard.bind_once([], b"s")
        with self.assertRaises(ValueError):  # empty session id
            guard.bind_once(self.entries, b"")
        with self.assertRaises(ValueError):  # expiry above uint64
            guard.bind_once(self.entries, b"s", expires_at=2**64)
        with self.assertRaises(ValueError):  # negative expiry
            guard.bind_once(self.entries, b"s", expires_at=-1)
        binding = guard.bind_once(self.entries, b"s")
        with self.assertRaises(ValueError):  # rebind of a pending id
            guard.bind_once(self.entries, b"s")
        self.assertTrue(
            guard.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )
        with self.assertRaises(ValueError):  # rebind of a consumed id
            guard.bind_once(self.entries, b"s")

    def test_bind_once_type_errors(self):
        guard = self.GUARD()
        with self.assertRaises(TypeError):  # entries not a sequence
            guard.bind_once(object(), b"s")
        for bad in (b"raw", b"", "text"):
            with self.assertRaises(TypeError):  # string/bytes are not batches
                guard.bind_once(bad, b"s")
        with self.assertRaises(TypeError):  # entry of the wrong type
            guard.bind_once([object()], b"s")
        with self.assertRaises(TypeError):  # bool masquerading as an int
            guard.bind_once([self.make_bool_field_entry()], b"s")
        with self.assertRaises(TypeError):  # session id must be bytes
            guard.bind_once(self.entries, "s")
        with self.assertRaises(TypeError):  # bool expiry is not an int
            guard.bind_once(self.entries, b"s", expires_at=True)
        with self.assertRaises(TypeError):  # store must be an SQLiteReplayStore
            self.GUARD(store=object())

    # ---- check: success, rejection and state transitions (in-memory) -----------

    def test_check_success_consumes_exactly_once(self):
        guard = self.GUARD()
        binding = guard.bind_once(self.entries, b"s")
        self.assertTrue(
            guard.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )
        self.assertFalse(  # the consumed id rejects every later check
            guard.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )

    def test_check_rejections_leave_the_id_pending(self):
        guard = self.GUARD()
        binding = guard.bind_once(self.entries, b"s", expires_at=1000)
        # unknown id
        foreign = self.GUARD().bind_once(self.entries, b"other")
        self.assertFalse(
            guard.check(self.entries, foreign, now=1, randbelow=counter_randbelow())
        )
        # unequal binding for a known id
        forged = ReplayBinding(b"s", b"\x00" * 32, 1000)
        self.assertFalse(
            guard.check(self.entries, forged, now=1, randbelow=counter_randbelow())
        )
        # tampered batch (digest mismatch)
        self.assertFalse(
            guard.check(self.entries[::-1], binding, now=1, randbelow=counter_randbelow())
        )
        # empty batch
        self.assertFalse(
            guard.check([], binding, now=1, randbelow=counter_randbelow())
        )
        # expiry reached: now >= expires_at
        self.assertFalse(
            guard.check(self.entries, binding, now=1000, randbelow=counter_randbelow())
        )
        # failing proof verification
        broken = self.make_broken_proof_entries()
        broken_binding = guard.bind_once(broken, b"broken")
        self.assertFalse(
            guard.check(broken, broken_binding, now=1, randbelow=counter_randbelow())
        )
        # none of the rejections consumed anything: the original binding still checks
        self.assertTrue(
            guard.check(self.entries, binding, now=999, randbelow=counter_randbelow())
        )
        self.assertFalse(
            guard.check(self.entries, binding, now=999, randbelow=counter_randbelow())
        )

    def test_check_argument_type_errors(self):
        guard = self.GUARD()
        binding = guard.bind_once(self.entries, b"s")
        with self.assertRaises(TypeError):
            guard.check(object(), binding, now=1)
        with self.assertRaises(TypeError):
            guard.check(self.entries, "not-a-binding", now=1)
        with self.assertRaises(TypeError):
            guard.check(self.entries, binding, now=True)
        with self.assertRaises(TypeError):
            guard.check(self.entries, binding, now=1, randbelow=42)
        with self.assertRaises(ValueError):  # explicit now above uint64
            guard.check(self.entries, binding, now=2**64)
        with self.assertRaises(ValueError):  # negative now
            guard.check(self.entries, binding, now=-1)
        # the id survived every argument error
        self.assertTrue(
            guard.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )

    def test_bad_randbelow_propagates_and_releases_the_claim(self):
        guard = self.GUARD()
        binding = guard.bind_once(self.entries, b"s")
        with self.assertRaises(TypeError):  # a draw that is not an integer
            guard.check(self.entries, binding, now=1, randbelow=lambda upper: 1.5)
        with self.assertRaises(TypeError):  # a bool draw
            guard.check(self.entries, binding, now=1, randbelow=lambda upper: True)
        with self.assertRaises(ValueError):  # a draw outside [0, upper)
            guard.check(self.entries, binding, now=1, randbelow=lambda upper: upper)
        # the claim was released each time: a retry with a good source succeeds
        self.assertTrue(
            guard.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )

    def test_failed_verification_releases_the_claim_for_retry(self):
        guard = self.GUARD()
        broken = self.make_broken_proof_entries()
        binding = guard.bind_once(broken, b"s")
        self.assertFalse(
            guard.check(broken, binding, now=1, randbelow=counter_randbelow())
        )
        # still pending: the same (still broken) batch fails again rather than
        # being rejected as consumed
        self.assertFalse(
            guard.check(broken, binding, now=1, randbelow=counter_randbelow())
        )
        # and a fresh id on the same guard verifies normally
        good = guard.bind_once(self.entries, b"s2")
        self.assertTrue(
            guard.check(self.entries, good, now=1, randbelow=counter_randbelow())
        )

    def test_randbelow_call_sequence_matches_direct_batch_verify(self):
        direct_calls = []

        def direct_randbelow(upper):
            direct_calls.append(upper)
            return 1

        self.VERIFY(self.entries, randbelow=direct_randbelow)
        guard = self.GUARD()
        binding = guard.bind_once(self.entries, b"s")
        guard_calls = []

        def guard_randbelow(upper):
            guard_calls.append(upper)
            return 1

        self.assertTrue(guard.check(self.entries, binding, now=1, randbelow=guard_randbelow))
        self.assertTrue(direct_calls)
        self.assertEqual(guard_calls, direct_calls)

    # ---- concurrency (in-memory) ---------------------------------------------

    def test_concurrent_checks_of_one_id_admit_a_single_success(self):
        guard = self.GUARD()
        binding = guard.bind_once(self.entries, b"s")
        claimed = threading.Event()
        release = threading.Event()

        def slow_randbelow(upper):
            claimed.set()
            release.wait(5)
            return 1

        results = []
        thread = threading.Thread(
            target=lambda: results.append(
                guard.check(self.entries, binding, now=1, randbelow=slow_randbelow)
            )
        )
        thread.start()
        self.assertTrue(claimed.wait(5))
        # the same id is claimed: a concurrent check loses immediately
        self.assertFalse(
            guard.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )
        release.set()
        thread.join(5)
        self.assertEqual(results, [True])

    def test_verification_of_one_id_does_not_block_other_ids(self):
        guard = self.GUARD()
        first = guard.bind_once(self.entries, b"s1")
        second = guard.bind_once(self.entries, b"s2")
        claimed = threading.Event()
        release = threading.Event()

        def slow_randbelow(upper):
            claimed.set()
            release.wait(5)
            return 1

        results = []
        thread = threading.Thread(
            target=lambda: results.append(
                guard.check(self.entries, first, now=1, randbelow=slow_randbelow)
            )
        )
        thread.start()
        self.assertTrue(claimed.wait(5))
        # a different id checks through while the first verification is stuck
        self.assertTrue(
            guard.check(self.entries, second, now=1, randbelow=counter_randbelow())
        )
        release.set()
        thread.join(5)
        self.assertEqual(results, [True])

    def test_memory_instances_do_not_share_state(self):
        entries = self.entries
        binding = self.GUARD().bind_once(entries, b"s")
        other = self.GUARD()
        self.assertFalse(
            other.check(entries, binding, now=1, randbelow=counter_randbelow())
        )
        other.bind_once(entries, b"s")  # the id is free on the other instance

    # ---- SQLite backend ---------------------------------------------------------

    def test_store_shares_state_across_instances_and_restarts(self):
        store = self.make_store()
        binding = self.GUARD(store=store).bind_once(self.entries, b"s", expires_at=1000)
        self.assertTrue(
            self.GUARD(store=store).check(
                self.entries, binding, now=999, randbelow=counter_randbelow()
            )
        )
        store.close()
        # a reopened store keeps the consumed id
        reopened = self.make_store()
        guard = self.GUARD(store=reopened)
        self.assertFalse(
            guard.check(self.entries, binding, now=999, randbelow=counter_randbelow())
        )
        with self.assertRaises(ValueError):
            guard.bind_once(self.entries, b"s")
        reopened.close()

    def test_store_pending_record_survives_restart(self):
        store = self.make_store()
        binding = self.GUARD(store=store).bind_once(self.entries, b"s")
        store.close()
        reopened = self.make_store()
        guard = self.GUARD(store=reopened)
        self.assertTrue(
            guard.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )
        reopened.close()

    def test_store_records_in_the_existing_format_still_verify(self):
        # A pending/consumed row written with the pre-refactor database format
        # (same table, same E expiry framing) must keep its semantics.
        store = self.make_store()  # creates the table
        digest = self.expected_digest(self.entries, b"legacy")
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "INSERT INTO replay_sessions_v1 "
                "(namespace, domain, session_id, state, digest, expires_at, token, claim_expires) "
                "VALUES (?, ?, ?, 'pending', ?, ?, NULL, NULL)",
                (b"default", self.DOMAIN, b"legacy", digest, b"\x00"),
            )
            conn.execute(
                "INSERT INTO replay_sessions_v1 "
                "(namespace, domain, session_id, state, digest, expires_at, token, claim_expires) "
                "VALUES (?, ?, ?, 'consumed', ?, ?, NULL, NULL)",
                (b"default", self.DOMAIN, b"spent", digest, b"\x00"),
            )
            conn.commit()
        finally:
            conn.close()
        guard = self.GUARD(store=store)
        self.assertTrue(
            guard.check(
                self.entries,
                ReplayBinding(b"legacy", digest),
                now=1,
                randbelow=counter_randbelow(),
            )
        )
        self.assertFalse(
            guard.check(
                self.entries,
                ReplayBinding(b"spent", digest),
                now=1,
                randbelow=counter_randbelow(),
            )
        )
        with self.assertRaises(ValueError):
            guard.bind_once(self.entries, b"spent")
        store.close()

    def test_store_rejection_restores_pending_for_other_instances(self):
        store = self.make_store()
        binding = self.GUARD(store=store).bind_once(self.entries, b"s")
        checker = self.GUARD(store=store)
        self.assertFalse(
            checker.check(self.entries[::-1], binding, now=1, randbelow=counter_randbelow())
        )
        self.assertTrue(
            self.GUARD(store=store).check(
                self.entries, binding, now=1, randbelow=counter_randbelow()
            )
        )
        store.close()

    def test_store_namespace_isolation(self):
        first = self.make_store(namespace=b"a")
        second = self.make_store(namespace=b"b")
        binding = self.GUARD(store=first).bind_once(self.entries, b"s")
        self.assertFalse(
            self.GUARD(store=second).check(
                self.entries, binding, now=1, randbelow=counter_randbelow()
            )
        )
        self.assertTrue(
            self.GUARD(store=first).check(
                self.entries, binding, now=1, randbelow=counter_randbelow()
            )
        )
        first.close()
        second.close()

    def test_store_lease_takeover_leaves_stale_holder_powerless(self):
        clock = {"t": 1000}
        store = self.make_store(lease_seconds=10, clock=lambda: clock["t"])
        guard_a = self.GUARD(store=store)
        guard_b = self.GUARD(store=store)
        binding = guard_a.bind_once(self.entries, b"s")
        claimed = threading.Event()
        release = threading.Event()

        def slow_randbelow(upper):
            claimed.set()
            release.wait(5)
            return 1

        results = []
        thread = threading.Thread(
            target=lambda: results.append(
                guard_a.check(self.entries, binding, now=1, randbelow=slow_randbelow)
            )
        )
        thread.start()
        self.assertTrue(claimed.wait(5))
        clock["t"] = 2000  # the first claim's lease has expired
        # a later equal check takes the claim over and consumes the id
        self.assertTrue(
            guard_b.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )
        release.set()
        thread.join(5)
        # the stale holder can neither consume nor release the new owner's state
        self.assertEqual(results, [False])
        self.assertFalse(
            guard_a.check(self.entries, binding, now=1, randbelow=counter_randbelow())
        )
        with self.assertRaises(ValueError):
            guard_b.bind_once(self.entries, b"s")
        store.close()


class RangeBatchReplayGuardRegressionTest(BatchReplayGuardRegressionMixin, unittest.TestCase):
    """Regression pins for RangeBatchReplayGuard (domain b"zr/rbr/v1")."""

    GUARD = RangeBatchReplayGuard
    DOMAIN = b"zr/rbr/v1"
    VERIFY = staticmethod(verify_range_batch)
    LEAF = staticmethod(bound_range_leaf)

    def make_entry(self, value, *, prime, blinding, lower=0, upper=10, context=b"batch"):
        commitment, r = pedersen_commit(
            value, lower, upper, prime=prime, generator=3, blinding=blinding
        )
        proof = prove_range(
            commitment, value, r, context=context, randbelow=counter_randbelow()
        )
        return RangeBatchEntry(commitment, proof, context)

    def make_entries(self):
        return [
            self.make_entry(4, prime=SMALL_PRIME, blinding=1001),
            self.make_entry(7, prime=SMALL_PRIME, blinding=1002),
            self.make_entry(3, prime=OTHER_PRIME, blinding=2001),
        ]

    def make_bool_field_entry(self):
        entry = self.entries[0]
        proof = entry.proof
        bool_proof = RangeProof((True,) + proof.t[1:], proof.e, proof.s)
        return RangeBatchEntry(entry.commitment, bool_proof, entry.context)

    def make_broken_proof_entries(self):
        entry = self.entries[0]
        proof = entry.proof
        broken = RangeProof(proof.t, proof.e, tuple(v + 1 for v in proof.s))
        return [RangeBatchEntry(entry.commitment, broken, entry.context)]


class RegionBatchReplayGuardRegressionTest(BatchReplayGuardRegressionMixin, unittest.TestCase):
    """Regression pins for RegionBatchReplayGuard (domain b"zr/rgbr/v1")."""

    GUARD = RegionBatchReplayGuard
    DOMAIN = b"zr/rgbr/v1"
    VERIFY = staticmethod(verify_region_batch)
    LEAF = staticmethod(bound_region_leaf)

    def make_entry(
        self, x, y, *, prime, x_blinding, y_blinding, region=None, context=b"batch"
    ):
        region = Region(0, 10, 20, 30) if region is None else region
        x_commitment, x_r = pedersen_commit(
            x, region.min_x, region.max_x, prime=prime, generator=3, blinding=x_blinding
        )
        y_commitment, y_r = pedersen_commit(
            y, region.min_y, region.max_y, prime=prime, generator=3, blinding=y_blinding
        )
        proof = prove_region(
            x_commitment, y_commitment, x, y, x_r, y_r, region,
            context=context, randbelow=counter_randbelow(),
        )
        return RegionBatchEntry(x_commitment, y_commitment, region, proof, context)

    def make_entries(self):
        return [
            self.make_entry(4, 22, prime=SMALL_PRIME, x_blinding=1001, y_blinding=1002),
            self.make_entry(7, 28, prime=SMALL_PRIME, x_blinding=2001, y_blinding=2002),
            self.make_entry(3, 25, prime=OTHER_PRIME, x_blinding=3001, y_blinding=3002),
        ]

    def make_bool_field_entry(self):
        entry = self.entries[0]
        bool_region = Region(True, 10, 20, 30)
        return RegionBatchEntry(
            entry.x_commitment, entry.y_commitment, bool_region,
            entry.proof, entry.context,
        )

    def make_broken_proof_entries(self):
        entry = self.entries[0]
        y_proof = entry.proof.y_proof
        broken_y = RangeProof(y_proof.t, y_proof.e, tuple(v + 1 for v in y_proof.s))
        broken = RegionProof(entry.proof.x_proof, broken_y)
        return [
            RegionBatchEntry(
                entry.x_commitment, entry.y_commitment, entry.region,
                broken, entry.context,
            )
        ]


class BatchGuardCrossDomainTest(unittest.TestCase):
    """The two refactored guards keep isolated store domains on one file."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "shared.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_range_and_region_domains_do_not_collide(self):
        range_entry = RangeBatchReplayGuardRegressionTest.make_entry(
            self, 4, prime=SMALL_PRIME, blinding=1001
        )
        region_entry = RegionBatchReplayGuardRegressionTest.make_entry(
            self, 4, 22, prime=SMALL_PRIME, x_blinding=1001, y_blinding=1002
        )
        store = SQLiteReplayStore(self.path)
        range_guard = RangeBatchReplayGuard(store=store)
        region_guard = RegionBatchReplayGuard(store=store)
        range_binding = range_guard.bind_once([range_entry], b"same-id")
        region_binding = region_guard.bind_once([region_entry], b"same-id")
        self.assertNotEqual(range_binding.digest, region_binding.digest)
        self.assertTrue(
            range_guard.check([range_entry], range_binding, now=1,
                              randbelow=counter_randbelow())
        )
        # the region id is unaffected by the range guard consuming its own
        self.assertTrue(
            region_guard.check([region_entry], region_binding, now=1,
                               randbelow=counter_randbelow())
        )
        conn = sqlite3.connect(self.path)
        try:
            domains = {
                row[0]
                for row in conn.execute(
                    "SELECT DISTINCT domain FROM replay_sessions_v1"
                )
            }
        finally:
            conn.close()
        self.assertEqual(domains, {b"zr/rbr/v1", b"zr/rgbr/v1"})
        store.close()


if __name__ == "__main__":
    unittest.main()
