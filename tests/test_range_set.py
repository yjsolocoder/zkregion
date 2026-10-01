"""Tests for the sparse range-set proofs.

``prove_range_set`` / ``verify_range_set`` extend the plain Pedersen range
proof (Schnorr OR) to an ordered list of disjoint closed intervals with
gaps allowed: the verifier learns the public interval list, the commitment
and the context, but never the hit interval, the opening value or the
blinding. ``verify_range_set_batch`` random-linearly aggregates the OR
branches of several entries in the same style as ``verify_range_batch``.
The acceptance tests cover honest round trips over gaps and endpoints,
structural validation of the interval list, transcript binding to order,
bounds, commitment and context, the TypeError / ValueError / False error
matrix, batch ordering and duplicates, and input non-mutation.
"""

import dataclasses
import hashlib
import unittest

from zkregion import (
    DEFAULT_PRIME,
    PedersenCommitment,
    RangeSetBatchEntry,
    RangeSetProof,
    pedersen_commit,
    prove_range_set,
    verify_range_set,
    verify_range_set_batch,
)

SMALL_PRIME = 104729  # a small prime keeps the group arithmetic readable


def counter_randbelow(start: int = 1):
    state = {"value": start}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


class RangeSetProofTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5
    INTERVALS = ((0, 4), (10, 14), (90, 100))

    def commit(self, value=50, lower=0, upper=100, blinding=1234, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def prove(
        self,
        value=12,
        intervals=INTERVALS,
        lower=0,
        upper=100,
        blinding=1234,
        context=b"ctx",
        **kwargs,
    ):
        commitment, returned = self.commit(value, lower, upper, blinding, **kwargs)
        proof = prove_range_set(
            commitment, value, returned, intervals, context,
            randbelow=counter_randbelow(),
        )
        return commitment, returned, proof

    # ---- honest round trip -------------------------------------------------

    def test_honest_proof_verifies(self):
        commitment, _, proof = self.prove()
        self.assertIsInstance(proof, RangeSetProof)
        self.assertTrue(verify_range_set(commitment, self.INTERVALS, proof, b"ctx"))
        self.assertTrue(
            verify_range_set(commitment, self.INTERVALS, proof, context=b"ctx")
        )

    def test_one_branch_per_covered_integer_in_interval_order(self):
        commitment, _, proof = self.prove(value=12)
        self.assertEqual(len(proof.t), 5 + 5 + 11)
        self.assertEqual(len(proof.t), len(proof.e))
        self.assertEqual(len(proof.e), len(proof.s))
        for field in (proof.t, proof.e, proof.s):
            self.assertIsInstance(field, tuple)
            for item in field:
                self.assertIsInstance(item, int)
                self.assertNotIsInstance(item, bool)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.t = proof.t + (1,)

    def test_every_covered_value_proves_and_gap_values_are_rejected(self):
        covered = list(range(0, 5)) + list(range(10, 15)) + list(range(90, 101))
        for value in covered:
            commitment, blinding, proof = self.prove(value=value)
            self.assertTrue(
                verify_range_set(commitment, self.INTERVALS, proof, b"ctx"),
                f"covered value={value}",
            )
        for value in (5, 9, 15, 50, 89):
            commitment, blinding = self.commit(value=value)
            with self.assertRaises(ValueError):
                prove_range_set(
                    commitment, value, blinding, self.INTERVALS, b"ctx",
                    randbelow=counter_randbelow(),
                )

    def test_single_point_and_single_interval_lists(self):
        intervals = ((40, 40),)
        commitment, blinding, proof = self.prove(value=40, intervals=intervals)
        self.assertEqual(len(proof.t), 1)
        self.assertTrue(verify_range_set(commitment, intervals, proof, b"ctx"))
        intervals = ((0, 100),)
        commitment, blinding, proof = self.prove(value=0, intervals=intervals)
        self.assertEqual(len(proof.t), 101)
        self.assertTrue(verify_range_set(commitment, intervals, proof, b"ctx"))

    def test_negative_ranges_supported(self):
        intervals = ((-500, -450), (-301, -301))
        commitment, blinding, proof = self.prove(
            value=-470, intervals=intervals, lower=-500, upper=-300
        )
        self.assertTrue(verify_range_set(commitment, intervals, proof, b"ctx"))

    def test_lists_are_accepted_on_both_sides(self):
        commitment, _, proof = self.prove()
        as_list = [list(pair) for pair in self.INTERVALS]
        # list-of-lists is a type error: pairs must be tuples
        with self.assertRaises(TypeError):
            verify_range_set(commitment, as_list, proof, b"ctx")
        self.assertTrue(
            verify_range_set(commitment, list(self.INTERVALS), proof, b"ctx")
        )

    def test_maximum_256_points_accepted(self):
        intervals = tuple(
            (2 * i, 2 * i) for i in range(256)
        )  # 256 single-point intervals
        commitment, blinding, proof = self.prove(
            value=6, intervals=intervals, lower=0, upper=511
        )
        self.assertEqual(len(proof.t), 256)
        self.assertTrue(verify_range_set(commitment, intervals, proof, b"ctx"))

    def test_257_points_rejected(self):
        intervals = tuple((i, i) for i in range(257))
        commitment, blinding = self.commit(value=0, lower=0, upper=256)
        with self.assertRaises(ValueError):
            prove_range_set(
                commitment, 0, blinding, intervals, b"ctx",
                randbelow=counter_randbelow(),
            )
        # verification of an oversized cover returns False whatever the proof
        self.assertFalse(
            verify_range_set(
                commitment, intervals, RangeSetProof((), (), ()), b"ctx"
            )
        )

    def test_fixed_randbelow_is_reproducible(self):
        commitment, blinding = self.commit(value=12)
        first = prove_range_set(
            commitment, 12, blinding, self.INTERVALS, b"c",
            randbelow=counter_randbelow(),
        )
        second = prove_range_set(
            commitment, 12, blinding, self.INTERVALS, b"c",
            randbelow=counter_randbelow(),
        )
        self.assertEqual(first, second)

    def test_default_group_parameters_are_usable(self):
        commitment, blinding = pedersen_commit(40, 0, 100, blinding=987654321)
        proof = prove_range_set(
            commitment, 40, blinding, ((10, 50), (60, 90)), b"demo"
        )
        self.assertTrue(
            verify_range_set(commitment, ((10, 50), (60, 90)), proof, b"demo")
        )

    # ---- transcript --------------------------------------------------------

    def test_challenge_matches_transcript(self):
        commitment, _, proof = self.prove()
        items = [b"zkregion/pedersen-range-set/v1"]
        for field in (
            commitment.element,
            commitment.lower,
            commitment.upper,
            commitment.prime,
            commitment.generator,
            commitment.h,
        ):
            items.append(str(field).encode("ascii"))
        items.append(b"ctx")
        items.append(b"3")  # interval count
        for lower, upper in self.INTERVALS:
            items.append(str(lower).encode("ascii"))
            items.append(str(upper).encode("ascii"))
        items.append(b"21")  # covered value count
        items.extend(str(t_i).encode("ascii") for t_i in proof.t)
        transcript = hashlib.sha256()
        for item in items:
            transcript.update(len(item).to_bytes(4, "big"))
            transcript.update(item)
        c = int.from_bytes(transcript.digest(), "big") % self.PRIME
        self.assertEqual(sum(proof.e) % self.PRIME, c)
        for share in proof.e:
            self.assertTrue(0 <= share < self.PRIME)
        for response in proof.s:
            self.assertGreaterEqual(response, 0)

    def test_each_branch_satisfies_the_schnorr_equation(self):
        commitment, _, proof = self.prove(value=95)
        covered = [
            value
            for lo, hi in self.INTERVALS
            for value in range(lo, hi + 1)
        ]
        for i, (t_i, e_i, s_i) in enumerate(zip(proof.t, proof.e, proof.s)):
            offset = covered[i] - commitment.lower
            statement = commitment.element * pow(self.G, -offset, self.PRIME) % self.PRIME
            self.assertEqual(
                pow(self.H, s_i, self.PRIME),
                t_i * pow(statement, e_i, self.PRIME) % self.PRIME,
                f"branch {i}",
            )

    # ---- prove-time validation ---------------------------------------------

    def test_prove_requires_a_valid_opening(self):
        commitment, blinding = self.commit(value=12)
        with self.assertRaises(ValueError):
            prove_range_set(
                commitment, 13, blinding, self.INTERVALS,
                randbelow=counter_randbelow(),
            )
        with self.assertRaises(ValueError):
            prove_range_set(
                commitment, 12, blinding + 1, self.INTERVALS,
                randbelow=counter_randbelow(),
            )

    def test_prove_interval_structure_value_errors(self):
        commitment, blinding = self.commit(value=12)

        def prove(intervals, value=12):
            return prove_range_set(
                commitment, value, blinding, intervals, b"ctx",
                randbelow=counter_randbelow(),
            )

        with self.assertRaises(ValueError):
            prove(())  # empty
        with self.assertRaises(ValueError):
            prove(((14, 10),))  # inverted
        with self.assertRaises(ValueError):
            prove(((0, 4), (3, 8)))  # overlapping
        with self.assertRaises(ValueError):
            prove(((0, 4), (4, 8)))  # touching: lowers must be strictly past
        with self.assertRaises(ValueError):
            prove(((10, 14), (0, 4)))  # unordered lowers
        with self.assertRaises(ValueError):
            prove(((-1, 4), (10, 14)))  # below declared lower
        with self.assertRaises(ValueError):
            prove(((0, 4), (10, 101)))  # above declared upper
        # structurally fine but the opening is not covered
        with self.assertRaises(ValueError):
            prove(((0, 4), (90, 100)), value=12)

    def test_prove_type_errors(self):
        commitment, blinding = self.commit()
        with self.assertRaises(TypeError):
            prove_range_set("commitment", 12, blinding, self.INTERVALS)
        bad = dataclasses.replace(commitment, element=1.5)
        with self.assertRaises(TypeError):
            prove_range_set(bad, 12, blinding, self.INTERVALS)
        for bad_value in (1.5, "12", True, None):
            with self.assertRaises(TypeError):
                prove_range_set(commitment, bad_value, blinding, self.INTERVALS)
            with self.assertRaises(TypeError):
                prove_range_set(commitment, 12, bad_value, self.INTERVALS)
        with self.assertRaises(TypeError):
            prove_range_set(commitment, 12, blinding, self.INTERVALS, "ctx")
        with self.assertRaises(TypeError):
            prove_range_set(commitment, 12, blinding, self.INTERVALS, randbelow=7)
        for bad_intervals in (
            "intervals",
            b"\x00\x01",
            bytearray(b"\x00"),
            42,
            None,
        ):
            with self.assertRaises(TypeError):
                prove_range_set(commitment, 12, blinding, bad_intervals)
        # a list container is accepted, but its pairs must still be tuples
        with self.assertRaises(TypeError):
            prove_range_set(commitment, 12, blinding, ((0, 4), [10, 14]))
        with self.assertRaises(TypeError):
            prove_range_set(commitment, 12, blinding, ((0, 4, 9),))
        with self.assertRaises(TypeError):
            prove_range_set(commitment, 12, blinding, ((0,),))
        with self.assertRaises(TypeError):
            prove_range_set(commitment, 12, blinding, (("0", 4),))
        with self.assertRaises(TypeError):
            prove_range_set(commitment, 12, blinding, ((0, True),))

    def test_prove_randbelow_draws_are_validated(self):
        commitment, blinding = self.commit(value=12)
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                prove_range_set(
                    commitment, 12, blinding, self.INTERVALS,
                    randbelow=lambda upper, bad=bad: bad,
                )
        for bad in (-1, self.PRIME):
            with self.assertRaises(ValueError):
                prove_range_set(
                    commitment, 12, blinding, self.INTERVALS,
                    randbelow=lambda upper, bad=bad: bad,
                )

    # ---- verify-time rejection ---------------------------------------------

    def test_tampering_fails(self):
        commitment, _, proof = self.prove()
        self.assertFalse(
            verify_range_set(
                commitment, self.INTERVALS,
                RangeSetProof(proof.t, proof.e, proof.s[:-1] + (proof.s[-1] + 1,)),
                b"ctx",
            )
        )
        self.assertFalse(
            verify_range_set(
                commitment, self.INTERVALS,
                RangeSetProof(
                    proof.t,
                    proof.e[:-1] + ((proof.e[-1] + 1) % self.PRIME,),
                    proof.s,
                ),
                b"ctx",
            )
        )
        self.assertFalse(
            verify_range_set(
                commitment, self.INTERVALS,
                RangeSetProof(
                    proof.t[:-1] + ((proof.t[-1] % (self.PRIME - 1)) + 1,),
                    proof.e, proof.s,
                ),
                b"ctx",
            )
        )

    def test_context_binds_proof(self):
        commitment, _, proof = self.prove(context=b"ctx")
        self.assertFalse(verify_range_set(commitment, self.INTERVALS, proof))
        self.assertFalse(verify_range_set(commitment, self.INTERVALS, proof, b"other"))

    def test_interval_order_and_bounds_bind_proof(self):
        commitment, _, proof = self.prove(value=12)
        # endpoint replaced
        self.assertFalse(
            verify_range_set(
                commitment, ((0, 4), (10, 13), (90, 100)), proof, b"ctx"
            )
        )
        self.assertFalse(
            verify_range_set(
                commitment, ((0, 4), (11, 14), (90, 100)), proof, b"ctx"
            )
        )
        # intervals swapped (count preserved, transcripts differ)
        self.assertFalse(
            verify_range_set(
                commitment, ((0, 4), (90, 100), (10, 14)), proof, b"ctx"
            )
        )
        # interval dropped: the cover count changes and the branch tuple
        # no longer matches
        self.assertFalse(
            verify_range_set(
                commitment, ((0, 4), (10, 14)), proof, b"ctx"
            )
        )
        # an interval appended: tuple length mismatch
        self.assertFalse(
            verify_range_set(
                commitment, ((0, 4), (10, 14), (90, 100), (101, 101)),
                proof, b"ctx",
            )
        )

    def test_foreign_commitment_fails(self):
        commitment, _, proof = self.prove()
        other, _ = self.commit(value=13, blinding=4321)
        self.assertFalse(verify_range_set(other, self.INTERVALS, proof, b"ctx"))
        shifted = dataclasses.replace(
            commitment, element=(commitment.element + 1) % self.PRIME
        )
        self.assertFalse(verify_range_set(shifted, self.INTERVALS, proof, b"ctx"))
        # the same element under a declared range that shifts offsets fails
        for field, bad in (("lower", 1), ("upper", 99), ("prime", self.PRIME + 2)):
            broken = dataclasses.replace(commitment, **{field: bad})
            self.assertFalse(
                verify_range_set(broken, self.INTERVALS, proof, b"ctx"), field
            )

    def test_structural_errors_return_false(self):
        commitment, _, proof = self.prove()
        # wrong tuple lengths
        self.assertFalse(
            verify_range_set(
                commitment, self.INTERVALS,
                RangeSetProof(proof.t[:-1], proof.e, proof.s), b"ctx",
            )
        )
        self.assertFalse(
            verify_range_set(
                commitment, self.INTERVALS,
                RangeSetProof(proof.t, proof.e, proof.s + (1,)), b"ctx",
            )
        )
        self.assertFalse(
            verify_range_set(
                commitment, self.INTERVALS, RangeSetProof((), (), ()), b"ctx"
            )
        )
        # t outside [1, prime)
        for bad_t in (0, self.PRIME, self.PRIME + 1, -1):
            forged = RangeSetProof(proof.t[:-1] + (bad_t,), proof.e, proof.s)
            self.assertFalse(
                verify_range_set(commitment, self.INTERVALS, forged, b"ctx"),
                f"t={bad_t}",
            )
        # e outside [0, prime)
        for bad_e in (-1, self.PRIME, self.PRIME + 1):
            forged = RangeSetProof(proof.t, proof.e[:-1] + (bad_e,), proof.s)
            self.assertFalse(
                verify_range_set(commitment, self.INTERVALS, forged, b"ctx"),
                f"e={bad_e}",
            )
        # negative response
        forged = RangeSetProof(proof.t, proof.e, proof.s[:-1] + (-1,))
        self.assertFalse(
            verify_range_set(commitment, self.INTERVALS, forged, b"ctx")
        )
        # challenge shares that no longer sum to c
        forged = RangeSetProof(
            proof.t, (proof.e[0] + 1,) + proof.e[1:], proof.s
        )
        self.assertFalse(
            verify_range_set(commitment, self.INTERVALS, forged, b"ctx")
        )

    def test_bad_interval_structure_returns_false(self):
        commitment, _, proof = self.prove()
        for intervals in (
            (),
            ((14, 10),),
            ((0, 4), (3, 8)),
            ((0, 4), (4, 8)),
            ((10, 14), (0, 4)),
            ((-1, 4),),
            ((0, 101),),
        ):
            self.assertFalse(
                verify_range_set(commitment, intervals, proof, b"ctx"),
                f"intervals={intervals}",
            )

    def test_bad_embedded_parameters_return_false(self):
        commitment, _, proof = self.prove()
        for field, bad_value in (
            ("prime", 3),
            ("generator", 1),
            ("generator", self.PRIME),
            ("h", 1),
            ("h", self.PRIME),
            ("element", 0),
            ("element", self.PRIME),
            ("lower", 101),
        ):
            bad = dataclasses.replace(commitment, **{field: bad_value})
            self.assertFalse(
                verify_range_set(bad, self.INTERVALS, proof, b"ctx"),
                f"{field}={bad_value}",
            )

    def test_verify_type_errors(self):
        commitment, _, proof = self.prove()
        with self.assertRaises(TypeError):
            verify_range_set("commitment", self.INTERVALS, proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_range_set(
                commitment, self.INTERVALS, (proof.t, proof.e, proof.s), b"ctx"
            )
        with self.assertRaises(TypeError):
            verify_range_set(commitment, self.INTERVALS, proof, "ctx")
        with self.assertRaises(TypeError):
            verify_range_set(
                commitment, self.INTERVALS,
                RangeSetProof(list(proof.t), proof.e, proof.s), b"ctx",
            )
        for bad_container in ("intervals", b"\x00\x01", bytearray(b"x"), 42, None):
            with self.assertRaises(TypeError):
                verify_range_set(commitment, bad_container, proof, b"ctx")
        # list containers are accepted; list pairs are not
        with self.assertRaises(TypeError):
            verify_range_set(commitment, [[0, 4]], proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_range_set(commitment, ((0, 4), [10, 14]), proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_range_set(commitment, ((0, 4, 9),), proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_range_set(commitment, (("0", 4),), proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_range_set(commitment, ((0, False),), proof, b"ctx")
        for bad_item in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_range_set(
                    commitment, self.INTERVALS,
                    RangeSetProof(proof.t[:-1] + (bad_item,), proof.e, proof.s),
                    b"ctx",
                )
            with self.assertRaises(TypeError):
                verify_range_set(
                    commitment, self.INTERVALS,
                    RangeSetProof(proof.t, proof.e[:-1] + (bad_item,), proof.s),
                    b"ctx",
                )
            with self.assertRaises(TypeError):
                verify_range_set(
                    commitment, self.INTERVALS,
                    RangeSetProof(proof.t, proof.e, proof.s[:-1] + (bad_item,)),
                    b"ctx",
                )
        bad_commitment = dataclasses.replace(commitment, h=True)
        with self.assertRaises(TypeError):
            verify_range_set(bad_commitment, self.INTERVALS, proof, b"ctx")

    def test_verifier_does_not_leak_the_hit_branch(self):
        # honest proofs for the same value under independent randomness only
        # differ in their simulated branches; equality is not asserted, but
        # every proof carries one branch per covered value and verifies.
        commitment, blinding = self.commit(value=12)
        first = prove_range_set(
            commitment, 12, blinding, self.INTERVALS, b"ctx",
            randbelow=counter_randbelow(1),
        )
        second = prove_range_set(
            commitment, 12, blinding, self.INTERVALS, b"ctx",
            randbelow=counter_randbelow(2),
        )
        self.assertEqual(len(first.t), len(second.t))
        self.assertTrue(verify_range_set(commitment, self.INTERVALS, first, b"ctx"))
        self.assertTrue(verify_range_set(commitment, self.INTERVALS, second, b"ctx"))

    def test_inputs_are_not_mutated(self):
        commitment, blinding, proof = self.prove()
        interval_snapshot = tuple(self.INTERVALS)
        commitment_snapshot = dataclasses.replace(commitment)
        proof_snapshot = RangeSetProof(proof.t, proof.e, proof.s)
        prove_range_set(
            commitment, 12, blinding, list(self.INTERVALS), b"ctx",
            randbelow=counter_randbelow(),
        )
        verify_range_set(commitment, list(self.INTERVALS), proof, b"ctx")
        self.assertEqual(tuple(self.INTERVALS), interval_snapshot)
        self.assertEqual(commitment, commitment_snapshot)
        self.assertEqual(proof, proof_snapshot)
        self.assertEqual(blinding, 1234)


class RangeSetBatchTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5
    INTERVALS = ((0, 4), (10, 14), (90, 100))

    def commit(self, value=5, lower=0, upper=100, blinding=1234, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def entry(
        self,
        value=12,
        intervals=INTERVALS,
        context=b"ctx",
        blinding=1234,
        lower=0,
        upper=100,
        **kwargs,
    ):
        commitment, returned = self.commit(value, lower, upper, blinding, **kwargs)
        proof = prove_range_set(
            commitment, value, returned, intervals, context,
            randbelow=counter_randbelow(),
        )
        return RangeSetBatchEntry(tuple(intervals), commitment, proof, context)

    # ---- entry object ------------------------------------------------------

    def test_entry_positional_defaults_equality_and_immutability(self):
        commitment, blinding = self.commit(value=12)
        intervals = ((10, 14),)
        proof = prove_range_set(
            commitment, 12, blinding, intervals, b"", randbelow=counter_randbelow()
        )
        entry = RangeSetBatchEntry(intervals, commitment, proof)
        self.assertEqual(entry.context, b"")
        self.assertEqual(RangeSetBatchEntry(intervals, commitment, proof, b""), entry)
        self.assertEqual(
            tuple(
                getattr(entry, name)
                for name in ("intervals", "commitment", "proof", "context")
            ),
            (tuple(intervals), commitment, proof, b""),
        )
        self.assertNotEqual(
            entry, RangeSetBatchEntry(intervals, commitment, proof, b"other")
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.context = b"other"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.proof = proof

    def test_entry_field_types(self):
        entry = self.entry()
        self.assertIsInstance(entry.intervals, tuple)
        self.assertIsInstance(entry.commitment, PedersenCommitment)
        self.assertIsInstance(entry.proof, RangeSetProof)
        self.assertIsInstance(entry.context, bytes)

    # ---- honest round trip -------------------------------------------------

    def test_honest_batch_verifies(self):
        entries = [self.entry(value=value) for value in (1, 11, 99)]
        self.assertTrue(verify_range_set_batch(entries, randbelow=counter_randbelow()))
        self.assertTrue(verify_range_set_batch(tuple(entries)))  # default source

    def test_single_entry_agrees_with_verify_range_set(self):
        entry = self.entry()
        self.assertTrue(
            verify_range_set_batch([entry], randbelow=counter_randbelow())
        )
        self.assertTrue(
            verify_range_set(
                entry.commitment, entry.intervals, entry.proof, entry.context
            )
        )

    def test_empty_batch_returns_false(self):
        self.assertFalse(verify_range_set_batch([], randbelow=counter_randbelow()))
        self.assertFalse(verify_range_set_batch(()))

    def test_ordering_and_duplicates_do_not_change_the_result(self):
        entries = [self.entry(value=value, blinding=1000 + value)
                   for value in (1, 11, 99)]
        self.assertTrue(
            verify_range_set_batch(list(reversed(entries)),
                                   randbelow=counter_randbelow())
        )
        shuffled = [entries[2], entries[0], entries[2], entries[1]]
        self.assertTrue(
            verify_range_set_batch(shuffled, randbelow=counter_randbelow())
        )

    def test_distinct_interval_lists_share_one_group(self):
        entries = [
            self.entry(value=12, intervals=((0, 4), (10, 14), (90, 100))),
            self.entry(
                value=25, intervals=((20, 30),), blinding=4321, lower=20, upper=30
            ),
        ]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_range_set_batch(entries, randbelow=recording))
        # 21 branches for the first entry, 11 for the second
        self.assertEqual(calls, [self.PRIME - 1] * 32)

    def test_mixed_groups_each_checked_under_its_own_parameters(self):
        small = self.entry()
        commitment, blinding = pedersen_commit(40, 0, 100, blinding=987654321)
        intervals = ((10, 50), (60, 90))
        proof = prove_range_set(commitment, 40, blinding, intervals, b"ctx")
        default_entry = RangeSetBatchEntry(intervals, commitment, proof, b"ctx")
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(
            verify_range_set_batch([small, default_entry], randbelow=recording)
        )
        self.assertEqual(sorted(set(calls)), sorted({self.PRIME - 1, DEFAULT_PRIME - 1}))
        self.assertEqual(len(calls), 21 + 72)

    # ---- randomness --------------------------------------------------------

    def test_randbelow_called_once_per_branch(self):
        entries = [self.entry(), self.entry(blinding=4321)]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_range_set_batch(entries, randbelow=recording))
        self.assertEqual(calls, [self.PRIME - 1] * 42)

    def test_fixed_coefficient_source_is_reproducible(self):
        entries = [self.entry(), self.entry(blinding=4321)]
        first = verify_range_set_batch(entries, randbelow=counter_randbelow(9))
        second = verify_range_set_batch(entries, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_random_linear_combination_not_per_proof_summary(self):
        # coefficients all 1: +1 and -1 response deltas cancel in the single
        # aggregate exponent sum, even though neither proof verifies alone
        first, second = self.entry(blinding=1234), self.entry(blinding=5555)
        first_tampered = RangeSetProof(
            first.proof.t, first.proof.e,
            first.proof.s[:-1] + (first.proof.s[-1] + 1,),
        )
        second_tampered = RangeSetProof(
            second.proof.t, second.proof.e,
            second.proof.s[:-1] + (second.proof.s[-1] - 1,),
        )
        self.assertFalse(
            verify_range_set(
                first.commitment, first.intervals, first_tampered, b"ctx"
            )
        )
        self.assertFalse(
            verify_range_set(
                second.commitment, second.intervals, second_tampered, b"ctx"
            )
        )
        forged = [
            RangeSetBatchEntry(first.intervals, first.commitment, first_tampered, b"ctx"),
            RangeSetBatchEntry(second.intervals, second.commitment, second_tampered, b"ctx"),
        ]
        self.assertTrue(verify_range_set_batch(forged, randbelow=lambda upper: 0))

    # ---- rejection ---------------------------------------------------------

    def test_one_invalid_entry_returns_false(self):
        good = self.entry()
        bad = RangeSetBatchEntry(
            good.intervals,
            good.commitment,
            RangeSetProof(
                good.proof.t, good.proof.e,
                good.proof.s[:-1] + (good.proof.s[-1] + 1,),
            ),
            good.context,
        )
        self.assertFalse(
            verify_range_set_batch([good, bad], randbelow=counter_randbelow())
        )
        self.assertFalse(
            verify_range_set_batch([bad, good], randbelow=counter_randbelow())
        )

    def test_tampering_fails(self):
        entry = self.entry()
        proof = entry.proof
        cases = [
            RangeSetProof(proof.t, proof.e, proof.s[:-1] + (proof.s[-1] + 1,)),
            RangeSetProof(
                proof.t,
                proof.e[:-1] + ((proof.e[-1] + 1) % self.PRIME,),
                proof.s,
            ),
            RangeSetProof(
                proof.t[:-1] + ((proof.t[-1] % (self.PRIME - 1)) + 1,),
                proof.e,
                proof.s,
            ),
        ]
        for forged in cases:
            self.assertFalse(
                verify_range_set_batch(
                    [RangeSetBatchEntry(entry.intervals, entry.commitment, forged, entry.context)],
                    randbelow=counter_randbelow(),
                ),
                f"batch accepted: {forged!r}",
            )

    def test_context_binds_proof(self):
        entry = self.entry(context=b"ctx")
        for bad_context in (b"", b"other"):
            bad = RangeSetBatchEntry(
                entry.intervals, entry.commitment, entry.proof, bad_context
            )
            self.assertFalse(
                verify_range_set_batch([bad], randbelow=counter_randbelow())
            )

    def test_interval_binding_fails(self):
        entry = self.entry()
        for intervals in (
            ((0, 4), (10, 13), (90, 100)),
            ((0, 4), (90, 100), (10, 14)),
            ((0, 4), (10, 14)),
        ):
            bad = RangeSetBatchEntry(
                intervals, entry.commitment, entry.proof, entry.context
            )
            self.assertFalse(
                verify_range_set_batch([bad], randbelow=counter_randbelow()),
                f"intervals={intervals}",
            )

    def test_foreign_commitment_fails(self):
        entry = self.entry()
        other, _ = self.commit(value=13, blinding=4321)
        self.assertFalse(
            verify_range_set_batch(
                [RangeSetBatchEntry(entry.intervals, other, entry.proof, entry.context)],
                randbelow=counter_randbelow(),
            )
        )

    def test_cancellation_does_not_cross_group_boundaries(self):
        first = self.entry(blinding=1234)
        commitment, blinding = self.commit(12, 0, 100, 333, h=7)
        other_proof = prove_range_set(
            commitment, 12, blinding, self.INTERVALS, b"ctx",
            randbelow=counter_randbelow(),
        )
        first_tampered = RangeSetProof(
            first.proof.t, first.proof.e,
            first.proof.s[:-1] + (first.proof.s[-1] + 1,),
        )
        other_tampered = RangeSetProof(
            other_proof.t, other_proof.e,
            other_proof.s[:-1] + (other_proof.s[-1] - 1,),
        )
        forged = [
            RangeSetBatchEntry(first.intervals, first.commitment, first_tampered, b"ctx"),
            RangeSetBatchEntry(self.INTERVALS, commitment, other_tampered, b"ctx"),
        ]
        self.assertFalse(verify_range_set_batch(forged, randbelow=lambda upper: 0))

    def test_bad_interval_structure_returns_false(self):
        entry = self.entry()
        for intervals in (
            (),
            ((14, 10),),
            ((0, 4), (3, 8)),
            ((10, 14), (0, 4)),
            ((-1, 4),),
            ((0, 101),),
            tuple((i, i) for i in range(257)),
        ):
            bad = RangeSetBatchEntry(
                intervals, entry.commitment, entry.proof, entry.context
            )
            self.assertFalse(
                verify_range_set_batch([bad], randbelow=counter_randbelow()),
                f"intervals={intervals}",
            )

    def test_bad_embedded_commitment_parameters_return_false(self):
        entry = self.entry()
        for name, value in (
            ("element", 0),
            ("prime", 3),
            ("generator", 1),
            ("h", self.PRIME),
            ("lower", 101),
        ):
            broken = dataclasses.replace(entry.commitment, **{name: value})
            bad = RangeSetBatchEntry(
                entry.intervals, broken, entry.proof, entry.context
            )
            self.assertFalse(
                verify_range_set_batch([bad], randbelow=counter_randbelow()), name
            )

    def test_invalid_entry_short_circuits_before_drawing(self):
        entry = self.entry()
        short = RangeSetProof(
            entry.proof.t[:-1], entry.proof.e, entry.proof.s
        )
        invalid = RangeSetBatchEntry(
            entry.intervals, entry.commitment, short, entry.context
        )
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertFalse(
            verify_range_set_batch([invalid, entry], randbelow=recording)
        )
        self.assertEqual(calls, [])  # invalid entry rejected before any draw
        self.assertFalse(
            verify_range_set_batch([entry, invalid], randbelow=recording)
        )
        self.assertEqual(calls, [self.PRIME - 1] * 21)

    # ---- type errors -------------------------------------------------------

    def test_type_errors(self):
        entry = self.entry()
        for bad in ("entries", b"entries", bytearray(b"x"), 42, None):
            with self.assertRaises(TypeError):
                verify_range_set_batch(bad)
        with self.assertRaises(TypeError):
            verify_range_set_batch([(entry.intervals, entry.commitment, entry.proof)])
        with self.assertRaises(TypeError):
            verify_range_set_batch([
                RangeSetBatchEntry(entry.intervals, entry.commitment, entry.proof, "ctx")
            ])
        with self.assertRaises(TypeError):
            verify_range_set_batch([
                RangeSetBatchEntry(
                    entry.intervals, entry.commitment,
                    (entry.proof.t, entry.proof.e, entry.proof.s), b"ctx",
                )
            ])
        with self.assertRaises(TypeError):
            verify_range_set_batch([
                RangeSetBatchEntry(entry.intervals, "commitment", entry.proof, b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_range_set_batch([
                RangeSetBatchEntry(
                    [(0, 4)], entry.commitment, entry.proof, b"ctx"
                )
            ])
        with self.assertRaises(TypeError):
            verify_range_set_batch([
                RangeSetBatchEntry(
                    ((0, 4, 9),), entry.commitment, entry.proof, b"ctx"
                )
            ])
        bool_proof = RangeSetProof(
            (True,) * len(entry.proof.t), entry.proof.e, entry.proof.s
        )
        with self.assertRaises(TypeError):
            verify_range_set_batch([
                RangeSetBatchEntry(entry.intervals, entry.commitment, bool_proof, b"ctx")
            ])
        list_intervals = RangeSetBatchEntry(
            list(entry.intervals), entry.commitment, entry.proof, b"ctx"
        )
        with self.assertRaises(TypeError):
            verify_range_set_batch([list_intervals])
        with self.assertRaises(TypeError):
            verify_range_set_batch([entry], randbelow=7)

    def test_type_errors_are_preflighted_for_whole_batch(self):
        good = self.entry()
        bad = RangeSetBatchEntry(
            good.intervals, "commitment", good.proof, good.context
        )
        # the bad entry is found even when it comes last, before any drawing
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        with self.assertRaises(TypeError):
            verify_range_set_batch([good, bad], randbelow=recording)
        self.assertEqual(calls, [])

    def test_coefficient_source_errors(self):
        entry = self.entry()
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_range_set_batch(
                    [entry], randbelow=lambda upper, bad=bad: bad
                )
        for bad in (-1, self.PRIME - 1, self.PRIME):
            with self.assertRaises(ValueError):
                verify_range_set_batch(
                    [entry], randbelow=lambda upper, bad=bad: bad
                )

    # ---- hygiene -----------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = [self.entry(), self.entry(blinding=4321)]
        snapshot = [dataclasses.replace(entry) for entry in entries]
        verify_range_set_batch(entries, randbelow=counter_randbelow())
        self.assertEqual(entries, snapshot)

    def test_default_group_parameters_are_usable(self):
        commitment, blinding = pedersen_commit(40, 0, 100, blinding=987654321)
        intervals = ((10, 50), (60, 90))
        proof = prove_range_set(commitment, 40, blinding, intervals, b"demo")
        entry = RangeSetBatchEntry(intervals, commitment, proof, b"demo")
        self.assertTrue(
            verify_range_set_batch([entry], randbelow=counter_randbelow())
        )


if __name__ == "__main__":
    unittest.main()
