"""Tests for BoundRegionBundleBatch / prove/verify_region_bundle_batch_bound.

The bound batch freezes an ordered sequence of RegionProofBundle envelopes —
RegionProof, RegionWideProof and RegionIntervalProof envelopes may mix, each
with its own legal group parameters — into one Merkle root. Each leaf is the
domain separator ``b"zkregion/rbb/v1"`` concatenated with the envelope's
canonical encode_region_proof_bundle bytes; the complete MerkleMultiProof
covers every index from zero to the batch length minus one with empty
siblings, and verification re-runs the unchanged per-envelope
verify_region_proof_bundle checks under the committed root.
"""

import dataclasses
import unittest

from zkregion import (
    BoundRegionBundleBatch,
    IntervalRangeProof,
    MerkleMultiProof,
    PedersenCommitment,
    RangeProof,
    Region,
    RegionIntervalProof,
    RegionProof,
    RegionProofBundle,
    RegionWideProof,
    WideRangeProof,
    encode_region_proof_bundle,
    merkle_root,
    pedersen_commit,
    prove_multi_inclusion,
    prove_region,
    prove_region_bundle_batch_bound,
    prove_region_interval,
    prove_region_wide,
    verify_region_bundle_batch_bound,
)
import zkregion

SMALL_PRIME = 104729  # a small prime keeps the group arithmetic readable
DOMAIN = b"zkregion/rbb/v1"


def counter_randbelow(start: int = 1):
    state = {"value": start}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


def _commit(value, lower, upper, blinding, **kwargs):
    kwargs.setdefault("prime", SMALL_PRIME)
    kwargs.setdefault("generator", 3)
    kwargs.setdefault("h", 5)
    return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)


def _narrow(x=40, y=60, region=None, context=b"ctx", **commit_kwargs):
    region = Region(0, 100, 0, 100) if region is None else region
    x_commitment, x_r = _commit(x, region.min_x, region.max_x, 1234, **commit_kwargs)
    y_commitment, y_r = _commit(y, region.min_y, region.max_y, 4321, **commit_kwargs)
    proof = prove_region(
        x_commitment, y_commitment, x, y, x_r, y_r, region, context,
        randbelow=counter_randbelow(),
    )
    return RegionProofBundle(x_commitment, y_commitment, region, context, proof)


def _wide(x=40, y=60, region=None, context=b"wide-ctx", **commit_kwargs):
    region = Region(0, 255, -2048, 2047) if region is None else region
    x_commitment, x_r = _commit(x, region.min_x, region.max_x, 1234, **commit_kwargs)
    y_commitment, y_r = _commit(y, region.min_y, region.max_y, 4321, **commit_kwargs)
    proof = prove_region_wide(
        x_commitment, y_commitment, x, y, x_r, y_r, region, context,
        randbelow=counter_randbelow(),
    )
    return RegionProofBundle(x_commitment, y_commitment, region, context, proof)


def _interval(x=40, y=-300, region=None, context=b"interval-ctx", **commit_kwargs):
    region = Region(-5, 100, -1000, 2000) if region is None else region
    x_commitment, x_r = _commit(x, region.min_x, region.max_x, 1234, **commit_kwargs)
    y_commitment, y_r = _commit(y, region.min_y, region.max_y, 4321, **commit_kwargs)
    proof = prove_region_interval(
        x_commitment, y_commitment, x, y, x_r, y_r, region, context,
        randbelow=counter_randbelow(),
    )
    return RegionProofBundle(x_commitment, y_commitment, region, context, proof)


def _mixed():
    return [_narrow(), _wide(), _interval()]


def _leaves(entries):
    return [DOMAIN + encode_region_proof_bundle(entry) for entry in entries]


class BoundRegionBundleBatchConstructionTest(unittest.TestCase):
    def test_positional_fields_equality_frozen_and_unchecked(self):
        entries = tuple(_mixed())
        proof = MerkleMultiProof(3, (0, 1, 2), ())
        batch = BoundRegionBundleBatch(entries, 3, proof)
        self.assertEqual(
            [field.name for field in dataclasses.fields(batch)],
            ["entries", "leaf_count", "proof"],
        )
        self.assertEqual(batch.entries, entries)
        self.assertEqual(batch.leaf_count, 3)
        self.assertIs(batch.proof, proof)
        again = BoundRegionBundleBatch(entries, 3, proof)
        self.assertEqual(again, batch)
        self.assertEqual(hash(again), hash(batch))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 4
        # construction performs no validation at all
        raw = BoundRegionBundleBatch("entries", True, "proof")
        self.assertEqual(raw.entries, "entries")
        self.assertIs(raw.leaf_count, True)
        self.assertEqual(raw.proof, "proof")


class ProveRegionBundleBatchBoundTest(unittest.TestCase):
    def test_mixed_batch_binds_and_verifies(self):
        entries = _mixed()
        batch, root = prove_region_bundle_batch_bound(entries)
        self.assertIsInstance(batch, BoundRegionBundleBatch)
        self.assertIsInstance(root, bytes)
        self.assertEqual(len(root), 32)
        self.assertEqual(batch.entries, tuple(entries))
        self.assertEqual(batch.leaf_count, 3)
        self.assertEqual(batch.proof.leaf_count, 3)
        self.assertEqual(batch.proof.indices, (0, 1, 2))
        self.assertEqual(batch.proof.siblings, ())
        self.assertTrue(verify_region_bundle_batch_bound(batch, root))

    def test_root_matches_merkle_root_over_domain_separated_envelopes(self):
        entries = _mixed()
        batch, root = prove_region_bundle_batch_bound(entries)
        leaves = _leaves(entries)
        self.assertEqual(root, merkle_root(leaves))
        self.assertEqual(batch.proof, prove_multi_inclusion(leaves, (0, 1, 2)))

    def test_single_odd_even_and_duplicate_batches(self):
        narrow, wide, interval = _mixed()
        for entries in (
            [narrow],
            [narrow, wide],
            [narrow, wide, interval],
            [narrow, wide, interval, narrow, wide],
            [narrow, narrow],
        ):
            batch, root = prove_region_bundle_batch_bound(entries)
            self.assertEqual(batch.leaf_count, len(entries))
            self.assertEqual(batch.entries, tuple(entries))
            self.assertEqual(batch.proof.indices, tuple(range(len(entries))))
            self.assertEqual(batch.proof.siblings, ())
            self.assertTrue(verify_region_bundle_batch_bound(batch, root))

    def test_determinism_same_ordered_inputs(self):
        entries = _mixed()
        batch1, root1 = prove_region_bundle_batch_bound(entries)
        batch2, root2 = prove_region_bundle_batch_bound(list(entries))
        self.assertEqual(batch1, batch2)
        self.assertEqual(root1, root2)

    def test_tuple_input_and_distinct_group_parameters(self):
        entries = (
            _narrow(),
            _wide(prime=zkregion.DEFAULT_PRIME, generator=zkregion.DEFAULT_GENERATOR, h=None),
            _interval(generator=7, h=11),
        )
        batch, root = prove_region_bundle_batch_bound(entries)
        self.assertEqual(batch.entries, entries)
        self.assertTrue(verify_region_bundle_batch_bound(batch, root))

    def test_inputs_never_mutated_and_result_immune_to_caller_mutation(self):
        entries = _mixed()
        snapshot = list(entries)
        batch, root = prove_region_bundle_batch_bound(entries)
        self.assertEqual(entries, snapshot)
        entries.append(_narrow())
        entries[0] = _wide()
        self.assertEqual(batch.entries, tuple(snapshot))
        self.assertTrue(verify_region_bundle_batch_bound(batch, root))

    def test_empty_batch_raises_value_error(self):
        for entries in ([], ()):
            with self.assertRaises(ValueError):
                prove_region_bundle_batch_bound(entries)

    def test_container_type_errors(self):
        for entries in (object(), "entries", b"entries", (x for x in [])):
            with self.assertRaises(TypeError):
                prove_region_bundle_batch_bound(entries)

    def test_nested_type_errors_cover_the_whole_batch(self):
        good = _narrow()
        bool_commitment = PedersenCommitment(
            element=1, lower=True, upper=5,
            prime=SMALL_PRIME, generator=3, h=5,
        )
        bad_bool = RegionProofBundle(
            bool_commitment, good.y_commitment, good.region, b"c", good.proof
        )
        bad_context = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, "c", good.proof
        )
        bad_proof = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, b"c", object()
        )
        for bad in (bad_bool, bad_context, bad_proof, object()):
            with self.assertRaises(TypeError):
                prove_region_bundle_batch_bound([bad])
            # a late wrong type still raises behind an earlier valid entry
            with self.assertRaises(TypeError):
                prove_region_bundle_batch_bound([good, bad])

    def test_failing_envelope_raises_value_error(self):
        good = _narrow()
        tampered = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, b"other", good.proof
        )
        with self.assertRaises(ValueError):
            prove_region_bundle_batch_bound([tampered])
        with self.assertRaises(ValueError):
            prove_region_bundle_batch_bound([good, tampered])

    def test_invalid_interval_proof_shape_raises_value_error(self):
        good = _interval()
        malformed = IntervalRangeProof(
            low_commitments=(1, 2),
            low_challenges=((1, 2),),
            low_responses=((1, 2),),
            high_commitments=(3, 4),
            high_challenges=((3, 4),),
            high_responses=((3, 4),),
        )
        proof = RegionIntervalProof(x_proof=malformed, y_proof=malformed)
        bundle = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, b"c", proof
        )
        with self.assertRaises(ValueError):
            prove_region_bundle_batch_bound([bundle])


class VerifyRegionBundleBatchBoundTest(unittest.TestCase):
    def setUp(self):
        self.entries = _mixed()
        self.batch, self.root = prove_region_bundle_batch_bound(self.entries)

    def _batch(self, entries=None, leaf_count=None, proof=None):
        return BoundRegionBundleBatch(
            self.batch.entries if entries is None else tuple(entries),
            self.batch.leaf_count if leaf_count is None else leaf_count,
            self.batch.proof if proof is None else proof,
        )

    def test_round_trip_true(self):
        self.assertTrue(verify_region_bundle_batch_bound(self.batch, self.root))

    def test_deleted_inserted_swapped_or_replaced_entries_return_false(self):
        entries = list(self.batch.entries)
        # deletion
        self.assertFalse(
            verify_region_bundle_batch_bound(
                self._batch(entries[:-1], 2, MerkleMultiProof(3, (0, 1), ())),
                self.root,
            )
        )
        # insertion
        self.assertFalse(
            verify_region_bundle_batch_bound(
                self._batch(entries + [entries[0]], 4), self.root
            )
        )
        # swapped distinct entries
        swapped = [entries[1], entries[0], entries[2]]
        self.assertFalse(
            verify_region_bundle_batch_bound(self._batch(swapped), self.root)
        )
        # a replaced public field (context) under the original root
        good = entries[0]
        replaced = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, b"other", good.proof
        )
        self.assertFalse(
            verify_region_bundle_batch_bound(
                self._batch([replaced] + entries[1:]), self.root
            )
        )

    def test_wrong_and_malformed_roots_return_false(self):
        self.assertFalse(verify_region_bundle_batch_bound(self.batch, b"\x00" * 32))
        _, other_root = prove_region_bundle_batch_bound([_narrow()])
        self.assertFalse(verify_region_bundle_batch_bound(self.batch, other_root))
        for root in (b"", b"\x00" * 31, b"\x00" * 33):
            self.assertFalse(verify_region_bundle_batch_bound(self.batch, root))

    def test_count_mismatches_return_false(self):
        for leaf_count in (0, -1, 2, 4):
            self.assertFalse(
                verify_region_bundle_batch_bound(
                    self._batch(leaf_count=leaf_count), self.root
                )
            )
        # proof leaf_count disagreeing with the batch count
        proof = MerkleMultiProof(4, (0, 1, 2), ())
        self.assertFalse(
            verify_region_bundle_batch_bound(self._batch(proof=proof), self.root)
        )

    def test_incomplete_duplicate_or_reordered_coverage_returns_false(self):
        for indices in ((), (0, 1), (1, 2), (0, 0, 1), (0, 2, 1), (0, 1, 3)):
            proof = MerkleMultiProof(3, indices, ())
            self.assertFalse(
                verify_region_bundle_batch_bound(self._batch(proof=proof), self.root),
                indices,
            )

    def test_extra_sibling_digests_return_false(self):
        proof = MerkleMultiProof(3, (0, 1, 2), (b"\x00" * 32,))
        self.assertFalse(
            verify_region_bundle_batch_bound(self._batch(proof=proof), self.root)
        )

    def test_empty_batch_returns_false(self):
        batch = BoundRegionBundleBatch((), 0, MerkleMultiProof(0, (), ()))
        self.assertFalse(verify_region_bundle_batch_bound(batch, self.root))

    def test_partial_disclosure_proof_is_rejected(self):
        # a genuine multi-proof over a strict subset never verifies
        leaves = _leaves(self.entries)
        partial = prove_multi_inclusion(leaves, (0, 2))
        batch = BoundRegionBundleBatch(self.batch.entries, 3, partial)
        self.assertFalse(verify_region_bundle_batch_bound(batch, self.root))

    def test_envelope_whose_own_verification_fails_returns_false(self):
        good = self.entries[0]
        tampered = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, b"other", good.proof
        )
        entries = [tampered] + list(self.entries[1:])
        leaves = _leaves(entries)
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, (0, 1, 2))
        batch = BoundRegionBundleBatch(tuple(entries), 3, proof)
        self.assertFalse(verify_region_bundle_batch_bound(batch, root))

    def test_type_errors(self):
        good_batch = self.batch
        with self.assertRaises(TypeError):
            verify_region_bundle_batch_bound(object(), self.root)
        for root in ("root", 7, None):
            with self.assertRaises(TypeError):
                verify_region_bundle_batch_bound(good_batch, root)
        # non-tuple entries
        with self.assertRaises(TypeError):
            verify_region_bundle_batch_bound(
                BoundRegionBundleBatch(list(self.entries), 3, good_batch.proof),
                self.root,
            )
        # bool / non-integer leaf_count
        for leaf_count in (True, "3"):
            with self.assertRaises(TypeError):
                verify_region_bundle_batch_bound(
                    self._batch(leaf_count=leaf_count), self.root
                )
        # wrong proof object and malformed proof fields
        with self.assertRaises(TypeError):
            verify_region_bundle_batch_bound(self._batch(proof="proof"), self.root)
        for proof in (
            MerkleMultiProof(True, (0, 1, 2), ()),
            MerkleMultiProof(3, [0, 1, 2], ()),
            MerkleMultiProof(3, (0, True, 2), ()),
            MerkleMultiProof(3, (0, 1, 2), [b"\x00" * 32]),
            MerkleMultiProof(3, (0, 1, 2), ("sibling",)),
        ):
            with self.assertRaises(TypeError):
                verify_region_bundle_batch_bound(self._batch(proof=proof), self.root)

    def test_nested_entry_type_errors_raise_before_any_semantic_check(self):
        good = self.entries[0]
        bool_commitment = PedersenCommitment(
            element=1, lower=False, upper=5,
            prime=SMALL_PRIME, generator=3, h=5,
        )
        bad_bool = RegionProofBundle(
            bool_commitment, good.y_commitment, good.region, b"c", good.proof
        )
        bad_context = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, 7, good.proof
        )
        bad_proof = RegionProofBundle(
            good.x_commitment, good.y_commitment, good.region, b"c", object()
        )
        for bad in (bad_bool, bad_context, bad_proof, object()):
            with self.assertRaises(TypeError):
                verify_region_bundle_batch_bound(
                    self._batch([bad]), self.root
                )
            # a wrong type in the last envelope raises even when an earlier
            # envelope is already doomed to fail the root check
            with self.assertRaises(TypeError):
                verify_region_bundle_batch_bound(
                    self._batch([bad, good]), self.root
                )

    def test_inputs_never_mutated(self):
        entries = list(self.batch.entries)
        batch = BoundRegionBundleBatch(tuple(entries), 3, self.batch.proof)
        self.assertTrue(verify_region_bundle_batch_bound(batch, self.root))
        self.assertEqual(list(batch.entries), entries)


if __name__ == "__main__":
    unittest.main()
