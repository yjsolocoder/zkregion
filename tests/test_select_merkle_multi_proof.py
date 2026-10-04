"""Tests for selective disclosure on Merkle multi-proof bundles.

select_merkle_multi_proof shrinks a MerkleMultiProofBundle to a subset of
its proven indices without the full leaf set. These tests pin the field-
for-field equality with prove_multi_inclusion, envelope round-trip and
verification behavior, type/value error precedence and input immutability.
"""

import copy
import dataclasses
import itertools
import unittest

from zkregion import (
    MerkleInclusionBatchEntry,
    MerkleMultiProof,
    MerkleMultiProofBundle,
    decode_merkle_multi_proof_bundle,
    encode_merkle_multi_proof_bundle,
    merge_inclusion_proofs,
    merkle_root,
    prove_inclusion,
    prove_multi_inclusion,
    select_merkle_multi_proof,
    verify_merkle_multi_proof_bundle,
)

DIGEST = b"\x00" * 32


def _bundle(leaves, subset):
    return MerkleMultiProofBundle(
        root=merkle_root(leaves),
        proof=prove_multi_inclusion(leaves, list(subset)),
        entries=tuple((index, leaves[index]) for index in subset),
    )


def _full_bundle(leaves):
    return _bundle(leaves, range(len(leaves)))


class SelectMerkleMultiProofEquivalenceTests(unittest.TestCase):
    def test_exhaustive_small_trees(self):
        for leaf_count in range(1, 9):
            leaves = [bytes([index, 7]) for index in range(leaf_count)]
            full = _full_bundle(leaves)
            self.assertTrue(verify_merkle_multi_proof_bundle(full))
            self.assertEqual(
                select_merkle_multi_proof(full, list(range(leaf_count))),
                full,
            )
            for size in range(1, leaf_count + 1):
                for subset in itertools.combinations(range(leaf_count), size):
                    with self.subTest(leaf_count=leaf_count, subset=subset):
                        selected = select_merkle_multi_proof(
                            full, list(subset)
                        )
                        self.assertEqual(
                            selected.proof,
                            prove_multi_inclusion(leaves, list(subset)),
                        )
                        self.assertEqual(selected.root, full.root)
                        self.assertEqual(
                            selected.proof.leaf_count, leaf_count
                        )
                        self.assertEqual(
                            selected.entries,
                            tuple((i, leaves[i]) for i in subset),
                        )
                        self.assertTrue(
                            verify_merkle_multi_proof_bundle(selected)
                        )
                        # No unselected leaf bytes appear in the envelope.
                        self.assertEqual(
                            sorted(index for index, _ in selected.entries),
                            list(subset),
                        )
                        decoded = decode_merkle_multi_proof_bundle(
                            encode_merkle_multi_proof_bundle(selected)
                        )
                        self.assertEqual(decoded, selected)
                        self.assertTrue(
                            verify_merkle_multi_proof_bundle(decoded)
                        )

    def test_unordered_and_duplicate_indices(self):
        leaves = [bytes([i]) for i in range(7)]
        full = _full_bundle(leaves)
        ordered = select_merkle_multi_proof(full, [1, 3, 5])
        self.assertEqual(
            select_merkle_multi_proof(full, [5, 3, 1, 5, 1]), ordered
        )
        self.assertEqual(
            select_merkle_multi_proof(full, (3, 1, 5, 3, 5)), ordered
        )
        self.assertEqual(ordered.proof.indices, (1, 3, 5))

    def test_tuple_and_list_indices(self):
        leaves = [b"a", b"b", b"c", b"d"]
        full = _full_bundle(leaves)
        subset = [0, 2]
        from_list = select_merkle_multi_proof(full, list(subset))
        from_tuple = select_merkle_multi_proof(full, tuple(subset))
        self.assertEqual(from_list, from_tuple)

    def test_keep_all_equals_original(self):
        for leaf_count in (1, 2, 3, 5, 8):
            leaves = [bytes([index]) for index in range(leaf_count)]
            full = _full_bundle(leaves)
            self.assertEqual(
                select_merkle_multi_proof(full, list(range(leaf_count))),
                full,
            )
            self.assertEqual(
                select_merkle_multi_proof(
                    full, list(range(leaf_count))[::-1] * 2
                ),
                full,
            )

    def test_sequential_pruning_equals_direct(self):
        leaves = [bytes([index]) for index in range(8)]
        full = _full_bundle(leaves)
        target = {1, 4, 7}
        removed = [i for i in range(8) if i not in target]
        current = full
        for step in range(len(removed)):
            kept = sorted(target | set(removed[step + 1:]))
            current = select_merkle_multi_proof(full, kept)
        direct = select_merkle_multi_proof(full, sorted(target))
        self.assertEqual(current, direct)
        # Also chain each call on the previous envelope.
        current = full
        for index in removed:
            kept = [
                i
                for i in range(8)
                if i != index and i in {p for p, _ in current.entries}
            ]
            current = select_merkle_multi_proof(current, kept)
        self.assertEqual(current, direct)

    def test_single_leaf_tree(self):
        full = _full_bundle([b"only"])
        selected = select_merkle_multi_proof(full, [0, 0])
        self.assertEqual(selected, full)
        self.assertEqual(selected.proof.siblings, ())
        self.assertTrue(verify_merkle_multi_proof_bundle(selected))

    def test_last_leaf_only_odd_and_even(self):
        for leaf_count in (1, 2, 3, 4, 5, 6, 7, 8):
            leaves = [bytes([index]) for index in range(leaf_count)]
            full = _full_bundle(leaves)
            selected = select_merkle_multi_proof(full, [leaf_count - 1])
            self.assertEqual(
                selected.proof,
                prove_multi_inclusion(leaves, [leaf_count - 1]),
            )
            self.assertTrue(verify_merkle_multi_proof_bundle(selected))

    def test_duplicate_leaf_contents_kept_separately(self):
        leaves = [b"same", b"other", b"same", b"same", b"tail"]
        full = _full_bundle(leaves)
        selected = select_merkle_multi_proof(full, [0, 2, 3])
        self.assertEqual(
            selected.entries,
            ((0, b"same"), (2, b"same"), (3, b"same")),
        )
        self.assertEqual(
            selected.proof, prove_multi_inclusion(leaves, [0, 2, 3])
        )
        self.assertTrue(verify_merkle_multi_proof_bundle(selected))

    def test_partial_bundle_input(self):
        leaves = [bytes([index]) for index in range(6)]
        partial = _bundle(leaves, [0, 2, 4])
        selected = select_merkle_multi_proof(partial, [4, 0])
        self.assertEqual(
            selected.proof, prove_multi_inclusion(leaves, [0, 4])
        )
        self.assertEqual(
            selected.entries, ((0, leaves[0]), (4, leaves[4]))
        )
        self.assertTrue(verify_merkle_multi_proof_bundle(selected))
        self.assertEqual(
            select_merkle_multi_proof(partial, [0, 2, 4]), partial
        )

    def test_input_from_merge_inclusion_proofs(self):
        leaves = [bytes([index, 9]) for index in range(6)]
        root = merkle_root(leaves)
        entries = [
            MerkleInclusionBatchEntry(
                leaf=leaves[index],
                root=root,
                proof=prove_inclusion(leaves, index),
            )
            for index in (0, 2, 4)
        ]
        merged = merge_inclusion_proofs(entries, 6)
        selected = select_merkle_multi_proof(merged, (4,))
        self.assertEqual(
            selected.proof, prove_multi_inclusion(leaves, [4])
        )
        self.assertTrue(verify_merkle_multi_proof_bundle(selected))
        decoded = decode_merkle_multi_proof_bundle(
            encode_merkle_multi_proof_bundle(selected)
        )
        self.assertEqual(decoded, selected)

    def test_deterministic(self):
        leaves = [bytes([index]) for index in range(6)]
        full = _full_bundle(leaves)
        first = select_merkle_multi_proof(full, [1, 4])
        second = select_merkle_multi_proof(full, [1, 4])
        self.assertEqual(first, second)
        self.assertEqual(
            encode_merkle_multi_proof_bundle(first),
            encode_merkle_multi_proof_bundle(second),
        )

    def test_result_is_immutable(self):
        leaves = [b"a", b"b"]
        selected = select_merkle_multi_proof(_full_bundle(leaves), [0])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            selected.root = b"x"  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            selected.proof = None  # type: ignore[misc]


class SelectMerkleMultiProofTypeTests(unittest.TestCase):
    def setUp(self):
        leaves = [bytes([index]) for index in range(6)]
        self.bundle = _bundle(leaves, [1, 3, 5])

    def test_indices_container_types(self):
        for bad in ("abc", b"abc", bytearray(b"abc"), 42, 3.14, None, {1}):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    select_merkle_multi_proof(self.bundle, bad)

    def test_indices_element_types(self):
        for bad in (1.0, "1", None, b"1", True, False, object()):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    select_merkle_multi_proof(self.bundle, [1, bad])

    def test_type_error_precedence(self):
        # Semantically invalid bundle but type-bad indices: TypeError wins.
        bad_root = MerkleMultiProofBundle(
            root=b"x", proof=self.bundle.proof, entries=self.bundle.entries
        )
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(bad_root, {1, 2})
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(bad_root, [True])
        # Type-bad element together with an out-of-range value.
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(self.bundle, [6, True])

    def test_bundle_and_nested_field_types(self):
        with self.assertRaises(TypeError):
            select_merkle_multi_proof("not a bundle", [1])
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(
                MerkleMultiProofBundle(
                    "x", self.bundle.proof, self.bundle.entries
                ),
                [1],
            )
        bad_proof = MerkleMultiProof(
            leaf_count=6, indices=[1, 3, 5], siblings=()
        )
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(
                MerkleMultiProofBundle(
                    DIGEST, bad_proof, self.bundle.entries
                ),
                [1],
            )
        bool_count = MerkleMultiProof(
            leaf_count=True, indices=(1,), siblings=()
        )
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(
                MerkleMultiProofBundle(
                    DIGEST, bool_count, ((1, b"x"),)
                ),
                [1],
            )
        bad_entries = ((1, "not bytes"), (3, b"y"), (5, b"z"))
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(
                MerkleMultiProofBundle(
                    DIGEST, self.bundle.proof, bad_entries
                ),
                [1],
            )
        bad_sibling = MerkleMultiProof(
            leaf_count=6, indices=(1, 3), siblings=(1,)
        )
        with self.assertRaises(TypeError):
            select_merkle_multi_proof(
                MerkleMultiProofBundle(
                    DIGEST, bad_sibling, ((1, b"a"), (3, b"b"))
                ),
                [1],
            )


class SelectMerkleMultiProofValueTests(unittest.TestCase):
    def setUp(self):
        self.leaves = [bytes([index]) for index in range(6)]
        self.bundle = _bundle(self.leaves, [1, 3, 5])

    def test_bad_selection(self):
        for bad in ([], [-1], [6], [100], [0], [2], [-5, 1], [4]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    select_merkle_multi_proof(self.bundle, bad)

    def test_invalid_bundle_rejected_even_if_leaf_would_be_removed(self):
        tampered = MerkleMultiProofBundle(
            root=self.bundle.root,
            proof=self.bundle.proof,
            entries=tuple(
                (index, self.leaves[index] if index != 1 else b"ZZ")
                for index in (1, 3, 5)
            ),
        )
        with self.assertRaises(ValueError):
            select_merkle_multi_proof(tampered, [3, 5])

    def test_bad_root_length_and_value(self):
        for root in (b"\x01" * 31, b"\x01" * 32):
            bad = MerkleMultiProofBundle(
                root=root, proof=self.bundle.proof, entries=self.bundle.entries
            )
            with self.assertRaises(ValueError):
                select_merkle_multi_proof(bad, [1])

    def test_extra_and_missing_siblings(self):
        extra = MerkleMultiProof(
            leaf_count=self.bundle.proof.leaf_count,
            indices=self.bundle.proof.indices,
            siblings=self.bundle.proof.siblings + (b"\x02" * 32,),
        )
        with self.assertRaises(ValueError):
            select_merkle_multi_proof(
                MerkleMultiProofBundle(
                    self.bundle.root, extra, self.bundle.entries
                ),
                [1],
            )
        missing = MerkleMultiProof(
            leaf_count=self.bundle.proof.leaf_count,
            indices=self.bundle.proof.indices,
            siblings=self.bundle.proof.siblings[:-1],
        )
        with self.assertRaises(ValueError):
            select_merkle_multi_proof(
                MerkleMultiProofBundle(
                    self.bundle.root, missing, self.bundle.entries
                ),
                [1],
            )

    def test_wrong_sibling_length(self):
        proof = MerkleMultiProof(
            leaf_count=6, indices=(1, 3), siblings=(b"short",)
        )
        bundle = MerkleMultiProofBundle(
            DIGEST, proof, ((1, b"a"), (3, b"b"))
        )
        with self.assertRaises(ValueError):
            select_merkle_multi_proof(bundle, [1])

    def test_entries_indices_mismatch(self):
        bad = MerkleMultiProofBundle(
            root=self.bundle.root,
            proof=self.bundle.proof,
            entries=tuple(
                (index, self.leaves[index]) for index in (1, 3, 4)
            ),
        )
        with self.assertRaises(ValueError):
            select_merkle_multi_proof(bad, [1])

    def test_duplicate_proof_indices(self):
        proof = MerkleMultiProof(
            leaf_count=6,
            indices=(1, 1),
            siblings=(DIGEST, DIGEST, DIGEST),
        )
        bundle = MerkleMultiProofBundle(
            self.bundle.root,
            proof,
            ((1, self.leaves[1]), (1, self.leaves[1])),
        )
        with self.assertRaises(ValueError):
            select_merkle_multi_proof(bundle, [1])

    def test_non_positive_leaf_count(self):
        proof = MerkleMultiProof(leaf_count=0, indices=(0,), siblings=())
        bundle = MerkleMultiProofBundle(
            DIGEST, proof, ((0, b"x"),)
        )
        with self.assertRaises(ValueError):
            select_merkle_multi_proof(bundle, [0])


class SelectMerkleMultiProofInputSafetyTests(unittest.TestCase):
    def test_inputs_not_mutated(self):
        leaves = [bytes([index]) for index in range(6)]
        bundle = _bundle(leaves, [1, 3, 5])
        bundle_snapshot = copy.deepcopy(bundle)
        indices = [5, 1, 3, 1]
        indices_snapshot = list(indices)
        select_merkle_multi_proof(bundle, indices)
        self.assertEqual(indices, indices_snapshot)
        self.assertEqual(bundle, bundle_snapshot)
        self.assertEqual(bundle.entries, bundle_snapshot.entries)
        self.assertEqual(bundle.proof, bundle_snapshot.proof)


if __name__ == "__main__":
    unittest.main()
