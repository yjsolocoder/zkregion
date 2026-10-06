"""Tests for BoundEqualValueBatch / prove/verify_equal_value_batch_bound.

The bound batch freezes a complete equal-value batch together with the
Merkle multi-inclusion proof committing to every entry. Each leaf binds
the twelve left/right commitment public fields, the context and the
complete proof; the verifier checks the outer inclusion against the
given root first (drawing no randomness) and only then delegates to the
unchanged verify_equal_value_batch.
"""

import dataclasses
import unittest

import zkregion
from zkregion import (
    DEFAULT_PRIME,
    BoundEqualValueBatch,
    EqualValueBatchEntry,
    EqualValueProof,
    MerkleMultiProof,
    PedersenCommitment,
    merkle_root,
    pedersen_commit,
    prove_equal_value,
    prove_equal_value_batch_bound,
    prove_multi_inclusion,
    verify_equal_value,
    verify_equal_value_batch,
    verify_equal_value_batch_bound,
)


def _entry(
    value,
    left_range,
    right_range,
    *,
    context=b"",
    prime=DEFAULT_PRIME,
    generator=None,
    blinding_left=7,
    blinding_right=11,
):
    kwargs = {"prime": prime, "blinding": blinding_left}
    if generator is not None:
        kwargs["generator"] = generator
    left, used_left = pedersen_commit(value, left_range[0], left_range[1], **kwargs)
    kwargs = {"prime": prime, "blinding": blinding_right}
    if generator is not None:
        kwargs["generator"] = generator
    right, used_right = pedersen_commit(
        value, right_range[0], right_range[1], **kwargs
    )
    proof = prove_equal_value(
        left, right, value, used_left, used_right, context
    )
    return EqualValueBatchEntry(left, right, proof, context)


def _recording_randbelow():
    calls = []

    def randbelow(upper):
        calls.append(upper)
        return 0

    return randbelow, calls


def _rebound(entries):
    """Recompute root and complete multi proof over replacement entries."""
    ordered = tuple(entries)
    leaves = [zkregion._bound_equal_value_leaf(entry) for entry in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    return BoundEqualValueBatch(ordered, len(ordered), proof), root


class BoundEqualValueBatchConstructionTest(unittest.TestCase):
    def test_frozen_value_equality_and_no_validation(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4), context=b"session")
        batch, root = prove_equal_value_batch_bound([e1, e2])
        self.assertEqual(
            [field.name for field in dataclasses.fields(batch)],
            ["entries", "leaf_count", "proof"],
        )
        self.assertIsInstance(batch, BoundEqualValueBatch)
        self.assertEqual(batch.entries, (e1, e2))
        self.assertEqual(batch.leaf_count, 2)
        self.assertIsInstance(batch.proof, MerkleMultiProof)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 3
        # construction performs no validation at all
        raw = EqualValueProof((), (), (), (), ())
        unchecked = BoundEqualValueBatch("entries", True, "proof")
        self.assertEqual(unchecked.entries, "entries")
        self.assertIs(unchecked.proof, "proof")
        self.assertTrue(unchecked.leaf_count)


class ProveEqualValueBatchBoundTest(unittest.TestCase):
    def test_single_odd_even_and_duplicates_roundtrip(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4), context=b"session")
        e3 = _entry(0, (-3, 3), (-1, 1))
        for ordered in ([e1], [e1, e2, e3], [e1, e2], [e1, e1], [e2, e1, e2]):
            batch, root = prove_equal_value_batch_bound(ordered)
            self.assertEqual(len(root), 32)
            self.assertEqual(batch.leaf_count, len(ordered))
            self.assertEqual(batch.entries, tuple(ordered))
            # complete coverage from zero, no siblings needed
            self.assertEqual(batch.proof.indices, tuple(range(len(ordered))))
            self.assertEqual(batch.proof.siblings, ())
            self.assertEqual(batch.proof.leaf_count, len(ordered))
            self.assertTrue(
                verify_equal_value_batch_bound(batch, root), ordered
            )

    def test_determinism_same_ordered_input(self):
        e1 = _entry(5, (0, 10), (2, 8), context=b"a")
        e2 = _entry(-7, (-10, 0), (-7, -1), context=b"b")
        batch1, root1 = prove_equal_value_batch_bound([e1, e2])
        batch2, root2 = prove_equal_value_batch_bound((e1, e2))
        self.assertEqual(batch1, batch2)
        self.assertEqual(root1, root2)
        # order matters
        batch_rev, root_rev = prove_equal_value_batch_bound([e2, e1])
        self.assertNotEqual(batch1, batch_rev)
        self.assertNotEqual(root1, root_rev)

    def test_boundary_ranges_mixed_groups_and_contexts(self):
        entries = [
            _entry(-100, (-200, -50), (-150, -90)),  # negative bounds
            _entry(0, (-10, 10), (-2, 2)),  # cross zero
            _entry(4, (4, 10), (0, 4)),  # single-point intersection
            _entry(5, (0, 10), (5, 200)),  # different declared ranges
        ]
        entries.append(_entry(1, (0, 5), (0, 5), prime=1019, generator=2))
        entries.append(_entry(5, (0, 10), (2, 8), context=b"other"))
        batch, root = prove_equal_value_batch_bound(entries)
        self.assertTrue(verify_equal_value_batch_bound(batch, root))

    def test_input_list_mutation_does_not_affect_batch(self):
        e1 = _entry(5, (0, 10), (2, 8))
        entries = [e1]
        batch, root = prove_equal_value_batch_bound(entries)
        entries.append(_entry(3, (-5, 5), (3, 4)))
        del entries[0]
        self.assertEqual(batch.entries, (e1,))
        self.assertEqual(batch.leaf_count, 1)
        self.assertTrue(verify_equal_value_batch_bound(batch, root))

    def test_inputs_are_not_mutated(self):
        entries = [_entry(5, (0, 10), (2, 8)), _entry(0, (-3, 3), (-1, 1))]
        snapshot = [dataclasses.replace(entry) for entry in entries]
        prove_equal_value_batch_bound(entries)
        self.assertEqual(entries, snapshot)

    def test_empty_and_invalid_entries_raise_valueerror(self):
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound([])
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound(())
        good = _entry(5, (0, 10), (2, 8))
        widened = dataclasses.replace(good.left, upper=good.left.upper + 1)
        bad = EqualValueBatchEntry(widened, good.right, good.proof, b"")
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound([good, bad])
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound([bad, good])

    def test_type_errors(self):
        for bad in ("entries", b"entries", bytearray(b"entries"), {1}, 7, None):
            with self.assertRaises(TypeError):
                prove_equal_value_batch_bound(bad)
        good = _entry(5, (0, 10), (2, 8))
        # wrong item type, including in the last position
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound([good, "nope"])
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound([42])
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound([True])
        tampered = EqualValueBatchEntry(
            "left", good.right, good.proof, good.context
        )
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound([good, tampered])
        # bool posed as a commitment integer
        moved = dataclasses.replace(good.left, element=True)
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound(
                [EqualValueBatchEntry(moved, good.right, good.proof, b"")]
            )
        bad_proof = dataclasses.replace(good.proof, e=list(good.proof.e))
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound(
                [EqualValueBatchEntry(good.left, good.right, bad_proof, b"")]
            )

    def test_prove_draws_no_randomness(self):
        # prove_equal_value_batch_bound has no randbelow parameter at all
        e1 = _entry(5, (0, 10), (2, 8))
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound([e1], randbelow=lambda n: 0)


class VerifyEqualValueBatchBoundTest(unittest.TestCase):
    def setUp(self):
        self.e1 = _entry(5, (0, 10), (2, 8), context=b"a")
        self.e2 = _entry(3, (-5, 5), (3, 4), context=b"b")
        self.batch, self.root = prove_equal_value_batch_bound([self.e1, self.e2])

    def test_default_randbelow_roundtrip(self):
        self.assertTrue(
            verify_equal_value_batch_bound(self.batch, self.root)
        )

    def test_wrong_root_sizes_and_values(self):
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(
                self.batch, b"\x00" * 32, randbelow=randbelow
            )
        )
        self.assertFalse(
            verify_equal_value_batch_bound(
                self.batch, self.root[:-1], randbelow=randbelow
            )
        )
        self.assertFalse(
            verify_equal_value_batch_bound(
                self.batch, self.root + b"x", randbelow=randbelow
            )
        )
        self.assertFalse(
            verify_equal_value_batch_bound(
                self.batch, b"", randbelow=randbelow
            )
        )
        # outer failure must not consume randomness
        self.assertEqual(calls, [])

    def test_deletion_insertion_count_mismatch(self):
        # deletion: a single entry cannot pass under the two-leaf root
        sub_leaves = [zkregion._bound_equal_value_leaf(self.e1)]
        sub_proof = prove_multi_inclusion(sub_leaves, (0,))
        for forged in (
            BoundEqualValueBatch((self.e1,), 1, sub_proof),
            BoundEqualValueBatch((self.e1, self.e1), 2, sub_proof),
            BoundEqualValueBatch(
                self.batch.entries, 3, self.batch.proof
            ),
            BoundEqualValueBatch(
                self.batch.entries, 1, self.batch.proof
            ),
        ):
            randbelow, calls = _recording_randbelow()
            self.assertFalse(
                verify_equal_value_batch_bound(
                    forged, self.root, randbelow=randbelow
                )
            )
            self.assertEqual(calls, [])

    def test_legal_subset_cannot_impersonate_whole_batch(self):
        leaves = [zkregion._bound_equal_value_leaf(e) for e in (self.e1, self.e2)]
        # a perfectly valid single-leaf inclusion proof against the same tree
        subset_proof = prove_multi_inclusion(leaves, (1,))
        forged = BoundEqualValueBatch((self.e2,), 1, subset_proof)
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(forged, self.root, randbelow=randbelow)
        )
        self.assertEqual(calls, [])

    def test_reordering_and_duplicate_replacement(self):
        # swap the two distinct entries
        swapped, swapped_root = _rebound([self.e2, self.e1])
        self.assertTrue(verify_equal_value_batch_bound(swapped, swapped_root))
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(
                swapped, self.root, randbelow=randbelow
            )
        )
        self.assertEqual(calls, [])
        # duplicate one entry in place of the other
        dup, dup_root = _rebound([self.e1, self.e1])
        self.assertTrue(verify_equal_value_batch_bound(dup, dup_root))
        self.assertFalse(verify_equal_value_batch_bound(dup, self.root))

    def test_field_replacements_change_root(self):
        # context replacement
        tampered_ctx = EqualValueBatchEntry(
            self.e1.left, self.e1.right, self.e1.proof, b"z"
        )
        # left commitment public field replacement
        moved = dataclasses.replace(
            self.e1.left, element=self.e1.left.element + 1
        )
        tampered_commit = EqualValueBatchEntry(
            moved, self.e1.right, self.e1.proof, self.e1.context
        )
        # a proof field replacement
        prime = self.e1.left.prime
        tampered_proof_obj = dataclasses.replace(
            self.e1.proof,
            t_left=((self.e1.proof.t_left[0] + 1) % (prime - 1) + 1,)
            + self.e1.proof.t_left[1:],
        )
        tampered_proof = EqualValueBatchEntry(
            self.e1.left, self.e1.right, tampered_proof_obj, self.e1.context
        )
        for replacement in (tampered_ctx, tampered_commit, tampered_proof):
            forged, forged_root = _rebound([replacement, self.e2])
            self.assertNotEqual(forged_root, self.root)
            randbelow, calls = _recording_randbelow()
            self.assertFalse(
                verify_equal_value_batch_bound(
                    forged, self.root, randbelow=randbelow
                )
            )
            self.assertEqual(calls, [])

    def test_index_gaps_duplicates_reordering_and_bad_proof(self):
        leaves = [zkregion._bound_equal_value_leaf(e) for e in (self.e1, self.e2)]
        good = self.batch.proof
        variants = (
            MerkleMultiProof(2, (), ()),  # empty coverage
            MerkleMultiProof(2, (1,), good.siblings),  # gap at zero
            MerkleMultiProof(2, (0, 0), good.siblings),  # duplicate
            MerkleMultiProof(2, (1, 0), good.siblings),  # reordered
            MerkleMultiProof(3, (0, 1), good.siblings),  # wrong proof leaf_count
            MerkleMultiProof(
                2, (0, 1), (b"\x00" * 32,)
            ),  # superfluous sibling
        )
        for proof in variants:
            forged = BoundEqualValueBatch(self.batch.entries, 2, proof)
            randbelow, calls = _recording_randbelow()
            self.assertFalse(
                verify_equal_value_batch_bound(
                    forged, self.root, randbelow=randbelow
                ),
                proof,
            )
            self.assertEqual(calls, [])

    def test_distinct_domain_separator(self):
        leaves = [zkregion._bound_equal_value_leaf(e) for e in (self.e1, self.e2)]
        other = b"zkregion/evb/v1"
        replacement = b"zkregion/xxx/v1"
        self.assertEqual(len(other), len(replacement))
        foreign_leaves = [leaf.replace(other, replacement) for leaf in leaves]
        foreign_root = merkle_root(foreign_leaves)
        self.assertNotEqual(foreign_root, self.root)
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(
                self.batch, foreign_root, randbelow=randbelow
            )
        )
        self.assertEqual(calls, [])

    def test_inner_crypto_failure_after_outer_passes_draws(self):
        # rebind entries whose response was tampered: the root matches the
        # tampered bytes, so the outer check passes and randomness is drawn
        # before the aggregate equations fail
        bad_proof = dataclasses.replace(
            self.e1.proof,
            s_left=(self.e1.proof.s_left[0] + 1,) + self.e1.proof.s_left[1:],
        )
        bad_entry = EqualValueBatchEntry(
            self.e1.left, self.e1.right, bad_proof, self.e1.context
        )
        forged, forged_root = _rebound([bad_entry, self.e2])
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(
                forged, forged_root, randbelow=randbelow
            )
        )
        # intersection sizes: 7 and 2 -> 2*(7+2) = 18 draws
        self.assertEqual(calls, [DEFAULT_PRIME - 1] * 18)

    def test_inner_structural_failure_after_outer_passes(self):
        # illegal commitment rebinds to a matching root: outer passes,
        # inner verify_equal_value_batch returns False before any draw
        illegal = dataclasses.replace(self.e1.left, element=0)
        bad_entry = EqualValueBatchEntry(
            illegal, self.e1.right, self.e1.proof, self.e1.context
        )
        forged, forged_root = _rebound([bad_entry, self.e2])
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(
                forged, forged_root, randbelow=randbelow
            )
        )
        self.assertEqual(calls, [])

    def test_randbelow_protocol_passthrough(self):
        # draw order/count matches the plain equal-value batch exactly
        randbelow, calls = _recording_randbelow()
        self.assertTrue(
            verify_equal_value_batch_bound(
                self.batch, self.root, randbelow=randbelow
            )
        )
        plain_calls = []
        plain = lambda upper: plain_calls.append(upper) or 0
        self.assertTrue(
            verify_equal_value_batch(list(self.batch.entries), randbelow=plain)
        )
        self.assertEqual(calls, plain_calls)
        self.assertEqual(calls, [DEFAULT_PRIME - 1] * (2 * 7 + 2 * 2))
        # randbelow is keyword-only
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(self.batch, self.root, None)
        # source exceptions propagate unchanged after outer passes
        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            verify_equal_value_batch_bound(self.batch, self.root, randbelow=boom)
        for returned in (True, False, 1.0, "0", None):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    self.batch, self.root, randbelow=lambda upper: returned
                )
        for returned in (-1, DEFAULT_PRIME - 1):
            with self.assertRaises(ValueError):
                verify_equal_value_batch_bound(
                    self.batch,
                    self.root,
                    randbelow=lambda upper, value=returned: value,
                )

    # ------------------------------------------------------------------
    # TypeError preflight: the whole nested batch is walked first

    def test_typeerror_container_and_object_types(self):
        for bad in ("x", b"x", bytearray(b"x"), 42, 3.5, object(), None):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(bad, self.root)
        for bad in ("0" * 32, 1, bytearray(b"0" * 32), None):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(self.batch, bad)
        # entries must be a tuple
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(
                    list(self.batch.entries), 2, self.batch.proof
                ),
                self.root,
            )
        # bool / non-int count
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(
                    self.batch.entries, True, self.batch.proof
                ),
                self.root,
            )
        # wrong proof object
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(self.batch.entries, 2, "proof"),
                self.root,
            )

    def test_typeerror_nested_proof_fields(self):
        bad_proof = MerkleMultiProof("2", (0, 1), ())
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(self.batch.entries, 2, bad_proof),
                self.root,
            )
        bad_proof = MerkleMultiProof(2, [0, 1], ())
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(self.batch.entries, 2, bad_proof),
                self.root,
            )
        bad_proof = MerkleMultiProof(2, (False, 1), ())
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(self.batch.entries, 2, bad_proof),
                self.root,
            )
        bad_proof = MerkleMultiProof(2, (0, 1), ("sibling",))
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(self.batch.entries, 2, bad_proof),
                self.root,
            )

    def test_typeerror_wrong_entry_type_including_last(self):
        good = self.e1
        for bad in (42, True, False, (good.left, good.right, good.proof), "x"):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch((bad,), 1, self.batch.proof),
                    self.root,
                )
            # a bad last entry is not hidden by an earlier invalid entry
            structurally_bad = EqualValueBatchEntry(
                dataclasses.replace(good.left, element=0),
                good.right,
                good.proof,
                b"",
            )
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch(
                        (structurally_bad, bad), 2, self.batch.proof
                    ),
                    self.root,
                )

    def test_typeerror_commitment_proof_context_fields(self):
        good = self.e1
        for side_name, side in (("left", good.left), ("right", good.right)):
            other = good.right if side_name == "left" else good.left
            kwargs = {
                "left": good.left,
                "right": good.right,
                "proof": good.proof,
                "context": good.context,
                side_name: "not-a-commitment",
            }
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch(
                        (EqualValueBatchEntry(**kwargs),), 1, self.batch.proof
                    ),
                    self.root,
                )
            for field_name in (
                "element", "lower", "upper", "prime", "generator", "h"
            ):
                tampered = dataclasses.replace(
                    side, **{field_name: True}
                )
                kwargs = {
                    "left": good.left,
                    "right": good.right,
                    "proof": good.proof,
                    "context": good.context,
                    side_name: tampered,
                }
                with self.assertRaises(TypeError):
                    verify_equal_value_batch_bound(
                        BoundEqualValueBatch(
                            (EqualValueBatchEntry(**kwargs),),
                            1,
                            self.batch.proof,
                        ),
                        self.root,
                    )
        # proof fields: non-tuple and a bool inside a tuple
        for field_name in ("t_left", "t_right", "e", "s_left", "s_right"):
            tampered = dataclasses.replace(
                good.proof,
                **{field_name: list(getattr(good.proof, field_name))},
            )
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch(
                        (
                            EqualValueBatchEntry(
                                good.left, good.right, tampered, good.context
                            ),
                        ),
                        1,
                        self.batch.proof,
                    ),
                    self.root,
                )
            original = getattr(good.proof, field_name)
            tampered = dataclasses.replace(
                good.proof, **{field_name: (True,) + original[1:]}
            )
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch(
                        (
                            EqualValueBatchEntry(
                                good.left, good.right, tampered, good.context
                            ),
                        ),
                        1,
                        self.batch.proof,
                    ),
                    self.root,
                )
        for bad_context in ("bytes", 1, bytearray(b"x"), None):
            entry = EqualValueBatchEntry(
                good.left, good.right, good.proof, bad_context
            )
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch((entry,), 1, self.batch.proof),
                    self.root,
                )

    def test_typeerror_randbelow_not_callable(self):
        for bad in (None, 5, b"x", object()):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(self.batch, self.root, randbelow=bad)
        # checked during preflight: even an outer failure raises
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                self.batch, b"\x00" * 32, randbelow=123
            )


if __name__ == "__main__":
    unittest.main()
