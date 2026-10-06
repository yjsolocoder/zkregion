"""Tests for BoundEqualValueBatch / prove/verify_equal_value_batch_bound.

The bound batch freezes a complete verify_equal_value_batch input sequence
— order, count and duplicates included — into a Merkle root. Each leaf
binds both commitments' twelve public fields, the context and every field
of the EqualValueProof under the category-specific domain separator
``b"zkregion/evb/v1"``; the outer inclusion check must pass before the
unchanged inner random linear batch verification draws any randomness.
"""

import dataclasses
import itertools
import unittest

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
    verify_equal_value_batch,
    verify_equal_value_batch_bound,
)
import zkregion


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


def _bound_over(entries):
    """Build (batch, root) over arbitrary (possibly invalid) entry leaves."""
    ordered = tuple(entries)
    leaves = [zkregion._bound_equal_value_leaf(entry) for entry in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    return BoundEqualValueBatch(ordered, len(ordered), proof), root


class BoundEqualValueBatchConstructionTest(unittest.TestCase):
    def test_positional_fields_equality_frozen_and_unchecked(self):
        e1 = _entry(5, (0, 10), (2, 8))
        batch, root = prove_equal_value_batch_bound([e1])
        self.assertEqual(
            [field.name for field in dataclasses.fields(batch)],
            ["entries", "leaf_count", "proof"],
        )
        self.assertEqual(batch.entries, (e1,))
        self.assertEqual(batch.leaf_count, 1)
        self.assertIsInstance(batch.proof, MerkleMultiProof)
        again = BoundEqualValueBatch(batch.entries, 1, batch.proof)
        self.assertEqual(again, batch)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 2
        # construction performs no validation at all
        raw = BoundEqualValueBatch("entries", True, "proof")
        self.assertEqual(raw.entries, "entries")
        self.assertIs(raw.leaf_count, True)
        self.assertEqual(raw.proof, "proof")


class ProveEqualValueBatchBoundTest(unittest.TestCase):
    def test_single_odd_even_and_duplicate_batches(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4), context=b"s")
        e3 = _entry(0, (-3, 3), (-1, 1))
        for entries in ([e1], [e1, e2, e3], [e1, e2], [e2, e2]):
            batch, root = prove_equal_value_batch_bound(entries)
            self.assertEqual(len(root), 32)
            self.assertEqual(batch.leaf_count, len(entries))
            self.assertEqual(batch.entries, tuple(entries))
            self.assertEqual(batch.proof.indices, tuple(range(len(entries))))
            self.assertEqual(batch.proof.siblings, ())
            self.assertEqual(batch.proof.leaf_count, len(entries))
            self.assertTrue(verify_equal_value_batch_bound(batch, root))

    def test_determinism_same_ordered_inputs(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4), context=b"s")
        b1, r1 = prove_equal_value_batch_bound([e1, e2])
        b2, r2 = prove_equal_value_batch_bound((e1, e2))
        self.assertEqual(b1, b2)
        self.assertEqual(r1, r2)
        # order is part of the binding
        b3, r3 = prove_equal_value_batch_bound([e2, e1])
        self.assertNotEqual(b3, b1)
        self.assertNotEqual(r3, r1)

    def test_negative_cross_zero_single_point_mixed_groups_contexts(self):
        entries = [
            _entry(-100, (-200, -50), (-150, -90)),
            _entry(0, (-10, 10), (-2, 2), context=b"zero"),
            _entry(4, (4, 10), (0, 4)),  # single-point intersection
            _entry(5, (0, 10), (5, 200)),  # very different declared ranges
            _entry(1, (0, 5), (0, 5), prime=1019, generator=2),
            _entry(2, (0, 6), (1, 3), prime=1019, generator=3),
            _entry(5, (0, 10), (2, 8), context=b"other"),
        ]
        batch, root = prove_equal_value_batch_bound(entries)
        self.assertTrue(verify_equal_value_batch_bound(batch, root))

    def test_caller_list_mutation_does_not_change_result(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4))
        source = [e1]
        batch, root = prove_equal_value_batch_bound(source)
        source.append(e2)
        source[0] = e2
        del source[:]
        self.assertEqual(batch.leaf_count, 1)
        self.assertEqual(batch.entries, (e1,))
        self.assertTrue(verify_equal_value_batch_bound(batch, root))

    def test_accepts_generic_sequence_but_rejects_strings(self):
        from collections.abc import Sequence as SequenceABC

        e1 = _entry(5, (0, 10), (2, 8))

        class Seq(SequenceABC):
            def __init__(self, items):
                self._items = items

            def __len__(self):
                return len(self._items)

            def __getitem__(self, index):
                return self._items[index]

        batch, root = prove_equal_value_batch_bound(Seq([e1]))
        self.assertTrue(verify_equal_value_batch_bound(batch, root))
        for bad in ("x", b"x", bytearray(b"x"), 42, {e1}, None):
            with self.assertRaises(TypeError):
                prove_equal_value_batch_bound(bad)

    def test_no_plaintext_values_or_blindings_accepted(self):
        import inspect

        signature = inspect.signature(prove_equal_value_batch_bound)
        # only the entry sequence: no value, blinding or random source
        self.assertEqual(list(signature.parameters), ["entries"])

    def test_prove_is_deterministic_and_draws_no_randomness(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4), context=b"s")
        b1, r1 = prove_equal_value_batch_bound([e1, e2])
        b2, r2 = prove_equal_value_batch_bound([e1, e2])
        self.assertEqual(b1, b2)
        self.assertEqual(r1, r2)

    # ------------------------------------------------------------------
    # ValueError: emptiness and invalid inner proofs

    def test_empty_batch_raises_valueerror(self):
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound([])
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound(())

    def test_invalid_inner_proof_raises_valueerror(self):
        good = _entry(5, (0, 10), (2, 8))
        # illegal commitment
        illegal = dataclasses.replace(good.left, element=0)
        bad_commitment = EqualValueBatchEntry(
            illegal, good.right, good.proof, b""
        )
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound([good, bad_commitment])
        # wrong group between the two commitments
        small = _entry(1, (0, 5), (0, 5), prime=1019, generator=2)
        mismatched = EqualValueBatchEntry(good.left, small.right, good.proof, b"")
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound([mismatched])
        # structurally impossible proof (empty intersection)
        left, _ = pedersen_commit(1, 0, 3, blinding=2)
        right, _ = pedersen_commit(9, 7, 10, blinding=2)
        proof = EqualValueProof(
            (1,) * 4, (1,) * 4, (0,) * 4, (0,) * 4, (0,) * 4
        )
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound(
                [EqualValueBatchEntry(left, right, proof, b"")]
            )
        # tampered response fails the deterministic per-branch equations
        tampered = dataclasses.replace(
            good.proof,
            s_left=(good.proof.s_left[0] + 1,) + good.proof.s_left[1:],
        )
        with self.assertRaises(ValueError):
            prove_equal_value_batch_bound(
                [EqualValueBatchEntry(good.left, good.right, tampered, b"")]
            )

    # ------------------------------------------------------------------
    # TypeError preflight walks the whole batch

    def test_typeerror_wrong_entry_and_nested_types(self):
        good = _entry(5, (0, 10), (2, 8))
        for bad in (42, True, False, (good.left, good.right, good.proof), "x"):
            with self.assertRaises(TypeError):
                prove_equal_value_batch_bound([bad])
            # a wrong later entry is not hidden by an earlier invalid entry
            with self.assertRaises(TypeError):
                prove_equal_value_batch_bound([good, good, bad])

    def test_typeerror_commitment_proof_context_and_randbelow(self):
        good = _entry(5, (0, 10), (2, 8), context=b"c")
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound(
                [EqualValueBatchEntry("L", good.right, good.proof, b"")]
            )
        for field_name in (
            "element", "lower", "upper", "prime", "generator", "h"
        ):
            tampered_commitment = dataclasses.replace(
                good.left, **{field_name: True}
            )
            with self.assertRaises(TypeError):
                prove_equal_value_batch_bound(
                    [
                        good,
                        EqualValueBatchEntry(
                            tampered_commitment, good.right, good.proof, b""
                        ),
                    ]
                )
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound(
                [EqualValueBatchEntry(good.left, good.right, "proof", b"")]
            )
        for field_name in ("t_left", "t_right", "e", "s_left", "s_right"):
            tampered = dataclasses.replace(
                good.proof,
                **{field_name: (True,) + getattr(good.proof, field_name)[1:]},
            )
            with self.assertRaises(TypeError):
                prove_equal_value_batch_bound(
                    [
                        good,
                        EqualValueBatchEntry(
                            good.left, good.right, tampered, b""
                        ),
                    ]
                )
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound(
                [EqualValueBatchEntry(good.left, good.right, good.proof, 1)]
            )
        # the generation entry has no random-source parameter
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound([good], randbelow=lambda n: 0)

    def test_type_preflight_walks_whole_batch(self):
        good = _entry(5, (0, 10), (2, 8))
        # structural problems must not mask type problems in later entries
        illegal = dataclasses.replace(good.left, element=0)
        structurally_bad = EqualValueBatchEntry(
            illegal, good.right, good.proof, b""
        )
        with self.assertRaises(TypeError):
            prove_equal_value_batch_bound([structurally_bad, "x"])


class VerifyEqualValueBatchBoundTest(unittest.TestCase):
    def test_roundtrip_default_randbelow_and_inputs_unchanged(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(-7, (-10, 0), (-7, -1), context=b"c")
        entries = [e1, e2]
        snapshot = [dataclasses.replace(entry) for entry in entries]
        batch, root = prove_equal_value_batch_bound(entries)
        self.assertTrue(verify_equal_value_batch_bound(batch, root))
        self.assertEqual(entries, snapshot)

    # ------------------------------------------------------------------
    # outer failures: False and no randomness consumed

    def test_wrong_root_and_root_length(self):
        e1 = _entry(5, (0, 10), (2, 8))
        batch, root = prove_equal_value_batch_bound([e1])
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(
                batch, b"\x00" * 32, randbelow=randbelow
            )
        )
        self.assertFalse(
            verify_equal_value_batch_bound(batch, root[:-1], randbelow=randbelow)
        )
        self.assertFalse(
            verify_equal_value_batch_bound(batch, root + b"x", randbelow=randbelow)
        )
        self.assertEqual(calls, [])

    def test_reorder_delete_append_and_count_mismatch(self):
        e1 = _entry(5, (0, 10), (2, 8), context=b"a")
        e2 = _entry(3, (-5, 5), (3, 4), context=b"b")
        batch, root = prove_equal_value_batch_bound([e1, e2])
        randbelow, calls = _recording_randbelow()
        # a valid subset cannot stand in for the whole batch
        self.assertFalse(
            verify_equal_value_batch_bound(
                BoundEqualValueBatch((e1,), 1, batch.proof),
                root,
                randbelow=randbelow,
            )
        )
        self.assertFalse(
            verify_equal_value_batch_bound(
                BoundEqualValueBatch((e2, e1), 2, batch.proof),
                root,
                randbelow=randbelow,
            )
        )
        self.assertFalse(
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 3, batch.proof),
                root,
                randbelow=randbelow,
            )
        )
        self.assertFalse(
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 1, batch.proof),
                root,
                randbelow=randbelow,
            )
        )
        self.assertEqual(calls, [])

    def test_index_gaps_duplicates_and_reordering(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4))
        batch, root = prove_equal_value_batch_bound([e1, e2])
        for indices in ((1,), (0, 0), (1, 0), (0, 2), ()):
            proof = MerkleMultiProof(
                batch.proof.leaf_count, indices, batch.proof.siblings
            )
            self.assertFalse(
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch(batch.entries, 2, proof), root
                ),
                indices,
            )
        # proof leaf_count disagreeing with the batch count
        proof = MerkleMultiProof(3, (0, 1), batch.proof.siblings)
        self.assertFalse(
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 2, proof), root
            )
        )

    def test_field_tampering_changes_leaves(self):
        e1 = _entry(5, (0, 10), (2, 8), context=b"a")
        e2 = _entry(3, (-5, 5), (3, 4), context=b"b")
        batch, root = prove_equal_value_batch_bound([e1, e2])
        randbelow, calls = _recording_randbelow()

        def reject(variant, label):
            self.assertFalse(
                verify_equal_value_batch_bound(
                    BoundEqualValueBatch(
                        (variant, e2), 2, batch.proof
                    ),
                    root,
                    randbelow=randbelow,
                ),
                label,
            )

        # every public field of both commitments participates
        for field_name in (
            "element", "lower", "upper", "prime", "generator", "h"
        ):
            reject(
                EqualValueBatchEntry(
                    dataclasses.replace(
                        e1.left,
                        **{field_name: getattr(e1.left, field_name) + 1},
                    ),
                    e1.right,
                    e1.proof,
                    e1.context,
                ),
                f"left {field_name}",
            )
            reject(
                EqualValueBatchEntry(
                    e1.left,
                    dataclasses.replace(
                        e1.right,
                        **{field_name: getattr(e1.right, field_name) + 1},
                    ),
                    e1.proof,
                    e1.context,
                ),
                f"right {field_name}",
            )
        reject(
            EqualValueBatchEntry(e1.left, e1.right, e1.proof, b"z"),
            "context",
        )
        # swapped left/right
        reject(
            EqualValueBatchEntry(e1.right, e1.left, e1.proof, e1.context),
            "swapped sides",
        )
        # every field of the inner proof participates
        prime = e1.left.prime
        for field_name, altered in (
            ("t_left", (e1.proof.t_left[0] + 1) % (prime - 1) + 1),
            ("t_right", (e1.proof.t_right[0] + 1) % (prime - 1) + 1),
            ("e", (e1.proof.e[0] + 1) % prime),
            ("s_left", e1.proof.s_left[0] + 1),
            ("s_right", e1.proof.s_right[0] + 1),
        ):
            original = getattr(e1.proof, field_name)
            reject(
                EqualValueBatchEntry(
                    e1.left,
                    e1.right,
                    dataclasses.replace(
                        e1.proof, **{field_name: (altered,) + original[1:]}
                    ),
                    e1.context,
                ),
                f"proof {field_name}",
            )
        self.assertEqual(calls, [])

    def test_empty_batch_false_without_draws(self):
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch_bound(
                BoundEqualValueBatch((), 0, MerkleMultiProof(0,(), ())),
                b"\x00" * 32,
                randbelow=randbelow,
            )
        )
        self.assertEqual(calls, [])

    # ------------------------------------------------------------------
    # outer passes, inner rejection: False (root rebuilt over the same leaves)

    def test_inner_rejection_after_outer_pass(self):
        good = _entry(5, (0, 10), (2, 8))

        def inner_false(variant, label):
            batch, root = _bound_over([variant])
            randbelow, calls = _recording_randbelow()
            self.assertFalse(
                verify_equal_value_batch_bound(
                    batch, root, randbelow=randbelow
                ),
                label,
            )
            self.assertEqual(calls, [], label)

        # illegal commitment
        inner_false(
            EqualValueBatchEntry(
                dataclasses.replace(good.left, element=0),
                good.right,
                good.proof,
                b"",
            ),
            "illegal commitment",
        )
        # mismatched in-entry group
        small = _entry(1, (0, 5), (0, 5), prime=1019, generator=2)
        inner_false(
            EqualValueBatchEntry(good.left, small.right, good.proof, b""),
            "group mismatch",
        )
        # context mismatch breaks the challenge binding
        inner_false(
            EqualValueBatchEntry(good.left, good.right, good.proof, b"other"),
            "context mismatch",
        )
        # empty intersection
        left, _ = pedersen_commit(1, 0, 3, blinding=2)
        right, _ = pedersen_commit(9, 7, 10, blinding=2)
        proof = EqualValueProof(
            (1,) * 4, (1,) * 4, (0,) * 4, (0,) * 4, (0,) * 4
        )
        inner_false(
            EqualValueBatchEntry(left, right, proof, b""),
            "empty intersection",
        )
        # oversized intersection (>256 integers)
        wide_left, _ = pedersen_commit(0, 0, 256, blinding=2)
        wide_right, _ = pedersen_commit(0, 0, 256, blinding=3)
        oversized = EqualValueProof(
            (1,) * 257, (1,) * 257, (0,) * 257, (0,) * 257, (0,) * 257
        )
        inner_false(
            EqualValueBatchEntry(wide_left, wide_right, oversized, b""),
            "oversized intersection",
        )
        # wrong proof field lengths
        inner_false(
            EqualValueBatchEntry(
                good.left,
                good.right,
                dataclasses.replace(
                    good.proof, t_left=good.proof.t_left[:-1]
                ),
                b"",
            ),
            "short t_left",
        )

    def test_inner_crypto_failure_after_outer_pass_draws_then_fails(self):
        good = _entry(5, (0, 10), (2, 8))
        tampered = dataclasses.replace(
            good.proof,
            s_left=(good.proof.s_left[0] + 1,) + good.proof.s_left[1:],
        )
        variant = EqualValueBatchEntry(good.left, good.right, tampered, b"")
        batch, root = _bound_over([variant])
        randbelow, calls = _recording_randbelow()  # weight 1 still detects
        self.assertFalse(
            verify_equal_value_batch_bound(batch, root, randbelow=randbelow)
        )
        self.assertEqual(len(calls), 14)

    # ------------------------------------------------------------------
    # randomness contract after a successful outer check

    def test_draws_only_after_outer_pass_in_batch_order(self):
        e1 = _entry(5, (0, 10), (2, 8))  # intersection size 7 -> 14 draws
        e2 = _entry(0, (-3, 3), (-1, 1))  # intersection size 3 -> 6 draws
        batch, root = prove_equal_value_batch_bound([e1, e2])
        randbelow, calls = _recording_randbelow()
        self.assertTrue(
            verify_equal_value_batch_bound(batch, root, randbelow=randbelow)
        )
        self.assertEqual(calls, [DEFAULT_PRIME - 1] * 20)
        order = []
        sequence = itertools.count()

        def numbered(upper):
            order.append(next(sequence))
            return 0

        self.assertTrue(
            verify_equal_value_batch_bound(batch, root, randbelow=numbered)
        )
        self.assertEqual(order, list(range(20)))

    def test_randbelow_return_protocol_after_outer_pass(self):
        e1 = _entry(5, (0, 10), (2, 8))
        batch, root = prove_equal_value_batch_bound([e1])
        for returned in (True, False, 1.0, "0", None):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(
                    batch, root, randbelow=lambda upper, value=returned: value
                )
        for returned in (-1, DEFAULT_PRIME - 1, DEFAULT_PRIME):
            with self.assertRaises(ValueError):
                verify_equal_value_batch_bound(
                    batch,
                    root,
                    randbelow=lambda upper, value=returned: value,
                )

        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            verify_equal_value_batch_bound(batch, root, randbelow=boom)

    # ------------------------------------------------------------------
    # TypeError preflight of the nested bound structure

    def test_typeerror_container_and_field_types(self):
        e1 = _entry(5, (0, 10), (2, 8))
        batch, root = prove_equal_value_batch_bound([e1])
        for bad_batch in ("batch", 42, None, object()):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(bad_batch, root)
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(batch, "0" * 32)
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(batch, bytearray(root))
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, True, batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch([e1], 1, batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 1, "proof"), root
            )
        # proof internals
        bad_proof = MerkleMultiProof(True, batch.proof.indices, batch.proof.siblings)
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 1, bad_proof), root
            )
        bad_proof = MerkleMultiProof(1, [0], batch.proof.siblings)
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 1, bad_proof), root
            )
        bad_proof = MerkleMultiProof(1, (True,), batch.proof.siblings)
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 1, bad_proof), root
            )
        bad_proof = MerkleMultiProof(1, (0,), ["0" * 32])
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(batch.entries, 1, bad_proof), root
            )
        for bad_rand in (None, 5, b"x", object()):
            with self.assertRaises(TypeError):
                verify_equal_value_batch_bound(batch, root, randbelow=bad_rand)

    def test_typeerror_nested_entries_walked_fully(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4))
        batch, root = prove_equal_value_batch_bound([e1, e2])
        # a wrong last-entry type is not hidden by an earlier invalid entry
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch((e1, "wrong"), 2, batch.proof), root
            )
        bool_commitment = dataclasses.replace(e2.left, element=True)
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(
                    (
                        EqualValueBatchEntry(
                            dataclasses.replace(e1.left, element=0),
                            e1.right,
                            e1.proof,
                            b"",
                        ),
                        EqualValueBatchEntry(
                            bool_commitment, e2.right, e2.proof, b""
                        ),
                    ),
                    2,
                    batch.proof,
                ),
                root,
            )
        bad_proof = dataclasses.replace(e2.proof, t_left=list(e2.proof.t_left))
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(
                    (
                        e1,
                        EqualValueBatchEntry(
                            e2.left, e2.right, bad_proof, e2.context
                        ),
                    ),
                    2,
                    batch.proof,
                ),
                root,
            )
        with self.assertRaises(TypeError):
            verify_equal_value_batch_bound(
                BoundEqualValueBatch(
                    (
                        e1,
                        EqualValueBatchEntry(
                            e2.left, e2.right, e2.proof, 1
                        ),
                    ),
                    2,
                    batch.proof,
                ),
                root,
            )

    # ------------------------------------------------------------------

    def test_leaf_encoding_binds_everything_with_dedicated_domain(self):
        e1 = _entry(5, (0, 10), (2, 8), context=b"c")
        leaf = zkregion._bound_equal_value_leaf(e1)
        # length-prefixed category-specific domain separator (15 bytes)
        self.assertTrue(leaf.startswith(b"\x00\x00\x00\x0fzkregion/evb/v1"))
        # and it differs from every other batch category's separator
        from zkregion import (
            _RANGE_SET_BOUND_DOMAIN,
            _WIDE_RANGE_BOUND_DOMAIN,
            _INTERVAL_RANGE_BOUND_DOMAIN,
        )
        own = zkregion._EQUAL_VALUE_BOUND_DOMAIN
        self.assertEqual(len({own, _RANGE_SET_BOUND_DOMAIN,
                              _WIDE_RANGE_BOUND_DOMAIN,
                              _INTERVAL_RANGE_BOUND_DOMAIN}), 4)
        # leaves differ when any bound ingredient differs
        variants = {
            "context": EqualValueBatchEntry(
                e1.left, e1.right, e1.proof, b"other"
            ),
            "side": EqualValueBatchEntry(
                e1.right, e1.left, e1.proof, e1.context
            ),
        }
        baseline = leaf
        for label, variant in variants.items():
            self.assertNotEqual(
                baseline, zkregion._bound_equal_value_leaf(variant), label
            )

    def test_agrees_with_plain_batch_verification(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(0, (-3, 3), (-1, 1), context=b"c")
        batch, root = prove_equal_value_batch_bound([e1, e2])
        self.assertTrue(verify_equal_value_batch(batch.entries))
        self.assertTrue(verify_equal_value_batch_bound(batch, root))


if __name__ == "__main__":
    unittest.main()
