"""Tests for EqualValueBatchEntry / verify_equal_value_batch.

The batch entry bundles the exact arguments of verify_equal_value and the
batch verifier reuses the equal-value transcript byte for byte, combining
the per-branch Schnorr equations of entries sharing one group into random
linear checks with independent left/right weights.
"""

import dataclasses
import itertools
import unittest

import zkregion
from zkregion import (
    DEFAULT_PRIME,
    EqualValueBatchEntry,
    EqualValueProof,
    PedersenCommitment,
    pedersen_commit,
    prove_equal_value,
    verify_equal_value,
    verify_equal_value_batch,
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


class EqualValueBatchEntryTest(unittest.TestCase):
    def test_positional_construction_default_context_equality_frozen(self):
        entry = _entry(5, (0, 10), (2, 8))
        left, right, proof = entry.left, entry.right, entry.proof
        default_context = EqualValueBatchEntry(left, right, proof)
        self.assertEqual(default_context.context, b"")
        positional = EqualValueBatchEntry(left, right, proof, b"")
        self.assertEqual(positional, default_context)
        self.assertEqual(
            dataclasses.astuple(positional)[:3],
            dataclasses.astuple(default_context)[:3],
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.context = b"other"
        # construction performs no validation at all
        raw = EqualValueProof((), (), (), (), ())
        unchecked = EqualValueBatchEntry("left", "right", raw, 1234)
        self.assertEqual(unchecked.left, "left")
        self.assertEqual(unchecked.right, "right")
        self.assertIs(unchecked.proof, raw)
        self.assertEqual(unchecked.context, 1234)

    def test_fields_are_left_right_proof_context(self):
        entry = _entry(0, (-3, 3), (-1, 1), context=b"c")
        self.assertEqual(
            [field.name for field in dataclasses.fields(entry)],
            ["left", "right", "proof", "context"],
        )
        self.assertEqual(entry.context, b"c")


class VerifyEqualValueBatchTest(unittest.TestCase):
    def test_basic_lists_tuples_and_duplicates(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(3, (-5, 5), (3, 4), context=b"session")
        for batch in (
            [e1],
            (e1, e2),
            [e1, e1],
            (e2, e1, e2),
            [e1, e2, e1, e2],
        ):
            self.assertTrue(verify_equal_value_batch(batch), batch)

    def test_default_randbelow_accepts_real_batch(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(-7, (-10, 0), (-7, -1), context=b"c")
        self.assertTrue(verify_equal_value_batch([e1, e2]))

    def test_negative_cross_zero_single_point_different_ranges(self):
        entries = [
            _entry(-100, (-200, -50), (-150, -90)),  # negative bounds
            _entry(0, (-10, 10), (-2, 2)),  # cross zero
            _entry(4, (4, 10), (0, 4)),  # single-point intersection at endpoint
            _entry(5, (0, 10), (5, 200)),  # very different declared ranges
        ]
        self.assertTrue(verify_equal_value_batch(entries))
        self.assertTrue(verify_equal_value_batch(list(reversed(entries))))

    def test_entries_may_mix_groups_but_pair_shares_one_group(self):
        big = _entry(5, (0, 10), (2, 8))
        small = _entry(1, (0, 5), (0, 5), prime=1019, generator=2)
        other_generator = _entry(2, (0, 6), (1, 3), prime=1019, generator=3)
        self.assertTrue(
            verify_equal_value_batch([big, small, other_generator, small])
        )

    def test_contexts_need_not_match_across_entries(self):
        e_a = _entry(5, (0, 10), (2, 8), context=b"a")
        e_b = _entry(5, (0, 10), (2, 8), context=b"b")
        e_c = _entry(5, (0, 10), (2, 8), context=b"")
        self.assertTrue(verify_equal_value_batch([e_a, e_b, e_c]))

    def test_empty_batch_false_and_draws_nothing(self):
        randbelow, calls = _recording_randbelow()
        self.assertFalse(verify_equal_value_batch([], randbelow=randbelow))
        self.assertFalse(verify_equal_value_batch((), randbelow=randbelow))
        self.assertEqual(calls, [])

    def test_accepts_generic_sequence_but_rejects_strings_and_sets(self):
        from collections.abc import Sequence as SequenceABC

        e1 = _entry(5, (0, 10), (2, 8))

        class Seq(SequenceABC):
            def __init__(self, items):
                self._items = items

            def __len__(self):
                return len(self._items)

            def __getitem__(self, index):
                return self._items[index]

        self.assertTrue(verify_equal_value_batch(Seq([e1])))
        for bad in ("entries", b"entries", bytearray(b"entries"), {e1}, 7, None):
            with self.assertRaises(TypeError):
                verify_equal_value_batch(bad)

    def test_draw_count_arguments_and_order(self):
        # intersection sizes: 7 (2..8) and 3 (-1..1); two draws per integer.
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(0, (-3, 3), (-1, 1))
        randbelow, calls = _recording_randbelow()
        self.assertTrue(verify_equal_value_batch([e1, e2], randbelow=randbelow))
        self.assertEqual(calls, [DEFAULT_PRIME - 1] * (2 * 7 + 2 * 3))

        # order is entry order, ascending intersection points, left then right
        order = []
        sequence = itertools.count()

        def numbered(upper):
            order.append((next(sequence), upper))
            return 0

        self.assertTrue(verify_equal_value_batch([e1, e2], randbelow=numbered))
        positions = [position for position, _ in order]
        self.assertEqual(positions, list(range(20)))
        self.assertEqual([upper for _, upper in order], [DEFAULT_PRIME - 1] * 20)

    def test_duplicate_entries_draw_independent_weights(self):
        e1 = _entry(5, (0, 10), (2, 8))
        randbelow, calls = _recording_randbelow()
        self.assertTrue(verify_equal_value_batch([e1, e1], randbelow=randbelow))
        self.assertEqual(len(calls), 2 * 2 * 7)

    def test_independent_left_right_weights_drawn_interleaved(self):
        e1 = _entry(5, (0, 10), (2, 8))
        seen = []

        def randbelow(upper):
            seen.append(upper)
            # weight must stay in [1, prime - 1]; alternate distinct values
            return (len(seen) * 1234577) % (upper - 1)

        self.assertTrue(verify_equal_value_batch([e1], randbelow=randbelow))
        # exactly two draws per branch, so the two sides never share a draw
        self.assertEqual(len(seen), 14)

    # ------------------------------------------------------------------
    # TypeError preflight: the whole nested batch is walked first

    def test_typeerror_non_sequence_inputs(self):
        for bad in ("x", b"x", bytearray(b"x"), 42, 3.5, object()):
            with self.assertRaises(TypeError):
                verify_equal_value_batch(bad)

    def test_typeerror_wrong_entry_types_including_bool_and_tuple(self):
        good = _entry(5, (0, 10), (2, 8))
        for bad in (42, True, False, (good.left, good.right, good.proof), "x"):
            with self.assertRaises(TypeError):
                verify_equal_value_batch([bad])
            # a bad later entry is not hidden by an earlier valid one
            with self.assertRaises(TypeError):
                verify_equal_value_batch([good, good, bad])

    def test_typeerror_wrong_commitment_and_field_types(self):
        good = _entry(5, (0, 10), (2, 8))
        for side in ("left", "right"):
            with self.subTest(side=side):
                kwargs = {
                    "left": good.left,
                    "right": good.right,
                    "proof": good.proof,
                    "context": good.context,
                    side: "not-a-commitment",
                }
                with self.assertRaises(TypeError):
                    verify_equal_value_batch([EqualValueBatchEntry(**kwargs)])
            # bool posed as a commitment field
            for field_name in ("element", "lower", "upper", "prime", "generator", "h"):
                tampered_commitment = dataclasses.replace(
                    getattr(good, side), **{field_name: True}
                )
                kwargs = {
                    "left": good.left,
                    "right": good.right,
                    "proof": good.proof,
                    "context": good.context,
                    side: tampered_commitment,
                }
                with self.assertRaises(TypeError):
                    verify_equal_value_batch(
                        [good, EqualValueBatchEntry(**kwargs)]
                    )

    def test_typeerror_wrong_proof_types(self):
        good = _entry(5, (0, 10), (2, 8))
        with self.assertRaises(TypeError):
            verify_equal_value_batch(
                [EqualValueBatchEntry(good.left, good.right, "proof", b"")]
            )
        for field_name in ("t_left", "t_right", "e", "s_left", "s_right"):
            # non-tuple field
            tampered = dataclasses.replace(
                good.proof, **{field_name: list(getattr(good.proof, field_name))}
            )
            with self.assertRaises(TypeError):
                verify_equal_value_batch(
                    [EqualValueBatchEntry(good.left, good.right, tampered, b"")]
                )
            # bool posed as an integer inside the tuple
            original = getattr(good.proof, field_name)
            tampered = dataclasses.replace(
                good.proof, **{field_name: (True,) + original[1:]}
            )
            with self.assertRaises(TypeError):
                verify_equal_value_batch(
                    [EqualValueBatchEntry(good.left, good.right, tampered, b"")]
                )

    def test_typeerror_context_must_be_bytes(self):
        good = _entry(5, (0, 10), (2, 8))
        for bad_context in ("bytes", 1, bytearray(b"x"), None):
            entry = EqualValueBatchEntry(
                good.left, good.right, good.proof, bad_context
            )
            with self.assertRaises(TypeError):
                verify_equal_value_batch([entry])

    def test_typeerror_randbelow_must_be_callable(self):
        good = _entry(5, (0, 10), (2, 8))
        for bad in (None, 5, b"x", object()):
            with self.assertRaises(TypeError):
                verify_equal_value_batch([good], randbelow=bad)
        # keyword-only
        with self.assertRaises(TypeError):
            verify_equal_value_batch([good], None)

    def test_type_preflight_walks_whole_batch_and_draws_nothing(self):
        good = _entry(5, (0, 10), (2, 8))
        randbelow, calls = _recording_randbelow()
        # structural problems must not mask type problems in later entries
        illegal_commitment = dataclasses.replace(good.left, element=0)
        structurally_bad = EqualValueBatchEntry(
            illegal_commitment, good.right, good.proof, b""
        )
        with self.assertRaises(TypeError):
            verify_equal_value_batch(
                [structurally_bad, "wrong-type"], randbelow=randbelow
            )
        self.assertEqual(calls, [])
        # non-callable randbelow plus wrong entry types: still TypeError, no draw
        with self.assertRaises(TypeError):
            verify_equal_value_batch([good, 1], randbelow=123)

    # ------------------------------------------------------------------
    # Structural/value failures: False, and still no randomness drawn

    def test_false_illegal_commitments(self):
        good = _entry(5, (0, 10), (2, 8))
        replacements = (
            {"element": 0},
            {"element": good.left.prime},
            {"prime": 3},
            {"lower": 11},
            {"generator": good.left.prime},
        )
        for change in replacements:
            tampered_commitment = dataclasses.replace(good.left, **change)
            entry = EqualValueBatchEntry(
                tampered_commitment, good.right, good.proof, b""
            )
            randbelow, calls = _recording_randbelow()
            self.assertFalse(
                verify_equal_value_batch([entry], randbelow=randbelow), change
            )
            self.assertEqual(calls, [])

    def test_false_in_entry_group_mismatch(self):
        e1 = _entry(5, (0, 10), (2, 8))
        small = _entry(1, (0, 5), (0, 5), prime=1019, generator=2)
        for left, right in (
            (e1.left, small.right),
            (small.left, e1.right),
        ):
            entry = EqualValueBatchEntry(left, right, e1.proof, b"")
            randbelow, calls = _recording_randbelow()
            self.assertFalse(verify_equal_value_batch([entry], randbelow=randbelow))
            self.assertEqual(calls, [])

    def test_false_empty_and_oversized_intersection(self):
        left, _ = pedersen_commit(1, 0, 3, blinding=2)
        right, _ = pedersen_commit(9, 7, 10, blinding=2)
        proof = EqualValueProof(
            (1,) * 4, (1,) * 4, (0,) * 4, (0,) * 4, (0,) * 4
        )
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(left, right, proof, b"")],
                randbelow=randbelow,
            )
        )
        self.assertEqual(calls, [])

        wide_left, _ = pedersen_commit(0, 0, 256, blinding=2)
        wide_right, _ = pedersen_commit(0, 0, 256, blinding=3)
        oversized = EqualValueProof(
            (1,) * 257, (1,) * 257, (0,) * 257, (0,) * 257, (0,) * 257
        )
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(wide_left, wide_right, oversized, b"")],
                randbelow=randbelow,
            )
        )
        self.assertEqual(calls, [])

    def test_false_proof_lengths_and_value_ranges(self):
        good = _entry(5, (0, 10), (2, 8))
        prime = good.left.prime
        cases = {
            "short t_left": dataclasses.replace(good.proof, t_left=good.proof.t_left[:-1]),
            "short s_right": dataclasses.replace(good.proof, s_right=good.proof.s_right[1:]),
            "t_left zero": dataclasses.replace(
                good.proof, t_left=(0,) + good.proof.t_left[1:]
            ),
            "t_right prime": dataclasses.replace(
                good.proof, t_right=(prime,) + good.proof.t_right[1:]
            ),
            "e prime": dataclasses.replace(
                good.proof, e=(prime,) + good.proof.e[1:]
            ),
            "e negative": dataclasses.replace(
                good.proof, e=(-1,) + good.proof.e[1:]
            ),
            "s_left negative": dataclasses.replace(
                good.proof, s_left=(-1,) + good.proof.s_left[1:]
            ),
        }
        for label, proof in cases.items():
            entry = EqualValueBatchEntry(good.left, good.right, proof, good.context)
            randbelow, calls = _recording_randbelow()
            self.assertFalse(
                verify_equal_value_batch([entry], randbelow=randbelow), label
            )
            self.assertEqual(calls, [], label)

    def test_false_binding_mismatches(self):
        good = _entry(5, (0, 10), (2, 8), context=b"ctx")
        randbelow, calls = _recording_randbelow()
        # wrong context
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(good.left, good.right, good.proof, b"other")],
                randbelow=randbelow,
            )
        )
        # swapped left/right
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(good.right, good.left, good.proof, b"ctx")],
                randbelow=randbelow,
            )
        )
        # changed public commitment field
        moved = dataclasses.replace(good.left, element=good.left.element + 1)
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(moved, good.right, good.proof, b"ctx")],
                randbelow=randbelow,
            )
        )
        # tampered challenge share
        prime = good.left.prime
        tampered_share = dataclasses.replace(
            good.proof,
            e=((good.proof.e[0] + 1) % prime,) + good.proof.e[1:],
        )
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(good.left, good.right, tampered_share, b"ctx")],
                randbelow=randbelow,
            )
        )
        self.assertEqual(calls, [])

    def test_false_missing_modular_inverse_draws_nothing(self):
        # Composite modulus with a generator sharing a factor: 3 has no
        # inverse modulo 15, and the single intersection point x=1 lies
        # above left.lower=0, so recomputing D = element * 3**(-1) mod 15
        # must fail False.
        left = PedersenCommitment(7, 0, 1, 15, 3, 2)
        right = PedersenCommitment(7, 1, 2, 15, 3, 2)
        challenge = zkregion._equal_value_challenge(
            left, right, b"", 1, (1,), (1,)
        )
        proof = EqualValueProof((1,), (1,), (challenge,), (0,), (0,))
        randbelow, calls = _recording_randbelow()
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(left, right, proof, b"")],
                randbelow=randbelow,
            )
        )
        self.assertEqual(calls, [])

    # ------------------------------------------------------------------
    # Failures detected by the aggregate equations (randomness already drawn)

    def test_tampered_response_fails_aggregate(self):
        good = _entry(5, (0, 10), (2, 8))
        randbelow, calls = _recording_randbelow()  # weight 1 still detects
        tampered = dataclasses.replace(
            good.proof,
            s_left=(good.proof.s_left[0] + 1,) + good.proof.s_left[1:],
        )
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(good.left, good.right, tampered, b"")],
                randbelow=randbelow,
            )
        )
        self.assertNotEqual(calls, [])
        # breaking both sides cannot cancel: separate weights, separate sums
        tampered_both = dataclasses.replace(
            tampered,
            s_right=(good.proof.s_right[0] - 1,) + good.proof.s_right[1:],
        )
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(good.left, good.right, tampered_both, b"")],
                randbelow=randbelow,
            )
        )
        # a bad equation in a second, different group is still caught
        small = _entry(1, (0, 5), (0, 5), prime=1019, generator=2)
        small_bad = dataclasses.replace(
            small.proof,
            s_left=(small.proof.s_left[0] + 1,) + small.proof.s_left[1:],
        )
        self.assertFalse(
            verify_equal_value_batch(
                [good, EqualValueBatchEntry(small.left, small.right, small_bad, b"")]
            )
        )

    def test_one_bad_entry_falsifies_whole_batch(self):
        good = _entry(5, (0, 10), (2, 8))
        tampered = dataclasses.replace(
            good.proof,
            s_right=(good.proof.s_right[0] + 1,) + good.proof.s_right[1:],
        )
        bad = EqualValueBatchEntry(good.left, good.right, tampered, b"")
        self.assertFalse(verify_equal_value_batch([good, bad]))
        self.assertFalse(verify_equal_value_batch([bad, good]))

    def test_structural_preflight_of_later_entry_draws_nothing(self):
        good = _entry(5, (0, 10), (2, 8))
        illegal = dataclasses.replace(good.left, element=0)
        structurally_bad = EqualValueBatchEntry(
            illegal, good.right, good.proof, b""
        )
        for order in ([good, structurally_bad], [structurally_bad, good]):
            randbelow, calls = _recording_randbelow()
            self.assertFalse(
                verify_equal_value_batch(order, randbelow=randbelow)
            )
            self.assertEqual(calls, [])

    # ------------------------------------------------------------------
    # randbelow return-value protocol

    def test_randbelow_non_integer_and_bool_raise_typeerror(self):
        good = _entry(5, (0, 10), (2, 8))
        for returned in (True, False, 1.0, "0", None):
            with self.assertRaises(TypeError):
                verify_equal_value_batch([good], randbelow=lambda upper: returned)

    def test_randbelow_out_of_half_open_interval_raises_valueerror(self):
        good = _entry(5, (0, 10), (2, 8))
        for returned in (-1, DEFAULT_PRIME - 1, DEFAULT_PRIME):
            with self.assertRaises(ValueError):
                verify_equal_value_batch(
                    [good], randbelow=lambda upper, value=returned: value
                )

    def test_randbelow_own_exception_propagates(self):
        good = _entry(5, (0, 10), (2, 8))

        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            verify_equal_value_batch([good], randbelow=boom)

    def test_randbelow_not_called_until_preflight_passes(self):
        good = _entry(5, (0, 10), (2, 8))
        randbelow, calls = _recording_randbelow()
        # type failure
        with self.assertRaises(TypeError):
            verify_equal_value_batch([good, "x"], randbelow=randbelow)
        self.assertEqual(calls, [])
        # structural failure
        illegal = dataclasses.replace(good.left, element=0)
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(illegal, good.right, good.proof, b"")],
                randbelow=randbelow,
            )
        )
        self.assertEqual(calls, [])
        # now a valid batch consumes draws
        self.assertTrue(verify_equal_value_batch([good], randbelow=randbelow))
        self.assertEqual(len(calls), 14)

    # ------------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        e1 = _entry(5, (0, 10), (2, 8))
        e2 = _entry(0, (-3, 3), (-1, 1), context=b"c")
        batch = [e1, e2]
        snapshot = [dataclasses.replace(entry) for entry in batch]
        self.assertTrue(verify_equal_value_batch(batch))
        self.assertEqual(batch, snapshot)
        self.assertEqual(len(batch), 2)

    def test_single_entry_agrees_with_verify_equal_value(self):
        entry = _entry(5, (0, 10), (2, 8), context=b"ctx")
        self.assertTrue(
            verify_equal_value(entry.left, entry.right, entry.proof, b"ctx")
        )
        self.assertTrue(verify_equal_value_batch([entry]))
        # proof generated by prove_equal_value is accepted unchanged
        self.assertIsInstance(entry.proof, EqualValueProof)


if __name__ == "__main__":
    unittest.main()
