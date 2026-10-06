"""Smoke tests for the equal-value batch verification API."""

import dataclasses
import unittest

from zkregion import (
    EqualValueBatchEntry,
    EqualValueProof,
    PedersenCommitment,
    pedersen_commit,
    prove_equal_value,
    verify_equal_value,
    verify_equal_value_batch,
)


def _entry(left_range, right_range, value, *, context=b"", prime=None, h=None):
    kwargs = {}
    if prime is not None:
        kwargs["prime"] = prime
    if h is not None:
        kwargs["h"] = h
    left, blinding_left = pedersen_commit(value, *left_range, **kwargs)
    right, blinding_right = pedersen_commit(value, *right_range, **kwargs)
    proof = prove_equal_value(left, right, value, blinding_left, blinding_right, context)
    return EqualValueBatchEntry(left, right, proof, context)


class _Recorder:
    """A deterministic randbelow that always returns 0 and logs its uppers."""

    def __init__(self):
        self.calls = []

    def __call__(self, upper):
        self.calls.append(upper)
        return 0


class EqualValueBatchEntryTest(unittest.TestCase):
    def test_positional_construction_equality_and_immutability(self):
        entry = _entry((0, 7), (3, 9), 5, context=b"c")
        again = EqualValueBatchEntry(entry.left, entry.right, entry.proof, b"c")
        self.assertEqual(entry, again)
        self.assertEqual(entry.context, b"c")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.context = b"other"

    def test_default_context_is_empty_bytes(self):
        left, blinding_left = pedersen_commit(2, 0, 5)
        right, blinding_right = pedersen_commit(2, 1, 4)
        proof = prove_equal_value(left, right, 2, blinding_left, blinding_right)
        entry = EqualValueBatchEntry(left, right, proof)
        self.assertEqual(entry.context, b"")
        self.assertTrue(verify_equal_value_batch([entry]))

    def test_construction_does_not_validate(self):
        entry = EqualValueBatchEntry("left", "right", "proof", "context")
        self.assertEqual(entry.left, "left")


class VerifyEqualValueBatchTest(unittest.TestCase):
    def test_batch_verifies_list_and_tuple(self):
        e1 = _entry((0, 7), (3, 9), 5)
        e2 = _entry((-10, 10), (-4, 2), 0, context=b"c")  # cross zero
        e3 = _entry((5, 5), (5, 5), 5)  # single-point intersection
        e4 = _entry((-100, -90), (-95, -80), -95)  # negative bounds
        batch = [e1, e2, e3, e4]
        self.assertTrue(verify_equal_value_batch(batch))
        self.assertTrue(verify_equal_value_batch(tuple(batch)))

    def test_duplicate_entries_verify(self):
        e1 = _entry((0, 7), (3, 9), 5)
        self.assertTrue(verify_equal_value_batch([e1, e1, e1]))

    def test_mixed_groups_across_entries(self):
        other_prime = (1 << 89) - 1
        e1 = _entry((0, 7), (3, 9), 5)
        e2 = _entry((0, 4), (2, 6), 3, prime=other_prime)
        self.assertTrue(verify_equal_value_batch([e1, e2]))

    def test_different_contexts_across_entries(self):
        e1 = _entry((0, 7), (3, 9), 5, context=b"session-1")
        e2 = _entry((0, 7), (3, 9), 5, context=b"session-2")
        e3 = _entry((0, 7), (3, 9), 5)
        self.assertTrue(verify_equal_value_batch([e1, e2, e3]))

    def test_empty_batch_false(self):
        self.assertFalse(verify_equal_value_batch([]))
        self.assertFalse(verify_equal_value_batch(()))

    def test_swapped_sides_false(self):
        entry = _entry((0, 7), (3, 9), 5, context=b"c")
        swapped = EqualValueBatchEntry(
            entry.right, entry.left, entry.proof, entry.context
        )
        self.assertFalse(verify_equal_value_batch([swapped]))

    def test_wrong_context_false(self):
        entry = _entry((0, 7), (3, 9), 5, context=b"c")
        replayed = EqualValueBatchEntry(
            entry.left, entry.right, entry.proof, b"other"
        )
        self.assertFalse(verify_equal_value_batch([replayed]))

    def test_tampered_response_false(self):
        entry = _entry((0, 7), (3, 9), 5)
        proof = entry.proof
        tampered = EqualValueProof(
            proof.t_left,
            proof.t_right,
            proof.e,
            (proof.s_left[0] + 1,) + proof.s_left[1:],
            proof.s_right,
        )
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(entry.left, entry.right, tampered)]
            )
        )

    def test_tampered_announcement_false(self):
        entry = _entry((0, 7), (3, 9), 5)
        proof = entry.proof
        tampered = EqualValueProof(
            (proof.t_left[0] % (entry.left.prime - 1) + 1,) + proof.t_left[1:],
            proof.t_right,
            proof.e,
            proof.s_left,
            proof.s_right,
        )
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(entry.left, entry.right, tampered)]
            )
        )

    def test_group_mismatch_inside_entry_false_and_no_draws(self):
        entry = _entry((0, 7), (3, 9), 5)
        other, _ = pedersen_commit(5, 3, 9, prime=(1 << 89) - 1)
        mismatched = EqualValueBatchEntry(entry.left, other, entry.proof)
        recorder = _Recorder()
        self.assertFalse(verify_equal_value_batch([mismatched], randbelow=recorder))
        self.assertEqual(recorder.calls, [])

    def test_illegal_commitment_false_and_no_draws(self):
        entry = _entry((0, 7), (3, 9), 5)
        illegal = PedersenCommitment(
            0,  # element out of range
            entry.left.lower,
            entry.left.upper,
            entry.left.prime,
            entry.left.generator,
            entry.left.h,
        )
        recorder = _Recorder()
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(illegal, entry.right, entry.proof)],
                randbelow=recorder,
            )
        )
        self.assertEqual(recorder.calls, [])

    def test_empty_intersection_false(self):
        left, _ = pedersen_commit(1, 0, 2)
        right, _ = pedersen_commit(4, 3, 5)
        proof = EqualValueProof((), (), (), (), ())
        self.assertFalse(verify_equal_value_batch([EqualValueBatchEntry(left, right, proof)]))

    def test_oversized_intersection_false(self):
        left, _ = pedersen_commit(1, 0, 300)
        right, _ = pedersen_commit(1, 0, 300)
        proof = EqualValueProof((), (), (), (), ())
        self.assertFalse(verify_equal_value_batch([EqualValueBatchEntry(left, right, proof)]))

    def test_proof_length_mismatch_false(self):
        entry = _entry((0, 7), (3, 9), 5)
        proof = entry.proof
        short = EqualValueProof(
            proof.t_left[:-1], proof.t_right, proof.e, proof.s_left, proof.s_right
        )
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(entry.left, entry.right, short)]
            )
        )

    def test_missing_inverse_false_and_no_draws(self):
        from zkregion import _equal_value_challenge

        commitment = PedersenCommitment(5, 0, 3, 15, 3, 7)  # gcd(3, 15) != 1
        challenge = _equal_value_challenge(
            commitment, commitment, b"", 4, (1, 1, 1, 1), (1, 1, 1, 1)
        )
        proof = EqualValueProof(
            (1, 1, 1, 1), (1, 1, 1, 1), (challenge, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0)
        )
        recorder = _Recorder()
        self.assertFalse(
            verify_equal_value_batch(
                [EqualValueBatchEntry(commitment, commitment, proof)],
                randbelow=recorder,
            )
        )
        self.assertEqual(recorder.calls, [])

    def test_draw_count_and_order(self):
        e1 = _entry((0, 7), (3, 9), 5)  # intersection [3, 7]: 5 points
        e2 = _entry((5, 5), (5, 5), 5)  # 1 point
        recorder = _Recorder()
        self.assertTrue(verify_equal_value_batch([e1, e2], randbelow=recorder))
        # two equations (left then right) per intersection integer per entry
        self.assertEqual(
            recorder.calls, [e1.left.prime - 1] * 10 + [e2.left.prime - 1] * 2
        )

    def test_duplicate_entries_draw_independently(self):
        entry = _entry((0, 7), (3, 9), 5)
        recorder = _Recorder()
        self.assertTrue(verify_equal_value_batch([entry, entry], randbelow=recorder))
        self.assertEqual(len(recorder.calls), 20)

    def test_randbelow_keyword_only(self):
        entry = _entry((0, 7), (3, 9), 5)
        with self.assertRaises(TypeError):
            verify_equal_value_batch([entry], _Recorder())

    def test_randbelow_non_integer_or_bool_raises_type_error(self):
        entry = _entry((0, 7), (3, 9), 5)
        with self.assertRaises(TypeError):
            verify_equal_value_batch([entry], randbelow=lambda upper: 1.5)
        with self.assertRaises(TypeError):
            verify_equal_value_batch([entry], randbelow=lambda upper: True)

    def test_randbelow_out_of_range_raises_value_error(self):
        entry = _entry((0, 7), (3, 9), 5)
        prime = entry.left.prime
        with self.assertRaises(ValueError):
            verify_equal_value_batch([entry], randbelow=lambda upper: upper)
        with self.assertRaises(ValueError):
            verify_equal_value_batch([entry], randbelow=lambda upper: -1)
        with self.assertRaises(ValueError):
            verify_equal_value_batch([entry], randbelow=lambda upper: prime)

    def test_randbelow_exception_propagates(self):
        entry = _entry((0, 7), (3, 9), 5)

        def broken(upper):
            raise RuntimeError("source failure")

        with self.assertRaises(RuntimeError):
            verify_equal_value_batch([entry], randbelow=broken)

    def test_type_errors(self):
        entry = _entry((0, 7), (3, 9), 5)
        # non-sequence and string/bytes batches
        for bad in ("entries", b"entries", 42, {entry}, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verify_equal_value_batch(bad)
        # wrong entry object
        with self.assertRaises(TypeError):
            verify_equal_value_batch([(entry.left, entry.right, entry.proof)])
        # non-commitment sides
        with self.assertRaises(TypeError):
            verify_equal_value_batch([EqualValueBatchEntry("l", entry.right, entry.proof)])
        with self.assertRaises(TypeError):
            verify_equal_value_batch([EqualValueBatchEntry(entry.left, None, entry.proof)])
        # bool posing as a commitment integer
        bool_left = PedersenCommitment(
            True,
            entry.left.lower,
            entry.left.upper,
            entry.left.prime,
            entry.left.generator,
            entry.left.h,
        )
        with self.assertRaises(TypeError):
            verify_equal_value_batch(
                [EqualValueBatchEntry(bool_left, entry.right, entry.proof)]
            )
        # non-proof, non-tuple proof field, bool inside a proof field
        with self.assertRaises(TypeError):
            verify_equal_value_batch(
                [EqualValueBatchEntry(entry.left, entry.right, "proof")]
            )
        proof = entry.proof
        list_field = EqualValueProof(
            list(proof.t_left), proof.t_right, proof.e, proof.s_left, proof.s_right
        )
        with self.assertRaises(TypeError):
            verify_equal_value_batch(
                [EqualValueBatchEntry(entry.left, entry.right, list_field)]
            )
        bool_item = EqualValueProof(
            (True,) + proof.t_left[1:],
            proof.t_right,
            proof.e,
            proof.s_left,
            proof.s_right,
        )
        with self.assertRaises(TypeError):
            verify_equal_value_batch(
                [EqualValueBatchEntry(entry.left, entry.right, bool_item)]
            )
        # non-bytes context
        with self.assertRaises(TypeError):
            verify_equal_value_batch(
                [EqualValueBatchEntry(entry.left, entry.right, proof, "ctx")]
            )
        # non-callable randbelow
        with self.assertRaises(TypeError):
            verify_equal_value_batch([entry], randbelow=7)

    def test_late_type_error_still_raises(self):
        good = _entry((0, 7), (3, 9), 5)
        bad = EqualValueBatchEntry(good.left, good.right, good.proof, "ctx")
        with self.assertRaises(TypeError):
            verify_equal_value_batch([good, bad])

    def test_inputs_not_mutated(self):
        e1 = _entry((0, 7), (3, 9), 5)
        e2 = _entry((5, 5), (5, 5), 5)
        batch = [e1, e2]
        verify_equal_value_batch(batch)
        self.assertEqual(batch, [e1, e2])

    def test_single_entry_semantics_match_verify_equal_value(self):
        entry = _entry((0, 7), (3, 9), 5, context=b"c")
        self.assertTrue(
            verify_equal_value(entry.left, entry.right, entry.proof, entry.context)
        )
        self.assertTrue(verify_equal_value_batch([entry]))


if __name__ == "__main__":
    unittest.main()
