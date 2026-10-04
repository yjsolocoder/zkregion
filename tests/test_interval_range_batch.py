"""Smoke tests for interval range batch + Merkle-bound batch APIs."""

import itertools
import unittest

from zkregion import (
    BoundIntervalRangeBatch,
    IntervalRangeBatchEntry,
    IntervalRangeProof,
    MerkleMultiProof,
    PedersenCommitment,
    prove_range_interval,
    prove_range_interval_batch_bound,
    pedersen_commit,
    verify_range_interval,
    verify_range_interval_batch,
    verify_range_interval_batch_bound,
)


def _entry(lower, upper, value, *, context=b"", prime=None, h=None):
    kwargs = {}
    if prime is not None:
        kwargs["prime"] = prime
    if h is not None:
        kwargs["h"] = h
    commitment, blinding = pedersen_commit(
        value, lower, upper, **kwargs
    )
    proof = prove_range_interval(commitment, value, blinding, context)
    return IntervalRangeBatchEntry(commitment, proof, context)


def _counter_randbelow():
    counter = itertools.count(1)
    return lambda upper: next(counter) % upper


class IntervalRangeBatchTest(unittest.TestCase):
    def test_batch_verifies_and_is_order_independent(self):
        e1 = _entry(0, 7, 3)
        e2 = _entry(-10, 10, 0, context=b"c")  # cross zero, non-power-of-two
        e3 = _entry(5, 5, 5)  # single point
        e4 = _entry(-100, -90, -95)  # negative bounds
        batch = [e1, e2, e3, e4]
        self.assertTrue(verify_range_interval_batch(batch))
        self.assertTrue(verify_range_interval_batch(list(reversed(batch))))
        self.assertTrue(verify_range_interval_batch([e1, e1, e2]))  # duplicates

    def test_empty_batch_false(self):
        self.assertFalse(verify_range_interval_batch([]))

    def test_one_invalid_entry_falsifies(self):
        good = _entry(0, 7, 3)
        widened = PedersenCommitment(
            good.commitment.element,
            good.commitment.lower,
            good.commitment.upper + 1,
            good.commitment.prime,
            good.commitment.generator,
            good.commitment.h,
        )
        bad = IntervalRangeBatchEntry(widened, good.proof, good.context)
        self.assertFalse(verify_range_interval_batch([good, bad]))
        self.assertFalse(verify_range_interval_batch([bad, good]))

    def test_type_errors_whole_batch_preflight(self):
        good = _entry(0, 7, 3)
        bad_proof = IntervalRangeProof((), (), (), (), (), ())
        bad_entry = IntervalRangeBatchEntry(
            good.commitment, bad_proof, good.context
        )
        # last item wrong type is not hidden by an earlier invalid entry
        with self.assertRaises(TypeError):
            verify_range_interval_batch([bad_entry, "nope"])
        with self.assertRaises(TypeError):
            verify_range_interval_batch("abc")
        with self.assertRaises(TypeError):
            verify_range_interval_batch(b"abc")
        with self.assertRaises(TypeError):
            verify_range_interval_batch(123)
        with self.assertRaises(TypeError):
            verify_range_interval_batch([IntervalRangeBatchEntry(
                good.commitment, good.proof, "not-bytes"
            )])
        with self.assertRaises(TypeError):
            verify_range_interval_batch([IntervalRangeBatchEntry(
                "not-a-commitment", good.proof
            )])

    def test_deterministic_proof_randbelow(self):
        commitment, blinding = pedersen_commit(3, 0, 7)
        p1 = prove_range_interval(
            commitment, 3, blinding, b"", randbelow=_counter_randbelow()
        )
        p2 = prove_range_interval(
            commitment, 3, blinding, b"", randbelow=_counter_randbelow()
        )
        self.assertEqual(p1, p2)


class BoundIntervalRangeBatchTest(unittest.TestCase):
    def test_bound_roundtrip_and_determinism(self):
        entries = [_entry(0, 7, 3), _entry(-10, 10, 0, context=b"x")]
        batch1, root1 = prove_range_interval_batch_bound(entries)
        batch2, root2 = prove_range_interval_batch_bound(list(entries))
        self.assertEqual(batch1, batch2)
        self.assertEqual(root1, root2)
        self.assertEqual(len(root1), 32)
        self.assertIsInstance(batch1, BoundIntervalRangeBatch)
        self.assertEqual(batch1.leaf_count, 2)
        self.assertEqual(batch1.entries, tuple(entries))
        self.assertEqual(batch1.proof.indices, (0, 1))
        self.assertEqual(batch1.proof.siblings, ())
        self.assertTrue(verify_range_interval_batch_bound(batch1, root1))

    def test_single_and_duplicates(self):
        e = _entry(0, 3, 1)
        batch, root = prove_range_interval_batch_bound([e, e, e])
        self.assertEqual(batch.leaf_count, 3)
        self.assertTrue(verify_range_interval_batch_bound(batch, root))

    def test_input_list_mutation_does_not_affect_batch(self):
        e = _entry(0, 3, 1)
        entries = [e]
        batch, root = prove_range_interval_batch_bound(entries)
        entries.append(_entry(0, 3, 2))
        self.assertEqual(batch.leaf_count, 1)
        self.assertTrue(verify_range_interval_batch_bound(batch, root))

    def test_wrong_root_and_length(self):
        e = _entry(0, 3, 1)
        batch, root = prove_range_interval_batch_bound([e])
        self.assertFalse(
            verify_range_interval_batch_bound(batch, b"\x00" * 32)
        )
        self.assertFalse(verify_range_interval_batch_bound(batch, root[:-1]))
        self.assertFalse(verify_range_interval_batch_bound(batch, root + b"x"))

    def test_tamper_fields_and_swaps(self):
        e1 = _entry(0, 7, 3, context=b"a")
        e2 = _entry(0, 7, 4, context=b"b")
        batch, root = prove_range_interval_batch_bound([e1, e2])
        # deletion
        self.assertFalse(verify_range_interval_batch_bound(
            BoundIntervalRangeBatch((e1,), 1, batch.proof), root
        ))
        # count mismatch
        self.assertFalse(verify_range_interval_batch_bound(
            BoundIntervalRangeBatch(batch.entries, 3, batch.proof), root
        ))
        # swapped different entries
        self.assertFalse(verify_range_interval_batch_bound(
            BoundIntervalRangeBatch((e2, e1), batch.leaf_count, batch.proof),
            root,
        ))
        # tampered context
        tampered = IntervalRangeBatchEntry(e1.commitment, e1.proof, b"z")
        self.assertFalse(verify_range_interval_batch_bound(
            BoundIntervalRangeBatch(
                (tampered, e2), batch.leaf_count, batch.proof
            ),
            root,
        ))
        # tampered proof field
        bad_proof = IntervalRangeProof(
            tuple(e1.proof.low_commitments),
            e1.proof.low_challenges,
            e1.proof.low_responses,
            e1.proof.high_commitments,
            e1.proof.high_challenges,
            e1.proof.high_responses[:-1]
            + ((0, e1.proof.high_responses[-1][1]),),
        )
        bad = IntervalRangeBatchEntry(e1.commitment, bad_proof, e1.context)
        self.assertFalse(verify_range_interval_batch_bound(
            BoundIntervalRangeBatch(
                (bad, e2), batch.leaf_count, batch.proof
            ),
            root,
        ))
        # indices don't cover every position
        proof_gap = MerkleMultiProof(
            batch.proof.leaf_count, (1,), batch.proof.siblings
        )
        self.assertFalse(verify_range_interval_batch_bound(
            BoundIntervalRangeBatch(
                batch.entries, batch.leaf_count, proof_gap
            ),
            root,
        ))

    def test_prove_empty_and_invalid_raise(self):
        with self.assertRaises(ValueError):
            prove_range_interval_batch_bound([])
        good = _entry(0, 7, 3)
        widened = PedersenCommitment(
            good.commitment.element,
            good.commitment.lower,
            good.commitment.upper + 1,
            good.commitment.prime,
            good.commitment.generator,
            good.commitment.h,
        )
        bad = IntervalRangeBatchEntry(widened, good.proof, good.context)
        with self.assertRaises(ValueError):
            prove_range_interval_batch_bound([good, bad])

    def test_bound_type_errors(self):
        e = _entry(0, 3, 1)
        batch, root = prove_range_interval_batch_bound([e])
        with self.assertRaises(TypeError):
            verify_range_interval_batch_bound("nope", root)
        with self.assertRaises(TypeError):
            verify_range_interval_batch_bound(batch, "0" * 32)
        with self.assertRaises(TypeError):
            verify_range_interval_batch_bound(
                BoundIntervalRangeBatch(batch.entries, True, batch.proof),
                root,
            )
        with self.assertRaises(TypeError):
            verify_range_interval_batch_bound(
                BoundIntervalRangeBatch([e], 1, batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_range_interval_batch_bound(
                BoundIntervalRangeBatch(
                    batch.entries, 1, "not-a-proof"
                ),
                root,
            )
        with self.assertRaises(TypeError):
            prove_range_interval_batch_bound("nope")
        with self.assertRaises(TypeError):
            prove_range_interval_batch_bound(b"bytes")

    def test_bound_verifies_crypto_and_entry_construction_unchecked(self):
        # construction performs no validation: nonsense entries are accepted
        raw = IntervalRangeProof((), (), (), (), (), ())
        entry = IntervalRangeBatchEntry("whatever", raw, "ctx")
        self.assertEqual(entry.commitment, "whatever")
        self.assertEqual(entry.context, "ctx")
        with self.assertRaises(TypeError):
            verify_range_interval_batch([entry])


if __name__ == "__main__":
    unittest.main()
