"""Tests for the Merkle-committed convex polygon batch."""

import dataclasses
import unittest

from zkregion import (
    BoundConvexPolygonBatch,
    ConvexPolygonBatchEntry,
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    DEFAULT_PRIME,
    MerkleMultiProof,
    PedersenCommitment,
    RangeProof,
    WideRangeProof,
    merkle_root,
    pedersen_commit,
    prove_convex_polygon,
    prove_convex_polygon_batch_bound,
    prove_multi_inclusion,
    verify_convex_polygon,
    verify_convex_polygon_batch,
    verify_convex_polygon_batch_bound,
    verify_multi_inclusion,
)
from zkregion import _bound_convex_polygon_leaf, _edge_offset_upper

TRIANGLE = ((0, 0), (4, 0), (0, 4))
PENTAGON = ((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))


class DetRand:
    """Deterministic randbelow replacement: same sequence for same counter."""

    def __init__(self, seed=1):
        self.calls = seed

    def __call__(self, upper):
        self.calls += 1
        return (self.calls * 7919 + 13) % upper


def frame_items(leaf: bytes) -> list:
    items = []
    offset = 0
    while offset < len(leaf):
        length = int.from_bytes(leaf[offset:offset + 4], "big")
        offset += 4
        items.append(leaf[offset:offset + length])
        offset += length
    return items


class ConvexPolygonBoundBatchFixture(unittest.TestCase):
    def _entry(
        self,
        x=1,
        y=2,
        vertices=TRIANGLE,
        context=b"ctx",
        x_blinding=None,
        y_blinding=None,
    ):
        polygon = ConvexPolygonRegion(vertices)
        cx_kwargs = {} if x_blinding is None else {"blinding": x_blinding}
        cy_kwargs = {} if y_blinding is None else {"blinding": y_blinding}
        x_commitment, x_blinding = pedersen_commit(
            x, polygon.min_x, polygon.max_x, **cx_kwargs
        )
        y_commitment, y_blinding = pedersen_commit(
            y, polygon.min_y, polygon.max_y, **cy_kwargs
        )
        proof = prove_convex_polygon(
            x_commitment, y_commitment, x, y, x_blinding, y_blinding,
            polygon, context, randbelow=DetRand(),
        )
        return ConvexPolygonBatchEntry(
            x_commitment, y_commitment, polygon, proof, context
        )

    def _expected_branch_count(self, entry):
        """One draw per bbox branch plus two draws per edge-proof bit."""
        polygon = entry.polygon
        count = (polygon.max_x - polygon.min_x + 1) + (
            polygon.max_y - polygon.min_y + 1
        )
        for edge in polygon._interior_edges():
            upper = _edge_offset_upper(polygon, edge)
            count += 2 * max(1, upper.bit_length())
        return count

    def honest_entries(self):
        return [
            self._entry(1, 2, context=b"a"),
            self._entry(3, 0, context=b"b"),
            self._entry(0, 3, vertices=PENTAGON, context=b"c"),
        ]

    def build(self, entries):
        leaves = [_bound_convex_polygon_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundConvexPolygonBatch(tuple(entries), len(entries), proof)
        return batch, root


class BoundConvexPolygonBatchTest(ConvexPolygonBoundBatchFixture):
    # ---- batch object -------------------------------------------------------

    def test_positional_equality_and_immutability(self):
        batch, root = self.build(self.honest_entries())
        rebuilt = BoundConvexPolygonBatch(batch.entries, 3, batch.proof)
        self.assertEqual(rebuilt, batch)
        self.assertEqual(hash(rebuilt), hash(batch))
        self.assertEqual(
            tuple(getattr(batch, name) for name in ("entries", "leaf_count", "proof")),
            (batch.entries, 3, batch.proof),
        )
        self.assertIsInstance(batch.entries, tuple)
        self.assertNotEqual(
            BoundConvexPolygonBatch(batch.entries, 4, batch.proof), batch
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 4
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.entries = ()

    def test_entries_must_be_tuple(self):
        batch, root = self.build(self.honest_entries())
        loose = BoundConvexPolygonBatch(list(batch.entries), 3, batch.proof)
        self.assertNotIsInstance(loose.entries, tuple)
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(loose, root, randbelow=DetRand())

    def test_field_types(self):
        batch, _ = self.build(self.honest_entries())
        self.assertIsInstance(batch.entries, tuple)
        for entry in batch.entries:
            self.assertIsInstance(entry, ConvexPolygonBatchEntry)
        self.assertIsInstance(batch.leaf_count, int)
        self.assertNotIsInstance(batch.leaf_count, bool)
        self.assertIsInstance(batch.proof, MerkleMultiProof)

    # ---- honest round trips -------------------------------------------------

    def test_honest_batch_verifies(self):
        batch, root = self.build(self.honest_entries())
        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )
        self.assertTrue(verify_convex_polygon_batch_bound(batch, root))

    def test_single_even_and_duplicate_batches(self):
        only = [self._entry()]
        batch, root = self.build(only)
        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )
        pair = [self._entry(1, 1, context=b"a"), self._entry(2, 2, context=b"b")]
        ebatch, eroot = self.build(pair)
        self.assertTrue(
            verify_convex_polygon_batch_bound(ebatch, eroot, randbelow=DetRand())
        )
        dup = [only[0], only[0], only[0]]
        dbatch, droot = self.build(dup)
        self.assertTrue(
            verify_convex_polygon_batch_bound(dbatch, droot, randbelow=DetRand())
        )

    def test_full_leaf_proof_has_empty_siblings(self):
        batch, _ = self.build(self.honest_entries())
        self.assertEqual(batch.proof.leaf_count, 3)
        self.assertEqual(batch.proof.indices, (0, 1, 2))
        self.assertEqual(batch.proof.siblings, ())

    # ---- leaf layout --------------------------------------------------------

    def test_leaf_layout(self):
        entry = self._entry()
        items = frame_items(_bound_convex_polygon_leaf(entry))
        cursor = 0
        self.assertEqual(items[cursor], b"zkregion/convex-polygon-bound/v1")
        cursor += 1
        for commitment in (entry.x_commitment, entry.y_commitment):
            for value in (
                commitment.element, commitment.lower, commitment.upper,
                commitment.prime, commitment.generator, commitment.h,
            ):
                self.assertEqual(items[cursor], str(value).encode("ascii"))
                cursor += 1
        polygon = entry.polygon
        self.assertEqual(items[cursor], str(len(polygon.vertices)).encode("ascii"))
        cursor += 1
        for vertex in polygon.vertices:
            self.assertEqual(items[cursor], str(vertex[0]).encode("ascii"))
            cursor += 1
            self.assertEqual(items[cursor], str(vertex[1]).encode("ascii"))
            cursor += 1
        self.assertEqual(items[cursor], entry.context)
        cursor += 1
        for sub_proof in (entry.proof.x_proof, entry.proof.y_proof):
            for sequence in (sub_proof.t, sub_proof.e, sub_proof.s):
                self.assertEqual(
                    items[cursor], str(len(sequence)).encode("ascii"))
                cursor += 1
                for value in sequence:
                    self.assertEqual(items[cursor], str(value).encode("ascii"))
                    cursor += 1
        for edge_proof in entry.proof.edge_proofs:
            self.assertEqual(
                items[cursor], str(len(edge_proof.commitments)).encode("ascii"))
            cursor += 1
            for value in edge_proof.commitments:
                self.assertEqual(items[cursor], str(value).encode("ascii"))
                cursor += 1
            for pairs in (edge_proof.challenges, edge_proof.responses):
                self.assertEqual(items[cursor], str(len(pairs)).encode("ascii"))
                cursor += 1
                for pair in pairs:
                    for value in pair:
                        self.assertEqual(items[cursor], str(value).encode("ascii"))
                        cursor += 1
        self.assertEqual(cursor, len(items))

    def test_leaf_item_counts_triangle(self):
        entry = self._entry()
        items = frame_items(_bound_convex_polygon_leaf(entry))
        polygon = entry.polygon
        expected = 1 + 12 + 1 + 2 * len(polygon.vertices) + 1
        for axis_size in (
            polygon.max_x - polygon.min_x + 1,
            polygon.max_y - polygon.min_y + 1,
        ):
            expected += 3 * (1 + axis_size)
        for edge_proof in entry.proof.edge_proofs:
            width = len(edge_proof.commitments)
            expected += (1 + width) + 2 * (1 + 2 * width)
        self.assertEqual(len(items), expected)

    def test_leaf_uses_merkle_leaf_domain(self):
        entries = self.honest_entries()
        batch, root = self.build(entries)
        self.assertEqual(
            merkle_root([_bound_convex_polygon_leaf(e) for e in batch.entries]),
            root,
        )

    def test_rotated_polygon_representation_has_identical_leaf(self):
        entry = self._entry()
        rotated = ConvexPolygonRegion(
            tuple(entry.polygon.vertices[1:] + entry.polygon.vertices[:1])
        )
        equivalent = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, rotated, entry.proof,
            entry.context,
        )
        self.assertEqual(
            _bound_convex_polygon_leaf(equivalent),
            _bound_convex_polygon_leaf(entry),
        )

    def test_empty_context_is_framed_as_zero_length(self):
        entry = self._entry(context=b"")
        items = frame_items(_bound_convex_polygon_leaf(entry))
        # 1 domain + 12 commitment fields + 1 vertex count + 6 vertex values
        self.assertEqual(items[1 + 12 + 1 + 6], b"")

    # ---- coverage / count checks -------------------------------------------

    def test_empty_batch_returns_false_without_drawing(self):
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        proof = MerkleMultiProof(0, (), ())
        batch = BoundConvexPolygonBatch((), 0, proof)
        self.assertIs(
            verify_convex_polygon_batch_bound(
                batch, bytes(32), randbelow=recording
            ),
            False,
        )
        self.assertEqual(calls, [])

    def test_leaf_count_must_equal_entry_count(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        for count in (1, 3, 0):
            bad = BoundConvexPolygonBatch(batch.entries, count, batch.proof)
            self.assertFalse(
                verify_convex_polygon_batch_bound(bad, root, randbelow=DetRand()),
                count,
            )

    def test_leaf_count_must_equal_proof_leaf_count(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        for claimed in (1, 3):
            bad_proof = dataclasses.replace(batch.proof, leaf_count=claimed)
            bad = BoundConvexPolygonBatch(batch.entries, 2, bad_proof)
            self.assertFalse(
                verify_convex_polygon_batch_bound(bad, root, randbelow=DetRand()),
                claimed,
            )

    def test_indices_must_cover_zero_to_n_without_gaps(self):
        batch, root = self.build(self.honest_entries())
        for bad_indices in (
            (0, 1),
            (0, 1, 1),
            (0, 0, 2),
            (2, 1, 0),
            (0, 2, 1),
            (1, 2, 3),
            (-1, 1, 2),
            (0, 1, 3),
            (),
        ):
            bad_proof = MerkleMultiProof(
                3, bad_indices, batch.proof.siblings
            )
            bad_batch = BoundConvexPolygonBatch(batch.entries, 3, bad_proof)
            self.assertFalse(
                verify_convex_polygon_batch_bound(
                    bad_batch, root, randbelow=DetRand()
                ),
                bad_indices,
            )

    def test_missing_entry_returns_false(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        leaves = [_bound_convex_polygon_leaf(e) for e in entries]
        root = merkle_root(leaves)
        proof = MerkleMultiProof(3, (0, 1, 2), ())
        batch = BoundConvexPolygonBatch(tuple(entries), 3, proof)
        self.assertFalse(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )

    # ---- Merkle binding rejection -------------------------------------------

    def test_wrong_root_returns_false(self):
        batch, _ = self.build(self.honest_entries())
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                batch, bytes(32), randbelow=DetRand())
        )
        other = merkle_root([b"alpha", b"beta", b"gamma"])
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                batch, other, randbelow=DetRand())
        )

    def test_reordered_and_replaced_entries_fail_the_root(self):
        entries = self.honest_entries()
        batch, root = self.build(entries)
        reordered = BoundConvexPolygonBatch(
            (batch.entries[1], batch.entries[0], batch.entries[2]),
            3,
            batch.proof,
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                reordered, root, randbelow=DetRand())
        )
        replacement = self._entry(0, 0, context=b"a")
        replaced = BoundConvexPolygonBatch(
            (replacement,) + batch.entries[1:], 3, batch.proof
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                replaced, root, randbelow=DetRand())
        )

    def test_tampered_leaf_returns_false_even_with_matching_proof(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        good = entries[0]
        tampered_commitment = dataclasses.replace(
            good.x_commitment, element=good.x_commitment.element + 1
        )
        bad_x = RangeProof(
            good.proof.x_proof.t,
            tuple(e + 1 for e in good.proof.x_proof.e),
            good.proof.x_proof.s,
        )
        other_polygon = ConvexPolygonRegion(((0, 0), (4, 0), (0, 3)))
        edge = good.proof.edge_proofs[0]
        bad_edge = WideRangeProof(
            tuple(c + 1 for c in edge.commitments),
            edge.challenges,
            edge.responses,
        )
        tampered_variants = (
            dataclasses.replace(good, context=b"other"),
            dataclasses.replace(good, x_commitment=tampered_commitment),
            ConvexPolygonBatchEntry(
                good.y_commitment, good.x_commitment, good.polygon,
                good.proof, good.context,
            ),
            dataclasses.replace(good, polygon=other_polygon),
            dataclasses.replace(
                good,
                proof=dataclasses.replace(good.proof, x_proof=bad_x),
            ),
            dataclasses.replace(
                good,
                proof=dataclasses.replace(
                    good.proof,
                    edge_proofs=(bad_edge,) + good.proof.edge_proofs[1:],
                ),
            ),
        )
        for tampered in tampered_variants:
            bad_batch = BoundConvexPolygonBatch(
                (tampered, entries[1]), 2, batch.proof
            )
            self.assertFalse(
                verify_convex_polygon_batch_bound(
                    bad_batch, root, randbelow=DetRand()
                ),
                tampered,
            )

    def test_committed_but_forged_proof_fails_at_batch_step(self):
        good = self._entry(context=b"a")
        second = self._entry(context=b"b")
        edge = good.proof.edge_proofs[0]
        last_pair = edge.responses[-1]
        forged_edge = WideRangeProof(
            edge.commitments,
            edge.challenges,
            edge.responses[:-1] + ((last_pair[0], last_pair[1] + 1),),
        )
        forged_proof = ConvexPolygonRegionProof(
            good.proof.x_proof,
            good.proof.y_proof,
            (forged_edge,) + good.proof.edge_proofs[1:],
        )
        forged_entry = dataclasses.replace(good, proof=forged_proof)
        forged_entries = [forged_entry, second]
        bad_batch, forged_root = self.build(forged_entries)
        leaves = [_bound_convex_polygon_leaf(e) for e in forged_entries]
        # the Merkle step alone passes against the forged root
        self.assertTrue(
            verify_multi_inclusion(
                list(enumerate(leaves)), bad_batch.proof, forged_root
            )
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, forged_root, randbelow=DetRand()
            )
        )

    def test_committed_dropped_edge_proof_fails_at_batch_step(self):
        good = self._entry()
        forged_proof = ConvexPolygonRegionProof(
            good.proof.x_proof, good.proof.y_proof, good.proof.edge_proofs[1:]
        )
        forged_entry = dataclasses.replace(good, proof=forged_proof)
        bad_batch, forged_root = self.build([forged_entry])
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, forged_root, randbelow=DetRand()
            )
        )

    def test_tampered_siblings_return_false(self):
        batch, root = self.build(self.honest_entries())
        self.assertEqual(batch.proof.siblings, ())
        bogus = MerkleMultiProof(3, batch.proof.indices, (root,))
        bad_batch = BoundConvexPolygonBatch(batch.entries, 3, bogus)
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, root, randbelow=DetRand())
        )

    # ---- randomness contract ------------------------------------------------

    def test_randbelow_passed_unchanged_with_expected_draw_count(self):
        entries = self.honest_entries()
        batch, root = self.build(entries)
        calls = []

        def recording(upper):
            calls.append(upper)
            return (len(calls) * 7919 + 13) % upper

        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=recording)
        )
        expected = sum(self._expected_branch_count(e) for e in entries)
        self.assertEqual(calls, [DEFAULT_PRIME - 1] * expected)

    def test_no_randomness_consumed_before_the_root_check(self):
        batch, _ = self.build(self.honest_entries())

        def boom(upper):
            raise AssertionError("randbelow must not be called before root checks")

        self.assertFalse(
            verify_convex_polygon_batch_bound(batch, bytes(32), randbelow=boom)
        )
        bad_proof = MerkleMultiProof(3, (0, 1), batch.proof.siblings)
        bad_batch = BoundConvexPolygonBatch(batch.entries, 3, bad_proof)
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, bytes(32), randbelow=boom)
        )
        empty = BoundConvexPolygonBatch((), 0, MerkleMultiProof(0, (), ()))
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                empty, bytes(32), randbelow=boom)
        )

    def test_fixed_randbelow_is_reproducible(self):
        batch, root = self.build(self.honest_entries())
        first = verify_convex_polygon_batch_bound(
            batch, root, randbelow=DetRand(9)
        )
        second = verify_convex_polygon_batch_bound(
            batch, root, randbelow=DetRand(9)
        )
        self.assertEqual(first, second)

    def test_bad_randomness_outcomes_raise(self):
        batch, root = self.build(self.honest_entries())
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_convex_polygon_batch_bound(
                    batch, root, randbelow=lambda upper, bad=bad: bad
                )
        for bad in (-1, DEFAULT_PRIME - 1, DEFAULT_PRIME):
            with self.assertRaises(ValueError):
                verify_convex_polygon_batch_bound(
                    batch, root, randbelow=lambda upper, bad=bad: bad
                )

    # ---- type errors --------------------------------------------------------

    def test_type_errors(self):
        entries = self.honest_entries()
        batch, root = self.build(entries)
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound("batch", root)
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(None, root)
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(list(batch.entries), 3, batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(("x",) * 3, 3, batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(batch.entries, True, batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(batch.entries, 3.0, batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(batch.entries, "3", batch.proof), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(batch.entries, 3, "proof"), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(batch, "root")
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(batch, bytearray(root))
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(batch, root, randbelow=7)

    def test_nested_entry_type_errors(self):
        entries = self.honest_entries()
        batch, root = self.build(entries)
        entry = entries[0]

        def expect(bad):
            with self.assertRaises(TypeError):
                verify_convex_polygon_batch_bound(
                    BoundConvexPolygonBatch(
                        (bad,) + batch.entries[1:], 3, batch.proof
                    ),
                    root,
                    randbelow=DetRand(),
                )

        expect(("x", entry.y_commitment, entry.polygon, entry.proof, b"c"))
        expect(ConvexPolygonBatchEntry(
            "x", entry.y_commitment, entry.polygon, entry.proof, b"c"
        ))
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            ((0, 0), (4, 0), (0, 4)), entry.proof, b"c",
        ))
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            entry.proof, "c",
        ))
        prime = entry.x_commitment.prime
        bool_commitment = PedersenCommitment(True, 0, 4, prime, 3, 9)
        expect(ConvexPolygonBatchEntry(
            bool_commitment, entry.y_commitment, entry.polygon, entry.proof, b"c"
        ))
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            ConvexPolygonRegionProof(
                "x", entry.proof.y_proof, entry.proof.edge_proofs),
            b"c",
        ))
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            ConvexPolygonRegionProof(
                RangeProof([1], (0,), (0,)),
                entry.proof.y_proof,
                entry.proof.edge_proofs,
            ),
            b"c",
        ))
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            ConvexPolygonRegionProof(
                entry.proof.x_proof, entry.proof.y_proof,
                list(entry.proof.edge_proofs),
            ),
            b"c",
        ))
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            ConvexPolygonRegionProof(
                entry.proof.x_proof, entry.proof.y_proof, (1, 2, 3)),
            b"c",
        ))
        edge = entry.proof.edge_proofs[0]
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            ConvexPolygonRegionProof(
                entry.proof.x_proof,
                entry.proof.y_proof,
                (WideRangeProof(
                    list(edge.commitments), edge.challenges, edge.responses
                ),) + entry.proof.edge_proofs[1:],
            ),
            b"c",
        ))
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            ConvexPolygonRegionProof(
                entry.proof.x_proof,
                entry.proof.y_proof,
                (WideRangeProof(
                    edge.commitments,
                    ((edge.challenges[0][0], True),) + edge.challenges[1:],
                    edge.responses,
                ),) + entry.proof.edge_proofs[1:],
            ),
            b"c",
        ))
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", [(0, 0), (1, 0), (0, 1)])
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, forged, entry.proof, b"c"
        ))
        # the whole batch is walked: a bad type in the last entry still raises
        late_bad = dataclasses.replace(entries[2], context="late")
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(
                    (entries[0], entries[1], late_bad), 3, batch.proof
                ),
                root,
                randbelow=DetRand(),
            )

    def test_malformed_merkle_proof_field_types(self):
        batch, root = self.build(self.honest_entries())
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(
                    batch.entries, 3,
                    MerkleMultiProof(True, (0, 1, 2), ()),
                ),
                root,
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(
                    batch.entries, 3,
                    MerkleMultiProof(3, [0, 1, 2], ()),
                ),
                root,
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(
                    batch.entries, 3,
                    MerkleMultiProof(3, (0, 1, 2.0), ()),
                ),
                root,
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                BoundConvexPolygonBatch(
                    batch.entries, 3,
                    MerkleMultiProof(3, (0, 1, 2), ["x"]),
                ),
                root,
            )

    # ---- hygiene ------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = self.honest_entries()
        batch, root = self.build(entries)
        snapshot = BoundConvexPolygonBatch(
            tuple(dataclasses.replace(entry) for entry in batch.entries),
            batch.leaf_count,
            dataclasses.replace(batch.proof),
        )
        verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        self.assertEqual(batch, snapshot)


class ProveConvexPolygonBatchBoundTest(ConvexPolygonBoundBatchFixture):
    # ---- round trips --------------------------------------------------------

    def test_constructed_batch_passes_verify(self):
        entries = self.honest_entries()
        batch, root = prove_convex_polygon_batch_bound(
            entries, randbelow=DetRand()
        )
        self.assertTrue(
            verify_convex_polygon_batch_bound(
                batch, root, randbelow=DetRand())
        )
        self.assertTrue(verify_convex_polygon_batch_bound(batch, root))

    def test_single_even_and_duplicates(self):
        only = [self._entry()]
        batch, root = prove_convex_polygon_batch_bound(
            only, randbelow=DetRand())
        self.assertEqual(batch.leaf_count, 1)
        self.assertEqual(batch.entries, tuple(only))
        self.assertTrue(
            verify_convex_polygon_batch_bound(
                batch, root, randbelow=DetRand())
        )
        pair = [self._entry(1, 1), self._entry(2, 2)]
        ebatch, eroot = prove_convex_polygon_batch_bound(
            pair, randbelow=DetRand())
        self.assertEqual(ebatch.leaf_count, 2)
        self.assertTrue(
            verify_convex_polygon_batch_bound(
                ebatch, eroot, randbelow=DetRand())
        )
        dup = [only[0], only[0], only[0]]
        dbatch, droot = prove_convex_polygon_batch_bound(
            dup, randbelow=DetRand())
        self.assertEqual(dbatch.leaf_count, 3)
        self.assertEqual(dbatch.entries, (only[0], only[0], only[0]))
        self.assertTrue(
            verify_convex_polygon_batch_bound(
                dbatch, droot, randbelow=DetRand())
        )

    def test_full_proof_covers_every_position_from_zero(self):
        batch, _ = prove_convex_polygon_batch_bound(
            self.honest_entries(), randbelow=DetRand()
        )
        self.assertEqual(batch.leaf_count, 3)
        self.assertEqual(batch.proof.leaf_count, 3)
        self.assertEqual(batch.proof.indices, (0, 1, 2))
        self.assertEqual(batch.proof.siblings, ())

    def test_order_preserved(self):
        entries = self.honest_entries()
        reordered = [entries[2], entries[0], entries[1]]
        batch, _ = prove_convex_polygon_batch_bound(
            reordered, randbelow=DetRand())
        self.assertEqual(batch.entries, tuple(reordered))

    def test_equals_manual_construction_byte_for_byte(self):
        entries = self.honest_entries()
        batch, root = prove_convex_polygon_batch_bound(
            entries, randbelow=DetRand())
        leaves = [_bound_convex_polygon_leaf(e) for e in entries]
        manual_root = merkle_root(leaves)
        manual_proof = prove_multi_inclusion(
            leaves, tuple(range(len(entries))))
        manual_batch = BoundConvexPolygonBatch(
            tuple(entries), len(entries), manual_proof
        )
        self.assertEqual(root, manual_root)
        self.assertEqual(batch, manual_batch)
        self.assertEqual(
            dataclasses.asdict(batch), dataclasses.asdict(manual_batch))

    def test_repeated_construction_is_byte_identical(self):
        entries = self.honest_entries()
        batch, root = prove_convex_polygon_batch_bound(
            entries, randbelow=DetRand())
        batch2, root2 = prove_convex_polygon_batch_bound(
            list(entries), randbelow=DetRand())
        self.assertEqual(batch, batch2)
        self.assertEqual(root, root2)
        self.assertEqual(batch.proof, batch2.proof)

    # ---- input hygiene ------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = self.honest_entries()
        snapshot = [dataclasses.replace(entry) for entry in entries]
        prove_convex_polygon_batch_bound(entries, randbelow=DetRand())
        self.assertEqual(entries, snapshot)
        self.assertIsInstance(entries, list)

    # ---- rejections ---------------------------------------------------------

    def test_empty_batch_raises_value_error(self):
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound([], randbelow=DetRand())
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound((), randbelow=DetRand())

    def test_container_type_errors(self):
        good = self.honest_entries()
        for bad in (b"abc", "abc", 123, None, {good[0]}, 4.5):
            with self.assertRaises(TypeError):
                prove_convex_polygon_batch_bound(
                    bad, randbelow=DetRand())
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(iter(good), randbelow=DetRand())

    def test_nested_entry_type_errors(self):
        good = self.honest_entries()
        entry = good[0]
        prime = entry.x_commitment.prime
        cases = [
            ("x", entry.y_commitment, entry.polygon, entry.proof, b"c"),
            ConvexPolygonBatchEntry(
                PedersenCommitment(True, 0, 4, prime, 3, 9),
                entry.y_commitment, entry.polygon, entry.proof, b"c",
            ),
            ConvexPolygonBatchEntry(
                entry.x_commitment, entry.y_commitment,
                ((0, 0), (4, 0), (0, 4)), entry.proof, b"c",
            ),
            ConvexPolygonBatchEntry(
                entry.x_commitment, entry.y_commitment, entry.polygon,
                entry.proof, "c",
            ),
        ]
        for bad in cases:
            with self.assertRaises(TypeError):
                prove_convex_polygon_batch_bound(
                    [bad, good[1]], randbelow=DetRand())
        # a wrong type in the last entry is still caught in the preflight
        late_bad = dataclasses.replace(good[2], context="late")
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(
                [good[0], good[1], late_bad], randbelow=DetRand())

    def test_non_callable_randbelow_raises_type_error(self):
        entries = self.honest_entries()
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(entries, randbelow=7)
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(b"x", randbelow=7)

    def test_inner_batch_failure_raises_value_error(self):
        good = self._entry()
        bad = dataclasses.replace(good, context=b"tampered")
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound([bad], randbelow=DetRand())
        good_entries = self.honest_entries()
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound(
                [good_entries[0], bad], randbelow=DetRand())

    def test_random_source_exceptions_surface_per_inner_contract(self):
        entries = self.honest_entries()

        def non_integer(_):
            return "x"

        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(
                entries, randbelow=non_integer)

        def returns_bool(_):
            return False

        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(
                entries, randbelow=returns_bool)

        def out_of_range(_):
            return DEFAULT_PRIME - 1

        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound(
                entries, randbelow=out_of_range)

    def test_rejections_are_deterministic(self):
        bad = dataclasses.replace(self._entry(), context=b"tampered")
        for _ in range(3):
            with self.assertRaises(ValueError):
                prove_convex_polygon_batch_bound(
                    [bad], randbelow=DetRand())


if __name__ == "__main__":
    unittest.main()
