"""Tests for the convex polygon proof bundle batch and bound-batch APIs."""

import dataclasses
import itertools
import unittest

from zkregion import (
    BoundConvexPolygonBundleBatch,
    ConvexPolygonIntervalProof,
    ConvexPolygonProofBundle,
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    MerkleMultiProof,
    encode_convex_polygon_proof_bundle,
    merkle_root,
    pedersen_commit,
    prove_convex_polygon,
    prove_convex_polygon_bundle_batch_bound,
    prove_convex_polygon_interval,
    verify_convex_polygon_bundle_batch,
    verify_convex_polygon_bundle_batch_bound,
    verify_convex_polygon_proof_bundle,
)


class DetRand:
    """Deterministic randbelow replacement: same sequence for same counter."""

    def __init__(self, seed=1):
        self.calls = seed

    def __call__(self, upper):
        self.calls += 1
        return (self.calls * 7919 + 13) % upper


TRIANGLE = ((0, 0), (4, 0), (0, 4))
SQUARE = ((0, 0), (6, 0), (6, 6), (0, 6))
# Non-power-of-two bounding box widths and negative coordinates.
WIDE = ((-30, -10), (70, -10), (70, 40), (-30, 40))


def _region_bundle(vertices=TRIANGLE, x=1, y=2, context=b"ctx", seed=1):
    polygon = ConvexPolygonRegion(vertices)
    cx, rx = pedersen_commit(
        x, polygon.min_x, polygon.max_x, randbelow=DetRand(seed)
    )
    cy, ry = pedersen_commit(
        y, polygon.min_y, polygon.max_y, randbelow=DetRand(seed + 1)
    )
    proof = prove_convex_polygon(
        cx, cy, x, y, rx, ry, polygon, context, randbelow=DetRand(seed + 2)
    )
    return ConvexPolygonProofBundle(cx, cy, polygon, context, proof)


def _interval_bundle(vertices=WIDE, x=0, y=0, context=b"ictx", seed=11):
    polygon = ConvexPolygonRegion(vertices)
    cx, rx = pedersen_commit(
        x, polygon.min_x, polygon.max_x, randbelow=DetRand(seed)
    )
    cy, ry = pedersen_commit(
        y, polygon.min_y, polygon.max_y, randbelow=DetRand(seed + 1)
    )
    proof = prove_convex_polygon_interval(
        cx, cy, x, y, rx, ry, polygon, context, randbelow=DetRand(seed + 2)
    )
    return ConvexPolygonProofBundle(cx, cy, polygon, context, proof)


def _mixed_bundles():
    return [
        _region_bundle(),
        _interval_bundle(),
        _region_bundle(vertices=SQUARE, x=6, y=6, context=b"square", seed=21),
        _interval_bundle(vertices=TRIANGLE, x=0, y=4, context=b"", seed=31),
    ]


class ConvexPolygonBundleBatchTests(unittest.TestCase):
    def test_mixed_variants_polygons_and_contexts_pass(self):
        bundles = _mixed_bundles()
        self.assertIsInstance(bundles[1].proof, ConvexPolygonIntervalProof)
        self.assertTrue(verify_convex_polygon_bundle_batch(bundles))
        self.assertTrue(verify_convex_polygon_bundle_batch(tuple(bundles)))

    def test_single_entry_and_boundary_points(self):
        boundary = _interval_bundle(x=-30, y=-10, seed=41)  # polygon vertex
        self.assertTrue(verify_convex_polygon_bundle_batch([boundary]))
        self.assertTrue(verify_convex_polygon_bundle_batch([_region_bundle()]))

    def test_order_and_duplicates_are_irrelevant(self):
        bundles = _mixed_bundles()
        shuffled = [bundles[2], bundles[0], bundles[0], bundles[3], bundles[1]]
        self.assertTrue(verify_convex_polygon_bundle_batch(shuffled))

    def test_empty_batch_returns_false(self):
        self.assertFalse(verify_convex_polygon_bundle_batch([]))
        self.assertFalse(verify_convex_polygon_bundle_batch(()))

    def test_non_list_or_tuple_input_raises_type_error(self):
        bundle = _region_bundle()
        for bad in (
            "entries",
            b"entries",
            42,
            None,
            {bundle},
            (item for item in [bundle]),
        ):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(TypeError):
                    verify_convex_polygon_bundle_batch(bad)

    def test_wrong_entry_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch([_region_bundle(), object()])
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch([_region_bundle().proof])

    def test_last_entry_type_error_not_masked_by_invalid_first_entry(self):
        tampered = dataclasses.replace(
            _region_bundle(), context=b"wrong-context"
        )
        self.assertFalse(verify_convex_polygon_proof_bundle(tampered))
        # The first entry fails semantically, but the last entry's wrong
        # type must still surface as a TypeError.
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch([tampered, object()])
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch([tampered, _region_bundle(), 7])

    def test_nested_type_errors(self):
        bundle = _region_bundle()
        bad_context = dataclasses.replace(bundle, context="ctx")
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch([bad_context])
        bad_bool = dataclasses.replace(
            bundle,
            x_commitment=dataclasses.replace(bundle.x_commitment, element=True),
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch([bad_bool])
        bad_proof_field = dataclasses.replace(
            bundle,
            proof=dataclasses.replace(bundle.proof, edge_proofs=list(bundle.proof.edge_proofs)),
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch([bad_proof_field])

    def test_semantic_failures_return_false(self):
        good = _region_bundle()
        wrong_context = dataclasses.replace(good, context=b"other")
        self.assertFalse(verify_convex_polygon_bundle_batch([good, wrong_context]))
        other_polygon = dataclasses.replace(
            good, polygon=ConvexPolygonRegion(SQUARE)
        )
        self.assertFalse(verify_convex_polygon_bundle_batch([other_polygon]))
        tampered_proof = dataclasses.replace(
            good,
            proof=dataclasses.replace(
                good.proof,
                x_proof=dataclasses.replace(
                    good.proof.x_proof,
                    s=good.proof.x_proof.s[:-1] + (good.proof.x_proof.s[-1] + 1,),
                ),
            ),
        )
        self.assertFalse(verify_convex_polygon_bundle_batch([tampered_proof]))

    def test_inputs_are_not_mutated(self):
        bundles = _mixed_bundles()
        snapshot = list(bundles)
        verify_convex_polygon_bundle_batch(bundles)
        self.assertEqual(bundles, snapshot)


class ConvexPolygonBundleBatchBoundTests(unittest.TestCase):
    def test_construct_and_verify_round_trip(self):
        bundles = _mixed_bundles()
        batch, root = prove_convex_polygon_bundle_batch_bound(bundles)
        self.assertIsInstance(batch, BoundConvexPolygonBundleBatch)
        self.assertIsInstance(root, bytes)
        self.assertIsInstance(batch.entries, tuple)
        self.assertEqual(batch.entries, tuple(bundles))
        self.assertEqual(batch.leaf_count, len(bundles))
        self.assertIsInstance(batch.proof, MerkleMultiProof)
        self.assertEqual(batch.proof.leaf_count, len(bundles))
        self.assertEqual(batch.proof.indices, tuple(range(len(bundles))))
        self.assertEqual(batch.proof.siblings, ())
        self.assertTrue(verify_convex_polygon_bundle_batch_bound(batch, root))

    def test_leaf_encoding_and_root_semantics(self):
        bundles = _mixed_bundles()
        batch, root = prove_convex_polygon_bundle_batch_bound(bundles)
        leaves = [
            b"zkregion/cpbb/v1" + encode_convex_polygon_proof_bundle(bundle)
            for bundle in bundles
        ]
        self.assertEqual(root, merkle_root(leaves))
        self.assertEqual(batch.leaf_count, len(leaves))

    def test_single_entry_and_duplicates(self):
        single = _region_bundle()
        batch, root = prove_convex_polygon_bundle_batch_bound([single])
        self.assertEqual(batch.leaf_count, 1)
        self.assertTrue(verify_convex_polygon_bundle_batch_bound(batch, root))
        dup_batch, dup_root = prove_convex_polygon_bundle_batch_bound(
            [single, single, single]
        )
        self.assertEqual(dup_batch.entries, (single, single, single))
        self.assertTrue(
            verify_convex_polygon_bundle_batch_bound(dup_batch, dup_root)
        )

    def test_odd_and_even_sizes(self):
        bundles = _mixed_bundles()
        for size in (1, 2, 3, 4):
            with self.subTest(size=size):
                batch, root = prove_convex_polygon_bundle_batch_bound(
                    bundles[:size]
                )
                self.assertTrue(
                    verify_convex_polygon_bundle_batch_bound(batch, root)
                )

    def test_deterministic_reconstruction(self):
        bundles = _mixed_bundles()
        batch1, root1 = prove_convex_polygon_bundle_batch_bound(bundles)
        batch2, root2 = prove_convex_polygon_bundle_batch_bound(list(bundles))
        self.assertEqual(batch1, batch2)
        self.assertEqual(root1, root2)

    def test_caller_list_mutation_does_not_affect_result(self):
        bundles = _mixed_bundles()
        batch, root = prove_convex_polygon_bundle_batch_bound(bundles)
        bundles.append(_region_bundle(seed=51))
        bundles.pop(0)
        self.assertEqual(batch.leaf_count, 4)
        self.assertTrue(verify_convex_polygon_bundle_batch_bound(batch, root))

    def test_batch_is_immutable(self):
        batch, _ = prove_convex_polygon_bundle_batch_bound(_mixed_bundles())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 99

    def test_empty_batch_construction_raises_value_error(self):
        with self.assertRaises(ValueError):
            prove_convex_polygon_bundle_batch_bound([])
        with self.assertRaises(ValueError):
            prove_convex_polygon_bundle_batch_bound(())

    def test_invalid_envelope_construction_raises_value_error(self):
        wrong_context = dataclasses.replace(_region_bundle(), context=b"nope")
        with self.assertRaises(ValueError):
            prove_convex_polygon_bundle_batch_bound([wrong_context])
        with self.assertRaises(ValueError):
            prove_convex_polygon_bundle_batch_bound(
                [_region_bundle(), wrong_context]
            )

    def test_construction_type_errors(self):
        bundle = _region_bundle()
        with self.assertRaises(TypeError):
            prove_convex_polygon_bundle_batch_bound("not a batch")
        with self.assertRaises(TypeError):
            prove_convex_polygon_bundle_batch_bound([bundle, None])
        bad_bool = dataclasses.replace(
            bundle,
            y_commitment=dataclasses.replace(bundle.y_commitment, lower=False),
        )
        with self.assertRaises(TypeError):
            prove_convex_polygon_bundle_batch_bound([bad_bool])

    def test_verify_wrong_root_returns_false(self):
        batch, root = prove_convex_polygon_bundle_batch_bound(_mixed_bundles())
        other_root = merkle_root([b"zkregion/cpbb/v1" + b"other"])
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(batch, other_root))
        flipped = bytes([root[0] ^ 1]) + root[1:]
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(batch, flipped))

    def test_verify_deleted_inserted_reordered_replaced_entries(self):
        bundles = _mixed_bundles()
        batch, root = prove_convex_polygon_bundle_batch_bound(bundles)

        deleted = dataclasses.replace(
            batch, entries=batch.entries[:-1], leaf_count=len(bundles) - 1
        )
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(deleted, root))

        inserted = dataclasses.replace(
            batch,
            entries=batch.entries + (_region_bundle(seed=61),),
            leaf_count=len(bundles) + 1,
        )
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(inserted, root))

        reordered = dataclasses.replace(
            batch, entries=tuple(reversed(batch.entries))
        )
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(reordered, root))

        replaced = dataclasses.replace(
            batch,
            entries=batch.entries[:1]
            + (_region_bundle(seed=71),)
            + batch.entries[2:],
        )
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(replaced, root))

    def test_verify_count_mismatches_return_false(self):
        batch, root = prove_convex_polygon_bundle_batch_bound(_mixed_bundles())
        for bad_count in (0, -1, len(batch.entries) + 1, len(batch.entries) - 1):
            with self.subTest(bad_count=bad_count):
                forged = dataclasses.replace(batch, leaf_count=bad_count)
                self.assertFalse(
                    verify_convex_polygon_bundle_batch_bound(forged, root)
                )
        mismatched_proof = dataclasses.replace(
            batch,
            proof=dataclasses.replace(batch.proof, leaf_count=batch.leaf_count + 1),
        )
        self.assertFalse(
            verify_convex_polygon_bundle_batch_bound(mismatched_proof, root)
        )

    def test_verify_index_gaps_duplicates_and_reordering_return_false(self):
        batch, root = prove_convex_polygon_bundle_batch_bound(_mixed_bundles())
        n = batch.leaf_count
        for bad_indices in (
            tuple(range(1, n)),
            tuple(range(n - 1)),
            (0, 0) + tuple(range(2, n)),
            tuple(reversed(range(n))),
            (0, 2, 1, 3),
        ):
            with self.subTest(bad_indices=bad_indices):
                forged = dataclasses.replace(
                    batch,
                    proof=dataclasses.replace(batch.proof, indices=bad_indices),
                )
                self.assertFalse(
                    verify_convex_polygon_bundle_batch_bound(forged, root)
                )

    def test_verify_extra_siblings_return_false(self):
        batch, root = prove_convex_polygon_bundle_batch_bound(_mixed_bundles())
        forged = dataclasses.replace(
            batch,
            proof=dataclasses.replace(
                batch.proof, siblings=batch.proof.siblings + (b"\x00" * 32,)
            ),
        )
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(forged, root))

    def test_verify_tampered_envelope_content_returns_false(self):
        bundles = _mixed_bundles()
        batch, root = prove_convex_polygon_bundle_batch_bound(bundles)
        tampered = dataclasses.replace(bundles[0], context=b"tampered")
        forged = dataclasses.replace(
            batch, entries=(tampered,) + batch.entries[1:]
        )
        self.assertFalse(verify_convex_polygon_bundle_batch_bound(forged, root))

    def test_verify_type_errors(self):
        batch, root = prove_convex_polygon_bundle_batch_bound(_mixed_bundles())
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(object(), root)
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(batch, "root")
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(
                dataclasses.replace(batch, entries=list(batch.entries)), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(
                dataclasses.replace(batch, leaf_count=True), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(
                dataclasses.replace(batch, proof=batch.entries), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(
                dataclasses.replace(
                    batch,
                    proof=dataclasses.replace(batch.proof, leaf_count=True),
                ),
                root,
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(
                dataclasses.replace(
                    batch,
                    proof=dataclasses.replace(
                        batch.proof, indices=list(batch.proof.indices)
                    ),
                ),
                root,
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(
                dataclasses.replace(
                    batch,
                    proof=dataclasses.replace(
                        batch.proof, siblings=list(batch.proof.siblings)
                    ),
                ),
                root,
            )
        bad_entry = dataclasses.replace(
            batch, entries=(object(),) + batch.entries[1:]
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(bad_entry, root)

    def test_verify_last_entry_type_error_not_masked(self):
        bundles = _mixed_bundles()
        batch, root = prove_convex_polygon_bundle_batch_bound(bundles)
        tampered_first = dataclasses.replace(bundles[0], context=b"bad")
        forged = dataclasses.replace(
            batch, entries=(tampered_first,) + batch.entries[1:-1] + (42,)
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_bundle_batch_bound(forged, root)

    def test_inputs_are_not_mutated(self):
        bundles = _mixed_bundles()
        snapshot = list(bundles)
        batch, root = prove_convex_polygon_bundle_batch_bound(bundles)
        self.assertEqual(bundles, snapshot)
        verify_convex_polygon_bundle_batch_bound(batch, root)
        self.assertEqual(bundles, snapshot)


if __name__ == "__main__":
    unittest.main()
