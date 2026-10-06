"""Tests for the convex polygon interval-range membership proof API."""

import dataclasses
import itertools
import unittest

from zkregion import (
    ConvexPolygonIntervalProof,
    ConvexPolygonRegion,
    DEFAULT_PRIME,
    IntervalRangeProof,
    WideRangeProof,
    pedersen_commit,
    prove_convex_polygon,
    prove_convex_polygon_interval,
    verify_convex_polygon_interval,
)


def _counter_randbelow():
    counter = itertools.count(1)
    return lambda upper: next(counter) % upper


def _commit_pair(polygon, x, y):
    x_commitment, x_blinding = pedersen_commit(
        x, polygon.min_x, polygon.max_x, randbelow=_counter_randbelow()
    )
    y_commitment, y_blinding = pedersen_commit(
        y, polygon.min_y, polygon.max_y, randbelow=_counter_randbelow()
    )
    return x_commitment, y_commitment, x_blinding, y_blinding


def _prove(x_commitment, y_commitment, x, y, x_blinding, y_blinding, polygon,
           context=b""):
    return prove_convex_polygon_interval(
        x_commitment,
        y_commitment,
        x,
        y,
        x_blinding,
        y_blinding,
        polygon,
        context,
        randbelow=_counter_randbelow(),
    )


TRIANGLE = ConvexPolygonRegion(((0, 0), (1000, 0), (0, 1000)))


class ConvexPolygonIntervalProveTest(unittest.TestCase):
    def test_interior_edge_and_vertex_points_pass(self):
        for point in [(400, 500), (500, 500), (0, 0), (1000, 0), (0, 1000)]:
            with self.subTest(point=point):
                xc, yc, xb, yb = _commit_pair(TRIANGLE, *point)
                proof = _prove(xc, yc, *point, xb, yb, TRIANGLE, b"ctx")
                self.assertIsInstance(proof, ConvexPolygonIntervalProof)
                self.assertIsInstance(proof.x_proof, IntervalRangeProof)
                self.assertIsInstance(proof.y_proof, IntervalRangeProof)
                self.assertEqual(len(proof.edge_proofs), 3)
                self.assertTrue(
                    all(isinstance(p, WideRangeProof) for p in proof.edge_proofs)
                )
                self.assertTrue(
                    verify_convex_polygon_interval(xc, yc, TRIANGLE, proof, b"ctx")
                )

    def test_old_entry_keeps_256_limit(self):
        xc, yc, xb, yb = _commit_pair(TRIANGLE, 400, 500)
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                xc, yc, 400, 500, xb, yb, TRIANGLE,
                randbelow=_counter_randbelow(),
            )

    def test_point_outside_polygon_raises(self):
        xc, yc, xb, yb = _commit_pair(TRIANGLE, 700, 700)
        with self.assertRaises(ValueError):
            _prove(xc, yc, 700, 700, xb, yb, TRIANGLE)

    def test_non_power_of_two_negative_and_zero_crossing(self):
        polygon = ConvexPolygonRegion(
            ((-100, -50), (700, -50), (700, 333), (-100, 333))
        )
        self.assertEqual(polygon.max_x - polygon.min_x + 1, 801)
        for point in [(0, 0), (-100, -50), (700, 333), (0, 100)]:
            with self.subTest(point=point):
                xc, yc, xb, yb = _commit_pair(polygon, *point)
                proof = _prove(xc, yc, *point, xb, yb, polygon)
                self.assertTrue(
                    verify_convex_polygon_interval(xc, yc, polygon, proof)
                )

    def test_axis_limit_is_2_to_the_24(self):
        wide = ConvexPolygonRegion(
            ((0, 0), ((1 << 24) - 1, 0), ((1 << 24) - 1, 1), (0, 1))
        )
        xc, yc, xb, yb = _commit_pair(wide, 100, 1)
        proof = _prove(xc, yc, 100, 1, xb, yb, wide)
        self.assertTrue(verify_convex_polygon_interval(xc, yc, wide, proof))
        tall = ConvexPolygonRegion(
            ((0, 0), (1, 0), (1, (1 << 24) - 1), (0, (1 << 24) - 1))
        )
        xc, yc, xb, yb = _commit_pair(tall, 1, 99)
        proof = _prove(xc, yc, 1, 99, xb, yb, tall)
        self.assertTrue(verify_convex_polygon_interval(xc, yc, tall, proof))

    def test_axis_wider_than_2_to_the_24_raises_without_randomness(self):
        polygon = ConvexPolygonRegion(((0, 0), (1 << 24, 0), (1 << 24, 1), (0, 1)))
        xc, yc, xb, yb = _commit_pair(polygon, 5, 0)
        calls = []

        def counting(upper):
            calls.append(upper)
            return 0

        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(
                xc, yc, 5, 0, xb, yb, polygon, randbelow=counting
            )
        self.assertEqual(calls, [])

    def test_semantic_failures_draw_no_randomness(self):
        xc, yc, xb, yb = _commit_pair(TRIANGLE, 400, 500)
        other_h = dataclasses.replace(yc, h=yc.h + 1)
        bad_range = dataclasses.replace(xc, upper=999)
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(
            forged, "vertices", ((0, 0), (10, 0), (10, 0), (0, 10))
        )
        cases = [
            (xc, other_h, 400, 500, xb, yb, TRIANGLE),  # group mismatch
            (bad_range, yc, 400, 500, xb, yb, TRIANGLE),  # range mismatch
            (xc, yc, 400, 500, xb + 1, yb, TRIANGLE),  # failed opening
            (xc, yc, 700, 700, xb, yb, TRIANGLE),  # outside point
            (xc, yc, 400, 500, xb, yb, forged),  # invalid geometry
        ]
        for case in cases:
            with self.subTest(case=case[2:6]):
                calls = []

                def counting(upper):
                    calls.append(upper)
                    return 0

                with self.assertRaises(ValueError):
                    prove_convex_polygon_interval(
                        case[0], case[1], *case[2:6], case[6],
                        randbelow=counting,
                    )
                self.assertEqual(calls, [])

    def test_edge_span_limit_raises_without_randomness(self):
        # Legs of 2**24 - 1 give a hypotenuse offset span beyond 2**24.
        polygon = ConvexPolygonRegion(
            ((0, 0), ((1 << 24) - 1, 0), (0, (1 << 24) - 1))
        )
        xc, yc, xb, yb = _commit_pair(polygon, 1, 1)
        calls = []

        def counting(upper):
            calls.append(upper)
            return 0

        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(
                xc, yc, 1, 1, xb, yb, polygon, randbelow=counting
            )
        self.assertEqual(calls, [])

    def test_type_errors(self):
        xc, yc, xb, yb = _commit_pair(TRIANGLE, 400, 500)
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(xc, yc, True, 500, xb, yb, TRIANGLE)
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(
                xc, yc, 400, 500, xb, yb, TRIANGLE, context="s"
            )
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(
                xc, yc, 400, 500, xb, yb, TRIANGLE, randbelow=42
            )
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(
                xc, yc, 400, 500, xb, yb, "not a polygon"
            )
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ((0, 0), (True, 0), (0, 1)))
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(xc, yc, 1, 0, xb, yb, forged)

    def test_randbelow_contract(self):
        xc, yc, xb, yb = _commit_pair(TRIANGLE, 400, 500)
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(
                xc, yc, 400, 500, xb, yb, TRIANGLE, randbelow=lambda u: True
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(
                xc, yc, 400, 500, xb, yb, TRIANGLE, randbelow=lambda u: u
            )

        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            prove_convex_polygon_interval(
                xc, yc, 400, 500, xb, yb, TRIANGLE, randbelow=boom
            )

    def test_deterministic_and_frozen(self):
        xc, yc, xb, yb = _commit_pair(TRIANGLE, 400, 500)
        first = _prove(xc, yc, 400, 500, xb, yb, TRIANGLE, b"c")
        second = _prove(xc, yc, 400, 500, xb, yb, TRIANGLE, b"c")
        self.assertEqual(first, second)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.x_proof = second.x_proof

    def test_proof_size_grows_with_width_and_edges(self):
        def size(proof):
            total = (
                len(proof.x_proof.low_commitments)
                + len(proof.x_proof.high_commitments)
                + len(proof.y_proof.low_commitments)
                + len(proof.y_proof.high_commitments)
            )
            return total + sum(len(e.commitments) for e in proof.edge_proofs)

        narrow = ConvexPolygonRegion(((0, 0), (3, 0), (0, 3)))
        xc, yc, xb, yb = _commit_pair(narrow, 1, 1)
        small_proof = _prove(xc, yc, 1, 1, xb, yb, narrow)
        xc, yc, xb, yb = _commit_pair(TRIANGLE, 400, 500)
        big_proof = _prove(xc, yc, 400, 500, xb, yb, TRIANGLE)
        self.assertGreater(size(big_proof), size(small_proof))
        square = ConvexPolygonRegion(
            ((0, 0), (1000, 0), (1000, 1000), (0, 1000))
        )
        xc, yc, xb, yb = _commit_pair(square, 5, 5)
        square_proof = _prove(xc, yc, 5, 5, xb, yb, square)
        self.assertEqual(len(square_proof.edge_proofs), 4)
        self.assertEqual(len(big_proof.edge_proofs), 3)


class ConvexPolygonIntervalVerifyTest(unittest.TestCase):
    def setUp(self):
        self.xc, self.yc, self.xb, self.yb = _commit_pair(TRIANGLE, 400, 500)
        self.proof = _prove(
            self.xc, self.yc, 400, 500, self.xb, self.yb, TRIANGLE, b"c"
        )

    def verify(self, xc=None, yc=None, polygon=None, proof=None, context=b"c"):
        return verify_convex_polygon_interval(
            xc if xc is not None else self.xc,
            yc if yc is not None else self.yc,
            polygon if polygon is not None else TRIANGLE,
            proof if proof is not None else self.proof,
            context,
        )

    def test_rotation_and_reversal_invariant(self):
        for vertices in [
            ((1000, 0), (0, 1000), (0, 0)),
            ((0, 1000), (0, 0), (1000, 0)),
            ((0, 0), (0, 1000), (1000, 0)),
            ((1000, 0), (0, 0), (0, 1000)),
        ]:
            with self.subTest(vertices=vertices):
                self.assertTrue(
                    self.verify(polygon=ConvexPolygonRegion(vertices))
                )

    def test_tampering_returns_false(self):
        self.assertFalse(self.verify(context=b"other"))
        self.assertFalse(self.verify(xc=self.yc, yc=self.xc))  # swapped axes
        other = ConvexPolygonRegion(((0, 0), (1000, 0), (0, 999)))
        self.assertFalse(self.verify(polygon=other))
        bad_xc = dataclasses.replace(self.xc, h=self.xc.h + 1)
        self.assertFalse(self.verify(xc=bad_xc))
        # dropped, reordered and replaced edge proofs
        self.assertFalse(
            self.verify(proof=dataclasses.replace(
                self.proof, edge_proofs=self.proof.edge_proofs[:-1]
            ))
        )
        self.assertFalse(
            self.verify(proof=dataclasses.replace(
                self.proof, edge_proofs=self.proof.edge_proofs[::-1]
            ))
        )
        # sub-proofs spliced from a proof over a different context
        other_proof = _prove(
            self.xc, self.yc, 400, 500, self.xb, self.yb, TRIANGLE, b"other"
        )
        self.assertFalse(
            self.verify(proof=dataclasses.replace(
                self.proof, x_proof=other_proof.x_proof
            ))
        )
        self.assertFalse(
            self.verify(proof=dataclasses.replace(
                self.proof,
                edge_proofs=(other_proof.edge_proofs[0],)
                + self.proof.edge_proofs[1:],
            ))
        )

    def test_no_cross_variant_replay(self):
        small = ConvexPolygonRegion(((0, 0), (10, 0), (0, 10)))
        xc, yc, xb, yb = _commit_pair(small, 3, 3)
        old_proof = prove_convex_polygon(
            xc, yc, 3, 3, xb, yb, small, randbelow=_counter_randbelow()
        )
        new_proof = _prove(xc, yc, 3, 3, xb, yb, small)
        self.assertTrue(verify_convex_polygon_interval(xc, yc, small, new_proof))
        spliced = dataclasses.replace(
            new_proof, edge_proofs=old_proof.edge_proofs
        )
        self.assertFalse(verify_convex_polygon_interval(xc, yc, small, spliced))

    def test_oversized_axis_returns_false(self):
        polygon = ConvexPolygonRegion(((0, 0), (1 << 24, 0), (1 << 24, 1), (0, 1)))
        xc, yc, _, _ = _commit_pair(polygon, 5, 0)
        self.assertFalse(
            verify_convex_polygon_interval(xc, yc, polygon, self.proof)
        )

    def test_forged_polygon_with_invalid_geometry_returns_false(self):
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(
            forged, "vertices", ((0, 0), (1000, 0), (1000, 0), (0, 1000))
        )
        self.assertFalse(self.verify(polygon=forged))

    def test_type_errors_not_masked_by_semantic_failure(self):
        bad_xc = dataclasses.replace(self.xc, h=self.xc.h + 1)
        # non-bytes context
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                self.xc, self.yc, TRIANGLE, self.proof, "ctx"
            )
        # wrong proof container
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                self.xc, self.yc, TRIANGLE, "nope", b"c"
            )
        # bool vertex on a forged polygon
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ((0, 0), (True, 0), (0, 1)))
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                self.xc, self.yc, forged, self.proof, b"c"
            )
        # bool inside a late proof field, earlier commitment already doomed
        bad_edge = dataclasses.replace(
            self.proof.edge_proofs[0], commitments=(True,)
        )
        bad_proof = dataclasses.replace(
            self.proof,
            edge_proofs=(bad_edge,) + self.proof.edge_proofs[1:],
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(bad_xc, self.yc, TRIANGLE, bad_proof, b"c")
        # non-tuple edge_proofs container
        bad_container = dataclasses.replace(
            self.proof, edge_proofs=list(self.proof.edge_proofs)
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                self.xc, self.yc, TRIANGLE, bad_container, b"c"
            )

    def test_inputs_not_mutated(self):
        vertices = ((0, 0), (1000, 0), (0, 1000))
        polygon = ConvexPolygonRegion(vertices)
        xc, yc, xb, yb = _commit_pair(polygon, 1, 1)
        proof = _prove(xc, yc, 1, 1, xb, yb, polygon)
        self.assertEqual(polygon.vertices, ConvexPolygonRegion(vertices).vertices)
        self.assertTrue(verify_convex_polygon_interval(xc, yc, polygon, proof))


if __name__ == "__main__":
    unittest.main()
