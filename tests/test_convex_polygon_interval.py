import dataclasses
import unittest

from zkregion import (
    ConvexPolygonIntervalProof,
    ConvexPolygonRegion,
    IntervalRangeProof,
    PedersenCommitment,
    WideRangeProof,
    pedersen_commit,
    prove_convex_polygon,
    prove_convex_polygon_interval,
    verify_convex_polygon_interval,
)


class DetRand:
    """Deterministic randbelow replacement: same sequence for same counter."""

    def __init__(self, seed=1):
        self.calls = seed

    def __call__(self, upper):
        self.calls += 1
        return (self.calls * 7919 + 13) % upper


class CountingRand:
    """Counts how many draws a failing prove call consumed."""

    def __init__(self):
        self.calls = 0

    def __call__(self, upper):
        self.calls += 1
        return 0


TRIANGLE = ((0, 0), (1000, 0), (0, 1000))


def triangle_commit(x, y, polygon=None):
    polygon = polygon or ConvexPolygonRegion(TRIANGLE)
    cx, rx = pedersen_commit(x, polygon.min_x, polygon.max_x)
    cy, ry = pedersen_commit(y, polygon.min_y, polygon.max_y)
    return polygon, cx, cy, rx, ry


class ConvexPolygonIntervalProofTests(unittest.TestCase):
    def setUp(self):
        self.polygon, self.cx, self.cy, self.rx, self.ry = triangle_commit(400, 500)
        self.proof = prove_convex_polygon_interval(
            self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon
        )

    def test_shape_and_construction_unchecked(self):
        self.assertIsInstance(self.proof, ConvexPolygonIntervalProof)
        self.assertIsInstance(self.proof.x_proof, IntervalRangeProof)
        self.assertIsInstance(self.proof.y_proof, IntervalRangeProof)
        self.assertIsInstance(self.proof.edge_proofs, tuple)
        self.assertEqual(len(self.proof.edge_proofs), 3)
        self.assertTrue(
            all(isinstance(edge, WideRangeProof) for edge in self.proof.edge_proofs)
        )
        # positional construction, value equality, immutability, no validation
        clone = ConvexPolygonIntervalProof(
            self.proof.x_proof, self.proof.y_proof, self.proof.edge_proofs
        )
        self.assertEqual(clone, self.proof)
        self.assertEqual(hash(clone), hash(self.proof))
        junk = ConvexPolygonIntervalProof(1, 2, 3)
        self.assertEqual(junk.x_proof, 1)
        with self.assertRaises(Exception):
            self.proof.x_proof = None

    def test_interior_edge_and_vertex_points(self):
        for point in (
            (400, 500),  # interior
            (500, 500),  # on the hypotenuse
            (0, 700),  # on a leg
            (0, 0),  # vertices
            (1000, 0),
            (0, 1000),
        ):
            with self.subTest(point=point):
                polygon, cx, cy, rx, ry = triangle_commit(*point)
                proof = prove_convex_polygon_interval(
                    cx, cy, point[0], point[1], rx, ry, polygon
                )
                self.assertTrue(
                    verify_convex_polygon_interval(cx, cy, polygon, proof)
                )

    def test_outside_point_cannot_prove(self):
        polygon, cx, cy, rx, ry = triangle_commit(700, 700)
        self.assertTrue(polygon.min_x <= 700 <= polygon.max_x)
        self.assertTrue(polygon.min_y <= 700 <= polygon.max_y)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(cx, cy, 700, 700, rx, ry, polygon)

    def test_rotation_and_reversal_same_verdict(self):
        rotation = ConvexPolygonRegion(((1000, 0), (0, 1000), (0, 0)))
        reversal = ConvexPolygonRegion(((0, 0), (0, 1000), (1000, 0)))
        for polygon in (rotation, reversal):
            self.assertTrue(
                verify_convex_polygon_interval(
                    self.cx, self.cy, polygon, self.proof
                )
            )

    def test_context_commitment_polygon_tampering_false(self):
        self.assertFalse(
            verify_convex_polygon_interval(
                self.cx, self.cy, self.polygon, self.proof, b"other"
            )
        )
        # any commitment field changed
        for field, value in (
            ("element", self.cx.element + 1),
            ("lower", self.cx.lower + 1),
            ("upper", self.cx.upper - 1),
            ("prime", (1 << 61) - 1),
            ("generator", self.cx.generator + 1),
            ("h", self.cx.h + 1),
        ):
            with self.subTest(field=field):
                bad = dataclasses.replace(self.cx, **{field: value})
                self.assertFalse(
                    verify_convex_polygon_interval(
                        bad, self.cy, self.polygon, self.proof
                    )
                )
        # a different polygon with the same bounding box
        other = ConvexPolygonRegion(((0, 0), (1000, 0), (1000, 1000), (0, 1000)))
        self.assertFalse(
            verify_convex_polygon_interval(self.cx, self.cy, other, self.proof)
        )

    def test_swapped_axes_and_splicing_false(self):
        self.assertFalse(
            verify_convex_polygon_interval(
                self.cy, self.cx, self.polygon, self.proof
            )
        )
        swapped = dataclasses.replace(
            self.proof, x_proof=self.proof.y_proof, y_proof=self.proof.x_proof
        )
        self.assertFalse(
            verify_convex_polygon_interval(
                self.cx, self.cy, self.polygon, swapped
            )
        )
        # splice the x sub-proof of a proof over a different point
        _, cx2, cy2, rx2, ry2 = triangle_commit(100, 100)
        other = prove_convex_polygon_interval(cx2, cy2, 100, 100, rx2, ry2, self.polygon)
        spliced = dataclasses.replace(self.proof, x_proof=other.x_proof)
        self.assertFalse(
            verify_convex_polygon_interval(
                self.cx, self.cy, self.polygon, spliced
            )
        )

    def test_edge_proof_tampering_false(self):
        dropped = dataclasses.replace(
            self.proof, edge_proofs=self.proof.edge_proofs[:-1]
        )
        self.assertFalse(
            verify_convex_polygon_interval(
                self.cx, self.cy, self.polygon, dropped
            )
        )
        reordered = dataclasses.replace(
            self.proof,
            edge_proofs=(
                self.proof.edge_proofs[1],
                self.proof.edge_proofs[0],
                self.proof.edge_proofs[2],
            ),
        )
        self.assertFalse(
            verify_convex_polygon_interval(
                self.cx, self.cy, self.polygon, reordered
            )
        )
        last = self.proof.edge_proofs[-1]
        tampered = dataclasses.replace(
            last, commitments=(last.commitments[0] + 1,) + last.commitments[1:]
        )
        bad = dataclasses.replace(
            self.proof,
            edge_proofs=self.proof.edge_proofs[:-1] + (tampered,),
        )
        self.assertFalse(
            verify_convex_polygon_interval(self.cx, self.cy, self.polygon, bad)
        )

    def test_negative_and_cross_zero_coordinates(self):
        polygon = ConvexPolygonRegion(((-1000, -500), (1000, -500), (0, 500)))
        for point in ((0, 0), (-1000, -500), (0, 500), (400, -100)):
            with self.subTest(point=point):
                cx, rx = pedersen_commit(
                    point[0], polygon.min_x, polygon.max_x
                )
                cy, ry = pedersen_commit(
                    point[1], polygon.min_y, polygon.max_y
                )
                proof = prove_convex_polygon_interval(
                    cx, cy, point[0], point[1], rx, ry, polygon
                )
                self.assertTrue(
                    verify_convex_polygon_interval(cx, cy, polygon, proof)
                )

    def test_axis_up_to_2_pow_24(self):
        big = 1 << 24
        polygon = ConvexPolygonRegion(((-big + 1, 0), (0, 0), (0, 1)))
        self.assertEqual(polygon.max_x - polygon.min_x + 1, big)
        cx, rx = pedersen_commit(-5, polygon.min_x, polygon.max_x)
        cy, ry = pedersen_commit(0, polygon.min_y, polygon.max_y)
        proof = prove_convex_polygon_interval(cx, cy, -5, 0, rx, ry, polygon)
        self.assertTrue(verify_convex_polygon_interval(cx, cy, polygon, proof))
        self.assertEqual(len(proof.x_proof.low_commitments), 24)
        # one integer more per axis exceeds the limit
        oversized = ConvexPolygonRegion(((-big, 0), (0, 0), (0, 1)))
        ox, orx = pedersen_commit(-5, oversized.min_x, oversized.max_x)
        oy, ory = pedersen_commit(0, oversized.min_y, oversized.max_y)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(ox, oy, -5, 0, orx, ory, oversized)
        self.assertFalse(
            verify_convex_polygon_interval(ox, oy, oversized, proof)
        )

    def test_non_power_of_two_axis_padding_admits_nothing(self):
        # 6 integers per axis (padded to 8 by the interval bit decomposition)
        polygon = ConvexPolygonRegion(((0, 0), (5, 0), (0, 5)))
        self.assertEqual(polygon.max_x - polygon.min_x + 1, 6)
        for point in ((0, 0), (5, 0), (0, 5), (2, 3), (3, 2)):
            with self.subTest(point=point):
                cx, rx = pedersen_commit(point[0], 0, 5)
                cy, ry = pedersen_commit(point[1], 0, 5)
                proof = prove_convex_polygon_interval(
                    cx, cy, point[0], point[1], rx, ry, polygon
                )
                self.assertTrue(
                    verify_convex_polygon_interval(cx, cy, polygon, proof)
                )
        # a commitment declared over the padded power-of-two range does not
        # match the bounding box and cannot launder an out-of-range point
        wide_x, wrx = pedersen_commit(6, 0, 7)
        wide_y, wry = pedersen_commit(0, 0, 7)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(
                wide_x, wide_y, 6, 0, wrx, wry, polygon
            )
        _, cx, cy, rx, ry = triangle_commit(400, 500)
        proof = prove_convex_polygon_interval(cx, cy, 400, 500, rx, ry, self.polygon)
        self.assertFalse(
            verify_convex_polygon_interval(wide_x, wide_y, polygon, proof)
        )

    def test_proof_size_grows_with_width_and_edges(self):
        def proof_for(vertices, point):
            polygon = ConvexPolygonRegion(vertices)
            cx, rx = pedersen_commit(point[0], polygon.min_x, polygon.max_x)
            cy, ry = pedersen_commit(point[1], polygon.min_y, polygon.max_y)
            proof = prove_convex_polygon_interval(
                cx, cy, point[0], point[1], rx, ry, polygon
            )
            return polygon, proof

        _, small = proof_for(((0, 0), (5, 0), (0, 5)), (2, 2))
        _, large = proof_for(((0, 0), (1000, 0), (0, 1000)), (400, 500))
        self.assertLess(
            len(small.x_proof.low_commitments), len(large.x_proof.low_commitments)
        )
        _, quad = proof_for(((0, 0), (5, 0), (5, 5), (0, 5)), (2, 2))
        self.assertEqual(len(small.edge_proofs) + 1, len(quad.edge_proofs))

    def test_deterministic_under_same_random_source(self):
        first = prove_convex_polygon_interval(
            self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon,
            randbelow=DetRand(),
        )
        second = prove_convex_polygon_interval(
            self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon,
            randbelow=DetRand(),
        )
        self.assertEqual(first, second)
        self.assertTrue(
            verify_convex_polygon_interval(
                self.cx, self.cy, self.polygon, first
            )
        )

    def test_inputs_not_mutated(self):
        polygon, cx, cy, rx, ry = triangle_commit(400, 500)
        proof = prove_convex_polygon_interval(cx, cy, 400, 500, rx, ry, polygon)
        snapshot = (
            polygon,
            dataclasses.replace(cx),
            dataclasses.replace(cy),
            dataclasses.replace(proof),
        )
        verify_convex_polygon_interval(cx, cy, polygon, proof, b"ctx")
        prove_convex_polygon_interval(cx, cy, 400, 500, rx, ry, polygon, b"ctx")
        self.assertEqual(snapshot[0], polygon)
        self.assertEqual(snapshot[1], cx)
        self.assertEqual(snapshot[2], cy)
        self.assertEqual(snapshot[3], proof)

    def test_old_entry_point_still_capped_at_256(self):
        polygon = ConvexPolygonRegion(((0, 0), (1000, 0), (0, 1000)))
        cx, rx = pedersen_commit(400, 0, 1000)
        cy, ry = pedersen_commit(500, 0, 1000)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 400, 500, rx, ry, polygon)


class ConvexPolygonIntervalTypeTests(unittest.TestCase):
    def setUp(self):
        self.polygon, self.cx, self.cy, self.rx, self.ry = triangle_commit(400, 500)
        self.proof = prove_convex_polygon_interval(
            self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon
        )

    def test_prove_type_errors(self):
        base = (self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon)
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval("cx", *base[1:])
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(self.cx, "cy", *base[2:])
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base[:2], True, *base[3:])
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base[:3], 1.5, *base[4:])
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base[:4], False, *base[5:])
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base[:6], ((0, 0), (1, 0), (0, 1)))
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base, context="ctx")
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base, randbelow=42)

    def test_verify_type_errors(self):
        args = (self.cx, self.cy, self.polygon, self.proof)
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval("cx", *args[1:])
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(self.cx, None, *args[2:])
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(*args[:2], "polygon", *args[3:])
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(*args[:3], "proof")
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(*args, context=bytearray(b"x"))
        # old entry's proof type is a wrong type here
        small = ConvexPolygonRegion(((0, 0), (4, 0), (0, 4)))
        sx, srx = pedersen_commit(1, 0, 4)
        sy, sry = pedersen_commit(1, 0, 4)
        old_proof = prove_convex_polygon(sx, sy, 1, 1, srx, sry, small)
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(sx, sy, small, old_proof)

    def test_nested_type_errors_not_masked_by_semantic_failure(self):
        # a doomed semantic verdict (wrong declared range) must not hide a
        # wrong nested type anywhere in the input shape
        bad_range = dataclasses.replace(self.cx, lower=self.cx.lower + 1)
        bool_x = dataclasses.replace(self.cx, element=True)
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                bool_x, self.cy, self.polygon, self.proof
            )
        forged = ConvexPolygonRegion(TRIANGLE)
        object.__setattr__(forged, "vertices", ((0, 0), (1000, 0), (0, True)))
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                bad_range, self.cy, forged, self.proof
            )
        bad_proof = dataclasses.replace(self.proof, x_proof="nope")
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                bad_range, self.cy, self.polygon, bad_proof
            )
        bad_edges = dataclasses.replace(self.proof, edge_proofs=list(self.proof.edge_proofs))
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                bad_range, self.cy, self.polygon, bad_edges
            )
        bool_bit = dataclasses.replace(
            self.proof.x_proof, low_commitments=(True,) * len(self.proof.x_proof.low_commitments)
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                bad_range,
                self.cy,
                self.polygon,
                dataclasses.replace(self.proof, x_proof=bool_bit),
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_interval(
                bad_range, self.cy, self.polygon, self.proof, context="ctx"
            )

    def test_prove_forged_polygon_types(self):
        forged = ConvexPolygonRegion(TRIANGLE)
        object.__setattr__(forged, "vertices", ((0, 0), (1000, 0), (0, True)))
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(
                self.cx, self.cy, 400, 500, self.rx, self.ry, forged
            )


class ConvexPolygonIntervalValueTests(unittest.TestCase):
    def setUp(self):
        self.polygon, self.cx, self.cy, self.rx, self.ry = triangle_commit(400, 500)

    def test_prove_value_errors(self):
        base = (self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon)
        # mismatched group parameters
        other_h = dataclasses.replace(self.cy, h=self.cy.h + 1)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(self.cx, other_h, *base[2:])
        # declared range not equal to the bounding box
        shifted = dataclasses.replace(self.cx, upper=self.cx.upper - 1)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(shifted, self.cy, *base[2:])
        # failed openings
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(*base[:2], 401, *base[3:])
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(*base[:5], self.ry + 1, *base[6:])
        # point outside the polygon
        polygon, cx, cy, rx, ry = triangle_commit(700, 700)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(cx, cy, 700, 700, rx, ry, polygon)
        # forged polygon with well-typed but invalid geometry
        forged = ConvexPolygonRegion(TRIANGLE)
        object.__setattr__(forged, "vertices", ((0, 0), (1, 0), (2, 0), (0, 1)))
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(
                self.cx, self.cy, 400, 500, self.rx, self.ry, forged
            )
        # edge offset span beyond the wide-range limit
        big = (1 << 24) - 1
        wide = ConvexPolygonRegion(((0, 0), (big, 0), (0, big)))
        wx, wrx = pedersen_commit(1, wide.min_x, wide.max_x)
        wy, wry = pedersen_commit(1, wide.min_y, wide.max_y)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(wx, wy, 1, 1, wrx, wry, wide)

    def test_prove_failures_consume_no_randomness(self):
        def calls_of(fn):
            rand = CountingRand()
            with self.assertRaises(ValueError):
                fn(rand)
            return rand.calls

        self.assertEqual(
            calls_of(
                lambda r: prove_convex_polygon_interval(
                    self.cx,
                    dataclasses.replace(self.cy, h=self.cy.h + 1),
                    400, 500, self.rx, self.ry, self.polygon,
                    randbelow=r,
                )
            ),
            0,
        )
        self.assertEqual(
            calls_of(
                lambda r: prove_convex_polygon_interval(
                    dataclasses.replace(self.cx, upper=self.cx.upper - 1),
                    self.cy, 400, 500, self.rx, self.ry, self.polygon,
                    randbelow=r,
                )
            ),
            0,
        )
        self.assertEqual(
            calls_of(
                lambda r: prove_convex_polygon_interval(
                    self.cx, self.cy, 400, 500, self.rx + 1, self.ry,
                    self.polygon, randbelow=r,
                )
            ),
            0,
        )
        polygon, cx, cy, rx, ry = triangle_commit(700, 700)
        self.assertEqual(
            calls_of(
                lambda r: prove_convex_polygon_interval(
                    cx, cy, 700, 700, rx, ry, polygon, randbelow=r
                )
            ),
            0,
        )
        forged = ConvexPolygonRegion(TRIANGLE)
        object.__setattr__(forged, "vertices", ((0, 0), (1, 0), (2, 0), (0, 1)))
        self.assertEqual(
            calls_of(
                lambda r: prove_convex_polygon_interval(
                    self.cx, self.cy, 400, 500, self.rx, self.ry, forged,
                    randbelow=r,
                )
            ),
            0,
        )
        big = (1 << 24) - 1
        wide = ConvexPolygonRegion(((0, 0), (big, 0), (0, big)))
        wx, wrx = pedersen_commit(1, wide.min_x, wide.max_x)
        wy, wry = pedersen_commit(1, wide.min_y, wide.max_y)
        self.assertEqual(
            calls_of(
                lambda r: prove_convex_polygon_interval(
                    wx, wy, 1, 1, wrx, wry, wide, randbelow=r
                )
            ),
            0,
        )

    def test_randbelow_contract(self):
        base = (self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon)
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base, randbelow=lambda upper: True)
        with self.assertRaises(TypeError):
            prove_convex_polygon_interval(*base, randbelow=lambda upper: "0")
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(*base, randbelow=lambda upper: upper)
        with self.assertRaises(ValueError):
            prove_convex_polygon_interval(*base, randbelow=lambda upper: -1)

        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            prove_convex_polygon_interval(*base, randbelow=boom)

    def test_verify_semantic_failures_return_false(self):
        proof = prove_convex_polygon_interval(
            self.cx, self.cy, 400, 500, self.rx, self.ry, self.polygon
        )
        # forged polygon with well-typed but invalid geometry
        forged = ConvexPolygonRegion(TRIANGLE)
        object.__setattr__(forged, "vertices", ((0, 0), (1, 0), (2, 0), (0, 1)))
        self.assertFalse(
            verify_convex_polygon_interval(self.cx, self.cy, forged, proof)
        )
        # mismatched group parameters and declared ranges
        self.assertFalse(
            verify_convex_polygon_interval(
                self.cx,
                dataclasses.replace(self.cy, h=self.cy.h + 1),
                self.polygon,
                proof,
            )
        )
        self.assertFalse(
            verify_convex_polygon_interval(
                dataclasses.replace(self.cx, upper=self.cx.upper - 1),
                self.cy,
                self.polygon,
                proof,
            )
        )
        # edge offset span beyond the wide-range limit
        big = (1 << 24) - 1
        wide = ConvexPolygonRegion(((0, 0), (big, 0), (0, big)))
        wx, _ = pedersen_commit(1, wide.min_x, wide.max_x)
        wy, _ = pedersen_commit(1, wide.min_y, wide.max_y)
        self.assertFalse(verify_convex_polygon_interval(wx, wy, wide, proof))


if __name__ == "__main__":
    unittest.main()
