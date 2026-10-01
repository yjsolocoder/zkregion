import unittest

from zkregion import (
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    DEFAULT_PRIME,
    RangeProof,
    WideRangeProof,
    pedersen_commit,
    prove_convex_polygon,
    verify_convex_polygon,
)


class DetRand:
    """Deterministic randbelow replacement: same sequence for same counter."""

    def __init__(self, seed=1):
        self.calls = seed

    def __call__(self, upper):
        self.calls += 1
        return (self.calls * 7919 + 13) % upper


TRIANGLE = ((0, 0), (4, 0), (0, 4))


def triangle_commit(x, y):
    polygon = ConvexPolygonRegion(TRIANGLE)
    cx, rx = pedersen_commit(x, polygon.min_x, polygon.max_x)
    cy, ry = pedersen_commit(y, polygon.min_y, polygon.max_y)
    return polygon, cx, cy, rx, ry


class ConvexPolygonRegionTests(unittest.TestCase):
    def test_canonical_rotation_and_reversal(self):
        polygon = ConvexPolygonRegion(TRIANGLE)
        # canonical sequence starts at the lexicographically smallest vertex
        self.assertEqual(polygon.vertices, ((0, 0), (0, 4), (4, 0)))
        rotation = ConvexPolygonRegion(((0, 4), (4, 0), (0, 0)))
        reversal = ConvexPolygonRegion(((0, 0), (0, 4), (4, 0)))
        self.assertEqual(rotation.vertices, polygon.vertices)
        self.assertEqual(reversal.vertices, polygon.vertices)
        self.assertEqual(polygon, rotation)
        self.assertEqual(polygon, reversal)
        self.assertEqual(hash(polygon), hash(rotation))

    def test_immutable(self):
        polygon = ConvexPolygonRegion(TRIANGLE)
        with self.assertRaises(Exception):
            polygon.vertices = ((1, 2), (3, 4), (5, 6))
        self.assertIsInstance(polygon.vertices, tuple)

    def test_bounding_box(self):
        polygon = ConvexPolygonRegion(((-2, -3), (4, -3), (4, 5), (-2, 5)))
        self.assertEqual((polygon.min_x, polygon.max_x,
                          polygon.min_y, polygon.max_y), (-2, 4, -3, 5))

    def test_contains_closed(self):
        polygon = ConvexPolygonRegion(TRIANGLE)
        for point in ((0, 0), (1, 1), (2, 2), (4, 0), (0, 4), (0, 2), (3, 0)):
            self.assertTrue(polygon.contains(*point), point)
        for point in ((3, 2), (0, 5), (-1, 1), (2, 3)):
            self.assertFalse(polygon.contains(*point), point)

    def test_contains_type_error(self):
        polygon = ConvexPolygonRegion(TRIANGLE)
        with self.assertRaises(TypeError):
            polygon.contains(True, 0)
        with self.assertRaises(TypeError):
            polygon.contains(0, 1.0)

    def test_value_errors(self):
        bad = (
            (),
            ((0, 0), (1, 0)),
            ((0, 0), (1, 0), (0, 0)),
            ((0, 0), (1, 0), (2, 0), (0, 1)),
            ((0, 0), (2, 0), (0, 2), (1, 1)),
            ((0, 0), (3, 0), (1, 1), (3, 3), (0, 3)),
            ((0, 0), (2, 2), (2, 0), (0, 2)),
        )
        for vertices in bad:
            with self.subTest(vertices=vertices):
                with self.assertRaises(ValueError):
                    ConvexPolygonRegion(vertices)

    def test_self_intersect_winding_two(self):
        with self.assertRaises(ValueError):
            ConvexPolygonRegion(((0, 0), (4, 0), (0, 4), (4, 4), (2, 2)))

    def test_type_errors(self):
        for vertices in (
            "((0,0),(1,0),(0,1))",
            b"abc",
            [(0, 0), [1, 0], (0, 1)],
            ((0, 0), (1, 0, 0), (0, 1)),
            ((0, 0), (True, 0), (0, 1)),
            ((0, 0), (1.0, 0), (0, 1)),
        ):
            with self.subTest(vertices=vertices):
                with self.assertRaises(TypeError):
                    ConvexPolygonRegion(vertices)
        with self.assertRaises(TypeError):
            ConvexPolygonRegion(v for v in ((0, 0), (1, 0), (0, 1)))


class ProveConvexPolygonTests(unittest.TestCase):
    def test_valid_points_verify(self):
        polygon = ConvexPolygonRegion(TRIANGLE)
        for point in ((0, 0), (1, 1), (2, 2), (3, 0), (0, 3), (4, 0), (1, 2)):
            _, cx, cy, rx, ry = triangle_commit(*point)
            proof = prove_convex_polygon(
                cx, cy, *point, rx, ry, polygon, b"ctx", randbelow=DetRand()
            )
            self.assertIsInstance(proof, ConvexPolygonRegionProof)
            self.assertEqual(len(proof.edge_proofs), 3)
            self.assertTrue(
                verify_convex_polygon(cx, cy, polygon, proof, b"ctx"), point
            )

    def test_deterministic(self):
        polygon, cx, cy, rx, ry = triangle_commit(1, 2)
        p1 = prove_convex_polygon(cx, cy, 1, 2, rx, ry, polygon,
                                  b"ctx", randbelow=DetRand())
        p2 = prove_convex_polygon(cx, cy, 1, 2, rx, ry, polygon,
                                  b"ctx", randbelow=DetRand())
        self.assertEqual(p1, p2)
        self.assertIsInstance(p1.x_proof, RangeProof)
        for edge_proof in p1.edge_proofs:
            self.assertIsInstance(edge_proof, WideRangeProof)

    def test_outside_point_value_error(self):
        polygon, cx, cy, rx, ry = triangle_commit(3, 2)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 3, 2, rx, ry, polygon)

    def test_range_mismatch(self):
        polygon = ConvexPolygonRegion(TRIANGLE)
        cx, rx = pedersen_commit(2, 1, 5)
        cy, ry = pedersen_commit(1, 0, 4)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 2, 1, rx, ry, polygon)
        cx, rx = pedersen_commit(1, 0, 4)
        cy, ry = pedersen_commit(2, 1, 5)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 1, 2, rx, ry, polygon)

    def test_bad_opening(self):
        polygon, cx, cy, rx, ry = triangle_commit(1, 1)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 1, 1, rx + 1, ry, polygon)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 2, 1, rx, ry, polygon)

    def test_group_parameter_mismatch(self):
        polygon = ConvexPolygonRegion(TRIANGLE)
        cx, rx = pedersen_commit(1, 0, 4, prime=2 ** 61 - 1)
        cy, ry = pedersen_commit(1, 0, 4)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 1, 1, rx, ry, polygon)
        cx, rx = pedersen_commit(1, 0, 4, h=5)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 1, 1, rx, ry, polygon)

    def test_custom_group_parameters(self):
        prime = DEFAULT_PRIME
        generator, h = 5, pow(5, 7, prime)
        polygon = ConvexPolygonRegion(((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3)))
        for x, y in ((0, 0), (2, 3), (2, 6), (1, 4)):
            cx, rx = pedersen_commit(x, polygon.min_x, polygon.max_x,
                                     prime=prime, generator=generator, h=h)
            cy, ry = pedersen_commit(y, polygon.min_y, polygon.max_y,
                                     prime=prime, generator=generator, h=h)
            proof = prove_convex_polygon(cx, cy, x, y, rx, ry, polygon,
                                         b"g", randbelow=DetRand())
            self.assertTrue(
                verify_convex_polygon(cx, cy, polygon, proof, b"g"), (x, y)
            )

    def test_bbox_too_wide(self):
        polygon = ConvexPolygonRegion(
            ((0, 0), (256, 0), (256, 256), (0, 256))
        )
        cx, rx = pedersen_commit(10, 0, 256)
        cy, ry = pedersen_commit(20, 0, 256)
        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 10, 20, rx, ry, polygon)

    def test_type_errors(self):
        polygon, cx, cy, rx, ry = triangle_commit(1, 1)
        base = dict(x=1, y=1, x_blinding=rx, y_blinding=ry,
                    polygon=polygon, context=b"c")

        def expect(**override):
            kwargs = dict(x_commitment=cx, y_commitment=cy, **base)
            kwargs.update(override)
            with self.assertRaises(TypeError):
                prove_convex_polygon(**kwargs)

        expect(x_commitment="x")
        expect(y_commitment=42)
        expect(x=True)
        expect(y=1.0)
        expect(x_blinding=False)
        expect(polygon=((0, 0), (1, 0), (0, 1)))
        expect(context="c")
        expect(context=7)
        expect(randbelow=123)

    def test_randbelow_errors(self):
        polygon, cx, cy, rx, ry = triangle_commit(1, 1)

        def out_of_range(upper):
            return upper

        with self.assertRaises(ValueError):
            prove_convex_polygon(cx, cy, 1, 1, rx, ry, polygon,
                                 b"c", randbelow=out_of_range)

        def returns_bool(upper):
            return False

        with self.assertRaises(TypeError):
            prove_convex_polygon(cx, cy, 1, 1, rx, ry, polygon,
                                 b"c", randbelow=returns_bool)

    def test_inputs_not_mutated(self):
        source = [(0, 0), (4, 0), (0, 4)]
        snapshot = [tuple(v) for v in source]
        polygon = ConvexPolygonRegion(source)
        self.assertEqual(list(map(tuple, source)), snapshot)
        _, cx, cy, rx, ry = triangle_commit(1, 1)
        fields = (cx.element, cx.lower, cx.upper, cx.prime,
                  cx.generator, cx.h)
        prove_convex_polygon(cx, cy, 1, 1, rx, ry, polygon, b"c")
        self.assertEqual((cx.element, cx.lower, cx.upper, cx.prime,
                          cx.generator, cx.h), fields)


class VerifyConvexPolygonTests(unittest.TestCase):
    def setUp(self):
        self.polygon, self.cx, self.cy, self.rx, self.ry = triangle_commit(1, 2)
        self.proof = prove_convex_polygon(
            self.cx, self.cy, 1, 2, self.rx, self.ry, self.polygon,
            b"ctx", randbelow=DetRand(),
        )

    def verify(self, **override):
        kwargs = dict(x_commitment=self.cx, y_commitment=self.cy,
                      polygon=self.polygon, proof=self.proof, context=b"ctx")
        kwargs.update(override)
        return verify_convex_polygon(**kwargs)

    def test_valid(self):
        self.assertIs(self.verify(), True)

    def test_wrong_context(self):
        self.assertFalse(self.verify(context=b"other"))
        self.assertFalse(self.verify(context=b""))

    def test_swapped_axes(self):
        self.assertFalse(verify_convex_polygon(
            self.cy, self.cx, self.polygon, self.proof, b"ctx"))

    def test_changed_commitments(self):
        _, cx2, cy2, _, _ = triangle_commit(2, 1)
        self.assertFalse(self.verify(x_commitment=cx2))
        self.assertFalse(self.verify(y_commitment=cy2))

    def test_changed_polygon(self):
        other = ConvexPolygonRegion(((0, 0), (4, 0), (0, 3)))
        self.assertFalse(self.verify(polygon=other))
        shifted = ConvexPolygonRegion(((1, 0), (5, 0), (1, 4)))
        self.assertFalse(self.verify(polygon=shifted))

    def test_rotated_polygon_representation_verifies(self):
        rotated = ConvexPolygonRegion(
            tuple(self.polygon.vertices[1:] + self.polygon.vertices[:1])
        )
        self.assertTrue(self.verify(polygon=rotated))

    def _tamper(self, **fields):
        return ConvexPolygonRegionProof(
            x_proof=fields.get("x_proof", self.proof.x_proof),
            y_proof=fields.get("y_proof", self.proof.y_proof),
            edge_proofs=fields.get("edge_proofs", self.proof.edge_proofs),
        )

    def test_tampered_proof_fields(self):
        bad_x = RangeProof(self.proof.x_proof.t,
                           tuple(e + 1 for e in self.proof.x_proof.e),
                           self.proof.x_proof.s)
        self.assertFalse(self.verify(proof=self._tamper(x_proof=bad_x)))
        edge = self.proof.edge_proofs[0]
        bad_commitments = tuple(
            c + 1 if c < 100 else c - 1 for c in edge.commitments
        )
        bad_edge = WideRangeProof(bad_commitments, edge.challenges,
                                  edge.responses)
        self.assertFalse(self.verify(proof=self._tamper(
            edge_proofs=(bad_edge,) + self.proof.edge_proofs[1:])))
        self.assertFalse(self.verify(proof=self._tamper(
            edge_proofs=self.proof.edge_proofs[:1] + self.proof.edge_proofs[2:])))
        self.assertFalse(self.verify(proof=self._tamper(
            edge_proofs=(self.proof.edge_proofs[1],
                         self.proof.edge_proofs[0],
                         self.proof.edge_proofs[2]))))

    def test_forged_edge_proof(self):
        edge = self.proof.edge_proofs[0]
        forged_edge = WideRangeProof(
            commitments=tuple(5 for _ in edge.commitments),
            challenges=tuple((1, 2) for _ in edge.challenges),
            responses=tuple((3, 4) for _ in edge.responses),
        )
        forged = self._tamper(
            edge_proofs=(forged_edge,) + self.proof.edge_proofs[1:]
        )
        self.assertFalse(self.verify(proof=forged))

    def test_semantic_failures_return_false(self):
        mismatched_prime = pedersen_commit(1, 0, 4, prime=2 ** 61 - 1)[0]
        self.assertFalse(self.verify(x_commitment=mismatched_prime))

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            verify_convex_polygon("x", self.cy, self.polygon, self.proof, b"c")
        with self.assertRaises(TypeError):
            verify_convex_polygon(self.cx, self.cy, ((0, 0),), self.proof, b"c")
        with self.assertRaises(TypeError):
            verify_convex_polygon(self.cx, self.cy, self.polygon,
                                  RangeProof((), (), ()), b"c")
        with self.assertRaises(TypeError):
            verify_convex_polygon(self.cx, self.cy, self.polygon,
                                  self.proof, 7)
        bad = self._tamper(x_proof="x")
        with self.assertRaises(TypeError):
            verify_convex_polygon(self.cx, self.cy, self.polygon, bad, b"c")
        bad = self._tamper(edge_proofs=[1, 2, 3])
        with self.assertRaises(TypeError):
            verify_convex_polygon(self.cx, self.cy, self.polygon, bad, b"c")
        bad = self._tamper(edge_proofs=(1, 2, 3))
        with self.assertRaises(TypeError):
            verify_convex_polygon(self.cx, self.cy, self.polygon, bad, b"c")


if __name__ == "__main__":
    unittest.main()
