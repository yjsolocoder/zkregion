"""Tests for the convex polygon region and its non-interactive membership proof."""

import dataclasses
import unittest

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    PedersenCommitment,
    RangeProof,
    RegionProof,
    pedersen_commit,
    prove_convex_polygon,
    prove_range,
    verify_convex_polygon,
)

SMALL_PRIME = 104729  # a small prime keeps the group arithmetic readable in tests


def counter_randbelow(start: int = 1):
    state = {"value": start}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


# A diamond in [0, 10] x [0, 10]; (1, 1) and (9, 9) are inside the bounding
# box but outside the polygon.
DIAMOND = ((0, 5), (5, 10), (10, 5), (5, 0))
DIAMOND_ROTATED = ((5, 10), (10, 5), (5, 0), (0, 5))
DIAMOND_REVERSED = ((0, 5), (5, 0), (10, 5), (5, 10))


class ConvexPolygonRegionTest(unittest.TestCase):
    def test_vertices_are_stored_as_a_tuple(self):
        polygon = ConvexPolygonRegion(DIAMOND)
        self.assertIsInstance(polygon.vertices, tuple)
        self.assertTrue(all(isinstance(vertex, tuple) for vertex in polygon.vertices))

    def test_accepts_a_list_of_tuple_vertices(self):
        polygon = ConvexPolygonRegion(list(DIAMOND))
        self.assertEqual(polygon, ConvexPolygonRegion(DIAMOND))

    def test_rotation_and_reversal_canonicalize_to_one_sequence(self):
        canonical = ConvexPolygonRegion(DIAMOND)
        self.assertEqual(ConvexPolygonRegion(DIAMOND_ROTATED), canonical)
        self.assertEqual(ConvexPolygonRegion(DIAMOND_REVERSED), canonical)
        self.assertEqual(
            ConvexPolygonRegion(DIAMOND_ROTATED).vertices,
            ConvexPolygonRegion(DIAMOND_REVERSED).vertices,
        )

    def test_equal_regions_hash_equal(self):
        self.assertEqual(
            hash(ConvexPolygonRegion(DIAMOND_ROTATED)),
            hash(ConvexPolygonRegion(DIAMOND_REVERSED)),
        )

    def test_polygon_is_immutable(self):
        polygon = ConvexPolygonRegion(DIAMOND)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            polygon.vertices = ()

    def test_bounding_box_properties(self):
        polygon = ConvexPolygonRegion(DIAMOND)
        self.assertEqual((polygon.min_x, polygon.max_x, polygon.min_y, polygon.max_y),
                         (0, 10, 0, 10))
        shifted = ConvexPolygonRegion(((-5, 0), (0, 5), (5, 0), (0, -5)))
        self.assertEqual((shifted.min_x, shifted.max_x, shifted.min_y, shifted.max_y),
                         (-5, 5, -5, 5))

    def test_triangle_is_accepted(self):
        triangle = ConvexPolygonRegion(((0, 0), (4, 0), (2, 3)))
        self.assertEqual(len(triangle.vertices), 3)

    def test_contains_interior_and_exterior(self):
        polygon = ConvexPolygonRegion(DIAMOND)
        for point in ((5, 5), (4, 6), (6, 4)):
            self.assertTrue(polygon.contains(*point), point)
        for point in ((0, 0), (10, 10), (1, 1), (9, 9), (0, 10), (-1, 5), (11, 5)):
            self.assertFalse(polygon.contains(*point), point)

    def test_boundary_edges_and_vertices_belong_to_region(self):
        polygon = ConvexPolygonRegion(DIAMOND)
        for vertex in DIAMOND:
            self.assertTrue(polygon.contains(*vertex), vertex)
        # integer points on the edge from (0, 5) to (5, 10): (1, 6) ... (4, 9)
        for i in range(5):
            self.assertTrue(polygon.contains(i, 5 + i), (i, 5 + i))

    def test_contains_works_for_either_winding(self):
        ccw = ConvexPolygonRegion(DIAMOND_REVERSED)
        cw = ConvexPolygonRegion(DIAMOND_ROTATED)
        # canonical sequences may differ in winding, but membership must agree
        for point in ((5, 5), (1, 6), (0, 0), (9, 9), (5, 10)):
            self.assertEqual(ccw.contains(*point), cw.contains(*point), point)

    def test_contains_type_errors(self):
        polygon = ConvexPolygonRegion(DIAMOND)
        with self.assertRaises(TypeError):
            polygon.contains(1.5, 5)
        with self.assertRaises(TypeError):
            polygon.contains(True, 5)
        with self.assertRaises(TypeError):
            polygon.contains(5, "5")

    # ---- value errors -------------------------------------------------------

    def test_fewer_than_three_vertices_rejected(self):
        for vertices in ((), ((0, 0),), ((0, 0), (1, 1))):
            with self.assertRaises(ValueError):
                ConvexPolygonRegion(vertices)

    def test_repeated_vertices_rejected(self):
        with self.assertRaises(ValueError):
            ConvexPolygonRegion(((0, 0), (1, 1), (0, 0)))
        with self.assertRaises(ValueError):
            ConvexPolygonRegion(((0, 0), (1, 1), (2, 2), (0, 0)))

    def test_collinear_adjacent_triples_rejected(self):
        with self.assertRaises(ValueError):
            # extra collinear point on a rectangle edge
            ConvexPolygonRegion(((0, 0), (1, 0), (2, 0), (2, 2), (0, 2)))
        with self.assertRaises(ValueError):
            # collinear triple wrapping around the end of the sequence
            ConvexPolygonRegion(((0, 0), (2, 0), (2, 2), (1, 1)))

    def test_concave_polygon_rejected(self):
        # an indentation at (1, 1) makes the turn signs inconsistent
        with self.assertRaises(ValueError):
            ConvexPolygonRegion(((0, 0), (2, 0), (2, 2), (1, 1), (0, 2)))

    def test_self_intersecting_boundary_rejected(self):
        # bowtie: (0, 0) -> (2, 2) -> (0, 2) -> (2, 0)
        with self.assertRaises(ValueError):
            ConvexPolygonRegion(((0, 0), (2, 2), (0, 2), (2, 0)))

    def test_flat_polygon_rejected(self):
        with self.assertRaises(ValueError):
            ConvexPolygonRegion(((0, 0), (1, 1), (2, 2)))

    # ---- type errors --------------------------------------------------------

    def test_outer_container_type_errors(self):
        for vertices in ("abc", b"abc", bytearray(b"abc"), 42, None, True):
            with self.assertRaises(TypeError):
                ConvexPolygonRegion(vertices)

    def test_vertex_must_be_a_tuple(self):
        with self.assertRaises(TypeError):
            ConvexPolygonRegion([(0, 0), (1, 1), [2, 2]])

    def test_vertex_must_have_exactly_two_coordinates(self):
        for vertices in (((0,), (1, 1), (2, 2)), ((0, 0, 0), (1, 1), (2, 2))):
            with self.assertRaises(TypeError):
                ConvexPolygonRegion(vertices)

    def test_coordinate_type_errors_including_bool(self):
        for bad in (1.5, "2", True, False, None):
            with self.assertRaises(TypeError):
                ConvexPolygonRegion(((0, 0), (1, 1), (2, bad)))
            with self.assertRaises(TypeError):
                ConvexPolygonRegion(((bad, 0), (1, 1), (2, 2)))

    def test_a_later_bad_vertex_still_raises(self):
        with self.assertRaises(TypeError):
            ConvexPolygonRegion(((0, 0), (1, 1), (2, True)))


class ConvexPolygonProofTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def commit(self, value, lower, upper, blinding, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def polygon(self):
        return ConvexPolygonRegion(DIAMOND)

    def prove(self, x=4, y=6, polygon=None, context=b"ctx",
              x_blinding=1234, y_blinding=4321):
        polygon = self.polygon() if polygon is None else polygon
        x_commitment, x_r = self.commit(x, polygon.min_x, polygon.max_x, x_blinding)
        y_commitment, y_r = self.commit(y, polygon.min_y, polygon.max_y, y_blinding)
        proof = prove_convex_polygon(
            x_commitment, y_commitment, x, y, x_r, y_r, polygon, context,
            randbelow=counter_randbelow(),
        )
        return x_commitment, y_commitment, polygon, proof

    # ---- honest round trip --------------------------------------------------

    def test_honest_proof_verifies(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        self.assertIsInstance(proof, ConvexPolygonRegionProof)
        self.assertIsInstance(proof.x_proof, RangeProof)
        self.assertIsInstance(proof.y_proof, RangeProof)
        self.assertTrue(
            verify_convex_polygon(x_commitment, y_commitment, polygon, proof, b"ctx")
        )
        self.assertTrue(
            verify_convex_polygon(
                x_commitment, y_commitment, polygon, proof, context=b"ctx"
            )
        )
        # the empty context is legal too
        x_commitment, y_commitment, polygon, proof = self.prove(context=b"")
        self.assertTrue(
            verify_convex_polygon(x_commitment, y_commitment, polygon, proof)
        )

    def test_proof_is_immutable(self):
        _, _, _, proof = self.prove()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.x_proof = proof.y_proof
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.y_proof = proof.x_proof

    def test_vertices_and_edges_prove(self):
        polygon = self.polygon()
        points = [
            (0, 5), (5, 10), (10, 5), (5, 0),          # vertices
            (1, 6), (2, 7), (6, 6), (5, 5), (4, 4),    # edge / interior points
        ]
        for x, y in points:
            x_commitment, y_commitment, polygon, proof = self.prove(x=x, y=y)
            self.assertTrue(
                verify_convex_polygon(x_commitment, y_commitment, polygon, proof, b"ctx"),
                (x, y),
            )

    def test_negative_coordinates_supported(self):
        polygon = ConvexPolygonRegion(((-5, 0), (0, 5), (5, 0), (0, -5)))
        x_commitment, x_r = self.commit(-3, -5, 5, 1234)
        y_commitment, y_r = self.commit(2, -5, 5, 4321)
        proof = prove_convex_polygon(
            x_commitment, y_commitment, -3, 2, x_r, y_r, polygon,
            randbelow=counter_randbelow(),
        )
        self.assertTrue(
            verify_convex_polygon(x_commitment, y_commitment, polygon, proof)
        )

    def test_default_group_parameters_usable(self):
        polygon = ConvexPolygonRegion(((0, 0), (100, 0), (100, 100), (0, 100)))
        x_commitment, x_r = pedersen_commit(40, 0, 100, blinding=987654321)
        y_commitment, y_r = pedersen_commit(60, 0, 100, blinding=123456789)
        proof = prove_convex_polygon(
            x_commitment, y_commitment, 40, 60, x_r, y_r, polygon, b"demo"
        )
        self.assertEqual(x_commitment.prime, DEFAULT_PRIME)
        self.assertEqual(x_commitment.generator, DEFAULT_GENERATOR)
        self.assertTrue(
            verify_convex_polygon(x_commitment, y_commitment, polygon, proof, b"demo")
        )

    def test_fixed_randbelow_is_reproducible(self):
        x_commitment, x_r = self.commit(4, 0, 10, 1234)
        y_commitment, y_r = self.commit(6, 0, 10, 4321)
        polygon = self.polygon()

        def make():
            return prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r, y_r, polygon, b"c",
                randbelow=counter_randbelow(),
            )

        self.assertEqual(make(), make())

    def test_proof_invariant_under_rotation_and_reversal(self):
        x_commitment, x_r = self.commit(4, 0, 10, 1234)
        y_commitment, y_r = self.commit(6, 0, 10, 4321)
        canonical = self.polygon()
        rotated = ConvexPolygonRegion(DIAMOND_ROTATED)
        reversed_polygon = ConvexPolygonRegion(DIAMOND_REVERSED)
        args = (x_commitment, y_commitment, 4, 6, x_r, y_r)
        p0 = prove_convex_polygon(*args, canonical, b"c", randbelow=counter_randbelow())
        p1 = prove_convex_polygon(*args, rotated, b"c", randbelow=counter_randbelow())
        p2 = prove_convex_polygon(
            *args, reversed_polygon, b"c", randbelow=counter_randbelow()
        )
        self.assertEqual(p0, p1)
        self.assertEqual(p0, p2)
        self.assertTrue(
            verify_convex_polygon(x_commitment, y_commitment, rotated, p0, b"c")
        )
        self.assertTrue(
            verify_convex_polygon(x_commitment, y_commitment, reversed_polygon, p0, b"c")
        )

    # ---- prove-time value validation ----------------------------------------

    def test_commitment_range_must_equal_bounding_box(self):
        polygon = self.polygon()
        x_commitment, x_r = self.commit(4, 0, 10, 1234)
        y_commitment, y_r = self.commit(6, 0, 10, 4321)
        x_wide, x_wide_r = self.commit(4, 0, 11, 1234)
        y_wide, y_wide_r = self.commit(6, 0, 11, 4321)
        x_shift, x_shift_r = self.commit(4, 1, 10, 1234)
        args = (4, 6)
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_wide, y_commitment, *args, x_wide_r, y_r, polygon
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_wide, *args, x_r, y_wide_r, polygon
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_shift, y_commitment, *args, x_shift_r, y_r, polygon
            )

    def test_commitments_must_share_group_parameters(self):
        polygon = self.polygon()
        x_commitment, x_r = self.commit(4, 0, 10, 1234)
        y_other, y_other_r = pedersen_commit(
            6, 0, 10, prime=self.PRIME, generator=3, h=7, blinding=4321
        )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_other, 4, 6, x_r, y_other_r, polygon
            )
        y_default, y_default_r = pedersen_commit(6, 0, 10, blinding=4321)
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_default, 4, 6, x_r, y_default_r, polygon
            )

    def test_invalid_opening_rejected(self):
        x_commitment, x_r = self.commit(4, 0, 10, 1234)
        y_commitment, y_r = self.commit(6, 0, 10, 4321)
        polygon = self.polygon()
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 5, 6, x_r, y_r, polygon
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r + 1, y_r, polygon
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 5, x_r, y_r, polygon
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r, y_r + 1, polygon
            )

    def test_point_outside_polygon_rejected(self):
        # (1, 1) is inside the bounding box but outside the diamond
        x_commitment, x_r = self.commit(1, 0, 10, 1234)
        y_commitment, y_r = self.commit(1, 0, 10, 4321)
        polygon = self.polygon()
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 1, 1, x_r, y_r, polygon
            )

    def test_axis_over_256_rejected(self):
        # a thin rectangle whose x axis spans 257 integers
        polygon = ConvexPolygonRegion(((0, 0), (256, 0), (256, 1), (0, 1)))
        x_commitment, x_r = self.commit(40, 0, 256, 1234)
        y_commitment, y_r = self.commit(0, 0, 1, 4321)
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 40, 0, x_r, y_r, polygon,
                randbelow=counter_randbelow(),
            )

    def test_prove_type_errors(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        x_r, y_r = 1234, 4321
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                "commitment", y_commitment, 4, 6, x_r, y_r, polygon
            )
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                x_commitment, "commitment", 4, 6, x_r, y_r, polygon
            )
        bad = dataclasses.replace(x_commitment, element=1.5)
        with self.assertRaises(TypeError):
            prove_convex_polygon(bad, y_commitment, 4, 6, x_r, y_r, polygon)
        bad = dataclasses.replace(y_commitment, h=True)
        with self.assertRaises(TypeError):
            prove_convex_polygon(x_commitment, bad, 4, 6, x_r, y_r, polygon)
        for bad_value in (1.5, "4", True, False, None):
            with self.assertRaises(TypeError):
                prove_convex_polygon(
                    x_commitment, y_commitment, bad_value, 6, x_r, y_r, polygon
                )
            with self.assertRaises(TypeError):
                prove_convex_polygon(
                    x_commitment, y_commitment, 4, bad_value, x_r, y_r, polygon
                )
            with self.assertRaises(TypeError):
                prove_convex_polygon(
                    x_commitment, y_commitment, 4, 6, bad_value, y_r, polygon
                )
            with self.assertRaises(TypeError):
                prove_convex_polygon(
                    x_commitment, y_commitment, 4, 6, x_r, bad_value, polygon
                )
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r, y_r, "polygon"
            )
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r, y_r,
                RegionProof(proof.x_proof, proof.y_proof),
            )
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r, y_r, polygon, "ctx"
            )
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r, y_r, polygon,
                randbelow=None,
            )
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, x_r, y_r, polygon,
                randbelow=5,
            )

    def test_randbelow_value_errors(self):
        x_commitment, y_commitment, polygon, _ = self.prove()
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, 1234, 4321, polygon,
                randbelow=lambda upper: True,
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, 1234, 4321, polygon,
                randbelow=lambda upper: upper,
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon(
                x_commitment, y_commitment, 4, 6, 1234, 4321, polygon,
                randbelow=lambda upper: -1,
            )

    # ---- verify-time rejection ----------------------------------------------

    def test_wrong_context_returns_false(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        self.assertFalse(
            verify_convex_polygon(x_commitment, y_commitment, polygon, proof, b"other")
        )

    def test_swapped_axes_return_false(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        self.assertFalse(
            verify_convex_polygon(y_commitment, x_commitment, polygon, proof, b"ctx")
        )

    def test_changed_polygon_returns_false(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        altered = ConvexPolygonRegion(((0, 5), (5, 10), (10, 6), (5, 0)))
        self.assertFalse(
            verify_convex_polygon(x_commitment, y_commitment, altered, proof, b"ctx")
        )
        # a genuinely different polygon that keeps the same bounding box
        triangle = ConvexPolygonRegion(((0, 0), (10, 0), (10, 10)))
        self.assertFalse(
            verify_convex_polygon(x_commitment, y_commitment, triangle, proof, b"ctx")
        )

    def test_different_point_commitment_returns_false(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        other_x, _ = self.commit(4, 0, 10, 999)
        other_y, _ = self.commit(6, 0, 10, 888)
        self.assertFalse(
            verify_convex_polygon(other_x, y_commitment, polygon, proof, b"ctx")
        )
        self.assertFalse(
            verify_convex_polygon(x_commitment, other_y, polygon, proof, b"ctx")
        )

    def test_group_mismatch_returns_false(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        other_y, _ = pedersen_commit(
            6, 0, 10, prime=self.PRIME, generator=3, h=7, blinding=4321
        )
        self.assertFalse(
            verify_convex_polygon(x_commitment, other_y, polygon, proof, b"ctx")
        )

    def test_range_mismatch_returns_false(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        wide_x, _ = self.commit(4, 0, 11, 1234)
        wide_y, _ = self.commit(6, 0, 11, 4321)
        self.assertFalse(
            verify_convex_polygon(wide_x, y_commitment, polygon, proof, b"ctx")
        )
        self.assertFalse(
            verify_convex_polygon(x_commitment, wide_y, polygon, proof, b"ctx")
        )

    def test_tampered_proof_fields_return_false(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        # swap the two sub-proofs between the axes
        self.assertFalse(
            verify_convex_polygon(
                x_commitment, y_commitment, polygon,
                ConvexPolygonRegionProof(proof.y_proof, proof.x_proof),
                b"ctx",
            )
        )
        # perturb one announcement
        tampered = dataclasses.replace(
            proof,
            x_proof=RangeProof(
                t=tuple(v + 1 for v in proof.x_proof.t),
                e=proof.x_proof.e,
                s=proof.x_proof.s,
            ),
        )
        self.assertFalse(
            verify_convex_polygon(x_commitment, y_commitment, polygon, tampered, b"ctx")
        )

    def test_forged_proof_returns_false(self):
        # range proofs produced under an unrelated context for commitments to
        # a box point outside the polygon (9, 9)
        x_commitment, x_r = self.commit(9, 0, 10, 1234)
        y_commitment, y_r = self.commit(9, 0, 10, 4321)
        polygon = self.polygon()
        forged = ConvexPolygonRegionProof(
            prove_range(x_commitment, 9, x_r, b"forged", randbelow=counter_randbelow()),
            prove_range(y_commitment, 9, y_r, b"forged", randbelow=counter_randbelow()),
        )
        self.assertFalse(
            verify_convex_polygon(x_commitment, y_commitment, polygon, forged, b"ctx")
        )
        self.assertFalse(
            verify_convex_polygon(x_commitment, y_commitment, polygon, forged, b"forged")
        )

    def test_malformed_subproof_returns_false_not_value_error(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        malformed = ConvexPolygonRegionProof(
            RangeProof(t=(1,), e=(1,), s=(1,)), proof.y_proof
        )
        self.assertFalse(
            verify_convex_polygon(x_commitment, y_commitment, polygon, malformed, b"ctx")
        )

    def test_verify_does_not_accept_rectangle_region_proof_type(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        rectangle_like = RegionProof(proof.x_proof, proof.y_proof)
        with self.assertRaises(TypeError):
            verify_convex_polygon(
                x_commitment, y_commitment, polygon, rectangle_like, b"ctx"
            )

    def test_verify_type_errors(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        with self.assertRaises(TypeError):
            verify_convex_polygon("x", y_commitment, polygon, proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_convex_polygon(x_commitment, "y", polygon, proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_convex_polygon(x_commitment, y_commitment, "polygon", proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_convex_polygon(x_commitment, y_commitment, polygon, "proof", b"ctx")
        with self.assertRaises(TypeError):
            verify_convex_polygon(x_commitment, y_commitment, polygon, proof, "ctx")
        bad = dataclasses.replace(x_commitment, lower="0")
        with self.assertRaises(TypeError):
            verify_convex_polygon(bad, y_commitment, polygon, proof, b"ctx")

    def test_inputs_are_not_mutated(self):
        x_commitment, y_commitment, polygon, proof = self.prove()
        snapshot = (
            dataclasses.asdict(x_commitment),
            dataclasses.asdict(y_commitment),
            polygon.vertices,
            (proof.x_proof.t, proof.x_proof.e, proof.x_proof.s),
        )
        self.assertTrue(
            verify_convex_polygon(x_commitment, y_commitment, polygon, proof, b"ctx")
        )
        self.assertEqual(dataclasses.asdict(x_commitment), snapshot[0])
        self.assertEqual(dataclasses.asdict(y_commitment), snapshot[1])
        self.assertEqual(polygon.vertices, snapshot[2])
        self.assertEqual(
            (proof.x_proof.t, proof.x_proof.e, proof.x_proof.s), snapshot[3]
        )

    def test_non_pedersen_commitment_rejected_at_prove_and_verify(self):
        _, y_commitment, polygon, proof = self.prove()
        fake = type(
            "Fake",
            (),
            {
                "element": 1,
                "lower": 0,
                "upper": 10,
                "prime": self.PRIME,
                "generator": 3,
                "h": 5,
            },
        )()
        with self.assertRaises(TypeError):
            prove_convex_polygon(
                fake, y_commitment, 4, 6, 1, 4321, polygon
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon(fake, y_commitment, polygon, proof, b"ctx")


if __name__ == "__main__":
    unittest.main()
