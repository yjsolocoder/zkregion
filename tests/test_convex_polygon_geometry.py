"""Geometry-semantics regression tests for convex polygon membership proofs.

These tests pin the *geometric* meaning of the public convex-polygon
entry points rather than their self-consistency: membership of every
integer point in the bounding box (expanded by one) is checked against
an independent oracle that shares no code with the product geometry
helpers or ``ConvexPolygonRegion.contains``, and proofs are rebuilt
after integer translations and axis swaps.  Vertex-sequence rotations
and reversals must normalize to the same polygon and keep the original
proof valid.  Everything runs on deterministic random sources, uses
only the standard library and leaves every input object unchanged.
"""

import math
import unittest
from fractions import Fraction

from zkregion import (
    ConvexPolygonBatchEntry,
    ConvexPolygonRegion,
    pedersen_commit,
    prove_convex_polygon,
    verify_convex_polygon,
    verify_convex_polygon_batch,
)


class _DetRand:
    """Deterministic randbelow replacement: same sequence for same seed."""

    def __init__(self, seed=1):
        self.calls = seed

    def __call__(self, upper):
        self.calls += 1
        return (self.calls * 7919 + 13) % upper


# name, vertices in boundary order.  Every sample mixes negative
# coordinates with slanted edges; the quadrilateral is deliberately
# thin and elongated and no edge of it is axis-aligned.  All bounding
# boxes and edge offset spans stay far below the proof limits.
SAMPLES = (
    ("triangle", ((-3, -2), (5, -1), (-1, 4))),
    ("thin-quad", ((-8, -2), (7, -3), (8, -1), (-7, 0))),
    ("pentagon", ((-4, -3), (3, -4), (6, 1), (1, 5), (-5, 2))),
)


def _context(name):
    return f"geom/{name}".encode("ascii")


# ---- independent membership oracle -------------------------------------
# Exact-arithmetic even-odd ray casting plus an on-segment boundary
# check, written from scratch on the raw vertex list.  It never calls
# ``contains`` or any zkregion geometry helper, works for any simple
# polygon (convexity is not assumed) and uses ``Fraction`` so no
# floating-point rounding can hide an off-by-one on an edge.


def _oracle_on_boundary(vertices, x, y):
    count = len(vertices)
    for i in range(count):
        ax, ay = vertices[i]
        bx, by = vertices[(i + 1) % count]
        cross = (bx - ax) * (y - ay) - (by - ay) * (x - ax)
        if (
            cross == 0
            and min(ax, bx) <= x <= max(ax, bx)
            and min(ay, by) <= y <= max(ay, by)
        ):
            return True
    return False


def _oracle_contains(vertices, x, y):
    """Closed-polygon membership of integer point ``(x, y)``."""
    if _oracle_on_boundary(vertices, x, y):
        return True
    crossings = 0
    count = len(vertices)
    for i in range(count):
        ax, ay = vertices[i]
        bx, by = vertices[(i + 1) % count]
        if (ay > y) == (by > y):
            continue  # edge does not strictly straddle the horizontal ray
        # Exact x-coordinate where the edge meets the horizontal line y.
        x_hit = Fraction(ax) + Fraction(y - ay, by - ay) * (bx - ax)
        if x_hit > x:
            crossings += 1
    return crossings % 2 == 1


def _grid(polygon, margin):
    for x in range(polygon.min_x - margin, polygon.max_x + margin + 1):
        for y in range(polygon.min_y - margin, polygon.max_y + margin + 1):
            yield x, y


def _commit_and_prove(polygon, x, y, context, seed=1):
    """Commit both axes over the polygon bounding box and prove membership."""
    x_commitment, x_blinding = pedersen_commit(
        x, polygon.min_x, polygon.max_x, randbelow=_DetRand(seed)
    )
    y_commitment, y_blinding = pedersen_commit(
        y, polygon.min_y, polygon.max_y, randbelow=_DetRand(seed + 1)
    )
    proof = prove_convex_polygon(
        x_commitment,
        y_commitment,
        x,
        y,
        x_blinding,
        y_blinding,
        polygon,
        context,
        randbelow=_DetRand(seed + 2),
    )
    return x_commitment, y_commitment, proof


class ConvexPolygonGridSemanticsTests(unittest.TestCase):
    """Closed-region semantics on the integer lattice around each sample."""

    def test_closed_region_matches_independent_oracle(self):
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            for point in _grid(polygon, margin=1):
                with self.subTest(
                    polygon=name, transform="identity", point=point
                ):
                    self.assertEqual(
                        polygon.contains(*point),
                        _oracle_contains(vertices, *point),
                        f"polygon={name} point={point}",
                    )

    def test_vertices_and_edge_lattice_points_are_inside(self):
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            count = len(vertices)
            for i in range(count):
                ax, ay = vertices[i]
                bx, by = vertices[(i + 1) % count]
                steps = math.gcd(abs(bx - ax), abs(by - ay))
                for k in range(steps + 1):
                    point = (
                        ax + (bx - ax) // steps * k,
                        ay + (by - ay) // steps * k,
                    )
                    with self.subTest(polygon=name, edge=i, point=point):
                        self.assertTrue(
                            polygon.contains(*point),
                            f"polygon={name} boundary point={point}",
                        )

    def test_grid_proofs_verify_and_outside_points_raise(self):
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            context = _context(name)
            for point in _grid(polygon, margin=0):
                x, y = point
                # Declared intervals match the bounding box exactly.
                x_commitment, x_blinding = pedersen_commit(
                    x, polygon.min_x, polygon.max_x, randbelow=_DetRand()
                )
                y_commitment, y_blinding = pedersen_commit(
                    y, polygon.min_y, polygon.max_y, randbelow=_DetRand()
                )
                with self.subTest(polygon=name, point=point):
                    self.assertEqual(
                        (x_commitment.lower, x_commitment.upper),
                        (polygon.min_x, polygon.max_x),
                    )
                    self.assertEqual(
                        (y_commitment.lower, y_commitment.upper),
                        (polygon.min_y, polygon.max_y),
                    )
                    if _oracle_contains(vertices, x, y):
                        proof = prove_convex_polygon(
                            x_commitment,
                            y_commitment,
                            x,
                            y,
                            x_blinding,
                            y_blinding,
                            polygon,
                            context,
                            randbelow=_DetRand(),
                        )
                        self.assertTrue(
                            verify_convex_polygon(
                                x_commitment,
                                y_commitment,
                                polygon,
                                proof,
                                context,
                            ),
                            f"polygon={name} point={point}",
                        )
                    else:
                        with self.assertRaises(ValueError):
                            prove_convex_polygon(
                                x_commitment,
                                y_commitment,
                                x,
                                y,
                                x_blinding,
                                y_blinding,
                                polygon,
                                context,
                                randbelow=_DetRand(),
                            )

    def test_points_outside_bbox_only_checked_for_membership(self):
        # The one-cell ring around the bounding box lies outside the
        # declared commitment intervals, so no commitments are built;
        # the region predicate must still agree with the oracle.
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            ring = [
                point
                for point in _grid(polygon, margin=1)
                if not (
                    polygon.min_x <= point[0] <= polygon.max_x
                    and polygon.min_y <= point[1] <= polygon.max_y
                )
            ]
            self.assertTrue(ring, f"polygon={name} has no out-of-bbox ring")
            for point in ring:
                with self.subTest(polygon=name, point=point):
                    self.assertEqual(
                        polygon.contains(*point),
                        _oracle_contains(vertices, *point),
                    )
                    self.assertFalse(
                        polygon.contains(*point),
                        f"polygon={name} out-of-bbox point={point} "
                        "reported inside",
                    )


class ConvexPolygonTransformTests(unittest.TestCase):
    """Membership and proofs under lattice-preserving transformations."""

    def _assert_membership_preserved(
        self, name, polygon, moved, point_map, transform
    ):
        for point in _grid(polygon, margin=1):
            mapped = point_map(*point)
            with self.subTest(polygon=name, transform=transform, point=point):
                self.assertEqual(
                    moved.contains(*mapped),
                    polygon.contains(*point),
                    f"polygon={name} transform={transform} "
                    f"point={point} mapped={mapped}",
                )

    def _assert_oracle_on_transformed(self, name, moved, moved_vertices, transform):
        for point in _grid(moved, margin=1):
            with self.subTest(polygon=name, transform=transform, point=point):
                self.assertEqual(
                    moved.contains(*point),
                    _oracle_contains(moved_vertices, *point),
                    f"polygon={name} transform={transform} point={point}",
                )

    def _assert_proofs_rebuilt_and_verify(self, name, moved, transform):
        context = _context(name) + b"/" + transform.encode("ascii")
        for point in _grid(moved, margin=0):
            if not moved.contains(*point):
                continue
            with self.subTest(polygon=name, transform=transform, point=point):
                x_commitment, y_commitment, proof = _commit_and_prove(
                    moved, point[0], point[1], context
                )
                self.assertTrue(
                    verify_convex_polygon(
                        x_commitment, y_commitment, moved, proof, context
                    ),
                    f"polygon={name} transform={transform} point={point}",
                )

    def test_integer_translation(self):
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            for tx, ty in ((7, -4), (-11, 9)):
                transform = f"translate({tx},{ty})"
                moved_vertices = tuple((x + tx, y + ty) for x, y in vertices)
                moved = ConvexPolygonRegion(moved_vertices)
                self._assert_oracle_on_transformed(
                    name, moved, moved_vertices, transform
                )
                self._assert_membership_preserved(
                    name,
                    polygon,
                    moved,
                    lambda x, y, tx=tx, ty=ty: (x + tx, y + ty),
                    transform,
                )
                # Commitments and proofs must be rebuilt over the
                # translated bounding box; the fresh proofs verify.
                self._assert_proofs_rebuilt_and_verify(name, moved, transform)

    def test_axis_swap(self):
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            transform = "swap-axes"
            swapped_vertices = tuple((y, x) for x, y in vertices)
            swapped = ConvexPolygonRegion(swapped_vertices)
            self._assert_oracle_on_transformed(
                name, swapped, swapped_vertices, transform
            )
            self._assert_membership_preserved(
                name, polygon, swapped, lambda x, y: (y, x), transform
            )
            # Commitments and proofs must be rebuilt with the axes
            # reassigned; the fresh proofs verify.
            self._assert_proofs_rebuilt_and_verify(name, swapped, transform)

    def test_rotation_and_reversal_keep_canonical_form_and_proof(self):
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            context = _context(name)
            # Prove at a vertex: vertices belong to the closed region.
            point = polygon.vertices[0]
            x_commitment, y_commitment, proof = _commit_and_prove(
                polygon, point[0], point[1], context
            )
            count = len(vertices)
            reversed_vertices = tuple(reversed(vertices))
            variants = []
            for shift in range(count):
                variants.append(
                    (f"rotate-{shift}", vertices[shift:] + vertices[:shift])
                )
            for shift in range(count):
                variants.append(
                    (
                        f"reversed-rotate-{shift}",
                        reversed_vertices[shift:] + reversed_vertices[:shift],
                    )
                )
            for label, variant in variants:
                with self.subTest(polygon=name, transform=label):
                    represented = ConvexPolygonRegion(variant)
                    self.assertEqual(represented.vertices, polygon.vertices)
                    self.assertEqual(represented, polygon)
                    self.assertEqual(hash(represented), hash(polygon))
                    # No re-commitment or re-proof: the original proof
                    # still verifies against the re-represented polygon.
                    self.assertTrue(
                        verify_convex_polygon(
                            x_commitment,
                            y_commitment,
                            represented,
                            proof,
                            context,
                        ),
                        f"polygon={name} transform={label}",
                    )


class ConvexPolygonMixedBatchTests(unittest.TestCase):
    """Batch verification across different shapes from the sample set."""

    def _entries(self):
        entries = []
        for seed, (name, vertices) in enumerate(SAMPLES, start=100):
            polygon = ConvexPolygonRegion(vertices)
            context = _context(name) + b"/batch"
            point = polygon.vertices[0]
            x_commitment, y_commitment, proof = _commit_and_prove(
                polygon, point[0], point[1], context, seed=seed
            )
            entries.append(
                ConvexPolygonBatchEntry(
                    x_commitment, y_commitment, polygon, proof, context
                )
            )
        return entries

    def test_mixed_shapes_batch_verifies(self):
        entries = self._entries()
        self.assertTrue(entries)
        self.assertIs(
            verify_convex_polygon_batch(entries, randbelow=_DetRand()), True
        )

    def test_reordered_and_duplicated_entries_still_verify(self):
        entries = self._entries()
        for order in ((2, 1, 0), (1, 2, 0), (0, 0, 1), (2, 0, 2, 1, 0)):
            with self.subTest(order=order):
                self.assertIs(
                    verify_convex_polygon_batch(
                        [entries[i] for i in order], randbelow=_DetRand()
                    ),
                    True,
                )

    def test_replaced_context_fails_single_and_batch(self):
        entries = self._entries()
        for index, entry in enumerate(entries):
            name = SAMPLES[index][0]
            bad_context = b"geom/tampered"
            self.assertNotEqual(entry.context, bad_context)
            with self.subTest(polygon=name):
                # Same proof, same commitments, same polygon: only the
                # context differs, so single verification must fail.
                self.assertFalse(
                    verify_convex_polygon(
                        entry.x_commitment,
                        entry.y_commitment,
                        entry.polygon,
                        entry.proof,
                        bad_context,
                    ),
                    f"polygon={name} single verify accepted wrong context",
                )
                tampered = ConvexPolygonBatchEntry(
                    entry.x_commitment,
                    entry.y_commitment,
                    entry.polygon,
                    entry.proof,
                    bad_context,
                )
                batch = list(entries)
                batch[index] = tampered
                self.assertIs(
                    verify_convex_polygon_batch(batch, randbelow=_DetRand()),
                    False,
                )


class ConvexPolygonInputPreservationTests(unittest.TestCase):
    """Vertices, commitments and proofs keep their values throughout."""

    def test_inputs_unchanged_after_all_checks(self):
        for name, vertices in SAMPLES:
            polygon = ConvexPolygonRegion(vertices)
            context = _context(name)
            point = polygon.vertices[0]
            x_commitment, y_commitment, proof = _commit_and_prove(
                polygon, point[0], point[1], context
            )
            snapshot = (
                vertices,
                polygon.vertices,
                repr(x_commitment),
                repr(y_commitment),
                repr(proof),
            )
            # Exercise every public entry point used by this module.
            for grid_point in _grid(polygon, margin=1):
                polygon.contains(*grid_point)
            self.assertTrue(
                verify_convex_polygon(
                    x_commitment, y_commitment, polygon, proof, context
                )
            )
            entry = ConvexPolygonBatchEntry(
                x_commitment, y_commitment, polygon, proof, context
            )
            self.assertIs(
                verify_convex_polygon_batch([entry], randbelow=_DetRand()),
                True,
            )
            rotated = ConvexPolygonRegion(vertices[1:] + vertices[:1])
            self.assertTrue(
                verify_convex_polygon(
                    x_commitment, y_commitment, rotated, proof, context
                )
            )
            with self.subTest(polygon=name):
                self.assertEqual(
                    snapshot,
                    (
                        vertices,
                        polygon.vertices,
                        repr(x_commitment),
                        repr(y_commitment),
                        repr(proof),
                    ),
                )


if __name__ == "__main__":
    unittest.main()
