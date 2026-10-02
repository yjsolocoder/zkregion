import dataclasses
import hashlib
import os
import tempfile
import threading
import unittest

from zkregion import (
    BoundConvexPolygonBatch,
    ConvexPolygonBatchEntry,
    ConvexPolygonBatchReplayGuard,
    ConvexPolygonProofBundle,
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    DEFAULT_PRIME,
    MerkleMultiProof,
    PedersenCommitment,
    RangeProof,
    ReplayBinding,
    SQLiteReplayStore,
    WideRangeProof,
    _bound_convex_polygon_leaf,
    _edge_offset_upper,
    decode_convex_polygon_proof_bundle,
    encode_convex_polygon_proof_bundle,
    merkle_root,
    pedersen_commit,
    prove_convex_polygon,
    prove_convex_polygon_batch_bound,
    prove_multi_inclusion,
    verify_convex_polygon,
    verify_convex_polygon_batch,
    verify_convex_polygon_batch_bound,
    verify_convex_polygon_proof_bundle,
    verify_multi_inclusion,
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


class ConvexPolygonProofBundleTests(unittest.TestCase):
    def bundle(
        self,
        x=1,
        y=2,
        polygon=None,
        context=b"ctx",
        vertices=TRIANGLE,
        x_blinding=1234,
        y_blinding=4321,
    ):
        polygon = ConvexPolygonRegion(vertices) if polygon is None else polygon
        x_commitment, x_r = pedersen_commit(
            x, polygon.min_x, polygon.max_x, blinding=x_blinding
        )
        y_commitment, y_r = pedersen_commit(
            y, polygon.min_y, polygon.max_y, blinding=y_blinding
        )
        proof = prove_convex_polygon(
            x_commitment, y_commitment, x, y, x_r, y_r, polygon, context,
            randbelow=DetRand(),
        )
        return ConvexPolygonProofBundle(
            x_commitment, y_commitment, polygon, context, proof
        )

    # ---- round trip ---------------------------------------------------------

    def test_round_trip_triangle(self):
        bundle = self.bundle()
        raw = encode_convex_polygon_proof_bundle(bundle)
        self.assertIsInstance(raw, bytes)
        decoded = decode_convex_polygon_proof_bundle(raw)
        self.assertEqual(decoded, bundle)
        self.assertIsInstance(decoded.proof, ConvexPolygonRegionProof)
        self.assertIsInstance(decoded.proof.x_proof, RangeProof)
        self.assertEqual(
            tuple(type(p) for p in decoded.proof.edge_proofs),
            (WideRangeProof,) * len(decoded.polygon.vertices),
        )
        self.assertTrue(verify_convex_polygon_proof_bundle(bundle))
        self.assertTrue(verify_convex_polygon_proof_bundle(decoded))

    def test_round_trip_pentagon_with_negative_coordinates(self):
        vertices = ((-5, -5), (5, -5), (8, 0), (5, 5), (-5, 5))
        bundle = self.bundle(x=0, y=0, vertices=vertices, context=b"pentagon")
        raw = encode_convex_polygon_proof_bundle(bundle)
        decoded = decode_convex_polygon_proof_bundle(raw)
        self.assertEqual(decoded, bundle)
        self.assertEqual(len(decoded.proof.edge_proofs), 5)
        self.assertTrue(verify_convex_polygon_proof_bundle(decoded))

    def test_round_trip_empty_and_arbitrary_binary_context(self):
        for context in (b"", b"\x00\xff", b"\x00\x00\x00\x09binary", b"a" * 300):
            with self.subTest(context=context):
                bundle = self.bundle(context=context)
                decoded = decode_convex_polygon_proof_bundle(
                    encode_convex_polygon_proof_bundle(bundle)
                )
                self.assertEqual(decoded, bundle)
                self.assertEqual(decoded.context, context)
                self.assertTrue(verify_convex_polygon_proof_bundle(decoded))

    def test_rotated_and_reversed_polygon_representations_round_trip_alike(self):
        bundle = self.bundle()
        canonical = bundle.polygon
        rotated = ConvexPolygonRegion(
            tuple(canonical.vertices[1:] + canonical.vertices[:1])
        )
        reversed_polygon = ConvexPolygonRegion(tuple(reversed(canonical.vertices)))
        raw = encode_convex_polygon_proof_bundle(bundle)
        for same_region in (rotated, reversed_polygon):
            other = ConvexPolygonProofBundle(
                bundle.x_commitment,
                bundle.y_commitment,
                same_region,
                bundle.context,
                bundle.proof,
            )
            self.assertEqual(
                encode_convex_polygon_proof_bundle(other), raw
            )
            self.assertEqual(
                decode_convex_polygon_proof_bundle(raw), other
            )

    def test_large_integers_round_trip(self):
        huge = 10**40
        polygon = ConvexPolygonRegion(
            ((-huge, -huge), (huge, -huge), (0, huge))
        )
        # Commitments need not open here: only the envelope is exercised.
        x_commitment = PedersenCommitment(
            element=1, lower=-huge, upper=huge, prime=2**255 - 19,
            generator=3, h=pow(3, 2, 2**255 - 19),
        )
        y_commitment = PedersenCommitment(
            element=1, lower=-huge, upper=huge, prime=2**255 - 19,
            generator=3, h=pow(3, 2, 2**255 - 19),
        )
        proof = ConvexPolygonRegionProof(
            x_proof=RangeProof((1,), (0,), (0,)),
            y_proof=RangeProof((1,), (0,), (0,)),
            edge_proofs=tuple(
                WideRangeProof((1,), ((0, 0),), ((0, 0),)) for _ in range(3)
            ),
        )
        bundle = ConvexPolygonProofBundle(
            x_commitment, y_commitment, polygon, b"big", proof
        )
        decoded = decode_convex_polygon_proof_bundle(
            encode_convex_polygon_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)

    def test_encode_is_deterministic(self):
        bundle = self.bundle()
        self.assertEqual(
            encode_convex_polygon_proof_bundle(bundle),
            encode_convex_polygon_proof_bundle(bundle),
        )
        self.assertEqual(
            encode_convex_polygon_proof_bundle(self.bundle()),
            encode_convex_polygon_proof_bundle(self.bundle()),
        )

    def test_re_encoding_is_byte_identical(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        decoded = decode_convex_polygon_proof_bundle(raw)
        self.assertEqual(encode_convex_polygon_proof_bundle(decoded), raw)

    def test_header_carries_magic_and_version(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        self.assertEqual(raw[:5], b"zrgp" + bytes((1,)))

    def test_bundle_is_frozen_and_value_compared(self):
        bundle = self.bundle()
        with self.assertRaises(Exception):
            bundle.context = b"other"
        self.assertEqual(bundle, self.bundle())

    def test_distinct_fields_never_share_encoding(self):
        base_raw = encode_convex_polygon_proof_bundle(self.bundle())
        other_polygon = ConvexPolygonRegion(((0, 0), (4, 0), (0, 3)))
        variants = (
            self.bundle(context=b"other"),
            self.bundle(polygon=other_polygon),
        )
        for variant in variants:
            self.assertNotEqual(
                encode_convex_polygon_proof_bundle(variant), base_raw
            )
        bundle = self.bundle()
        reordered_edges = ConvexPolygonRegionProof(
            bundle.proof.x_proof,
            bundle.proof.y_proof,
            (
                bundle.proof.edge_proofs[1],
                bundle.proof.edge_proofs[0],
                bundle.proof.edge_proofs[2],
            ),
        )
        variant = ConvexPolygonProofBundle(
            bundle.x_commitment,
            bundle.y_commitment,
            bundle.polygon,
            bundle.context,
            reordered_edges,
        )
        self.assertNotEqual(
            encode_convex_polygon_proof_bundle(variant), base_raw
        )

    # ---- decode failures ----------------------------------------------------

    def test_every_truncation_rejected(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        self.assertGreater(len(raw), 100)
        for cut in range(0, len(raw)):
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(raw[:cut])

    def test_trailing_and_prepended_data_rejected(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        for extra in (b"\x00", b"ab", b"\xff" * 8):
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(raw + extra)
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(extra + raw)

    def test_bad_magic_and_unknown_version_rejected(self):
        raw = bytearray(encode_convex_polygon_proof_bundle(self.bundle()))
        raw[0] = ord("X")
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(raw))
        raw = bytearray(encode_convex_polygon_proof_bundle(self.bundle()))
        raw[4] = 0
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(raw))
        raw[4] = 2
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(raw))
        raw[4] = 255
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(raw))

    def test_decode_requires_bytes(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        for bad in (
            bytearray(raw), memoryview(raw), str(raw), 123, None, [raw],
        ):
            with self.assertRaises(TypeError):
                decode_convex_polygon_proof_bundle(bad)

    def test_single_byte_tampering_never_yields_valid_original_bundle(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        for index in range(len(raw)):
            tampered = bytearray(raw)
            tampered[index] ^= 0xFF
            try:
                decoded = decode_convex_polygon_proof_bundle(bytes(tampered))
            except ValueError:
                continue
            self.assertNotEqual(decoded, self.bundle(), index)
            self.assertFalse(
                verify_convex_polygon_proof_bundle(decoded),
                f"tampered byte {index} verified",
            )

    def test_non_canonical_integers_rejected(self):
        raw = bytearray(encode_convex_polygon_proof_bundle(self.bundle()))
        # header (5) + first frame length (4) + commitment tuple count (4);
        # the first framed integer starts at offset 13.
        pos = 13
        length = int.from_bytes(raw[pos:pos + 4], "big")
        mutated = bytearray(raw)
        # insert a leading zero byte in the magnitude and grow both the
        # integer frame and the surrounding commitment frame by one
        mutated[5:9] = (
            int.from_bytes(mutated[5:9], "big") + 1
        ).to_bytes(4, "big")
        mutated[pos:pos + 4] = (length + 1).to_bytes(4, "big")
        mutated[pos + 5:pos + 5] = b"\x00"
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(mutated))
        # negative zero: a zero integer frames as uint32(2) 0x01 0x00
        marker = bytes((0, 0, 0, 2, 1, 0))
        zero_pos = bytes(raw).find(marker)
        self.assertGreaterEqual(zero_pos, 0)
        mutated = bytearray(raw)
        mutated[zero_pos + 4] = 255
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(mutated))
        mutated = bytearray(raw)
        mutated[zero_pos + 4] = 7
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(mutated))

    def test_invalid_commitment_field_values_rejected(self):
        prime = DEFAULT_PRIME
        good = dict(
            element=1, lower=0, upper=4, prime=prime, generator=3, h=9
        )
        bad_cases = (
            dict(element=0),
            dict(element=prime),
            dict(prime=3),
            dict(generator=1),
            dict(generator=prime),
            dict(h=1),
            dict(h=prime),
            dict(lower=5),
        )
        for overrides in bad_cases:
            values = dict(good)
            values.update(overrides)
            bundle = self.bundle()
            object.__setattr__(
                bundle, "x_commitment", PedersenCommitment(**values)
            )
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(
                    encode_convex_polygon_proof_bundle(bundle)
                )

    def test_wire_polygon_with_too_few_vertices_rejected(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        # header (5), then the x and y commitment frames, then the polygon
        # frame whose body starts with the vertex cardinality
        pos = 5
        for _ in range(2):
            length = int.from_bytes(raw[pos:pos + 4], "big")
            pos += 4 + length
        mutated = bytearray(raw)
        mutated[pos + 4:pos + 8] = (2).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(mutated))

    def test_wire_vertex_pair_with_wrong_cardinality_rejected(self):
        raw = encode_convex_polygon_proof_bundle(self.bundle())
        pos = 5
        for _ in range(2):
            length = int.from_bytes(raw[pos:pos + 4], "big")
            pos += 4 + length
        # polygon frame body: vertex count at [pos+4:pos+8], first vertex
        # frame length at [pos+8:pos+12], pair cardinality at [pos+12:+16]
        self.assertEqual(
            int.from_bytes(raw[pos + 12:pos + 16], "big"), 2
        )
        mutated = bytearray(raw)
        # declaring one coordinate leaves the second integer frame behind
        # as trailing data inside the vertex body
        mutated[pos + 12:pos + 16] = (1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(mutated))
        mutated = bytearray(raw)
        mutated[pos + 12:pos + 16] = (3).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(mutated))

    def test_edge_proof_count_mismatch_rejected(self):
        bundle = self.bundle()
        proof = bundle.proof
        cases = (
            ConvexPolygonRegionProof(
                proof.x_proof, proof.y_proof, proof.edge_proofs[:-1]
            ),
            ConvexPolygonRegionProof(
                proof.x_proof, proof.y_proof,
                proof.edge_proofs + proof.edge_proofs[:1],
            ),
        )
        for bad_proof in cases:
            bad = ConvexPolygonProofBundle(
                bundle.x_commitment,
                bundle.y_commitment,
                bundle.polygon,
                bundle.context,
                bad_proof,
            )
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(
                    encode_convex_polygon_proof_bundle(bad)
                )

    def test_malformed_range_proof_shape_rejected(self):
        bundle = self.bundle()
        good = bundle.proof.x_proof
        self.assertGreater(len(good.t), 1)
        for t, e, s in (
            (good.t[:-1], good.e, good.s),
            (good.t, good.e[:-1], good.s),
            (good.t, good.e, good.s[:-1]),
            ((), (), ()),
        ):
            bad_proof = ConvexPolygonRegionProof(
                RangeProof(t, e, s),
                bundle.proof.y_proof,
                bundle.proof.edge_proofs,
            )
            bad = ConvexPolygonProofBundle(
                bundle.x_commitment,
                bundle.y_commitment,
                bundle.polygon,
                bundle.context,
                bad_proof,
            )
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(
                    encode_convex_polygon_proof_bundle(bad)
                )

    def test_malformed_wide_edge_proof_shape_rejected(self):
        bundle = self.bundle()
        good = bundle.proof.edge_proofs[0]
        bad_edge = WideRangeProof(
            good.commitments[:-1], good.challenges, good.responses
        )
        bad_proof = ConvexPolygonRegionProof(
            bundle.proof.x_proof,
            bundle.proof.y_proof,
            (bad_edge,) + bundle.proof.edge_proofs[1:],
        )
        bad = ConvexPolygonProofBundle(
            bundle.x_commitment,
            bundle.y_commitment,
            bundle.polygon,
            bundle.context,
            bad_proof,
        )
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(
                encode_convex_polygon_proof_bundle(bad)
            )

    # ---- encode type errors -------------------------------------------------

    def test_encode_rejects_wrong_object_and_field_types(self):
        good = self.bundle()
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(object())
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    object(), good.y_commitment, good.polygon, b"c", good.proof
                )
            )
        bool_commitment = PedersenCommitment(True, 0, 4, DEFAULT_PRIME, 3, 9)
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    bool_commitment, good.y_commitment, good.polygon, b"c",
                    good.proof,
                )
            )
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, object(), b"c",
                    good.proof,
                )
            )
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, "c",
                    good.proof,
                )
            )
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, b"c",
                    object(),
                )
            )
        bad_proof = ConvexPolygonRegionProof(
            RangeProof([1], (0,), (0,)),
            good.proof.y_proof,
            good.proof.edge_proofs,
        )
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, b"c",
                    bad_proof,
                )
            )
        list_edges = ConvexPolygonRegionProof(
            good.proof.x_proof, good.proof.y_proof, list(good.proof.edge_proofs)
        )
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, b"c",
                    list_edges,
                )
            )
        int_edges = ConvexPolygonRegionProof(
            good.proof.x_proof, good.proof.y_proof, (1, 2, 3)
        )
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, b"c",
                    int_edges,
                )
            )

    def test_encode_rejects_forged_illegal_polygon(self):
        bundle = self.bundle()
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ((0, 0), (1, 1), (2, 2), (3, 3)))
        object.__setattr__(bundle, "polygon", forged)
        with self.assertRaises(ValueError):
            encode_convex_polygon_proof_bundle(bundle)
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ((0, 0), (1, 0), (0, 1), (1, 1)))
        object.__setattr__(bundle, "polygon", forged)
        with self.assertRaises(ValueError):
            encode_convex_polygon_proof_bundle(bundle)

    # ---- verify type errors -------------------------------------------------

    def test_verify_type_errors(self):
        good = self.bundle()
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(object())
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    object(), good.y_commitment, good.polygon, b"c", good.proof
                )
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, object(), b"c",
                    good.proof,
                )
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, 7,
                    good.proof,
                )
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, b"c",
                    object(),
                )
            )
        bad_edges = ConvexPolygonRegionProof(
            good.proof.x_proof, good.proof.y_proof, (1, 2, 3)
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon, b"c",
                    bad_edges,
                )
            )
        # malformed vertex container types on a forged polygon raise
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", [(0, 0), (1, 0), (0, 1)])
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, forged, b"c",
                    good.proof,
                )
            )

    # ---- verify False semantics ---------------------------------------------

    def test_verify_accepts_valid_bundle(self):
        self.assertIs(
            verify_convex_polygon_proof_bundle(self.bundle()), True
        )

    def test_verify_rejects_context_mismatch(self):
        bundle = self.bundle()
        object.__setattr__(bundle, "context", b"other")
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_verify_rejects_swapped_commitments(self):
        bundle = self.bundle()
        swapped = ConvexPolygonProofBundle(
            bundle.y_commitment,
            bundle.x_commitment,
            bundle.polygon,
            bundle.context,
            bundle.proof,
        )
        self.assertFalse(verify_convex_polygon_proof_bundle(swapped))

    def test_verify_rejects_swapped_axes(self):
        bundle = self.bundle()
        swapped = ConvexPolygonRegionProof(
            x_proof=bundle.proof.y_proof,
            y_proof=bundle.proof.x_proof,
            edge_proofs=bundle.proof.edge_proofs,
        )
        object.__setattr__(bundle, "proof", swapped)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_verify_rejects_wrong_polygon(self):
        bundle = self.bundle()
        other = ConvexPolygonRegion(((0, 0), (4, 0), (0, 3)))
        object.__setattr__(bundle, "polygon", other)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_verify_rejects_tampered_and_reordered_edge_proofs(self):
        bundle = self.bundle()
        edge = bundle.proof.edge_proofs[0]
        bad_commitments = tuple(c + 1 for c in edge.commitments)
        bad_edge = WideRangeProof(
            bad_commitments, edge.challenges, edge.responses
        )
        tampered = ConvexPolygonRegionProof(
            bundle.proof.x_proof,
            bundle.proof.y_proof,
            (bad_edge,) + bundle.proof.edge_proofs[1:],
        )
        object.__setattr__(bundle, "proof", tampered)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))
        bundle = self.bundle()
        reordered = ConvexPolygonRegionProof(
            bundle.proof.x_proof,
            bundle.proof.y_proof,
            (
                bundle.proof.edge_proofs[1],
                bundle.proof.edge_proofs[0],
                bundle.proof.edge_proofs[2],
            ),
        )
        object.__setattr__(bundle, "proof", reordered)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_verify_rejects_dropped_edge_proof(self):
        bundle = self.bundle()
        dropped = ConvexPolygonRegionProof(
            bundle.proof.x_proof,
            bundle.proof.y_proof,
            bundle.proof.edge_proofs[1:],
        )
        object.__setattr__(bundle, "proof", dropped)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_verify_rejects_mismatched_group_parameters(self):
        bundle = self.bundle()
        other_prime, _ = pedersen_commit(
            1, bundle.polygon.min_x, bundle.polygon.max_x, prime=2**61 - 1
        )
        object.__setattr__(bundle, "x_commitment", other_prime)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_verify_false_for_forged_geometrically_invalid_polygon(self):
        bundle = self.bundle()
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ((0, 0), (1, 1), (2, 2), (3, 3)))
        object.__setattr__(bundle, "polygon", forged)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_verify_false_for_forged_empty_vertex_polygon(self):
        bundle = self.bundle()
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ())
        object.__setattr__(bundle, "polygon", forged)
        self.assertFalse(verify_convex_polygon_proof_bundle(bundle))

    def test_round_trip_preserves_verification_failure(self):
        bundle = self.bundle()
        object.__setattr__(bundle, "context", b"other")
        raw = encode_convex_polygon_proof_bundle(bundle)
        decoded = decode_convex_polygon_proof_bundle(raw)
        self.assertEqual(decoded, bundle)
        self.assertFalse(verify_convex_polygon_proof_bundle(decoded))


class ConvexPolygonBatchTests(unittest.TestCase):
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
        from zkregion import _edge_offset_upper

        polygon = entry.polygon
        count = (polygon.max_x - polygon.min_x + 1) + (
            polygon.max_y - polygon.min_y + 1
        )
        for edge in polygon._interior_edges():
            upper = _edge_offset_upper(polygon, edge)
            count += 2 * max(1, upper.bit_length())
        return count

    # ---- happy paths --------------------------------------------------------

    def test_valid_batches(self):
        entries = [
            self._entry(1, 2, context=b"a"),
            self._entry(3, 0, context=b"b"),
            self._entry(0, 3, vertices=((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))),
        ]
        self.assertIs(verify_convex_polygon_batch(entries), True)
        self.assertIs(verify_convex_polygon_batch(tuple(entries)), True)
        self.assertIs(verify_convex_polygon_batch([entries[0]]), True)

    def test_duplicate_entries_are_legal(self):
        entry = self._entry()
        self.assertIs(
            verify_convex_polygon_batch([entry, entry, entry]), True
        )

    def test_empty_batch_returns_false_without_drawing(self):
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertIs(
            verify_convex_polygon_batch([], randbelow=recording), False
        )
        self.assertEqual(calls, [])

    def test_default_context_is_empty_bytes(self):
        entry = self._entry(context=b"")
        default = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon, entry.proof
        )
        self.assertEqual(default.context, b"")
        self.assertIs(verify_convex_polygon_batch([default]), True)

    def test_entry_is_frozen_and_value_compared(self):
        entry = self._entry(x_blinding=1234, y_blinding=4321)
        with self.assertRaises(Exception):
            entry.context = b"other"
        self.assertEqual(
            entry, self._entry(x_blinding=1234, y_blinding=4321)
        )

    def test_deterministic_under_same_random_source(self):
        entries = [self._entry(1, 1), self._entry(2, 2)]
        first = verify_convex_polygon_batch(entries, randbelow=DetRand())
        second = verify_convex_polygon_batch(entries, randbelow=DetRand())
        self.assertIs(first, True)
        self.assertEqual(first, second)

    def test_custom_group_parameters_share_one_group_check(self):
        prime = DEFAULT_PRIME
        generator, h = 5, pow(5, 7, prime)
        vertices = ((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))
        entries = []
        for x, y in ((0, 0), (2, 3), (2, 6), (1, 4)):
            polygon = ConvexPolygonRegion(vertices)
            cx, rx = pedersen_commit(
                x, polygon.min_x, polygon.max_x,
                prime=prime, generator=generator, h=h,
            )
            cy, ry = pedersen_commit(
                y, polygon.min_y, polygon.max_y,
                prime=prime, generator=generator, h=h,
            )
            proof = prove_convex_polygon(
                cx, cy, x, y, rx, ry, polygon, b"g", randbelow=DetRand()
            )
            entries.append(
                ConvexPolygonBatchEntry(cx, cy, polygon, proof, b"g")
            )
        self.assertIs(
            verify_convex_polygon_batch(entries, randbelow=DetRand()), True
        )

    # ---- agreement with per-item verification ------------------------------

    def test_matches_verify_convex_polygon_pointwise(self):
        entries = []
        for point in ((0, 0), (1, 1), (3, 0), (0, 3), (4, 0)):
            entries.append(self._entry(*point))
        for order in (entries, list(reversed(entries)), entries[::2]):
            batch_result = verify_convex_polygon_batch(order, randbelow=DetRand())
            single_result = all(
                verify_convex_polygon(
                    entry.x_commitment, entry.y_commitment, entry.polygon,
                    entry.proof, entry.context,
                )
                for entry in order
            )
            self.assertIs(batch_result, single_result)

    # ---- one draw per structurally valid branch ----------------------------

    def test_randbelow_called_once_per_structurally_valid_branch(self):
        entry = self._entry()
        calls = []

        def recording(upper):
            calls.append(upper)
            return (len(calls) * 7919 + 13) % upper

        self.assertIs(
            verify_convex_polygon_batch([entry], randbelow=recording), True
        )
        expected = self._expected_branch_count(entry)
        self.assertEqual(calls, [entry.x_commitment.prime - 1] * expected)

    def test_invalid_entry_short_circuits_before_its_first_draw(self):
        entry = self._entry()
        # dropping one edge proof is a structural failure detected before
        # any branch of that entry is drawn
        dropped = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof, entry.proof.edge_proofs[1:]
        )
        invalid = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon, dropped,
            entry.context,
        )
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertFalse(
            verify_convex_polygon_batch([invalid, entry], randbelow=recording)
        )
        self.assertEqual(calls, [])
        self.assertFalse(
            verify_convex_polygon_batch([entry, invalid], randbelow=recording)
        )
        self.assertEqual(
            calls, [entry.x_commitment.prime - 1]
            * self._expected_branch_count(entry)
        )

    # ---- False semantics ----------------------------------------------------

    def test_wrong_context_returns_false(self):
        entry = self._entry()
        for context in (b"other", b""):
            bad = ConvexPolygonBatchEntry(
                entry.x_commitment, entry.y_commitment, entry.polygon,
                entry.proof, context,
            )
            self.assertFalse(verify_convex_polygon_batch([bad]))

    def test_swapped_axes_return_false(self):
        entry = self._entry()
        swapped = ConvexPolygonBatchEntry(
            entry.y_commitment, entry.x_commitment, entry.polygon,
            entry.proof, entry.context,
        )
        self.assertFalse(
            verify_convex_polygon_batch([swapped], randbelow=DetRand())
        )

    def test_changed_polygon_returns_false(self):
        entry = self._entry()
        for vertices in (
            ((0, 0), (4, 0), (0, 3)),
            ((1, 0), (5, 0), (1, 4)),
        ):
            other = ConvexPolygonRegion(vertices)
            bad = ConvexPolygonBatchEntry(
                entry.x_commitment, entry.y_commitment, other, entry.proof,
                entry.context,
            )
            self.assertFalse(verify_convex_polygon_batch([bad]))

    def test_rotated_polygon_representation_still_verifies(self):
        entry = self._entry()
        rotated = ConvexPolygonRegion(
            tuple(entry.polygon.vertices[1:] + entry.polygon.vertices[:1])
        )
        equivalent = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, rotated, entry.proof,
            entry.context,
        )
        self.assertIs(verify_convex_polygon_batch([equivalent]), True)

    def test_tampered_subproofs_return_false(self):
        entry = self._entry()
        proof = entry.proof
        bad_x = RangeProof(
            proof.x_proof.t,
            tuple(e + 1 for e in proof.x_proof.e),
            proof.x_proof.s,
        )
        variants = (
            ConvexPolygonRegionProof(bad_x, proof.y_proof, proof.edge_proofs),
            ConvexPolygonRegionProof(
                proof.x_proof, proof.y_proof, proof.edge_proofs[:1]
                + proof.edge_proofs[2:]
            ),
            ConvexPolygonRegionProof(
                proof.x_proof, proof.y_proof,
                (
                    proof.edge_proofs[1],
                    proof.edge_proofs[0],
                    proof.edge_proofs[2],
                ),
            ),
        )
        for tampered in variants:
            bad = ConvexPolygonBatchEntry(
                entry.x_commitment, entry.y_commitment, entry.polygon,
                tampered, entry.context,
            )
            self.assertFalse(
                verify_convex_polygon_batch([bad], randbelow=DetRand())
            )

    def test_tampered_edge_commitment_binding_returns_false(self):
        entry = self._entry()
        edge = entry.proof.edge_proofs[0]
        bad_commitments = tuple(
            c + 1 if c < 100 else c - 1 for c in edge.commitments
        )
        bad_edge = WideRangeProof(
            bad_commitments, edge.challenges, edge.responses
        )
        tampered = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            (bad_edge,) + entry.proof.edge_proofs[1:],
        )
        bad = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            tampered, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([bad]))

    def test_forged_edge_proof_returns_false(self):
        entry = self._entry()
        edge = entry.proof.edge_proofs[0]
        forged_edge = WideRangeProof(
            commitments=tuple(5 for _ in edge.commitments),
            challenges=tuple((1, 2) for _ in edge.challenges),
            responses=tuple((3, 4) for _ in edge.responses),
        )
        forged = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            (forged_edge,) + entry.proof.edge_proofs[1:],
        )
        bad = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon,
            forged, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([bad]))

    def test_mismatched_group_parameters_return_false(self):
        entry = self._entry()
        other_prime = pedersen_commit(
            1, entry.polygon.min_x, entry.polygon.max_x, prime=2**61 - 1
        )[0]
        bad = ConvexPolygonBatchEntry(
            other_prime, entry.y_commitment, entry.polygon, entry.proof,
            entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([bad]))

    def test_one_invalid_entry_fails_the_whole_batch(self):
        good = self._entry(1, 1, context=b"a")
        bad = self._entry(2, 2, context=b"b")
        object.__setattr__(bad, "context", b"tampered")
        self.assertFalse(
            verify_convex_polygon_batch([good, bad], randbelow=DetRand())
        )
        self.assertFalse(
            verify_convex_polygon_batch([bad, good], randbelow=DetRand())
        )

    def test_forged_geometrically_invalid_polygon_returns_false(self):
        entry = self._entry()
        for vertices in (
            ((0, 0), (1, 1), (2, 2), (3, 3)),
            (),
        ):
            forged = object.__new__(ConvexPolygonRegion)
            object.__setattr__(forged, "vertices", vertices)
            bad = ConvexPolygonBatchEntry(
                entry.x_commitment, entry.y_commitment, forged, entry.proof,
                entry.context,
            )
            self.assertFalse(verify_convex_polygon_batch([bad]))

    # ---- type errors (whole-batch preflight) --------------------------------

    def test_entries_container_type_errors(self):
        entry = self._entry()
        for bad in ("entries", b"entries", bytearray(b"x"), 42, None, iter([entry])):
            with self.assertRaises(TypeError):
                verify_convex_polygon_batch(bad)

    def test_entry_and_nested_field_type_errors(self):
        entry = self._entry()

        def expect(bad):
            with self.assertRaises(TypeError):
                verify_convex_polygon_batch([entry, bad])

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
        # a bool masquerading as a commitment integer
        prime = entry.x_commitment.prime
        bool_commitment = PedersenCommitment(True, 0, 4, prime, 3, 9)
        expect(ConvexPolygonBatchEntry(
            bool_commitment, entry.y_commitment, entry.polygon, entry.proof,
            b"c",
        ))
        # a non-RangeProof x sub-proof
        bad_proof = ConvexPolygonRegionProof(
            "x", entry.proof.y_proof, entry.proof.edge_proofs
        )
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon, bad_proof,
            b"c",
        ))
        # edge_proofs that is a list rather than a tuple
        list_edges = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            list(entry.proof.edge_proofs),
        )
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon, list_edges,
            b"c",
        ))
        # a non-WideRangeProof edge entry
        int_edges = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof, (1, 2, 3)
        )
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon, int_edges,
            b"c",
        ))
        # a forged polygon whose vertices container has the wrong type
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", [(0, 0), (1, 0), (0, 1)])
        expect(ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, forged, entry.proof, b"c"
        ))

    def test_randbelow_type_error(self):
        entry = self._entry()
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([entry], randbelow=123)

    def test_coefficient_source_value_errors(self):
        entry = self._entry()
        prime = entry.x_commitment.prime
        for bad in (-1, prime - 1, prime):
            with self.assertRaises(ValueError):
                verify_convex_polygon_batch(
                    [entry], randbelow=lambda upper, bad=bad: bad
                )

    def test_coefficient_source_bool_return_is_type_error(self):
        entry = self._entry()
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([entry], randbelow=lambda upper: False)

    # ---- hygiene ------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = [self._entry(1, 1), self._entry(2, 2)]
        snapshot = [
            (
                entry.x_commitment.element,
                tuple(entry.proof.x_proof.e),
                entry.proof.edge_proofs[0].commitments,
            )
            for entry in entries
        ]
        original_order = list(entries)
        verify_convex_polygon_batch(entries, randbelow=DetRand())
        self.assertEqual(entries, original_order)
        self.assertEqual(
            [
                (
                    entry.x_commitment.element,
                    tuple(entry.proof.x_proof.e),
                    entry.proof.edge_proofs[0].commitments,
                )
                for entry in entries
            ],
            snapshot,
        )


def _frame_items(leaf: bytes) -> list:
    items = []
    offset = 0
    while offset < len(leaf):
        length = int.from_bytes(leaf[offset:offset + 4], "big")
        offset += 4
        items.append(leaf[offset:offset + length])
        offset += length
    return items


class BoundConvexPolygonBatchTest(unittest.TestCase):
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

    def build(self, entries):
        leaves = [_bound_convex_polygon_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundConvexPolygonBatch(tuple(entries), len(entries), proof)
        return batch, root

    def honest(self):
        pentagon = ((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))
        return self.build(
            [
                self._entry(1, 2, context=b"a"),
                self._entry(3, 0, context=b"b"),
                self._entry(0, 3, vertices=pentagon, context=b"c"),
            ]
        )

    # ---- batch object -------------------------------------------------------

    def test_batch_positional_equality_and_immutability(self):
        batch, root = self.honest()
        proof = batch.proof
        rebuilt = BoundConvexPolygonBatch(batch.entries, 3, proof)
        self.assertEqual(rebuilt, batch)
        self.assertEqual(hash(rebuilt), hash(batch))
        self.assertEqual(
            tuple(getattr(batch, name) for name in ("entries", "leaf_count", "proof")),
            (batch.entries, 3, proof),
        )
        self.assertIsInstance(batch.entries, tuple)
        self.assertNotEqual(
            BoundConvexPolygonBatch(batch.entries, 4, proof), batch
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 4
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.entries = ()

    def test_batch_construction_does_no_validation(self):
        batch = BoundConvexPolygonBatch(("x", "y"), True, "proof")
        self.assertEqual(
            (batch.entries, batch.leaf_count, batch.proof),
            (("x", "y"), True, "proof"),
        )

    def test_entries_must_be_tuple(self):
        batch, root = self.honest()
        loose = BoundConvexPolygonBatch(list(batch.entries), 3, batch.proof)
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(
                loose, root, randbelow=DetRand()
            )

    def test_field_types(self):
        batch, _ = self.honest()
        self.assertIsInstance(batch.entries, tuple)
        for entry in batch.entries:
            self.assertIsInstance(entry, ConvexPolygonBatchEntry)
        self.assertIsInstance(batch.leaf_count, int)
        self.assertNotIsInstance(batch.leaf_count, bool)
        self.assertIsInstance(batch.proof, MerkleMultiProof)

    # ---- honest round trip --------------------------------------------------

    def test_honest_batch_verifies(self):
        batch, root = self.honest()
        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )
        self.assertTrue(verify_convex_polygon_batch_bound(batch, root))

    def test_single_and_even_sized_batches_verify(self):
        only = [self._entry()]
        batch, root = self.build(only)
        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )
        pair = [
            self._entry(1, context=b"a"),
            self._entry(2, context=b"b"),
        ]
        ebatch, eroot = self.build(pair)
        self.assertTrue(
            verify_convex_polygon_batch_bound(ebatch, eroot, randbelow=DetRand())
        )

    def test_duplicate_entries_verify(self):
        entry = self._entry()
        batch, root = self.build([entry, entry, entry])
        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )

    def test_full_leaf_proof_has_empty_siblings(self):
        batch, _ = self.honest()
        self.assertEqual(batch.proof.leaf_count, 3)
        self.assertEqual(batch.proof.indices, (0, 1, 2))
        self.assertEqual(batch.proof.siblings, ())

    def test_leaf_layout(self):
        batch, _ = self.honest()
        entry = batch.entries[0]
        items = _frame_items(_bound_convex_polygon_leaf(entry))
        polygon = entry.polygon
        expected_count = 1 + 2 * 6 + 1 + 2 * len(polygon.vertices) + 1
        expected_count += sum(
            1 + len(getattr(sp, name))
            for sp in (entry.proof.x_proof, entry.proof.y_proof)
            for name in ("t", "e", "s")
        )
        expected_count += 1
        for edge_proof in entry.proof.edge_proofs:
            expected_count += (
                1
                + len(edge_proof.commitments)
                + 2
                + 2 * len(edge_proof.challenges)
                + 2 * len(edge_proof.responses)
            )
        self.assertEqual(len(items), expected_count)
        self.assertEqual(items[0], b"zkregion/convex-polygon-bound/v1")
        cursor = 1
        for commitment in (entry.x_commitment, entry.y_commitment):
            for value in (
                commitment.element,
                commitment.lower,
                commitment.upper,
                commitment.prime,
                commitment.generator,
                commitment.h,
            ):
                self.assertEqual(items[cursor], str(value).encode("ascii"))
                cursor += 1
        self.assertEqual(
            items[cursor], str(len(polygon.vertices)).encode("ascii")
        )
        cursor += 1
        for vertex in polygon.vertices:
            self.assertEqual(items[cursor], str(vertex[0]).encode("ascii"))
            self.assertEqual(items[cursor + 1], str(vertex[1]).encode("ascii"))
            cursor += 2
        self.assertEqual(items[cursor], entry.context)
        cursor += 1
        for sub_proof in (entry.proof.x_proof, entry.proof.y_proof):
            for name in ("t", "e", "s"):
                sequence = getattr(sub_proof, name)
                self.assertEqual(
                    items[cursor], str(len(sequence)).encode("ascii")
                )
                cursor += 1
                for value in sequence:
                    self.assertEqual(items[cursor], str(value).encode("ascii"))
                    cursor += 1
        self.assertEqual(
            items[cursor], str(len(entry.proof.edge_proofs)).encode("ascii")
        )
        cursor += 1
        for edge_proof in entry.proof.edge_proofs:
            self.assertEqual(
                items[cursor],
                str(len(edge_proof.commitments)).encode("ascii"),
            )
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

    def test_polygon_vertices_are_canonicalized_in_the_leaf(self):
        entry = self._entry()
        vertices = entry.polygon.vertices
        rotated = (vertices[1],) + vertices[2:] + (vertices[0],)
        reordered = ConvexPolygonRegion(rotated)
        self.assertEqual(reordered, entry.polygon)
        same_region = dataclasses.replace(entry, polygon=reordered)
        self.assertEqual(
            _bound_convex_polygon_leaf(same_region),
            _bound_convex_polygon_leaf(entry),
        )

    def test_negative_ints_keep_their_sign(self):
        pentagon = ((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))
        entry = self._entry(vertices=pentagon)
        items = _frame_items(_bound_convex_polygon_leaf(entry))
        self.assertIn(b"-2", items)

    def test_empty_context_is_framed_as_zero_length(self):
        entry = self._entry(context=b"")
        items = _frame_items(_bound_convex_polygon_leaf(entry))
        # domain, twelve commitment items, vertex count and 2*V coordinates
        position = 1 + 12 + 1 + 2 * len(entry.polygon.vertices)
        self.assertEqual(items[position], b"")

    def test_leaf_uses_merkle_leaf_domain(self):
        batch, root = self.honest()
        self.assertEqual(
            merkle_root(
                [_bound_convex_polygon_leaf(entry) for entry in batch.entries]
            ),
            root,
        )

    # ---- completeness / count checks ---------------------------------------

    def test_empty_batch_returns_false_without_drawing(self):
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        batch = BoundConvexPolygonBatch((), 0, MerkleMultiProof(0, (), ()))
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                batch, bytes(32), randbelow=recording
            )
        )
        self.assertEqual(calls, [])

    def test_leaf_count_must_equal_entry_and_proof_counts(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        proof = batch.proof
        for count in (1, 3, 0):
            bad = BoundConvexPolygonBatch(tuple(entries), count, proof)
            self.assertFalse(
                verify_convex_polygon_batch_bound(
                    bad, root, randbelow=DetRand()
                ),
                count,
            )
        bad_proof = dataclasses.replace(proof, leaf_count=3)
        bad = BoundConvexPolygonBatch(tuple(entries), 2, bad_proof)
        self.assertFalse(
            verify_convex_polygon_batch_bound(bad, root, randbelow=DetRand())
        )

    def test_indices_must_cover_zero_to_n_without_gaps(self):
        batch, root = self.honest()
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
        proof = MerkleMultiProof(3, (0, 1, 2), ())
        batch = BoundConvexPolygonBatch(tuple(entries), 3, proof)
        self.assertFalse(
            verify_convex_polygon_batch_bound(batch, bytes(32), randbelow=DetRand())
        )

    # ---- Merkle binding rejection -------------------------------------------

    def test_wrong_root_returns_false(self):
        batch, _ = self.honest()
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                batch, bytes(32), randbelow=DetRand()
            )
        )
        other = merkle_root([b"alpha", b"beta", b"gamma"])
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                batch, other, randbelow=DetRand()
            )
        )

    def test_root_of_a_prefix_does_not_verify(self):
        batch, _ = self.honest()
        prefix_root = merkle_root(
            [_bound_convex_polygon_leaf(batch.entries[0])]
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                batch, prefix_root, randbelow=DetRand()
            )
        )

    def test_reordered_entries_return_false(self):
        batch, root = self.honest()
        reordered = BoundConvexPolygonBatch(
            (batch.entries[2], batch.entries[0], batch.entries[1]),
            3,
            batch.proof,
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                reordered, root, randbelow=DetRand()
            )
        )

    def test_replaced_entry_returns_false(self):
        batch, root = self.honest()
        replacement = self._entry(0, 0, context=b"a")
        replaced = BoundConvexPolygonBatch(
            (replacement,) + batch.entries[1:], 3, batch.proof
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                replaced, root, randbelow=DetRand()
            )
        )

    def test_tampered_leaf_returns_false_even_with_matching_proof(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        good = entries[0]
        tampered_commitment = dataclasses.replace(
            good.x_commitment, element=good.x_commitment.element + 1
        )
        tampered_polygon = ConvexPolygonRegion(
            tuple(
                (x + 1 if vertex_index == 1 else x, y)
                for vertex_index, (x, y) in enumerate(good.polygon.vertices)
            )
        )
        tampered_share = good.proof.x_proof.e[:-1] + (good.proof.x_proof.e[-1] + 1,)
        edge_proofs = good.proof.edge_proofs
        tampered_edge = dataclasses.replace(
            edge_proofs[0],
            commitments=edge_proofs[0].commitments[:-1]
            + ((edge_proofs[0].commitments[-1] + 1) % good.x_commitment.prime,),
        )
        for tampered in (
            dataclasses.replace(good, context=b"other"),
            dataclasses.replace(good, x_commitment=tampered_commitment),
            dataclasses.replace(good, polygon=tampered_polygon),
            dataclasses.replace(
                good,
                proof=ConvexPolygonRegionProof(
                    dataclasses.replace(good.proof.x_proof, e=tampered_share),
                    good.proof.y_proof,
                    good.proof.edge_proofs,
                ),
            ),
            dataclasses.replace(
                good,
                proof=ConvexPolygonRegionProof(
                    good.proof.x_proof,
                    good.proof.y_proof,
                    (tampered_edge,) + edge_proofs[1:],
                ),
            ),
        ):
            bad_batch = BoundConvexPolygonBatch(
                (tampered, entries[1]), 2, batch.proof
            )
            self.assertFalse(
                verify_convex_polygon_batch_bound(
                    bad_batch, root, randbelow=DetRand()
                ),
                tampered,
            )

    def test_committed_but_forged_proof_fails_at_inner_batch_step(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        good = entries[0]
        proof = good.proof
        last_s = proof.x_proof.s[-1]
        forged_entries = [
            dataclasses.replace(
                good,
                proof=ConvexPolygonRegionProof(
                    dataclasses.replace(
                        proof.x_proof,
                        s=proof.x_proof.s[:-1] + (last_s + 1,),
                    ),
                    proof.y_proof,
                    proof.edge_proofs,
                ),
            ),
            entries[1],
        ]
        bad_batch, forged_root = self.build(forged_entries)
        # The outer root alone still verifies the committed (forged) leaf.
        self.assertTrue(
            verify_multi_inclusion(
                [
                    (i, _bound_convex_polygon_leaf(entry))
                    for i, entry in enumerate(forged_entries)
                ],
                bad_batch.proof,
                forged_root,
            )
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, forged_root, randbelow=DetRand()
            )
        )

    def test_dropped_edge_proof_returns_false(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        good = entries[0]
        dropped = ConvexPolygonRegionProof(
            good.proof.x_proof,
            good.proof.y_proof,
            good.proof.edge_proofs[1:],
        )
        bad_batch = BoundConvexPolygonBatch(
            (dataclasses.replace(good, proof=dropped), entries[1]),
            2,
            batch.proof,
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, root, randbelow=DetRand()
            )
        )

    def test_mismatched_group_parameters_return_false(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        good = entries[0]
        other_prime, _ = pedersen_commit(
            1, good.polygon.min_x, good.polygon.max_x, prime=2**61 - 1
        )
        bad_batch = BoundConvexPolygonBatch(
            (dataclasses.replace(good, x_commitment=other_prime), entries[1]),
            2,
            batch.proof,
        )
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, root, randbelow=DetRand()
            )
        )

    def test_tampered_siblings_return_false(self):
        batch, root = self.honest()
        bogus = MerkleMultiProof(3, batch.proof.indices, (root,))
        bad_batch = BoundConvexPolygonBatch(batch.entries, 3, bogus)
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, root, randbelow=DetRand()
            )
        )

    def test_forged_geometrically_invalid_polygon_returns_false(self):
        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        batch, root = self.build(entries)
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ((0, 0), (1, 1), (2, 2), (3, 3)))
        bad_entries = (
            dataclasses.replace(entries[0], polygon=forged),
            entries[1],
        )
        bad_batch = BoundConvexPolygonBatch(bad_entries, 2, batch.proof)
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, root, randbelow=DetRand()
            )
        )

    # ---- root-first randomness contract --------------------------------------

    def test_randbelow_passed_unchanged_and_called_per_subbranch(self):
        batch, root = self.honest()
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=recording)
        )
        expected = []
        for entry in batch.entries:
            expected.extend(
                [entry.x_commitment.prime - 1]
                * self._expected_branch_count(entry)
            )
        self.assertEqual(calls, expected)

    def test_no_randomness_consumed_before_the_root_check(self):
        batch, _ = self.honest()

        def boom(upper):
            raise AssertionError("randbelow must not be called before the root checks")

        self.assertFalse(
            verify_convex_polygon_batch_bound(
                batch, bytes(32), randbelow=boom
            )
        )
        bad_proof = MerkleMultiProof(3, (0, 1), batch.proof.siblings)
        bad_batch = BoundConvexPolygonBatch(batch.entries, 3, bad_proof)
        self.assertFalse(
            verify_convex_polygon_batch_bound(
                bad_batch, bytes(32), randbelow=boom
            )
        )

    def test_non_random_source_invalidates_or_raises_per_batch_contract(self):
        batch, root = self.honest()
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_convex_polygon_batch_bound(
                    batch, root, randbelow=lambda upper, bad=bad: bad
                )
        prime = batch.entries[0].x_commitment.prime
        for bad in (-1, prime - 1, prime):
            with self.assertRaises(ValueError):
                verify_convex_polygon_batch_bound(
                    batch, root, randbelow=lambda upper, bad=bad: bad
                )

    # ---- type errors ---------------------------------------------------------

    def test_type_errors(self):
        batch, root = self.honest()
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
                BoundConvexPolygonBatch(batch.entries, 3, "proof"), root
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(batch, "root")
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(batch, bytearray(root))
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch_bound(batch, root, randbelow=7)
        good = batch.entries[0]
        cases = [
            dataclasses.replace(good, x_commitment="c"),
            dataclasses.replace(good, y_commitment="c"),
            dataclasses.replace(
                good,
                x_commitment=dataclasses.replace(good.x_commitment, element=True),
            ),
            dataclasses.replace(good, polygon="r"),
            dataclasses.replace(good, context="c"),
            dataclasses.replace(good, proof="p"),
            dataclasses.replace(
                good,
                proof=ConvexPolygonRegionProof(
                    RangeProof(
                        list(good.proof.x_proof.t),
                        good.proof.x_proof.e,
                        good.proof.x_proof.s,
                    ),
                    good.proof.y_proof,
                    good.proof.edge_proofs,
                ),
            ),
            dataclasses.replace(
                good,
                proof=ConvexPolygonRegionProof(
                    RangeProof(
                        good.proof.x_proof.t[:-1] + (True,),
                        good.proof.x_proof.e,
                        good.proof.x_proof.s,
                    ),
                    good.proof.y_proof,
                    good.proof.edge_proofs,
                ),
            ),
            dataclasses.replace(
                good,
                proof=ConvexPolygonRegionProof(
                    good.proof.x_proof,
                    good.proof.y_proof,
                    tuple(
                        [
                            WideRangeProof(
                                list(edge.commitments),
                                edge.challenges,
                                edge.responses,
                            )
                            for edge in good.proof.edge_proofs
                        ]
                    ),
                ),
            ),
        ]
        for bad_entry in cases:
            bad_batch = BoundConvexPolygonBatch(
                (bad_entry,) + batch.entries[1:], 3, batch.proof
            )
            with self.assertRaises(TypeError):
                verify_convex_polygon_batch_bound(bad_batch, root)

    # ---- hygiene ------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = [self._entry(1, 1), self._entry(2, 2)]
        snapshot = [
            (
                entry.x_commitment.element,
                tuple(entry.proof.x_proof.e),
                entry.proof.edge_proofs[0].commitments,
            )
            for entry in entries
        ]
        batch, root = self.build(entries)
        verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        self.assertEqual(
            [
                (
                    entry.x_commitment.element,
                    tuple(entry.proof.x_proof.e),
                    entry.proof.edge_proofs[0].commitments,
                )
                for entry in entries
            ],
            snapshot,
        )


class ProveConvexPolygonBatchBoundTest(unittest.TestCase):
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

    def honest_entries(self):
        pentagon = ((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))
        return [
            self._entry(1, 2, context=b"a"),
            self._entry(3, 0, context=b"b"),
            self._entry(0, 3, vertices=pentagon, context=b"c"),
        ]

    # ---- round trip ----------------------------------------------------------

    def test_constructed_batch_passes_verify_once(self):
        entries = self.honest_entries()
        batch, root = prove_convex_polygon_batch_bound(
            entries, randbelow=DetRand()
        )
        self.assertIsInstance(batch, BoundConvexPolygonBatch)
        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )
        self.assertTrue(verify_convex_polygon_batch_bound(batch, root))

    def test_single_item_even_and_duplicates(self):
        only = [self._entry()]
        batch, root = prove_convex_polygon_batch_bound(
            only, randbelow=DetRand()
        )
        self.assertEqual(batch.leaf_count, 1)
        self.assertEqual(batch.entries, tuple(only))
        self.assertTrue(
            verify_convex_polygon_batch_bound(batch, root, randbelow=DetRand())
        )

        pair = [self._entry(1), self._entry(2)]
        ebatch, eroot = prove_convex_polygon_batch_bound(
            pair, randbelow=DetRand()
        )
        self.assertEqual(ebatch.leaf_count, 2)
        self.assertTrue(
            verify_convex_polygon_batch_bound(ebatch, eroot, randbelow=DetRand())
        )

        dup = [only[0], only[0], only[0]]
        dbatch, droot = prove_convex_polygon_batch_bound(
            dup, randbelow=DetRand()
        )
        self.assertEqual(dbatch.leaf_count, 3)
        self.assertEqual(dbatch.entries, (only[0], only[0], only[0]))
        self.assertTrue(
            verify_convex_polygon_batch_bound(dbatch, droot, randbelow=DetRand())
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
            reordered, randbelow=DetRand()
        )
        self.assertEqual(batch.entries, tuple(reordered))

    # ---- determinism ---------------------------------------------------------

    def test_equals_manual_construction_byte_for_byte(self):
        entries = self.honest_entries()
        batch, root = prove_convex_polygon_batch_bound(
            entries, randbelow=DetRand()
        )
        leaves = [_bound_convex_polygon_leaf(entry) for entry in entries]
        manual_root = merkle_root(leaves)
        manual_proof = prove_multi_inclusion(
            leaves, tuple(range(len(entries)))
        )
        manual_batch = BoundConvexPolygonBatch(
            tuple(entries), len(entries), manual_proof
        )
        self.assertEqual(root, manual_root)
        self.assertEqual(batch, manual_batch)
        self.assertEqual(
            dataclasses.asdict(batch), dataclasses.asdict(manual_batch)
        )

    def test_repeated_construction_is_byte_identical(self):
        entries = self.honest_entries()
        batch, root = prove_convex_polygon_batch_bound(
            entries, randbelow=DetRand()
        )
        batch2, root2 = prove_convex_polygon_batch_bound(
            list(entries), randbelow=DetRand()
        )
        self.assertEqual(batch, batch2)
        self.assertEqual(root, root2)
        self.assertEqual(batch.proof, batch2.proof)

    # ---- input hygiene -------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = self.honest_entries()
        snapshot = [dataclasses.replace(entry) for entry in entries]
        original_order = list(entries)
        prove_convex_polygon_batch_bound(entries, randbelow=DetRand())
        self.assertEqual(entries, snapshot)
        self.assertEqual(entries, original_order)
        self.assertIsInstance(entries, list)

    def test_returns_two_values(self):
        result = prove_convex_polygon_batch_bound(
            self.honest_entries(), randbelow=DetRand()
        )
        self.assertEqual(len(result), 2)

    # ---- rejections ----------------------------------------------------------

    def test_empty_batch_raises_value_error(self):
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound([], randbelow=DetRand())
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound((), randbelow=DetRand())

    def test_length_outside_uint64_raises_value_error(self):
        import zkregion

        entries = [self._entry(context=b"a"), self._entry(context=b"b")]
        original = zkregion._UINT64_MAX
        zkregion._UINT64_MAX = 1
        try:
            with self.assertRaises(ValueError):
                prove_convex_polygon_batch_bound(entries, randbelow=DetRand())
        finally:
            zkregion._UINT64_MAX = original

    def test_type_errors(self):
        good = self.honest_entries()
        for bad in (b"abc", "abc", 123, None, {good[0]}, 4.5):
            with self.assertRaises(TypeError):
                prove_convex_polygon_batch_bound(bad, randbelow=DetRand())
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(iter(good), randbelow=DetRand())
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(
                [good[0], 1], randbelow=DetRand()
            )
        proof = good[0].proof
        cases = [
            ConvexPolygonBatchEntry(
                "c", good[0].y_commitment, good[0].polygon, proof, b""
            ),
            ConvexPolygonBatchEntry(
                good[0].x_commitment,
                dataclasses.replace(good[0].y_commitment, element=True),
                good[0].polygon,
                proof,
                b"",
            ),
            ConvexPolygonBatchEntry(
                good[0].x_commitment, good[0].y_commitment, "r", proof, b""
            ),
            ConvexPolygonBatchEntry(
                good[0].x_commitment,
                good[0].y_commitment,
                good[0].polygon,
                proof,
                "c",
            ),
            ConvexPolygonBatchEntry(
                good[0].x_commitment,
                good[0].y_commitment,
                good[0].polygon,
                "p",
                b"",
            ),
            ConvexPolygonBatchEntry(
                good[0].x_commitment,
                good[0].y_commitment,
                good[0].polygon,
                ConvexPolygonRegionProof(
                    RangeProof(
                        list(proof.x_proof.t), proof.x_proof.e, proof.x_proof.s
                    ),
                    proof.y_proof,
                    proof.edge_proofs,
                ),
                b"",
            ),
            ConvexPolygonBatchEntry(
                good[0].x_commitment,
                good[0].y_commitment,
                good[0].polygon,
                ConvexPolygonRegionProof(
                    RangeProof(
                        proof.x_proof.t,
                        proof.x_proof.e[:-1] + (True,),
                        proof.x_proof.s,
                    ),
                    proof.y_proof,
                    proof.edge_proofs,
                ),
                b"",
            ),
        ]
        for bad_entry in cases:
            with self.assertRaises(TypeError):
                prove_convex_polygon_batch_bound(
                    [bad_entry], randbelow=DetRand()
                )
            with self.assertRaises(TypeError):
                prove_convex_polygon_batch_bound(
                    [good[1], bad_entry], randbelow=DetRand()
                )

    def test_non_callable_randbelow_raises_type_error(self):
        entries = self.honest_entries()
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(entries, randbelow=7)
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(b"x", randbelow=7)

    def test_inner_batch_failure_raises_value_error(self):
        good = self.honest_entries()
        proof = good[0].proof
        last_s = proof.x_proof.s[-1]
        tampered = dataclasses.replace(
            good[0],
            proof=ConvexPolygonRegionProof(
                dataclasses.replace(
                    proof.x_proof,
                    s=proof.x_proof.s[:-1] + (last_s + 1,),
                ),
                proof.y_proof,
                proof.edge_proofs,
            ),
        )
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound(
                [tampered], randbelow=DetRand()
            )

    def test_randbelow_return_type_and_range_contract(self):
        entries = self.honest_entries()
        with self.assertRaises(TypeError):
            prove_convex_polygon_batch_bound(
                entries, randbelow=lambda _: "x"
            )
        with self.assertRaises(ValueError):
            prove_convex_polygon_batch_bound(
                entries, randbelow=lambda _: DEFAULT_PRIME
            )


class ConvexPolygonBatchReplayGuardTest(unittest.TestCase):
    """Single-use replay bindings for convex polygon proof batches."""

    DOMAIN = b"zr/cpbr/v1"
    PENTAGON = ((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "cpbr.db")

    def tearDown(self):
        self._tmp.cleanup()

    def _entry(self, x=1, y=2, vertices=TRIANGLE, context=b"ctx"):
        polygon = ConvexPolygonRegion(vertices)
        x_commitment, x_blinding = pedersen_commit(
            x, polygon.min_x, polygon.max_x
        )
        y_commitment, y_blinding = pedersen_commit(
            y, polygon.min_y, polygon.max_y
        )
        proof = prove_convex_polygon(
            x_commitment, y_commitment, x, y, x_blinding, y_blinding,
            polygon, context, randbelow=DetRand(),
        )
        return ConvexPolygonBatchEntry(
            x_commitment, y_commitment, polygon, proof, context
        )

    def honest_entries(self):
        """Distinct entries plus a preserved duplicate, in batch order."""
        first = self._entry(1, 2, context=b"a")
        second = self._entry(0, 3, vertices=self.PENTAGON, context=b"b")
        return [first, second, first]

    def make_store(self, *args, **kwargs):
        return SQLiteReplayStore(self.path, *args, **kwargs)

    @staticmethod
    def expected_digest(entries, session_id, expires_at=None):
        def F(item):
            return len(item).to_bytes(4, "big") + item

        def U(value):
            return value.to_bytes(8, "big")

        def S(sequence, transform):
            return F(U(len(sequence))) + b"".join(
                F(transform(item)) for item in sequence
            )

        expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
        material = (
            F(b"zr/cpbr/v1") + F(session_id)
            + S(entries, _bound_convex_polygon_leaf) + F(expiry)
        )
        return hashlib.sha256(material).digest()

    # ---- binding / digest wire format ---------------------------------------

    def test_bind_once_returns_spec_digest(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s1")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"s1")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(len(binding.digest), 32)
        self.assertEqual(binding.digest, self.expected_digest(entries, b"s1"))
        binding = guard.bind_once(entries, b"s2", expires_at=1000)
        self.assertEqual(binding.expires_at, 1000)
        self.assertEqual(
            binding.digest, self.expected_digest(entries, b"s2", 1000)
        )

    # ---- register, check, consume (in-memory) -------------------------------

    def test_check_accepts_then_consumes(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s")
        self.assertTrue(guard.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertFalse(guard.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertEqual(guard._consumed, {b"s"})
        self.assertNotIn(b"s", guard._pending)

    def test_pending_and_consumed_ids_cannot_be_rebound(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s")
        with self.assertRaises(ValueError):  # still pending
            guard.bind_once(entries, b"s")
        self.assertTrue(guard.check(entries, binding, now=1, randbelow=DetRand()))
        with self.assertRaises(ValueError):  # already consumed
            guard.bind_once(entries, b"s")

    def test_inputs_are_not_mutated(self):
        entries = self.honest_entries()
        snapshots = [dataclasses.replace(entry) for entry in entries]
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s")
        binding_snapshot = dataclasses.replace(binding)
        self.assertTrue(guard.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertEqual(entries, snapshots)
        self.assertEqual(binding, binding_snapshot)

    # ---- rejection is not consumption ---------------------------------------

    def test_rejection_does_not_consume_registration(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s")
        changed_context = dataclasses.replace(entries[1], context=b"other")
        wrong_batches = (
            [entries[0], changed_context, entries[2]],  # altered context
            [entries[1], entries[0], entries[2]],  # swapped distinct entries
            entries[:-1],  # dropped duplicate
        )
        for wrong in wrong_batches:
            self.assertFalse(
                guard.check(wrong, binding, now=1, randbelow=DetRand())
            )
        self.assertIn(b"s", guard._pending)
        # the original batch is still accepted, exactly once
        self.assertTrue(guard.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertFalse(guard.check(entries, binding, now=1, randbelow=DetRand()))

    def test_rotated_and_reversed_polygons_are_not_rejected(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s")
        rotated = dataclasses.replace(
            entries[0], polygon=ConvexPolygonRegion(((0, 4), (4, 0), (0, 0)))
        )
        reversed_ = dataclasses.replace(
            entries[0], polygon=ConvexPolygonRegion(((0, 0), (0, 4), (4, 0)))
        )
        # canonicalization makes the representations value-equal
        self.assertEqual(rotated, entries[0])
        self.assertEqual(reversed_, entries[0])
        presented = [rotated, entries[1], reversed_]
        self.assertTrue(
            guard.check(presented, binding, now=1, randbelow=DetRand())
        )

    def test_unregistered_equal_binding_is_rejected(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = ConvexPolygonBatchReplayGuard().bind_once(entries, b"s")
        self.assertFalse(guard.check(entries, binding, now=1, randbelow=DetRand()))
        clone = ReplayBinding(binding.session_id, binding.digest, binding.expires_at)
        self.assertEqual(clone, binding)
        self.assertFalse(guard.check(entries, clone, now=1, randbelow=DetRand()))

    def test_expiry_boundary_rejects_without_consuming(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s", expires_at=1000)
        self.assertFalse(
            guard.check(entries, binding, now=1000, randbelow=DetRand())
        )
        self.assertIn(b"s", guard._pending)
        # the rejection did not consume the registration: an earlier
        # explicit timestamp still verifies and consumes exactly once
        self.assertTrue(
            guard.check(entries, binding, now=999, randbelow=DetRand())
        )
        self.assertFalse(
            guard.check(entries, binding, now=999, randbelow=DetRand())
        )

    def test_randbelow_errors_release_the_claim(self):
        entries = self.honest_entries()
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s")
        with self.assertRaises(TypeError):
            guard.check(entries, binding, now=1, randbelow=lambda upper: "x")
        with self.assertRaises(ValueError):
            guard.check(entries, binding, now=1, randbelow=lambda upper: -1)
        self.assertIn(b"s", guard._pending)
        self.assertTrue(guard.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertFalse(guard.check(entries, binding, now=1, randbelow=DetRand()))

    def test_tampered_proof_batch_binds_but_never_checks(self):
        entries = self.honest_entries()
        proof = entries[0].proof
        last_s = proof.x_proof.s[-1]
        tampered = dataclasses.replace(
            entries[0],
            proof=ConvexPolygonRegionProof(
                dataclasses.replace(
                    proof.x_proof, s=proof.x_proof.s[:-1] + (last_s + 1,)
                ),
                proof.y_proof,
                proof.edge_proofs,
            ),
        )
        bad = [tampered] + entries[1:]
        guard = ConvexPolygonBatchReplayGuard()
        # registration commits to the batch bytes; it does not verify proofs
        binding = guard.bind_once(bad, b"s")
        self.assertFalse(guard.check(bad, binding, now=1, randbelow=DetRand()))
        self.assertFalse(guard.check(bad, binding, now=1, randbelow=DetRand()))
        with self.assertRaises(ValueError):  # still pending, never consumed
            guard.bind_once(bad, b"s")

    # ---- concurrency (in-memory) ---------------------------------------------

    def test_concurrent_checks_have_exactly_one_winner(self):
        entries = self.honest_entries()
        for _ in range(5):  # the outcome does not depend on scheduling
            guard = ConvexPolygonBatchReplayGuard()
            binding = guard.bind_once(entries, b"s")
            barrier = threading.Barrier(8)
            results = []
            lock = threading.Lock()

            def attempt():
                barrier.wait()
                won = guard.check(entries, binding, now=1, randbelow=DetRand())
                with lock:
                    results.append(won)

            threads = [threading.Thread(target=attempt) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sum(results), 1)
            self.assertEqual(results.count(False), 7)

    def test_other_session_completes_while_one_check_is_in_flight(self):
        entries = self.honest_entries()
        other_entries = [self._entry(3, 0, context=b"c")]
        guard = ConvexPolygonBatchReplayGuard()
        binding = guard.bind_once(entries, b"s1")
        entered = threading.Event()
        release = threading.Event()

        def blocking_randbelow(upper):
            entered.set()
            release.wait(5)
            return 0

        outcome = []

        def slow_check():
            outcome.append(
                guard.check(entries, binding, now=1, randbelow=blocking_randbelow)
            )

        thread = threading.Thread(target=slow_check)
        thread.start()
        try:
            self.assertTrue(entered.wait(5))  # s1 claimed, verification blocked
            # another session registers and checks without waiting for s1
            other = guard.bind_once(other_entries, b"s2")
            self.assertTrue(
                guard.check(other_entries, other, now=1, randbelow=DetRand())
            )
        finally:
            release.set()
        thread.join(5)
        self.assertEqual(outcome, [True])
        self.assertFalse(guard.check(entries, binding, now=1, randbelow=DetRand()))

    def test_in_memory_guards_do_not_share_registrations(self):
        entries = self.honest_entries()
        first = ConvexPolygonBatchReplayGuard()
        second = ConvexPolygonBatchReplayGuard()
        binding = first.bind_once(entries, b"s")
        self.assertFalse(
            second.check(entries, binding, now=1, randbelow=DetRand())
        )
        other = second.bind_once(entries, b"s")  # the id is free on second
        self.assertEqual(other, binding)
        self.assertTrue(first.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertTrue(second.check(entries, other, now=1, randbelow=DetRand()))

    # ---- SQLite backend -------------------------------------------------------

    def test_store_check_accepts_then_consumes(self):
        entries = self.honest_entries()
        store = self.make_store()
        guard = ConvexPolygonBatchReplayGuard(store=store)
        binding = guard.bind_once(entries, b"s")
        with self.assertRaises(ValueError):  # pending id cannot be rebound
            guard.bind_once(entries, b"s")
        self.assertTrue(guard.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertFalse(guard.check(entries, binding, now=1, randbelow=DetRand()))
        with self.assertRaises(ValueError):  # consumed id cannot be rebound
            guard.bind_once(entries, b"s")
        store.close()

    def test_store_connections_share_registration_and_consumption(self):
        entries = self.honest_entries()
        first_store = self.make_store()
        second_store = self.make_store()
        binding = ConvexPolygonBatchReplayGuard(store=first_store).bind_once(
            entries, b"s"
        )
        checker = ConvexPolygonBatchReplayGuard(store=second_store)
        self.assertTrue(checker.check(entries, binding, now=1, randbelow=DetRand()))
        self.assertFalse(
            ConvexPolygonBatchReplayGuard(store=first_store).check(
                entries, binding, now=1, randbelow=DetRand()
            )
        )
        with self.assertRaises(ValueError):
            checker.bind_once(entries, b"s")
        first_store.close()
        second_store.close()

    def test_store_state_survives_reopen(self):
        entries = self.honest_entries()
        single = [entries[0]]
        store = self.make_store()
        guard = ConvexPolygonBatchReplayGuard(store=store)
        pending = guard.bind_once(entries, b"pending")
        consumed = guard.bind_once(single, b"consumed")
        self.assertTrue(guard.check(single, consumed, now=1, randbelow=DetRand()))
        store.close()
        reopened = self.make_store()
        guard = ConvexPolygonBatchReplayGuard(store=reopened)
        with self.assertRaises(ValueError):
            guard.bind_once(single, b"consumed")
        self.assertFalse(guard.check(single, consumed, now=1, randbelow=DetRand()))
        self.assertTrue(guard.check(entries, pending, now=1, randbelow=DetRand()))
        reopened.close()
        reopened_again = self.make_store()
        guard = ConvexPolygonBatchReplayGuard(store=reopened_again)
        self.assertEqual(guard._consumed, {b"consumed", b"pending"})
        reopened_again.close()

    def test_store_namespaces_are_isolated(self):
        entries = self.honest_entries()
        store_a = self.make_store(namespace=b"a")
        store_b = self.make_store(namespace=b"b")
        binding_a = ConvexPolygonBatchReplayGuard(store=store_a).bind_once(
            entries, b"s"
        )
        guard_b = ConvexPolygonBatchReplayGuard(store=store_b)
        self.assertFalse(
            guard_b.check(entries, binding_a, now=1, randbelow=DetRand())
        )
        binding_b = guard_b.bind_once(entries, b"s")  # same id, other namespace
        self.assertTrue(
            guard_b.check(entries, binding_b, now=1, randbelow=DetRand())
        )
        self.assertTrue(
            ConvexPolygonBatchReplayGuard(store=store_a).check(
                entries, binding_a, now=1, randbelow=DetRand()
            )
        )
        store_a.close()
        store_b.close()

    def test_store_randbelow_errors_release_the_claim(self):
        entries = self.honest_entries()
        store = self.make_store()
        guard = ConvexPolygonBatchReplayGuard(store=store)
        binding = guard.bind_once(entries, b"s")
        with self.assertRaises(TypeError):
            guard.check(entries, binding, now=1, randbelow=lambda upper: "x")
        with self.assertRaises(ValueError):
            guard.check(entries, binding, now=1, randbelow=lambda upper: -1)
        self.assertIn(b"s", guard._pending)
        self.assertTrue(guard.check(entries, binding, now=1, randbelow=DetRand()))
        store.close()

    def test_store_concurrent_checks_have_exactly_one_winner(self):
        entries = self.honest_entries()
        store = self.make_store(lease_seconds=1000, clock=lambda: 1000)
        for round_ in range(3):  # the outcome does not depend on scheduling
            session_id = f"s{round_}".encode()
            binding = ConvexPolygonBatchReplayGuard(store=store).bind_once(
                entries, session_id
            )
            barrier = threading.Barrier(8)
            results = []
            lock = threading.Lock()

            def attempt():
                barrier.wait()
                won = ConvexPolygonBatchReplayGuard(store=store).check(
                    entries, binding, now=1, randbelow=DetRand()
                )
                with lock:
                    results.append(won)

            threads = [threading.Thread(target=attempt) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sum(results), 1)
            self.assertEqual(results.count(False), 7)
        store.close()

    def test_store_other_session_completes_while_one_check_is_in_flight(self):
        entries = self.honest_entries()
        other_entries = [self._entry(3, 0, context=b"c")]
        store = self.make_store(lease_seconds=1000, clock=lambda: 1000)
        first_guard = ConvexPolygonBatchReplayGuard(store=store)
        second_guard = ConvexPolygonBatchReplayGuard(store=store)
        binding = first_guard.bind_once(entries, b"s1")
        entered = threading.Event()
        release = threading.Event()

        def blocking_randbelow(upper):
            entered.set()
            release.wait(5)
            return 0

        outcome = []

        def slow_check():
            outcome.append(
                first_guard.check(
                    entries, binding, now=1, randbelow=blocking_randbelow
                )
            )

        thread = threading.Thread(target=slow_check)
        thread.start()
        try:
            self.assertTrue(entered.wait(5))  # s1 claimed, verification blocked
            other = second_guard.bind_once(other_entries, b"s2")
            self.assertTrue(
                second_guard.check(
                    other_entries, other, now=1, randbelow=DetRand()
                )
            )
        finally:
            release.set()
        thread.join(5)
        self.assertEqual(outcome, [True])
        self.assertFalse(
            second_guard.check(entries, binding, now=1, randbelow=DetRand())
        )
        store.close()


if __name__ == "__main__":
    unittest.main()
