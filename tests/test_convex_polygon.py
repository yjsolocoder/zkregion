import unittest

from zkregion import (
    ConvexPolygonBatchEntry,
    ConvexPolygonProofBundle,
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    DEFAULT_PRIME,
    PedersenCommitment,
    RangeProof,
    WideRangeProof,
    decode_convex_polygon_proof_bundle,
    encode_convex_polygon_proof_bundle,
    pedersen_commit,
    prove_convex_polygon,
    verify_convex_polygon,
    verify_convex_polygon_batch,
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


ASYMMETRIC = ((0, 0), (5, 0), (0, 3))
QUAD = ((0, 0), (3, 0), (3, 3), (0, 3))


def polygon_entry(vertices, x, y, context=b"", seed=1):
    """Build a valid ConvexPolygonBatchEntry for (x, y) in the polygon."""
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
    return ConvexPolygonBatchEntry(cx, cy, polygon, proof, context)


class CountingRand:
    """Deterministic randbelow recording every requested upper bound."""

    def __init__(self, value=0):
        self.value = value
        self.uppers = []

    def __call__(self, upper):
        self.uppers.append(upper)
        return self.value % upper if upper else self.value


class ConvexPolygonBatchEntryTests(unittest.TestCase):
    def test_fields_follow_verify_convex_polygon_order(self):
        entry = polygon_entry(TRIANGLE, 1, 1, b"ctx")
        self.assertEqual(
            (entry.x_commitment, entry.y_commitment, entry.polygon,
             entry.proof, entry.context),
            (entry.x_commitment, entry.y_commitment, entry.polygon,
             entry.proof, b"ctx"),
        )
        default = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.polygon, entry.proof
        )
        self.assertEqual(default.context, b"")

    def test_immutable(self):
        entry = polygon_entry(TRIANGLE, 1, 1)
        with self.assertRaises(Exception):
            entry.context = b"other"
        with self.assertRaises(Exception):
            entry.proof = None


class VerifyConvexPolygonBatchTests(unittest.TestCase):
    def entries(self):
        return [
            polygon_entry(TRIANGLE, 1, 1, b"ctx", seed=10),
            polygon_entry(ASYMMETRIC, 2, 1, seed=20),
            polygon_entry(QUAD, 2, 2, b"quad", seed=30),
        ]

    def test_valid_batch_verifies(self):
        entries = self.entries()
        self.assertTrue(verify_convex_polygon_batch(entries, randbelow=DetRand()))

    def test_accepts_tuple_and_duplicate_entries(self):
        entries = self.entries()
        batch = tuple(entries + [entries[0], entries[0]])
        self.assertTrue(verify_convex_polygon_batch(batch, randbelow=DetRand()))

    def test_empty_batch_rejected(self):
        self.assertFalse(verify_convex_polygon_batch([], randbelow=DetRand()))
        self.assertFalse(verify_convex_polygon_batch((), randbelow=DetRand()))

    def test_agrees_with_per_item_verification(self):
        entries = self.entries()
        for entry in entries:
            self.assertTrue(verify_convex_polygon(
                entry.x_commitment, entry.y_commitment,
                entry.polygon, entry.proof, entry.context,
            ))
        self.assertTrue(verify_convex_polygon_batch(entries, randbelow=DetRand()))
        # one invalid item fails the whole batch
        broken = self.entries()
        object.__setattr__(
            broken[1], "context", broken[1].context + b"!"
        )
        per_item = [
            verify_convex_polygon(
                e.x_commitment, e.y_commitment, e.polygon, e.proof, e.context
            )
            for e in broken
        ]
        self.assertEqual(per_item, [True, False, True])
        self.assertFalse(verify_convex_polygon_batch(broken, randbelow=DetRand()))

    def test_deterministic_under_same_random_source(self):
        entries = self.entries()
        first = verify_convex_polygon_batch(entries, randbelow=DetRand(7))
        second = verify_convex_polygon_batch(entries, randbelow=DetRand(7))
        self.assertEqual(first, second)

    def test_inputs_not_mutated(self):
        entries = self.entries()
        snapshot = list(entries)
        verify_convex_polygon_batch(entries, randbelow=DetRand())
        self.assertEqual(entries, snapshot)

    def test_swapped_axes_rejected(self):
        entry = polygon_entry(ASYMMETRIC, 2, 1, b"c", seed=40)
        swapped = ConvexPolygonBatchEntry(
            entry.y_commitment, entry.x_commitment,
            entry.polygon, entry.proof, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([swapped], randbelow=DetRand()))

    def test_changed_context_rejected(self):
        entry = polygon_entry(TRIANGLE, 1, 1, b"ctx", seed=50)
        changed = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            entry.polygon, entry.proof, b"other",
        )
        self.assertFalse(verify_convex_polygon_batch([changed], randbelow=DetRand()))

    def test_changed_polygon_rejected(self):
        entry = polygon_entry(QUAD, 1, 1, seed=60)
        other = ConvexPolygonRegion(((0, 0), (3, 0), (1, 3), (0, 3)))
        changed = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            other, entry.proof, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([changed], randbelow=DetRand()))

    def test_reordered_edge_proofs_rejected(self):
        entry = polygon_entry(TRIANGLE, 1, 1, seed=70)
        edges = entry.proof.edge_proofs
        reordered = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            (edges[1], edges[0], edges[2]),
        )
        changed = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            entry.polygon, reordered, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([changed], randbelow=DetRand()))

    def test_replaced_edge_proof_rejected(self):
        entry = polygon_entry(TRIANGLE, 1, 1, seed=80)
        other = polygon_entry(TRIANGLE, 2, 2, seed=90)
        replaced = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            (other.proof.edge_proofs[0],) + entry.proof.edge_proofs[1:],
        )
        changed = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            entry.polygon, replaced, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([changed], randbelow=DetRand()))

    def test_dropped_edge_proof_rejected(self):
        entry = polygon_entry(TRIANGLE, 1, 1, seed=100)
        dropped = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            entry.proof.edge_proofs[1:],
        )
        changed = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            entry.polygon, dropped, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([changed], randbelow=DetRand()))

    def test_tampered_sub_proofs_rejected(self):
        entry = polygon_entry(TRIANGLE, 1, 1, seed=110)
        x_t = list(entry.proof.x_proof.t)
        x_t[0] = x_t[0] % (DEFAULT_PRIME - 1) + 1
        tampered_x = ConvexPolygonRegionProof(
            RangeProof(tuple(x_t), entry.proof.x_proof.e, entry.proof.x_proof.s),
            entry.proof.y_proof, entry.proof.edge_proofs,
        )
        y_e = list(entry.proof.y_proof.e)
        y_e[0] = (y_e[0] + 1) % DEFAULT_PRIME
        tampered_y = ConvexPolygonRegionProof(
            entry.proof.x_proof,
            RangeProof(entry.proof.y_proof.t, tuple(y_e), entry.proof.y_proof.s),
            entry.proof.edge_proofs,
        )
        edge = entry.proof.edge_proofs[0]
        edge_s = list(edge.responses)
        edge_s[0] = (edge_s[0][0] + 1, edge_s[0][1])
        tampered_edge = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            (WideRangeProof(edge.commitments, edge.challenges, tuple(edge_s)),)
            + entry.proof.edge_proofs[1:],
        )
        for proof in (tampered_x, tampered_y, tampered_edge):
            with self.subTest(proof=proof):
                changed = ConvexPolygonBatchEntry(
                    entry.x_commitment, entry.y_commitment,
                    entry.polygon, proof, entry.context,
                )
                self.assertFalse(
                    verify_convex_polygon_batch([changed], randbelow=DetRand())
                )

    def test_mismatched_group_parameters_rejected(self):
        entry = polygon_entry(TRIANGLE, 1, 1, seed=120)
        other, _ = pedersen_commit(
            1, entry.polygon.min_x, entry.polygon.max_x, prime=2**61 - 1
        )
        changed = ConvexPolygonBatchEntry(
            other, entry.y_commitment,
            entry.polygon, entry.proof, entry.context,
        )
        self.assertFalse(verify_convex_polygon_batch([changed], randbelow=DetRand()))

    def test_type_errors(self):
        entry = polygon_entry(TRIANGLE, 1, 1, seed=130)
        good = [entry]
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch("not a sequence")
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch(b"bytes")
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([object()])
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch(good, randbelow=42)
        bad_context = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            entry.polygon, entry.proof, "ctx",
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([bad_context])
        bad_commitment = ConvexPolygonBatchEntry(
            "cx", entry.y_commitment, entry.polygon, entry.proof, entry.context,
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([bad_commitment])
        bool_field = ConvexPolygonRegionProof(
            RangeProof((True,), (0,), (0,)),
            entry.proof.y_proof, entry.proof.edge_proofs,
        )
        bool_entry = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            entry.polygon, bool_field, entry.context,
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([bool_entry])
        edge = entry.proof.edge_proofs[0]
        bool_edge = ConvexPolygonRegionProof(
            entry.proof.x_proof, entry.proof.y_proof,
            (WideRangeProof(
                (True,) + edge.commitments[1:], edge.challenges, edge.responses
            ),) + entry.proof.edge_proofs[1:],
        )
        bool_edge_entry = ConvexPolygonBatchEntry(
            entry.x_commitment, entry.y_commitment,
            entry.polygon, bool_edge, entry.context,
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([bool_edge_entry])

    def test_preflight_walks_whole_batch_before_verifying(self):
        # entry 0 is semantically invalid (wrong context); the type error
        # in the last entry must still raise instead of returning False.
        entries = self.entries()
        object.__setattr__(entries[0], "context", b"wrong")
        bad = ConvexPolygonBatchEntry(
            entries[1].x_commitment, entries[1].y_commitment,
            entries[1].polygon, "not a proof", entries[1].context,
        )
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch(entries + [bad], randbelow=DetRand())

    def test_randbelow_contract(self):
        entry = polygon_entry(TRIANGLE, 1, 1, seed=140)
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([entry], randbelow=lambda upper: 1.5)
        with self.assertRaises(TypeError):
            verify_convex_polygon_batch([entry], randbelow=lambda upper: True)
        with self.assertRaises(ValueError):
            verify_convex_polygon_batch(
                [entry], randbelow=lambda upper: upper
            )
        with self.assertRaises(ValueError):
            verify_convex_polygon_batch([entry], randbelow=lambda upper: -1)

    def test_randbelow_called_once_per_branch_with_prime_minus_one(self):
        entries = self.entries()
        counter = CountingRand(value=0)
        self.assertTrue(verify_convex_polygon_batch(entries, randbelow=counter))
        expected = sum(
            len(e.proof.x_proof.t) + len(e.proof.y_proof.t)
            + sum(2 * len(ep.commitments) for ep in e.proof.edge_proofs)
            for e in entries
        )
        self.assertEqual(len(counter.uppers), expected)
        self.assertEqual(set(counter.uppers), {DEFAULT_PRIME - 1})

    def test_randbelow_not_called_for_structurally_invalid_proof(self):
        valid = polygon_entry(TRIANGLE, 1, 1, seed=150)
        broken = polygon_entry(TRIANGLE, 2, 1, seed=160)
        e_shares = list(broken.proof.x_proof.e)
        e_shares[0] = (e_shares[0] + 1) % DEFAULT_PRIME
        broken_proof = ConvexPolygonRegionProof(
            RangeProof(broken.proof.x_proof.t, tuple(e_shares),
                       broken.proof.x_proof.s),
            broken.proof.y_proof, broken.proof.edge_proofs,
        )
        broken_entry = ConvexPolygonBatchEntry(
            broken.x_commitment, broken.y_commitment,
            broken.polygon, broken_proof, broken.context,
        )
        counter = CountingRand(value=3)
        self.assertFalse(
            verify_convex_polygon_batch([valid, broken_entry], randbelow=counter)
        )
        expected = (
            len(valid.proof.x_proof.t) + len(valid.proof.y_proof.t)
            + sum(2 * len(ep.commitments) for ep in valid.proof.edge_proofs)
        )
        self.assertEqual(len(counter.uppers), expected)


if __name__ == "__main__":
    unittest.main()
