import dataclasses
import unittest

import zkregion
from zkregion import (
    ConvexPolygonProofBundle,
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    PedersenCommitment,
    RangeProof,
    Region,
    RegionProofBundle,
    WideRangeProof,
    decode_convex_polygon_proof_bundle,
    decode_region_proof_bundle,
    encode_convex_polygon_proof_bundle,
    encode_region_proof_bundle,
    pedersen_commit,
    prove_convex_polygon,
    prove_region,
    verify_convex_polygon,
    verify_convex_polygon_proof_bundle,
)


class DetRand:
    """Deterministic randbelow replacement: same sequence for same counter."""

    def __init__(self, seed=1):
        self.calls = seed

    def __call__(self, upper):
        self.calls += 1
        return (self.calls * 7919 + 13) % upper


PRIME = 104729
G = 3
H = 5

TRIANGLE = ((0, 0), (4, 0), (0, 4))
PENTAGON = ((0, 0), (5, 0), (6, 4), (2, 6), (-2, 3))


def make_bundle(vertices=TRIANGLE, point=(1, 2), context=b"ctx",
                prime=PRIME, generator=G, h=H,
                x_blinding=1234, y_blinding=4321):
    polygon = ConvexPolygonRegion(vertices)
    x, y = point
    x_commitment, x_blinding = pedersen_commit(
        x, polygon.min_x, polygon.max_x, prime=prime, generator=generator,
        h=h, blinding=x_blinding,
    )
    y_commitment, y_blinding = pedersen_commit(
        y, polygon.min_y, polygon.max_y, prime=prime, generator=generator,
        h=h, blinding=y_blinding,
    )
    proof = prove_convex_polygon(
        x_commitment, y_commitment, x, y, x_blinding, y_blinding,
        polygon, context, randbelow=DetRand(),
    )
    return ConvexPolygonProofBundle(
        x_commitment, y_commitment, polygon, context, proof
    )


def polygon_frame(raw):
    """Offset of the polygon frame in an encoded zrgp envelope."""
    # magic (4) + version (1), then two framed commitments
    offset = 5
    for _ in range(2):
        length = int.from_bytes(raw[offset:offset + 4], "big")
        offset += 4 + length
    return offset


def replace_polygon_frame(raw, vertices):
    """Reserialize only the polygon frame with raw ``vertices`` pairs."""
    offset = polygon_frame(raw)
    old_length = int.from_bytes(raw[offset:offset + 4], "big")
    body = zkregion._bundle_tuple(
        [
            zkregion._bundle_tuple(
                [zkregion._bundle_int(x), zkregion._bundle_int(y)]
            )
            for x, y in vertices
        ]
    )
    frame = zkregion._bundle_frame(body)
    return raw[:offset] + frame + raw[offset + 4 + old_length:]


class ConvexPolygonProofBundleTests(unittest.TestCase):
    # ---- round trip ---------------------------------------------------------

    def test_triangle_round_trip(self):
        bundle = make_bundle()
        raw = encode_convex_polygon_proof_bundle(bundle)
        self.assertIsInstance(raw, bytes)
        decoded = decode_convex_polygon_proof_bundle(raw)
        self.assertEqual(decoded, bundle)
        self.assertIsInstance(decoded.polygon, ConvexPolygonRegion)
        self.assertIsInstance(decoded.proof, ConvexPolygonRegionProof)
        self.assertTrue(verify_convex_polygon_proof_bundle(bundle))
        self.assertTrue(verify_convex_polygon_proof_bundle(decoded))

    def test_pentagon_round_trip(self):
        bundle = make_bundle(PENTAGON, point=(2, 3), context=b"pent")
        raw = encode_convex_polygon_proof_bundle(bundle)
        decoded = decode_convex_polygon_proof_bundle(raw)
        self.assertEqual(decoded, bundle)
        self.assertEqual(len(decoded.proof.edge_proofs), 5)
        self.assertTrue(verify_convex_polygon_proof_bundle(decoded))

    def test_default_group_parameters_round_trip(self):
        bundle = make_bundle(TRIANGLE, prime=zkregion.DEFAULT_PRIME,
                             generator=zkregion.DEFAULT_GENERATOR,
                             h=pow(zkregion.DEFAULT_GENERATOR, 2,
                                   zkregion.DEFAULT_PRIME))
        decoded = decode_convex_polygon_proof_bundle(
            encode_convex_polygon_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)
        self.assertTrue(verify_convex_polygon_proof_bundle(decoded))

    def test_zero_and_negative_coordinates_and_empty_context(self):
        square = ConvexPolygonRegion(((-4, -4), (4, -4), (4, 4), (-4, 4)))
        for point in ((0, 0), (-4, -4), (4, 4), (-1, 3)):
            bundle = self._square_bundle(square, point, b"")
            decoded = decode_convex_polygon_proof_bundle(
                encode_convex_polygon_proof_bundle(bundle)
            )
            self.assertEqual(decoded, bundle, point)
            self.assertEqual(decoded.context, b"")
            self.assertTrue(verify_convex_polygon_proof_bundle(decoded), point)

    @staticmethod
    def _square_bundle(polygon, point, context):
        x, y = point
        cx, rx = pedersen_commit(x, polygon.min_x, polygon.max_x)
        cy, ry = pedersen_commit(y, polygon.min_y, polygon.max_y)
        proof = prove_convex_polygon(
            cx, cy, x, y, rx, ry, polygon, context, randbelow=DetRand()
        )
        return ConvexPolygonProofBundle(cx, cy, polygon, context, proof)

    def test_arbitrary_precision_integers_round_trip(self):
        huge = 10**40
        prime = 2**255 - 19
        polygon = ConvexPolygonRegion(
            ((-huge, -huge), (-huge + 2, -huge), (-huge, -huge + 2))
        )
        x_commitment = PedersenCommitment(
            element=1, lower=polygon.min_x, upper=polygon.max_x,
            prime=prime, generator=3, h=pow(3, 2, prime),
        )
        y_commitment = PedersenCommitment(
            element=1, lower=polygon.min_y, upper=polygon.max_y,
            prime=prime, generator=3, h=pow(3, 2, prime),
        )
        edge_proofs = tuple(
            WideRangeProof((1,), ((1, 2),), ((3, 4),)) for _ in range(3)
        )
        proof = ConvexPolygonRegionProof(
            x_proof=RangeProof((1,), (0,), (0,)),
            y_proof=RangeProof((1,), (0,), (0,)),
            edge_proofs=edge_proofs,
        )
        bundle = ConvexPolygonProofBundle(
            x_commitment, y_commitment, polygon, b"big", proof
        )
        decoded = decode_convex_polygon_proof_bundle(
            encode_convex_polygon_proof_bundle(bundle)
        )
        self.assertEqual(decoded, bundle)
        # dummy proofs cannot verify
        self.assertFalse(verify_convex_polygon_proof_bundle(decoded))

    def test_decoded_structure_uses_tuples(self):
        bundle = make_bundle()
        decoded = decode_convex_polygon_proof_bundle(
            encode_convex_polygon_proof_bundle(bundle)
        )
        self.assertIsInstance(decoded.polygon.vertices, tuple)
        for vertex in decoded.polygon.vertices:
            self.assertIsInstance(vertex, tuple)
            self.assertEqual(len(vertex), 2)
        self.assertIsInstance(decoded.proof.edge_proofs, tuple)
        self.assertIsInstance(decoded.proof.x_proof.t, tuple)
        for edge_proof in decoded.proof.edge_proofs:
            self.assertIsInstance(edge_proof.commitments, tuple)
            self.assertIsInstance(edge_proof.challenges, tuple)
            self.assertIsInstance(edge_proof.responses, tuple)
            for pair in edge_proof.challenges:
                self.assertIsInstance(pair, tuple)

    def test_context_is_arbitrary_bytes(self):
        bundle = make_bundle(context=bytes(range(256)))
        decoded = decode_convex_polygon_proof_bundle(
            encode_convex_polygon_proof_bundle(bundle)
        )
        self.assertEqual(decoded.context, bytes(range(256)))
        self.assertTrue(verify_convex_polygon_proof_bundle(decoded))

    # ---- canonical encoding -------------------------------------------------

    def test_encode_is_deterministic(self):
        self.assertEqual(
            encode_convex_polygon_proof_bundle(make_bundle()),
            encode_convex_polygon_proof_bundle(make_bundle()),
        )
        bundle = make_bundle()
        self.assertEqual(
            encode_convex_polygon_proof_bundle(bundle),
            encode_convex_polygon_proof_bundle(bundle),
        )

    def test_re_encoding_is_byte_identical(self):
        for bundle in (make_bundle(), make_bundle(PENTAGON, (2, 3), b"p")):
            raw = encode_convex_polygon_proof_bundle(bundle)
            self.assertEqual(
                encode_convex_polygon_proof_bundle(
                    decode_convex_polygon_proof_bundle(raw)
                ),
                raw,
            )

    def test_header_carries_magic_and_version(self):
        raw = encode_convex_polygon_proof_bundle(make_bundle())
        self.assertEqual(raw[:5], b"zrgp" + bytes((1,)))

    def test_rotated_and_reversed_polygons_encode_identically(self):
        bundle = make_bundle()
        vertices = bundle.polygon.vertices
        rotation = ConvexPolygonRegion(tuple(vertices[1:] + vertices[:1]))
        reversal = ConvexPolygonRegion(tuple(reversed(vertices)))
        raw = encode_convex_polygon_proof_bundle(bundle)
        for other in (rotation, reversal):
            self.assertEqual(other, bundle.polygon)
            moved = ConvexPolygonProofBundle(
                bundle.x_commitment, bundle.y_commitment, other,
                bundle.context, bundle.proof,
            )
            self.assertEqual(
                encode_convex_polygon_proof_bundle(moved), raw
            )

    def test_distinct_fields_contexts_and_subproofs_encode_distinctly(self):
        bundle = make_bundle()
        raw = encode_convex_polygon_proof_bundle(bundle)

        def rebuild(**override):
            fields = dict(
                x_commitment=bundle.x_commitment,
                y_commitment=bundle.y_commitment,
                polygon=bundle.polygon,
                context=bundle.context,
                proof=bundle.proof,
            )
            fields.update(override)
            return ConvexPolygonProofBundle(**fields)

        other_poly = ConvexPolygonRegion(((0, 0), (4, 0), (0, 3)))
        cx2, _ = pedersen_commit(2, 0, 4, prime=PRIME, generator=G, h=H)
        cy2, _ = pedersen_commit(3, 0, 4, prime=PRIME, generator=G, h=H)
        edge = bundle.proof.edge_proofs[0]
        moved_edges = bundle.proof.edge_proofs[1:] + bundle.proof.edge_proofs[:1]
        tampered_x = RangeProof(
            bundle.proof.x_proof.t,
            tuple(e + 1 for e in bundle.proof.x_proof.e),
            bundle.proof.x_proof.s,
        )
        tampered_edge = WideRangeProof(
            tuple(c + 1 for c in edge.commitments),
            edge.challenges, edge.responses,
        )
        variants = (
            rebuild(x_commitment=cx2),
            rebuild(y_commitment=cy2),
            rebuild(polygon=other_poly),
            rebuild(context=b"other"),
            rebuild(context=b""),
            rebuild(proof=ConvexPolygonRegionProof(
                bundle.proof.x_proof, bundle.proof.y_proof, moved_edges)),
            rebuild(proof=ConvexPolygonRegionProof(
                tampered_x, bundle.proof.y_proof, bundle.proof.edge_proofs)),
            rebuild(proof=ConvexPolygonRegionProof(
                bundle.proof.x_proof, bundle.proof.y_proof,
                (tampered_edge,) + bundle.proof.edge_proofs[1:])),
        )
        for variant in variants:
            self.assertNotEqual(
                encode_convex_polygon_proof_bundle(variant), raw
            )

    def test_bundle_is_frozen_and_value_compared(self):
        bundle = make_bundle()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            bundle.context = b"other"
        self.assertEqual(bundle, make_bundle())
        self.assertEqual(hash(bundle), hash(make_bundle()))

    def test_positional_field_order(self):
        bundle = make_bundle()
        self.assertEqual(
            bundle,
            ConvexPolygonProofBundle(
                bundle.x_commitment, bundle.y_commitment, bundle.polygon,
                bundle.context, bundle.proof,
            ),
        )

    # ---- decode failures ----------------------------------------------------

    def test_every_truncation_rejected(self):
        raw = encode_convex_polygon_proof_bundle(make_bundle())
        self.assertGreater(len(raw), 100)
        for cut in range(0, len(raw)):
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(raw[:cut])

    def test_trailing_data_rejected(self):
        raw = encode_convex_polygon_proof_bundle(make_bundle())
        for extra in (b"\x00", b"ab", b"\xff" * 8):
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(raw + extra)
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(extra + raw)

    def test_bad_magic_and_version_rejected(self):
        raw = bytearray(encode_convex_polygon_proof_bundle(make_bundle()))
        raw[0] = ord("X")
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(raw))
        for version in (0, 2, 255):
            mutated = bytearray(encode_convex_polygon_proof_bundle(make_bundle()))
            mutated[4] = version
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(bytes(mutated))

    def test_envelope_magic_isolation(self):
        convex_raw = encode_convex_polygon_proof_bundle(make_bundle())
        region = Region(0, 100, 0, 100)
        x_commitment, x_blinding = pedersen_commit(40, 0, 100, blinding=1234)
        y_commitment, y_blinding = pedersen_commit(60, 0, 100, blinding=4321)
        region_proof = prove_region(
            x_commitment, y_commitment, 40, 60, x_blinding, y_blinding,
            region, b"ctx",
        )
        region_bundle = RegionProofBundle(
            x_commitment, y_commitment, region, b"ctx", region_proof
        )
        region_raw = encode_region_proof_bundle(region_bundle)
        with self.assertRaises(ValueError):
            decode_region_proof_bundle(convex_raw)
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(region_raw)

    def test_decode_requires_bytes(self):
        raw = encode_convex_polygon_proof_bundle(make_bundle())
        for bad in (bytearray(raw), memoryview(raw), str(raw), 123, None,
                    [raw]):
            with self.assertRaises(TypeError):
                decode_convex_polygon_proof_bundle(bad)

    def test_single_byte_tampering_never_repairs_the_bundle(self):
        bundle = make_bundle()
        raw = encode_convex_polygon_proof_bundle(bundle)
        for index in range(len(raw)):
            tampered = bytearray(raw)
            tampered[index] ^= 0xFF
            try:
                decoded = decode_convex_polygon_proof_bundle(bytes(tampered))
            except ValueError:
                continue
            self.assertNotEqual(decoded, bundle, index)
            self.assertFalse(
                verify_convex_polygon_proof_bundle(decoded),
                f"tampered byte {index} verified",
            )

    def test_non_canonical_integers_rejected(self):
        raw = bytearray(encode_convex_polygon_proof_bundle(make_bundle()))
        # header (5) + frame length (4) + commitment tuple count (4); the
        # first framed integer starts at offset 13.
        pos = 13
        length = int.from_bytes(raw[pos:pos + 4], "big")
        mutated = bytearray(raw)
        mutated[5:9] = (
            int.from_bytes(mutated[5:9], "big") + 1
        ).to_bytes(4, "big")
        mutated[pos:pos + 4] = (length + 1).to_bytes(4, "big")
        mutated[pos + 5:pos + 5] = b"\x00"
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(mutated))
        # negative zero / unknown sign byte: a framed zero is uint32(2) 01 00
        marker = bytes((0, 0, 0, 2, 1, 0))
        zero_pos = bytes(raw).find(marker)
        self.assertGreaterEqual(zero_pos, 0)
        for sign in (255, 7):
            mutated = bytearray(raw)
            mutated[zero_pos + 4] = sign
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(bytes(mutated))

    def test_invalid_commitment_field_values_rejected(self):
        good = dict(
            element=1, lower=0, upper=4, prime=PRIME, generator=3, h=5
        )
        bad_cases = (
            dict(element=0),
            dict(element=PRIME),
            dict(prime=3),
            dict(generator=1),
            dict(generator=PRIME),
            dict(h=1),
            dict(h=PRIME),
            dict(lower=5),
        )
        for overrides in bad_cases:
            values = dict(good)
            values.update(overrides)
            bundle = make_bundle()
            object.__setattr__(
                bundle, "x_commitment", PedersenCommitment(**values)
            )
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(
                    encode_convex_polygon_proof_bundle(bundle)
                )

    def test_inverted_commitment_range_rejected(self):
        bundle = make_bundle()
        bad = PedersenCommitment(
            element=1, lower=4, upper=0, prime=PRIME, generator=3, h=5
        )
        object.__setattr__(bundle, "x_commitment", bad)
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(
                encode_convex_polygon_proof_bundle(bundle)
            )

    def test_illegal_polygons_on_the_wire_rejected(self):
        raw = encode_convex_polygon_proof_bundle(
            make_bundle(((-4, -4), (4, -4), (4, 4), (-4, 4)), (0, 0))
        )
        illegal_vertices = (
            # collinear triple
            ((0, 0), (4, 0), (8, 0), (0, 4)),
            # concave vertex
            ((0, 0), (4, 0), (1, 1), (4, 4), (0, 4)),
            # self-intersecting bow tie
            ((0, 0), (4, 4), (4, 0), (0, 4)),
            # repeated vertex
            ((0, 0), (4, 0), (0, 0), (0, 4)),
        )
        for vertices in illegal_vertices:
            tampered = replace_polygon_frame(raw, vertices)
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(tampered)

    def test_bad_vertex_pair_cardinality_rejected(self):
        raw = encode_convex_polygon_proof_bundle(make_bundle())
        # hand-build a polygon frame whose first vertex holds three ints
        offset = polygon_frame(raw)
        old_length = int.from_bytes(raw[offset:offset + 4], "big")
        body = zkregion._bundle_tuple([
            zkregion._bundle_tuple(
                [zkregion._bundle_int(0), zkregion._bundle_int(0),
                 zkregion._bundle_int(0)]
            ),
            zkregion._bundle_tuple(
                [zkregion._bundle_int(4), zkregion._bundle_int(0)]
            ),
            zkregion._bundle_tuple(
                [zkregion._bundle_int(0), zkregion._bundle_int(4)]
            ),
        ])
        tampered = raw[:offset] + zkregion._bundle_frame(body) + raw[
            offset + 4 + old_length:]
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(tampered)

    def test_edge_proof_cardinality_mismatch_rejected(self):
        # vertex count 3 -> 2 while three edge proofs remain on the wire
        raw = encode_convex_polygon_proof_bundle(make_bundle())
        tampered = replace_polygon_frame(raw, ((0, 0), (4, 0)))
        self.assertLess(len(tampered), len(raw))
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(tampered)

    def test_proof_tuple_cardinality_mismatch_rejected(self):
        raw = bytearray(encode_convex_polygon_proof_bundle(make_bundle()))
        proof_start = len(raw) - 4
        raw[proof_start + 4:proof_start + 8] = (2).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(bytes(raw))

    def test_malformed_range_proof_shape_rejected(self):
        bundle = make_bundle()
        good = bundle.proof.x_proof
        cases = (
            (good.t[:-1], good.e, good.s),
            (good.t, good.e[:-1], good.s),
            (good.t, good.e, good.s[:-1]),
            ((), (), ()),
        )
        for t, e, s in cases:
            broken = make_bundle()
            bad_proof = ConvexPolygonRegionProof(
                RangeProof(t, e, s),
                broken.proof.y_proof,
                broken.proof.edge_proofs,
            )
            object.__setattr__(broken, "proof", bad_proof)
            with self.assertRaises(ValueError):
                decode_convex_polygon_proof_bundle(
                    encode_convex_polygon_proof_bundle(broken)
                )

    def test_malformed_wide_proof_shape_rejected(self):
        bundle = make_bundle()
        good = bundle.proof.edge_proofs[0]
        # a three-item pair is a type error at encode
        bad_pairs = tuple(
            (a, b, 0)
            for a, (b, _unused) in zip(
                (0,) * len(good.challenges), good.challenges
            )
        )
        bad_subproof = WideRangeProof(
            good.commitments, bad_pairs, good.responses
        )
        edges = (bad_subproof,) + bundle.proof.edge_proofs[1:]
        bad_proof = ConvexPolygonRegionProof(
            bundle.proof.x_proof, bundle.proof.y_proof, edges
        )
        object.__setattr__(bundle, "proof", bad_proof)
        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(bundle)
        # mismatched bit-entry counts are enforced by the envelope parser
        bundle = make_bundle()
        good = bundle.proof.edge_proofs[0]
        bad_subproof = WideRangeProof(
            good.commitments[:-1], good.challenges, good.responses
        )
        edges = (bad_subproof,) + bundle.proof.edge_proofs[1:]
        bad_proof = ConvexPolygonRegionProof(
            bundle.proof.x_proof, bundle.proof.y_proof, edges
        )
        object.__setattr__(bundle, "proof", bad_proof)
        with self.assertRaises(ValueError):
            decode_convex_polygon_proof_bundle(
                encode_convex_polygon_proof_bundle(bundle)
            )

    # ---- encode type / value errors ----------------------------------------

    def test_encode_rejects_wrong_object_and_field_types(self):
        good = make_bundle()

        def encode_with(**override):
            fields = dict(
                x_commitment=good.x_commitment,
                y_commitment=good.y_commitment,
                polygon=good.polygon,
                context=good.context,
                proof=good.proof,
            )
            fields.update(override)
            encode_convex_polygon_proof_bundle(ConvexPolygonProofBundle(**fields))

        with self.assertRaises(TypeError):
            encode_convex_polygon_proof_bundle(object())
        with self.assertRaises(TypeError):
            encode_with(x_commitment=object())
        bool_commitment = PedersenCommitment(True, 0, 4, PRIME, 3, 5)
        with self.assertRaises(TypeError):
            encode_with(x_commitment=bool_commitment)
        with self.assertRaises(TypeError):
            encode_with(polygon=((0, 0), (4, 0), (0, 4)))
        with self.assertRaises(TypeError):
            encode_with(context="ctx")
        with self.assertRaises(TypeError):
            encode_with(context=7)
        with self.assertRaises(TypeError):
            encode_with(proof=object())
        bad_x = RangeProof([1], (0,), (0,))
        with self.assertRaises(TypeError):
            encode_with(proof=ConvexPolygonRegionProof(
                bad_x, good.proof.y_proof, good.proof.edge_proofs))
        bool_x = RangeProof((True,), (0,), (0,))
        with self.assertRaises(TypeError):
            encode_with(proof=ConvexPolygonRegionProof(
                bool_x, good.proof.y_proof, good.proof.edge_proofs))
        with self.assertRaises(TypeError):
            encode_with(proof=ConvexPolygonRegionProof(
                good.proof.x_proof, good.proof.y_proof,
                [object() for _ in good.proof.edge_proofs]))
        with self.assertRaises(TypeError):
            encode_with(proof=ConvexPolygonRegionProof(
                good.proof.x_proof, good.proof.y_proof,
                (1, 2, 3)))

    def test_encode_rejects_illegal_polygon_and_edge_cardinality(self):
        good = make_bundle()
        forged = object.__new__(ConvexPolygonRegion)
        object.__setattr__(forged, "vertices", ((0, 0), (4, 0)))
        with self.assertRaises(ValueError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, forged,
                    good.context, good.proof,
                )
            )
        concave = object.__new__(ConvexPolygonRegion)
        object.__setattr__(
            concave, "vertices",
            ((0, 0), (4, 0), (1, 1), (4, 4), (0, 4)),
        )
        with self.assertRaises(ValueError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, concave,
                    good.context, good.proof,
                )
            )
        missing_edge = ConvexPolygonRegionProof(
            good.proof.x_proof, good.proof.y_proof, good.proof.edge_proofs[:2]
        )
        with self.assertRaises(ValueError):
            encode_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon,
                    good.context, missing_edge,
                )
            )

    # ---- verify type errors -------------------------------------------------

    def test_verify_type_errors(self):
        good = make_bundle()
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(object())
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    object(), good.y_commitment, good.polygon,
                    good.context, good.proof,
                )
            )
        bool_commitment = PedersenCommitment(True, 0, 4, PRIME, 3, 5)
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    bool_commitment, good.y_commitment, good.polygon,
                    good.context, good.proof,
                )
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment,
                    ((0, 0), (4, 0), (0, 4)), good.context, good.proof,
                )
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon,
                    7, good.proof,
                )
            )
        with self.assertRaises(TypeError):
            verify_convex_polygon_proof_bundle(
                ConvexPolygonProofBundle(
                    good.x_commitment, good.y_commitment, good.polygon,
                    good.context, object(),
                )
            )

    # ---- verify False semantics ---------------------------------------------

    def verify_with(self, bundle, **override):
        fields = dict(
            x_commitment=bundle.x_commitment,
            y_commitment=bundle.y_commitment,
            polygon=bundle.polygon,
            context=bundle.context,
            proof=bundle.proof,
        )
        fields.update(override)
        return verify_convex_polygon_proof_bundle(
            ConvexPolygonProofBundle(**fields)
        )

    def test_verify_rejects_context_mismatch(self):
        bundle = make_bundle()
        self.assertFalse(self.verify_with(bundle, context=b"other"))
        self.assertFalse(self.verify_with(bundle, context=b""))

    def test_verify_rejects_swapped_commitments(self):
        bundle = make_bundle()
        self.assertFalse(self.verify_with(
            bundle,
            x_commitment=bundle.y_commitment,
            y_commitment=bundle.x_commitment,
        ))

    def test_verify_rejects_changed_commitments(self):
        bundle = make_bundle()
        cx2, _ = pedersen_commit(2, 0, 4, prime=PRIME, generator=G, h=H)
        cy2, _ = pedersen_commit(3, 0, 4, prime=PRIME, generator=G, h=H)
        self.assertFalse(self.verify_with(bundle, x_commitment=cx2))
        self.assertFalse(self.verify_with(bundle, y_commitment=cy2))

    def test_verify_rejects_group_parameter_mismatch(self):
        bundle = make_bundle()
        mismatched = pedersen_commit(1, 0, 4, prime=2**61 - 1)[0]
        self.assertFalse(self.verify_with(bundle, x_commitment=mismatched))

    def test_verify_rejects_wrong_polygon(self):
        bundle = make_bundle()
        other = ConvexPolygonRegion(((0, 0), (4, 0), (0, 3)))
        shifted = ConvexPolygonRegion(((1, 0), (5, 0), (1, 4)))
        self.assertFalse(self.verify_with(bundle, polygon=other))
        self.assertFalse(self.verify_with(bundle, polygon=shifted))

    def test_verify_accepts_canonically_equal_polygon(self):
        bundle = make_bundle()
        vertices = bundle.polygon.vertices
        rotated = ConvexPolygonRegion(tuple(vertices[1:] + vertices[:1]))
        self.assertTrue(self.verify_with(bundle, polygon=rotated))

    def test_verify_rejects_tampered_bbox_subproofs(self):
        bundle = make_bundle()
        x_proof = bundle.proof.x_proof
        bad_x = RangeProof(
            x_proof.t, tuple(e + 1 for e in x_proof.e), x_proof.s
        )
        self.assertFalse(self.verify_with(
            bundle,
            proof=ConvexPolygonRegionProof(
                bad_x, bundle.proof.y_proof, bundle.proof.edge_proofs),
        ))
        y_proof = bundle.proof.y_proof
        bad_y = RangeProof(
            y_proof.t, tuple(e + 1 for e in y_proof.e), y_proof.s
        )
        self.assertFalse(self.verify_with(
            bundle,
            proof=ConvexPolygonRegionProof(
                bundle.proof.x_proof, bad_y, bundle.proof.edge_proofs),
        ))

    def test_verify_rejects_swapped_axes(self):
        bundle = make_bundle()
        swapped = ConvexPolygonRegionProof(
            bundle.proof.y_proof, bundle.proof.x_proof, bundle.proof.edge_proofs
        )
        self.assertFalse(self.verify_with(bundle, proof=swapped))

    def test_verify_rejects_tampered_reordered_and_missing_edge_proofs(self):
        bundle = make_bundle()
        edge = bundle.proof.edge_proofs[0]
        tampered_edge = WideRangeProof(
            tuple(c + 1 if c < 100 else c - 1 for c in edge.commitments),
            edge.challenges, edge.responses,
        )
        self.assertFalse(self.verify_with(
            bundle,
            proof=ConvexPolygonRegionProof(
                bundle.proof.x_proof, bundle.proof.y_proof,
                (tampered_edge,) + bundle.proof.edge_proofs[1:]),
        ))
        reordered = (
            bundle.proof.edge_proofs[1],
            bundle.proof.edge_proofs[0],
            bundle.proof.edge_proofs[2],
        )
        self.assertFalse(self.verify_with(
            bundle,
            proof=ConvexPolygonRegionProof(
                bundle.proof.x_proof, bundle.proof.y_proof, reordered),
        ))
        missing = bundle.proof.edge_proofs[:2]
        self.assertFalse(self.verify_with(
            bundle,
            proof=ConvexPolygonRegionProof(
                bundle.proof.x_proof, bundle.proof.y_proof, missing),
        ))

    def test_verify_rejects_forged_edge_proof(self):
        bundle = make_bundle()
        edge = bundle.proof.edge_proofs[0]
        forged_edge = WideRangeProof(
            tuple(5 for _ in edge.commitments),
            tuple((1, 2) for _ in edge.challenges),
            tuple((3, 4) for _ in edge.responses),
        )
        forged = ConvexPolygonRegionProof(
            bundle.proof.x_proof, bundle.proof.y_proof,
            (forged_edge,) + bundle.proof.edge_proofs[1:],
        )
        self.assertFalse(self.verify_with(bundle, proof=forged))

    def test_round_trip_preserves_verification_failure(self):
        bundle = make_bundle()
        moved = ConvexPolygonProofBundle(
            bundle.x_commitment, bundle.y_commitment, bundle.polygon,
            b"other", bundle.proof,
        )
        raw = encode_convex_polygon_proof_bundle(moved)
        decoded = decode_convex_polygon_proof_bundle(raw)
        self.assertEqual(decoded, moved)
        self.assertFalse(verify_convex_polygon_proof_bundle(decoded))

    def test_verify_matches_verify_convex_polygon(self):
        bundle = make_bundle(PENTAGON, (2, 4), b"match")
        self.assertEqual(
            verify_convex_polygon_proof_bundle(bundle),
            verify_convex_polygon(
                bundle.x_commitment, bundle.y_commitment, bundle.polygon,
                bundle.proof, bundle.context,
            ),
        )


if __name__ == "__main__":
    unittest.main()
