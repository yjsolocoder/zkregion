"""Tests for the deterministic decimal quantization entry points.

``quantize_coordinate`` / ``quantize_region`` turn external fixed-point
coordinates and rectangle bounds into the plain integers the existing
commitment and proof pipeline already consumes, so the acceptance tests also
drive the quantized integers through Pedersen commitments, the normal and
wide region proofs, batch verification, Merkle binding, proof envelopes and
replay guards — checking parity with hand-built integer entries.
"""

import unittest
from decimal import Decimal, localcontext

from zkregion import (
    BoundRegionReplayGuard,
    PedersenOpeningBatchEntry,
    Region,
    RegionBatchEntry,
    RegionProof,
    RegionProofBundle,
    RegionWideBatchEntry,
    RegionWideProof,
    commit,
    commit_coordinate,
    decode_region_proof_bundle,
    encode_region_proof_bundle,
    pedersen_commit,
    prove_region,
    prove_region_batch_bound,
    prove_region_wide,
    prove_region_wide_batch_bound,
    quantize_coordinate,
    quantize_region,
    region_contains_committed,
    verify_opening,
    verify_pedersen_opening_batch,
    verify_region,
    verify_region_batch,
    verify_region_bound,
    verify_region_proof_bundle,
    verify_region_wide,
    verify_region_wide_batch,
    verify_region_wide_batch_bound,
)


def counter_randbelow(start=1):
    state = {"value": start}

    def randbelow(upper):
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


class QuantizeCoordinateTest(unittest.TestCase):
    def test_default_scale_is_one_million(self):
        self.assertEqual(quantize_coordinate("12.345678", "-0.000001"), (12345678, -1))

    def test_nearest_grid_point_positive_negative_zero(self):
        with localcontext() as ctx:
            ctx.prec = 2  # must not influence integer-exact inputs
            self.assertEqual(quantize_coordinate(0, -0, scale=100), (0, 0))
        self.assertEqual(quantize_coordinate("2.34", "-2.34", scale=100), (234, -234))
        self.assertEqual(quantize_coordinate(Decimal("2.346"), Decimal("-2.346"),
                                             scale=100), (235, -235))
        self.assertEqual(quantize_coordinate("0.004", "-0.004", scale=1), (0, 0))

    def test_half_lattice_rounds_away_from_zero(self):
        cases = [
            (1, "0.5", 1), (1, "-0.5", -1), (1, "1.5", 2), (1, "-1.5", -2),
            (10, "0.25", 3), (10, "-0.25", -3),
            (10, "0.05", 1), (10, "-0.05", -1),
            (100, "0.015", 2), (100, "-0.015", -2),
        ]
        for scale, text, expected in cases:
            with self.subTest(scale=scale, text=text):
                self.assertEqual(quantize_coordinate(text, 0, scale=scale),
                                 (expected, 0))

    def test_integer_inputs_identity_at_scale_one(self):
        for value in (0, 1, -1, 2 ** 80, -(2 ** 80)):
            self.assertEqual(quantize_coordinate(value, -value, scale=1), (value, -value))

    def test_integer_inputs_scale_by_factor(self):
        self.assertEqual(quantize_coordinate(3, -7, scale=1000), (3000, -7000))
        self.assertEqual(quantize_coordinate(3, -7, scale=10 ** 9), (3 * 10 ** 9, -7 * 10 ** 9))

    def test_input_types_agree(self):
        text = quantize_coordinate("12.75", "-40.125", scale=1000)
        decimal = quantize_coordinate(Decimal("12.75"), Decimal("-40.125"), scale=1000)
        fraction = quantize_coordinate(Decimal(51) / Decimal(4),
                                       Decimal(-321) / Decimal(8), scale=1000)
        self.assertEqual(text, (12750, -40125))
        self.assertEqual(text, decimal)
        self.assertEqual(text, fraction)

    def test_deterministic(self):
        first = quantize_coordinate("1.5", "-1.5", scale=1)
        for _ in range(5):
            self.assertEqual(quantize_coordinate("1.5", "-1.5", scale=1), first)

    def test_precision_context_ignored(self):
        long_number = "12345678901234567890.1234567890123456789"
        with localcontext() as ctx:
            ctx.prec = 2
            ctx.Emax = 5
            ctx.Emin = -5
            got = quantize_coordinate(long_number, long_number, scale=10 ** 6)
        expected = 12345678901234567890123457  # nearest, last digit 8 rounds the ...678 up
        self.assertEqual(got, (expected, expected))

    def test_no_binary_floating_point(self):
        # 0.1-style inputs stay exact: 1000000 * 0.1 is exactly 100000,
        # whereas a binary-float path would drift on long runs.
        self.assertEqual(quantize_coordinate("0.1", "-0.1"), (100000, -100000))
        self.assertEqual(quantize_coordinate("9007199254740993.5", "0", scale=1)[0],
                         9007199254740994)


class QuantizeRegionTest(unittest.TestCase):
    def test_bounds_round_outward(self):
        region = quantize_region("12.341", "12.349", "-0.0019", "0.0011", scale=1000)
        self.assertEqual(region, Region(12341, 12349, -2, 2))
        self.assertIsInstance(region, Region)

    def test_min_floor_max_ceil_on_each_axis(self):
        region = quantize_region("0.2", "0.8", "-1.8", "-0.2")
        self.assertEqual(region, Region(200000, 800000, -1800000, -200000))

    def test_integer_bounds_identity_at_scale_one(self):
        region = quantize_region(0, 100, -5, 5, scale=1)
        self.assertEqual(region, Region(0, 100, -5, 5))
        self.assertEqual(quantize_region(0, 0, 0, 0, scale=1), Region(0, 0, 0, 0))

    def test_exact_integer_valued_decimals_stay_exact(self):
        region = quantize_region(Decimal("2"), Decimal("4"),
                                 Decimal("-3"), Decimal("-1"), scale=10)
        self.assertEqual(region, Region(20, 40, -30, -10))

    def test_inclusive_endpoints_covered(self):
        region = quantize_region("1.25", "3.75", "-2.5", "2.5", scale=100)
        # The two rectangle corners, quantized, stay inside the inclusive grid.
        self.assertTrue(region.contains(125, -250))
        self.assertTrue(region.contains(375, 250))

    def test_quantized_points_inside_rectangle_are_contained(self):
        import fractions
        import random

        rng = random.Random(20261001)
        for _ in range(100):
            values = [fractions.Fraction(rng.randint(-5000, 5000), 37)
                      for _ in range(4)]
            lo_x, hi_x = sorted(values[:2])
            lo_y, hi_y = sorted(values[2:])

            def dec(frac):
                return Decimal(frac.numerator) / Decimal(frac.denominator)

            region = quantize_region(dec(lo_x), dec(hi_x), dec(lo_y), dec(hi_y),
                                     scale=100)
            for _ in range(8):
                px = lo_x + fractions.Fraction(rng.randint(0, 1000), 1000) * (hi_x - lo_x)
                py = lo_y + fractions.Fraction(rng.randint(0, 1000), 1000) * (hi_y - lo_y)
                qx, qy = quantize_coordinate(dec(px), dec(py), scale=100)
                self.assertTrue(region.contains(qx, qy), (region, qx, qy))

    def test_straddling_bounds_expand_to_cover_zero(self):
        region = quantize_region("-0.2", "0.2", "-0.2", "0.2", scale=10)
        self.assertEqual(region, Region(-2, 2, -2, 2))

    def test_deterministic_and_type_equivalence(self):
        first = quantize_region("0.1", "2.9", "-3.1", "-0.1", scale=10)
        again = quantize_region(Decimal("0.1"), Decimal("2.9"),
                                Decimal("-3.1"), Decimal("-0.1"), scale=10)
        self.assertEqual(first, again)
        self.assertEqual(first, Region(1, 29, -31, -1))

    def test_precision_context_ignored(self):
        with localcontext() as ctx:
            ctx.prec = 1
            ctx.Emax = 3
            ctx.Emin = -3
            region = quantize_region(
                "12345678901234567890.0000001",
                "12345678901234567890.0000009",
                "-0.0000009",
                "0.0000001",
            )
        self.assertEqual(region, Region(
            12345678901234567890000000,
            12345678901234567890000001,
            -1, 1,
        ))

    def test_inverted_logical_rectangle_rejected(self):
        with self.assertRaises(ValueError):
            quantize_region("1.1", "1.0", 0, 1, scale=10)
        with self.assertRaises(ValueError):
            quantize_region(0, 1, "5", "4.9", scale=10)

    def test_inverted_rectangle_rejected_on_exact_values_even_when_rounding_outward(
            self):
        # floor(1.06)=10 and ceil(1.04)=11 would hide the inversion; the
        # logical order is checked on the exact decimals before rounding.
        with self.assertRaises(ValueError):
            quantize_region("1.06", "1.04", 0, 1, scale=10)
        with self.assertRaises(ValueError):
            quantize_region(0, 1, "-0.01", "-0.02", scale=100)
        # Equal bounds (in any representation) stay valid and expand.
        self.assertEqual(quantize_region("1.10", "1.1", 0, 0, scale=10),
                         Region(11, 11, 0, 0))


class QuantizeInputValidationTest(unittest.TestCase):
    BAD_OBJECTS = (1.5, 0.0, True, False, None, object(), b"1", [1], 1 + 0j)
    BAD_STRINGS = ("", "abc", "1.2.3", "1.2.3.4", "NaN", "sNaN", "Infinity",
                   "-Infinity", "inf", "-inf", "nan", "1e", "+-1", "x1",
                   "1 2", ".", "e3")

    def test_coordinate_type_errors(self):
        for bad in self.BAD_OBJECTS:
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    quantize_coordinate(bad, 0)
                with self.assertRaises(TypeError):
                    quantize_coordinate(0, bad)

    def test_region_type_errors_in_every_position(self):
        for index in range(4):
            for bad in self.BAD_OBJECTS:
                args = [0, 1, 0, 1]
                args[index] = bad
                with self.subTest(index=index, bad=bad):
                    with self.assertRaises(TypeError):
                        quantize_region(*args)

    def test_coordinate_value_errors(self):
        for bad in self.BAD_STRINGS:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    quantize_coordinate(bad, 0)
        for bad in (Decimal("NaN"), Decimal("sNaN"), Decimal("Inf"),
                    Decimal("-Inf")):
            with self.subTest(bad=str(bad)):
                with self.assertRaises(ValueError):
                    quantize_coordinate(bad, 0)

    def test_region_value_errors(self):
        for bad in self.BAD_STRINGS:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    quantize_region(0, bad, 0, 1, scale=1)
        for bad in (Decimal("NaN"), Decimal("Inf"), Decimal("-Inf")):
            with self.subTest(bad=str(bad)):
                with self.assertRaises(ValueError):
                    quantize_region(bad, 1, 0, 1, scale=1)

    def test_scale_type_errors(self):
        for bad in (True, False, 1.0, Decimal("1"), "1", None, 1 + 0j):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    quantize_coordinate(0, 0, scale=bad)
                with self.assertRaises(TypeError):
                    quantize_region(0, 1, 0, 1, scale=bad)

    def test_scale_value_errors(self):
        for bad in (0, -1, -10 ** 6):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    quantize_coordinate(0, 0, scale=bad)
                with self.assertRaises(ValueError):
                    quantize_region(0, 1, 0, 1, scale=bad)

    def test_no_partial_results(self):
        # Validation runs before any integer work; a bad scale alongside a
        # bad coordinate raises the coordinate type error, and nothing is
        # returned from any failure path.
        with self.assertRaises(TypeError):
            quantize_coordinate(1.5, 0, scale=0)
        result = quantize_region(0, 1, 2, 3, scale=1)
        self.assertEqual(result, Region(0, 1, 2, 3))

    def test_scale_is_keyword_only(self):
        with self.assertRaises(TypeError):
            quantize_coordinate(0, 0, 1000)
        with self.assertRaises(TypeError):
            quantize_region(0, 1, 0, 1, 1000)


class QuantizedRegionProofAcceptanceTest(unittest.TestCase):
    CONTEXT = b"session-quantized"

    def _fixed_point_scene(self):
        # scale 100 keeps each axis inside the 256-integer range-proof limit.
        scale = 100
        qx, qy = quantize_coordinate("12.5", "-7.25", scale=scale)
        region = quantize_region("12.25", "12.75", "-7.5", "-7.0",
                                 scale=scale)
        self.assertEqual((qx, qy), (1250, -725))
        self.assertEqual(region, Region(1225, 1275, -750, -700))
        xc, xr = pedersen_commit(qx, region.min_x, region.max_x,
                                 blinding=1001)
        yc, yr = pedersen_commit(qy, region.min_y, region.max_y,
                                 blinding=2002)
        proof = prove_region(xc, yc, qx, qy, xr, yr, region,
                             context=self.CONTEXT,
                             randbelow=counter_randbelow(7))
        return qx, qy, region, xc, yc, xr, yr, proof

    def test_verify_region_accepts_quantized_scene(self):
        _qx, _qy, region, xc, yc, _xr, _yr, proof = self._fixed_point_scene()
        self.assertTrue(verify_region(xc, yc, region, proof,
                                      context=self.CONTEXT))

    def test_verify_region_rejects_wrong_context(self):
        _qx, _qy, region, xc, yc, _xr, _yr, proof = self._fixed_point_scene()
        self.assertFalse(verify_region(xc, yc, region, proof, context=b"other"))

    def test_verify_region_rejects_swapped_commitments(self):
        _qx, _qy, region, xc, yc, _xr, _yr, proof = self._fixed_point_scene()
        self.assertFalse(verify_region(yc, xc, region, proof,
                                       context=self.CONTEXT))

    def test_verify_region_rejects_swapped_axis_proofs(self):
        _qx, _qy, region, xc, yc, _xr, _yr, proof = self._fixed_point_scene()
        swapped = RegionProof(proof.y_proof, proof.x_proof)
        self.assertFalse(verify_region(xc, yc, region, swapped,
                                       context=self.CONTEXT))

    def test_verify_region_rejects_another_quantized_rectangle(self):
        _qx, _qy, _region, xc, yc, _xr, _yr, proof = self._fixed_point_scene()
        other = quantize_region("12.26", "12.76", "-7.5", "-7.0", scale=100)
        self.assertNotEqual(other, _region)
        self.assertFalse(verify_region(xc, yc, other, proof,
                                       context=self.CONTEXT))

    def test_verify_region_rejects_commitments_to_another_point(self):
        _qx, _qy, region, _xc, _yc, _xr, _yr, proof = self._fixed_point_scene()
        other_x, other_y = quantize_coordinate("12.6", "-7.0", scale=100)
        xc2, _ = pedersen_commit(other_x, region.min_x, region.max_x,
                                 blinding=3003)
        yc2, _ = pedersen_commit(other_y, region.min_y, region.max_y,
                                 blinding=4004)
        self.assertFalse(verify_region(xc2, yc2, region, proof,
                                       context=self.CONTEXT))

    def test_positive_negative_zero_half_grid_points_prove_and_verify(self):
        # The acceptance matrix: positive, negative, zero and half-lattice
        # fixed points, each quantized then driven through both axes of the
        # ordinary region proof under the matching (outward) region.
        scenes = [
            # (x text, y text, min x, max x, min y, max y, scale)
            ("3.25", "5.75", "3.0", "4.0", "5.0", "6.0", 100),
            ("-3.25", "-5.75", "-4.0", "-3.0", "-6.0", "-5.0", 100),
            ("0.0", "0.0", "-0.5", "0.5", "-0.5", "0.5", 100),
            ("1.5", "-1.5", "1.0", "2.0", "-2.0", "-1.0", 1),
        ]
        for x_text, y_text, lo_x, hi_x, lo_y, hi_y, scale in scenes:
            with self.subTest(point=(x_text, y_text)):
                qx, qy = quantize_coordinate(x_text, y_text, scale=scale)
                region = quantize_region(lo_x, hi_x, lo_y, hi_y, scale=scale)
                self.assertTrue(region.contains(qx, qy))
                xc, xr = pedersen_commit(qx, region.min_x, region.max_x,
                                         blinding=901)
                yc, yr = pedersen_commit(qy, region.min_y, region.max_y,
                                         blinding=902)
                proof = prove_region(xc, yc, qx, qy, xr, yr, region,
                                     context=self.CONTEXT,
                                     randbelow=counter_randbelow(11))
                self.assertTrue(verify_region(xc, yc, region, proof,
                                               context=self.CONTEXT))
                self.assertFalse(verify_region(xc, yc, region, proof,
                                                context=b"other"))
                self.assertFalse(verify_region(yc, xc, region, proof,
                                                context=self.CONTEXT))

    def test_wide_region_proof_round_trip_and_rejections(self):
        region = quantize_region("0", "255", "-2048", "2047", scale=1)
        qx, qy = quantize_coordinate("40", "-1000.2", scale=1)
        self.assertEqual((qx, qy), (40, -1000))
        xc, xr = pedersen_commit(qx, region.min_x, region.max_x, blinding=11)
        yc, yr = pedersen_commit(qy, region.min_y, region.max_y, blinding=22)
        proof = prove_region_wide(xc, yc, qx, qy, xr, yr, region,
                                  context=self.CONTEXT,
                                  randbelow=counter_randbelow(9))
        self.assertTrue(verify_region_wide(xc, yc, region, proof,
                                           context=self.CONTEXT))
        self.assertFalse(verify_region_wide(xc, yc, region, proof,
                                            context=b"other"))
        swapped = RegionWideProof(proof.y_proof, proof.x_proof)
        self.assertFalse(verify_region_wide(xc, yc, region, swapped,
                                            context=self.CONTEXT))
        other = quantize_region("0", "255", "-1024", "1023", scale=1)
        self.assertFalse(verify_region_wide(xc, yc, other, proof,
                                            context=self.CONTEXT))
        self.assertFalse(verify_region_wide(yc, xc, region, proof,
                                            context=self.CONTEXT))

    def test_hash_coordinate_commitment_matches_literal_integers(self):
        qx, qy = quantize_coordinate("12.5", "-7.25", scale=100)
        quantized, nonce = commit_coordinate(qx, qy, nonce=b"fixed-nonce")
        literal, _ = commit(f"{qx}:{qy}".encode("utf-8"), nonce=b"fixed-nonce")
        self.assertEqual(quantized, literal)
        self.assertTrue(verify_opening(quantized, f"{qx}:{qy}".encode(), nonce))

    def test_pedersen_openings_batch_parity_with_handbuilt_entries(self):
        qx, qy = quantize_coordinate("12.5", "-7.25", scale=100)
        region = quantize_region("12.25", "12.75", "-7.5", "-7.0", scale=100)
        xc, xr = pedersen_commit(qx, region.min_x, region.max_x, blinding=77)
        yc, yr = pedersen_commit(qy, region.min_y, region.max_y, blinding=88)
        entries = [
            PedersenOpeningBatchEntry(xc, 1250, xr),
            PedersenOpeningBatchEntry(yc, -725, yr),
        ]
        self.assertTrue(verify_pedersen_opening_batch(entries))

    def test_batch_verification_and_parity_with_literal_entries(self):
        qx, qy, region, xc, yc, _xr, _yr, quantized_proof = \
            self._fixed_point_scene()
        # Literal integers equal to the quantized values produce an
        # identical proof under an identical random source.
        literal_proof = prove_region(
            xc, yc, 1250, -725, 1001, 2002, region,
            context=self.CONTEXT, randbelow=counter_randbelow(7),
        )
        self.assertEqual(quantized_proof, literal_proof)
        entries = [
            RegionBatchEntry(xc, yc, region, literal_proof, self.CONTEXT),
            RegionBatchEntry(xc, yc, region, literal_proof, self.CONTEXT),
        ]
        self.assertTrue(verify_region_batch(entries,
                                            randbelow=counter_randbelow(3)))
        self.assertFalse(verify_region_batch(
            [RegionBatchEntry(xc, yc, region, literal_proof, b"other")],
            randbelow=counter_randbelow(3),
        ))

    def test_merkle_binding_round_trip_and_root_parity(self):
        qx, qy, region, xc, yc, _xr, _yr, quantized_proof = \
            self._fixed_point_scene()
        quantized_batch, quantized_root = prove_region_batch_bound(
            [RegionBatchEntry(xc, yc, region, quantized_proof, self.CONTEXT)],
            randbelow=counter_randbelow(7))
        literal_proof = prove_region(xc, yc, 1250, -725, 1001, 2002, region,
                                     context=self.CONTEXT,
                                     randbelow=counter_randbelow(7))
        literal_batch, literal_root = prove_region_batch_bound(
            [RegionBatchEntry(xc, yc, region, literal_proof, self.CONTEXT)],
            randbelow=counter_randbelow(7),
        )
        self.assertEqual(quantized_root, literal_root)
        self.assertTrue(verify_region_bound(quantized_batch, quantized_root,
                                            randbelow=counter_randbelow(7)))
        self.assertEqual(quantized_batch, literal_batch)

    def test_wide_merkle_binding_round_trip(self):
        region = quantize_region("0", "255", "-2048", "2047", scale=1)
        qx, qy = quantize_coordinate("40", "-1000.2", scale=1)
        xc, xr = pedersen_commit(qx, region.min_x, region.max_x, blinding=11)
        yc, yr = pedersen_commit(qy, region.min_y, region.max_y, blinding=22)
        proof = prove_region_wide(xc, yc, qx, qy, xr, yr, region,
                                  context=self.CONTEXT,
                                  randbelow=counter_randbelow(9))
        entries = [RegionWideBatchEntry(xc, yc, region, proof, self.CONTEXT)]
        batch, root = prove_region_wide_batch_bound(
            entries, randbelow=counter_randbelow(9))
        self.assertTrue(verify_region_wide_batch(
            entries, randbelow=counter_randbelow(9)))
        self.assertTrue(verify_region_wide_batch_bound(
            batch, root, randbelow=counter_randbelow(9)))

    def test_replay_binding_single_use_and_digest_parity(self):
        qx, qy, region, xc, yc, _xr, _yr, _ = self._fixed_point_scene()

        def bound():
            proof = prove_region(xc, yc, qx, qy, 1001, 2002, region,
                                 context=self.CONTEXT,
                                 randbelow=counter_randbelow(7))
            return prove_region_batch_bound(
                [RegionBatchEntry(xc, yc, region, proof, self.CONTEXT)],
                randbelow=counter_randbelow(7),
            )

        batch, root = bound()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"session-id")
        self.assertTrue(guard.check(batch, root, binding,
                                    randbelow=counter_randbelow(7)))
        # The id is consumed: a replay is rejected.
        self.assertFalse(guard.check(batch, root, binding,
                                     randbelow=counter_randbelow(7)))

        # The same integer values entered from literal constructions bind to
        # the same digest under the same session id.
        literal_proof = prove_region(xc, yc, 1250, -725, 1001, 2002, region,
                                     context=self.CONTEXT,
                                     randbelow=counter_randbelow(7))
        literal_batch, literal_root = prove_region_batch_bound(
            [RegionBatchEntry(xc, yc, region, literal_proof, self.CONTEXT)],
            randbelow=counter_randbelow(7),
        )
        other_guard = BoundRegionReplayGuard()
        literal_binding = other_guard.bind_once(
            literal_batch, literal_root, b"session-id")
        self.assertEqual(literal_binding.digest, binding.digest)

    def test_proof_bundle_envelope_round_trip(self):
        _qx, _qy, region, xc, yc, _xr, _yr, proof = self._fixed_point_scene()
        bundle = RegionProofBundle(xc, yc, region, self.CONTEXT, proof)
        encoded = encode_region_proof_bundle(bundle)
        self.assertIsInstance(encoded, bytes)
        decoded = decode_region_proof_bundle(encoded)
        self.assertEqual(decoded, bundle)
        self.assertTrue(verify_region_proof_bundle(decoded))
        tampered = RegionProofBundle(xc, yc, region, b"other", proof)
        self.assertFalse(verify_region_proof_bundle(tampered))

    def test_region_contains_committed_accepts_quantized_point(self):
        scale = 100
        qx, qy = quantize_coordinate("12.5", "-7.25", scale=scale)
        region = quantize_region("12.25", "12.75", "-7.5", "-7.0", scale=scale)
        xc, xr = pedersen_commit(qx, region.min_x, region.max_x, blinding=501)
        yc, yr = pedersen_commit(qy, region.min_y, region.max_y, blinding=601)
        self.assertTrue(region_contains_committed(
            region, xc, yc, qx, qy, xr, yr))
        # Swapping the commitments makes the declared ranges mismatch, and a
        # tampered blinding fails the opening check: both reject.
        self.assertFalse(region_contains_committed(
            region, yc, xc, qx, qy, xr, yr))
        self.assertFalse(region_contains_committed(
            region, xc, yc, qx, qy, xr + 1, yr))
        # The hand-built integer equivalents agree.
        self.assertTrue(region_contains_committed(
            Region(1225, 1275, -750, -700), xc, yc, 1250, -725, xr, yr))


if __name__ == "__main__":
    unittest.main()
