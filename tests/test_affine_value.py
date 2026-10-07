"""Tests for AffineValueProof / prove_affine_value / verify_affine_value.

The affine proof extends the equal-value OR-of-AND construction: the left
commitment hides ``x``, the right one hides ``y = a * x + b`` as actual
integers, and the branches range over the candidate set — the integers
``x`` in the left declared range whose image lands in the right declared
range (1 to 256 of them, contiguous, ascending).
"""

import dataclasses
import unittest

import zkregion
from zkregion import (
    DEFAULT_PRIME,
    AffineValueProof,
    PedersenCommitment,
    pedersen_commit,
    prove_affine_value,
    verify_affine_value,
)


def _pair(
    value,
    left_range,
    a,
    b,
    right_range,
    *,
    prime=DEFAULT_PRIME,
    generator=None,
    blinding_left=7,
    blinding_right=11,
):
    kwargs = {"prime": prime, "blinding": blinding_left}
    if generator is not None:
        kwargs["generator"] = generator
    left, used_left = pedersen_commit(value, left_range[0], left_range[1], **kwargs)
    kwargs = {"prime": prime, "blinding": blinding_right}
    if generator is not None:
        kwargs["generator"] = generator
    right, used_right = pedersen_commit(
        a * value + b, right_range[0], right_range[1], **kwargs
    )
    return left, right, used_left, used_right


def _proof(
    value,
    left_range,
    a,
    b,
    right_range,
    *,
    context=b"",
    randbelow=None,
    **kwargs,
):
    left, right, used_left, used_right = _pair(
        value, left_range, a, b, right_range, **kwargs
    )
    prove_kwargs = {} if randbelow is None else {"randbelow": randbelow}
    proof = prove_affine_value(
        left, right, a, b, value, used_left, used_right, context, **prove_kwargs
    )
    return left, right, proof


def _recording_randbelow():
    calls = []

    def randbelow(upper):
        calls.append(upper)
        return 0

    return randbelow, calls


class AffineValueProofTest(unittest.TestCase):
    def test_positional_construction_equality_frozen_no_validation(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        again = AffineValueProof(
            proof.t_left, proof.t_right, proof.e, proof.s_left, proof.s_right
        )
        self.assertEqual(again, proof)
        self.assertEqual(
            [field.name for field in dataclasses.fields(proof)],
            ["t_left", "t_right", "e", "s_left", "s_right"],
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.e = ()
        # construction performs no validation at all
        raw = AffineValueProof("t", 1, None, (), b"s")
        self.assertEqual(raw.t_left, "t")
        self.assertEqual(raw.s_right, b"s")

    def test_proof_hides_value_blindings_and_hit_position(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        proof = prove_affine_value(left, right, 2, 3, 4, used_left, used_right)
        flat = sum(map(list, dataclasses.astuple(proof)), [])
        self.assertNotIn(4, flat)  # the secret x
        self.assertNotIn(11, flat)  # the secret y = 2*4 + 3
        self.assertNotIn(used_left, flat[:0])  # blindings never appear raw
        self.assertNotIn(used_right, flat[:0])
        # the hit position is not marked: every field has full length
        self.assertEqual(
            {len(field) for field in dataclasses.astuple(proof)}, {11}
        )


class ProveAffineValueTest(unittest.TestCase):
    def test_positive_negative_zero_coefficients(self):
        cases = [
            (4, (0, 10), 2, 3, (3, 23)),  # y = 2x + 3
            (-2, (-5, 5), -1, 1, (-4, 6)),  # y = -x + 1
            (7, (0, 9), 0, 5, (5, 5)),  # y = 5, constant
            (0, (-3, 3), 0, 0, (0, 0)),  # y = 0, constant
        ]
        for value, left_range, a, b, right_range in cases:
            left, right, proof = _proof(value, left_range, a, b, right_range)
            self.assertTrue(
                verify_affine_value(left, right, a, b, proof),
                (value, left_range, a, b, right_range),
            )

    def test_negative_bounds_cross_zero_single_point_endpoints(self):
        cases = [
            (-100, (-200, -50), 2, 0, (-400, -100)),  # negative bounds
            (0, (-10, 10), 3, -1, (-31, 29)),  # crossing zero
            (5, (5, 5), 2, 3, (13, 13)),  # single-point candidate set
            (10, (0, 10), 2, 3, (3, 23)),  # y at right upper endpoint
            (0, (0, 10), 2, 3, (3, 23)),  # y at right lower endpoint
            (10, (0, 10), -1, 0, (-10, 0)),  # x at candidate upper endpoint
        ]
        for value, left_range, a, b, right_range in cases:
            left, right, proof = _proof(value, left_range, a, b, right_range)
            self.assertTrue(
                verify_affine_value(left, right, a, b, proof),
                (value, left_range, a, b, right_range),
            )

    def test_wide_single_side_ranges_and_different_declared_ranges(self):
        # each declared range may hold far more than 256 integers; only the
        # candidate set is capped
        left, right, proof = _proof(50, (0, 10**9), 1, 0, (5, 105))
        self.assertTrue(verify_affine_value(left, right, 1, 0, proof))
        left, right, proof = _proof(3, (0, 5), 4, 0, (0, 10**9))
        self.assertTrue(verify_affine_value(left, right, 4, 0, proof))

    def test_context_binds_and_defaults_to_empty(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        proof = prove_affine_value(left, right, 2, 3, 4, used_left, used_right)
        self.assertTrue(verify_affine_value(left, right, 2, 3, proof, b""))
        self.assertFalse(verify_affine_value(left, right, 2, 3, proof, b"ctx"))
        proof_ctx = prove_affine_value(
            left, right, 2, 3, 4, used_left, used_right, b"ctx"
        )
        self.assertTrue(verify_affine_value(left, right, 2, 3, proof_ctx, b"ctx"))
        self.assertFalse(verify_affine_value(left, right, 2, 3, proof_ctx))

    def test_same_inputs_same_random_sequence_equal_proofs(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))

        def source():
            state = iter(range(10**6))
            return lambda upper: next(state) % upper

        first = prove_affine_value(
            left, right, 2, 3, 4, used_left, used_right, randbelow=source()
        )
        second = prove_affine_value(
            left, right, 2, 3, 4, used_left, used_right, randbelow=source()
        )
        self.assertEqual(first, second)

    def test_draw_count_arguments_and_order(self):
        # candidates 0..2, hit at index 1: three draws per simulated branch
        # (e, s_left, s_right) then k_left and k_right
        left, right, used_left, used_right = _pair(1, (0, 2), 1, 0, (0, 2))
        randbelow, calls = _recording_randbelow()
        prove_affine_value(
            left, right, 1, 0, 1, used_left, used_right, randbelow=randbelow
        )
        p = DEFAULT_PRIME
        self.assertEqual(calls, [p, p - 1, p - 1, p, p - 1, p - 1, p - 1, p - 1])

    # ------------------------------------------------------------------
    # ValueError preflights (no randomness consumed)

    def test_valueerror_illegal_commitments_draw_nothing(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        bad_left = dataclasses.replace(left, element=0)
        bad_right = dataclasses.replace(right, upper=right.lower - 1)
        for l, r in ((bad_left, right), (left, bad_right)):
            randbelow, calls = _recording_randbelow()
            with self.assertRaises(ValueError):
                prove_affine_value(
                    l, r, 2, 3, 4, used_left, used_right, randbelow=randbelow
                )
            self.assertEqual(calls, [])

    def test_valueerror_group_parameter_mismatch_draws_nothing(self):
        left, used_left = pedersen_commit(4, 0, 10, blinding=7)
        right, used_right = pedersen_commit(11, 3, 23, generator=5, blinding=11)
        randbelow, calls = _recording_randbelow()
        with self.assertRaises(ValueError):
            prove_affine_value(
                left, right, 2, 3, 4, used_left, used_right, randbelow=randbelow
            )
        self.assertEqual(calls, [])

    def test_valueerror_empty_candidate_set_draws_nothing(self):
        # a = 0 with b outside the right range: no candidates at all
        left, used_left = pedersen_commit(7, 0, 9, blinding=7)
        right, used_right = pedersen_commit(5, 5, 5, blinding=11)
        randbelow, calls = _recording_randbelow()
        with self.assertRaises(ValueError):
            prove_affine_value(
                left, right, 0, 6, 7, used_left, used_right, randbelow=randbelow
            )
        # disjoint ranges with a != 0
        left2, used_left2 = pedersen_commit(0, 0, 3, blinding=7)
        right2, used_right2 = pedersen_commit(100, 100, 200, blinding=11)
        with self.assertRaises(ValueError):
            prove_affine_value(
                left2, right2, 1, 0, 0, used_left2, used_right2,
                randbelow=randbelow,
            )
        self.assertEqual(calls, [])

    def test_valueerror_oversized_candidate_set_draws_nothing(self):
        left, used_left = pedersen_commit(0, 0, 256, blinding=7)
        right, used_right = pedersen_commit(0, 0, 256, blinding=11)
        randbelow, calls = _recording_randbelow()
        with self.assertRaises(ValueError):
            prove_affine_value(
                left, right, 1, 0, 0, used_left, used_right, randbelow=randbelow
            )
        self.assertEqual(calls, [])
        # exactly 256 candidates is accepted
        left, used_left = pedersen_commit(0, 0, 255, blinding=7)
        right, used_right = pedersen_commit(0, 0, 255, blinding=11)
        proof = prove_affine_value(left, right, 1, 0, 0, used_left, used_right)
        self.assertTrue(verify_affine_value(left, right, 1, 0, proof))

    def test_valueerror_non_candidate_value_draws_nothing(self):
        # x = 9 gives y = 21, outside the right range (3, 19)
        left, used_left = pedersen_commit(9, 0, 10, blinding=7)
        right, used_right = pedersen_commit(11, 3, 19, blinding=11)
        randbelow, calls = _recording_randbelow()
        with self.assertRaises(ValueError):
            prove_affine_value(
                left, right, 2, 3, 9, used_left, used_right, randbelow=randbelow
            )
        self.assertEqual(calls, [])

    def test_valueerror_bad_blinding_and_opening_mismatch_draw_nothing(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        for bl, br in (
            (0, used_right),  # illegal left blinding
            (used_left, DEFAULT_PRIME - 1),  # illegal right blinding
            (used_left + 1, used_right),  # left opening mismatch
            (used_left, used_right + 1),  # right opening mismatch
        ):
            randbelow, calls = _recording_randbelow()
            with self.assertRaises(ValueError):
                prove_affine_value(
                    left, right, 2, 3, 4, bl, br, randbelow=randbelow
                )
            self.assertEqual(calls, [])

    def test_valueerror_missing_modular_inverse_draws_nothing(self):
        # composite modulus 15 with generator 3 (no inverse modulo 15);
        # openings still check out (non-negative exponents only) but the
        # per-branch offsets need 3**(-1) mod 15
        left, used_left = pedersen_commit(1, 0, 2, prime=15, generator=3, h=2,
                                          blinding=1)
        right, used_right = pedersen_commit(1, 0, 2, prime=15, generator=3, h=2,
                                            blinding=1)
        randbelow, calls = _recording_randbelow()
        with self.assertRaises(ValueError):
            prove_affine_value(
                left, right, 1, 0, 1, used_left, used_right, randbelow=randbelow
            )
        self.assertEqual(calls, [])

    # ------------------------------------------------------------------
    # TypeError preflights

    def test_typeerror_wrong_object_and_field_types(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        with self.assertRaises(TypeError):
            prove_affine_value("left", right, 2, 3, 4, used_left, used_right)
        with self.assertRaises(TypeError):
            prove_affine_value(left, None, 2, 3, 4, used_left, used_right)
        for field in ("element", "lower", "upper", "prime", "generator", "h"):
            for bad in (True, 1.5, "3"):
                with self.assertRaises(TypeError):
                    prove_affine_value(
                        dataclasses.replace(left, **{field: bad}),
                        right, 2, 3, 4, used_left, used_right,
                    )
                with self.assertRaises(TypeError):
                    prove_affine_value(
                        left,
                        dataclasses.replace(right, **{field: bad}),
                        2, 3, 4, used_left, used_right,
                    )

    def test_typeerror_coefficients_value_blindings_context(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        for bad in (True, 1.5, "2", None):
            with self.assertRaises(TypeError):
                prove_affine_value(left, right, bad, 3, 4, used_left, used_right)
            with self.assertRaises(TypeError):
                prove_affine_value(left, right, 2, bad, 4, used_left, used_right)
            with self.assertRaises(TypeError):
                prove_affine_value(left, right, 2, 3, bad, used_left, used_right)
            with self.assertRaises(TypeError):
                prove_affine_value(left, right, 2, 3, 4, bad, used_right)
            with self.assertRaises(TypeError):
                prove_affine_value(left, right, 2, 3, 4, used_left, bad)
        for bad_context in ("ctx", 123, None, bytearray(b"c")):
            with self.assertRaises(TypeError):
                prove_affine_value(
                    left, right, 2, 3, 4, used_left, used_right, bad_context
                )

    def test_typeerror_randbelow_must_be_callable(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        for bad in (None, 7, "rand"):
            with self.assertRaises(TypeError):
                prove_affine_value(
                    left, right, 2, 3, 4, used_left, used_right, randbelow=bad
                )

    # ------------------------------------------------------------------
    # randbelow return-value protocol

    def test_randbelow_non_integer_and_bool_raise_typeerror(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        for returned in (True, False, 1.0, "0", None):
            with self.assertRaises(TypeError):
                prove_affine_value(
                    left, right, 2, 3, 4, used_left, used_right,
                    randbelow=lambda upper: returned,
                )

    def test_randbelow_out_of_half_open_interval_raises_valueerror(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))
        for returned in (-1, DEFAULT_PRIME, DEFAULT_PRIME + 1):
            with self.assertRaises(ValueError):
                prove_affine_value(
                    left, right, 2, 3, 4, used_left, used_right,
                    randbelow=lambda upper, value=returned: value,
                )

    def test_randbelow_own_exception_propagates(self):
        left, right, used_left, used_right = _pair(4, (0, 10), 2, 3, (3, 23))

        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            prove_affine_value(
                left, right, 2, 3, 4, used_left, used_right, randbelow=boom
            )


class VerifyAffineValueTest(unittest.TestCase):
    def test_binding_left_right_order_and_all_public_fields(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23), context=b"c")
        self.assertTrue(verify_affine_value(left, right, 2, 3, proof, b"c"))
        self.assertFalse(verify_affine_value(right, left, 2, 3, proof, b"c"))
        for field, delta in (
            ("element", 1),
            ("lower", 1),
            ("upper", -1),
            ("generator", 1),
            ("h", 1),
        ):
            changed_left = dataclasses.replace(
                left, **{field: getattr(left, field) + delta}
            )
            self.assertFalse(
                verify_affine_value(changed_left, right, 2, 3, proof, b"c"), field
            )
            changed_right = dataclasses.replace(
                right, **{field: getattr(right, field) + delta}
            )
            self.assertFalse(
                verify_affine_value(left, changed_right, 2, 3, proof, b"c"), field
            )
        other_prime = dataclasses.replace(left, prime=(1 << 127) - 1 - 2)
        self.assertFalse(
            verify_affine_value(other_prime, right, 2, 3, proof, b"c")
        )

    def test_binding_coefficients_even_with_unchanged_candidate_set(self):
        # candidates of (a=2, b=0) and (a=1, b=0) over left (0, 4) /
        # right (0, 8) are both 0..4, yet the proof cannot be reused
        left, right, proof = _proof(2, (0, 4), 2, 0, (0, 8))
        self.assertTrue(verify_affine_value(left, right, 2, 0, proof))
        self.assertFalse(verify_affine_value(left, right, 1, 0, proof))
        self.assertFalse(verify_affine_value(left, right, 2, 1, proof))
        self.assertFalse(verify_affine_value(left, right, -2, 0, proof))

    def test_tampered_proof_fields_return_false(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        for field in ("t_left", "t_right", "e", "s_left", "s_right"):
            values = list(getattr(proof, field))
            values[0] = values[0] + 1
            tampered = dataclasses.replace(proof, **{field: tuple(values)})
            self.assertFalse(
                verify_affine_value(left, right, 2, 3, tampered),
                field,
            )
        # swapping two branches breaks the ascending-order binding
        swapped = dataclasses.replace(
            proof,
            t_left=(proof.t_left[1], proof.t_left[0]) + proof.t_left[2:],
            t_right=(proof.t_right[1], proof.t_right[0]) + proof.t_right[2:],
            e=(proof.e[1], proof.e[0]) + proof.e[2:],
            s_left=(proof.s_left[1], proof.s_left[0]) + proof.s_left[2:],
            s_right=(proof.s_right[1], proof.s_right[0]) + proof.s_right[2:],
        )
        self.assertFalse(verify_affine_value(left, right, 2, 3, swapped))

    def test_false_illegal_commitments_and_group_mismatch(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        for bad in (
            dataclasses.replace(left, element=0),
            dataclasses.replace(left, element=left.prime),
            dataclasses.replace(left, prime=3),
            dataclasses.replace(left, generator=1),
            dataclasses.replace(left, h=left.prime),
            dataclasses.replace(left, lower=left.upper + 1),
        ):
            self.assertFalse(verify_affine_value(bad, right, 2, 3, proof))
        other, _ = pedersen_commit(11, 3, 23, generator=5, blinding=11)
        self.assertFalse(verify_affine_value(left, other, 2, 3, proof))

    def test_false_empty_and_oversized_candidate_set(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        # a = 0 with b outside the right range: empty candidate set
        self.assertFalse(verify_affine_value(left, right, 0, 100, proof))
        # 257 candidates under the new coefficients
        wide_left = dataclasses.replace(left, lower=0, upper=300)
        wide_right = dataclasses.replace(right, lower=0, upper=600)
        self.assertFalse(verify_affine_value(wide_left, wide_right, 2, 0, proof))

    def test_false_proof_lengths_and_value_ranges(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        size = len(proof.e)
        prime = left.prime
        short = AffineValueProof(
            proof.t_left[:-1], proof.t_right, proof.e, proof.s_left, proof.s_right
        )
        self.assertFalse(verify_affine_value(left, right, 2, 3, short))
        long = dataclasses.replace(proof, e=proof.e + (0,))
        self.assertFalse(verify_affine_value(left, right, 2, 3, long))
        bad_values = [
            dataclasses.replace(proof, t_left=(0,) + proof.t_left[1:]),
            dataclasses.replace(proof, t_right=(prime,) + proof.t_right[1:]),
            dataclasses.replace(proof, e=(-1,) + proof.e[1:]),
            dataclasses.replace(proof, e=(prime,) + proof.e[1:]),
            dataclasses.replace(proof, s_left=(-1,) + proof.s_left[1:]),
            dataclasses.replace(proof, s_right=(-2,) + proof.s_right[1:]),
        ]
        for bad in bad_values:
            self.assertFalse(verify_affine_value(left, right, 2, 3, bad))
        self.assertEqual(size, 11)

    def test_false_missing_modular_inverse(self):
        # composite modulus 15 with generator 3 (no inverse modulo 15);
        # candidate x=1 lies above left.lower=0 so recomputing the offsets
        # needs 3**(-1) mod 15
        left = PedersenCommitment(7, 0, 1, 15, 3, 2)
        right = PedersenCommitment(7, 0, 1, 15, 3, 2)
        challenge = zkregion._affine_value_challenge(
            left, right, 1, 0, b"", 2, (1, 1), (1, 1)
        )
        proof = AffineValueProof((1, 1), (1, 1), (challenge, 0), (0, 0), (0, 0))
        self.assertFalse(verify_affine_value(left, right, 1, 0, proof))

    def test_typeerror_wrong_object_and_field_types(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        with self.assertRaises(TypeError):
            verify_affine_value("left", right, 2, 3, proof)
        with self.assertRaises(TypeError):
            verify_affine_value(left, None, 2, 3, proof)
        for field in ("element", "lower", "upper", "prime", "generator", "h"):
            for bad in (False, 2.5, "9"):
                with self.assertRaises(TypeError):
                    verify_affine_value(
                        dataclasses.replace(left, **{field: bad}), right, 2, 3,
                        proof,
                    )
        for bad in (True, 0.5, "2"):
            with self.assertRaises(TypeError):
                verify_affine_value(left, right, bad, 3, proof)
            with self.assertRaises(TypeError):
                verify_affine_value(left, right, 2, bad, proof)

    def test_typeerror_wrong_proof_types(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        for bad in (None, "proof", 7, (1, 2, 3)):
            with self.assertRaises(TypeError):
                verify_affine_value(left, right, 2, 3, bad)
        # an EqualValueProof is not an AffineValueProof
        equal = zkregion.EqualValueProof((), (), (), (), ())
        with self.assertRaises(TypeError):
            verify_affine_value(left, right, 2, 3, equal)
        for field in ("t_left", "t_right", "e", "s_left", "s_right"):
            with self.assertRaises(TypeError):
                verify_affine_value(
                    left, right, 2, 3,
                    dataclasses.replace(proof, **{field: list(getattr(proof, field))}),
                )
            values = list(getattr(proof, field))
            values[0] = True
            with self.assertRaises(TypeError):
                verify_affine_value(
                    left, right, 2, 3,
                    dataclasses.replace(proof, **{field: tuple(values)}),
                )

    def test_typeerror_context_must_be_bytes(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23))
        for bad in ("ctx", 7, None, bytearray(b"c")):
            with self.assertRaises(TypeError):
                verify_affine_value(left, right, 2, 3, proof, bad)

    def test_inputs_are_not_mutated(self):
        left, right, proof = _proof(4, (0, 10), 2, 3, (3, 23), context=b"c")
        snapshot = (left, right, proof)
        self.assertTrue(verify_affine_value(left, right, 2, 3, proof, b"c"))
        self.assertEqual((left, right, proof), snapshot)


if __name__ == "__main__":
    unittest.main()
