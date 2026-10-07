"""Smoke tests for the two-commitment affine-relation proof APIs."""

import itertools
import unittest

from zkregion import (
    AffineValueProof,
    PedersenCommitment,
    pedersen_commit,
    prove_affine_value,
    verify_affine_value,
)


def _commit(value, lower, upper, **kwargs):
    return pedersen_commit(value, lower, upper, **kwargs)


def _counter_randbelow():
    counter = itertools.count(1)
    return lambda upper: next(counter) % upper


class AffineValueProofTest(unittest.TestCase):
    def setUp(self):
        # y = 2 * x + 3; every x in [-10, 10] maps into [-20, 23]
        self.left, self.blinding_left = _commit(4, -10, 10)
        self.right, self.blinding_right = _commit(11, -20, 23)
        self.proof = prove_affine_value(
            self.left,
            self.right,
            2,
            3,
            4,
            self.blinding_left,
            self.blinding_right,
            context=b"session-1",
        )

    def test_valid_proof_verifies(self):
        self.assertTrue(
            verify_affine_value(
                self.left, self.right, 2, 3, self.proof, context=b"session-1"
            )
        )

    def test_default_context_is_empty_bytes(self):
        proof = prove_affine_value(
            self.left, self.right, 2, 3, 4, self.blinding_left, self.blinding_right
        )
        self.assertTrue(verify_affine_value(self.left, self.right, 2, 3, proof))
        self.assertTrue(verify_affine_value(self.left, self.right, 2, 3, proof, b""))
        self.assertFalse(
            verify_affine_value(self.left, self.right, 2, 3, proof, context=b"x")
        )

    def test_proof_is_immutable_and_compares_by_value(self):
        again = prove_affine_value(
            self.left,
            self.right,
            2,
            3,
            4,
            self.blinding_left,
            self.blinding_right,
            context=b"session-1",
            randbelow=_counter_randbelow(),
        )
        same = prove_affine_value(
            self.left,
            self.right,
            2,
            3,
            4,
            self.blinding_left,
            self.blinding_right,
            context=b"session-1",
            randbelow=_counter_randbelow(),
        )
        self.assertEqual(again, same)
        with self.assertRaises(Exception):
            self.proof.e = ()

    def test_binding_to_order_commitments_coefficients_and_context(self):
        verify = verify_affine_value
        self.assertFalse(
            verify(self.right, self.left, 2, 3, self.proof, context=b"session-1")
        )
        self.assertFalse(
            verify(self.left, self.right, 3, 3, self.proof, context=b"session-1")
        )
        self.assertFalse(
            verify(self.left, self.right, 2, 4, self.proof, context=b"session-1")
        )
        self.assertFalse(verify(self.left, self.right, 2, 3, self.proof, context=b""))
        widened = PedersenCommitment(
            self.left.element,
            self.left.lower,
            self.left.upper + 1,
            self.left.prime,
            self.left.generator,
            self.left.h,
        )
        self.assertFalse(
            verify(widened, self.right, 2, 3, self.proof, context=b"session-1")
        )

    def test_changed_coefficients_cannot_reuse_proof_with_same_candidates(self):
        # candidate set is {0} for both a = 7 and a = 8 with b = 0
        left, blinding_left = _commit(0, -5, 5)
        right, blinding_right = _commit(0, 0, 0)
        proof = prove_affine_value(left, right, 7, 0, 0, blinding_left, blinding_right)
        self.assertTrue(verify_affine_value(left, right, 7, 0, proof))
        self.assertFalse(verify_affine_value(left, right, 8, 0, proof))
        self.assertFalse(verify_affine_value(left, right, 7, 1, proof))

    def test_negative_and_zero_coefficients(self):
        left, blinding_left = _commit(-3, -10, 10)
        right, blinding_right = _commit(7, -100, 100)  # -2 * -3 + 1 == 7
        proof = prove_affine_value(left, right, -2, 1, -3, blinding_left, blinding_right)
        self.assertTrue(verify_affine_value(left, right, -2, 1, proof))

        zero_left, zero_blinding_left = _commit(5, 0, 9)
        zero_right, zero_blinding_right = _commit(42, 40, 50)
        zero_proof = prove_affine_value(
            zero_left, zero_right, 0, 42, 5, zero_blinding_left, zero_blinding_right
        )
        self.assertTrue(verify_affine_value(zero_left, zero_right, 0, 42, zero_proof))

    def test_negative_bounds_endpoints_and_single_point(self):
        left, blinding_left = _commit(-7, -7, 3)
        right, blinding_right = _commit(-19, -30, 13)  # 2 * -7 - 5 == -19
        proof = prove_affine_value(left, right, 2, -5, -7, blinding_left, blinding_right)
        self.assertTrue(verify_affine_value(left, right, 2, -5, proof))

        one_left, one_blinding_left = _commit(0, -5, 5)
        one_right, one_blinding_right = _commit(0, 0, 0)
        one_proof = prove_affine_value(
            one_left, one_right, 7, 0, 0, one_blinding_left, one_blinding_right
        )
        self.assertTrue(verify_affine_value(one_left, one_right, 7, 0, one_proof))

    def test_prove_value_errors_draw_no_randomness(self):
        cases = []
        illegal = PedersenCommitment(0, -10, 10, self.left.prime, self.left.generator, self.left.h)
        cases.append((illegal, self.right, 2, 3, 4, self.blinding_left, self.blinding_right))
        mismatched = _commit(11, -20, 23, generator=5)[0]
        cases.append((self.left, mismatched, 2, 3, 4, self.blinding_left, self.blinding_right))
        # empty candidate set: a == 0 and b outside the right range
        cases.append((self.left, self.right, 0, 99, 4, self.blinding_left, self.blinding_right))
        # oversized candidate set
        big_left, big_blinding_left = _commit(0, 0, 1000)
        big_right, big_blinding_right = _commit(0, 0, 2000)
        cases.append((big_left, big_right, 1, 0, 0, big_blinding_left, big_blinding_right))
        # x not a candidate
        cases.append((self.left, self.right, 2, 3, 10, self.blinding_left, self.blinding_right))
        # opening mismatch (wrong blinding)
        cases.append((self.left, self.right, 2, 3, 4, self.blinding_left, self.blinding_right + 1))
        for args in cases:
            draws = []

            def randbelow(upper, draws=draws):
                draws.append(upper)
                return 0

            with self.assertRaises(ValueError):
                prove_affine_value(*args, randbelow=randbelow)
            self.assertEqual(draws, [])

    def test_prove_type_errors(self):
        base = (self.left, self.right, 2, 3, 4, self.blinding_left, self.blinding_right)
        with self.assertRaises(TypeError):
            prove_affine_value("left", *base[1:])
        with self.assertRaises(TypeError):
            prove_affine_value(self.left, self.right, True, 3, 4, *base[5:])
        with self.assertRaises(TypeError):
            prove_affine_value(self.left, self.right, 2, 3, 4.0, *base[5:])
        with self.assertRaises(TypeError):
            prove_affine_value(*base, context="session-1")
        with self.assertRaises(TypeError):
            prove_affine_value(*base, randbelow=42)
        with self.assertRaises(TypeError):
            prove_affine_value(*base, randbelow=lambda upper: True)
        with self.assertRaises(ValueError):
            prove_affine_value(*base, randbelow=lambda upper: upper)

        class Boom(Exception):
            pass

        def boom(upper):
            raise Boom()

        with self.assertRaises(Boom):
            prove_affine_value(*base, randbelow=boom)

    def test_verify_type_errors_and_false_cases(self):
        args = (self.left, self.right, 2, 3, self.proof)
        with self.assertRaises(TypeError):
            verify_affine_value("left", *args[1:])
        with self.assertRaises(TypeError):
            verify_affine_value(self.left, self.right, 2.0, 3, self.proof)
        with self.assertRaises(TypeError):
            verify_affine_value(self.left, self.right, 2, True, self.proof)
        with self.assertRaises(TypeError):
            verify_affine_value(self.left, self.right, 2, 3, "proof")
        with self.assertRaises(TypeError):
            verify_affine_value(self.left, self.right, 2, 3, self.proof, context=1)
        bad_fields = PedersenCommitment(0, -10, 10, 2, 3, 4)
        self.assertFalse(verify_affine_value(bad_fields, self.right, 2, 3, self.proof))
        tampered = AffineValueProof(
            self.proof.t_left,
            self.proof.t_right,
            tuple((v + 1) % self.left.prime for v in self.proof.e),
            self.proof.s_left,
            self.proof.s_right,
        )
        self.assertFalse(
            verify_affine_value(self.left, self.right, 2, 3, tampered, context=b"session-1")
        )
        shortened = AffineValueProof(
            self.proof.t_left[:-1],
            self.proof.t_right,
            self.proof.e,
            self.proof.s_left,
            self.proof.s_right,
        )
        self.assertFalse(verify_affine_value(self.left, self.right, 2, 3, shortened))
        negative = AffineValueProof(
            self.proof.t_left,
            self.proof.t_right,
            self.proof.e,
            (-1,) + self.proof.s_left[1:],
            self.proof.s_right,
        )
        self.assertFalse(verify_affine_value(self.left, self.right, 2, 3, negative))

    def test_deterministic_under_same_random_sequence(self):
        first = prove_affine_value(
            self.left, self.right, 2, 3, 4,
            self.blinding_left, self.blinding_right,
            randbelow=_counter_randbelow(),
        )
        second = prove_affine_value(
            self.left, self.right, 2, 3, 4,
            self.blinding_left, self.blinding_right,
            randbelow=_counter_randbelow(),
        )
        self.assertEqual(first, second)
        self.assertTrue(verify_affine_value(self.left, self.right, 2, 3, first))


if __name__ == "__main__":
    unittest.main()
