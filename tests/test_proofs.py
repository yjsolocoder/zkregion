import unittest

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    Region,
    SchnorrProver,
    SchnorrVerifier,
    commit,
    commit_coordinate,
    verify_opening,
)

SMALL_PRIME = 104729  # a small prime keeps the group arithmetic readable in tests


def counter_randbelow(start: int = 1):
    state = {"value": start}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


class CommitmentTest(unittest.TestCase):
    def test_opens_with_the_returned_nonce(self):
        commitment, nonce = commit(b"value")
        self.assertTrue(verify_opening(commitment, b"value", nonce))

    def test_wrong_value_fails(self):
        commitment, nonce = commit(b"value")
        self.assertFalse(verify_opening(commitment, b"other", nonce))

    def test_wrong_nonce_fails(self):
        commitment, nonce = commit(b"value")
        self.assertFalse(verify_opening(commitment, b"value", nonce + b"\x00"))

    def test_same_value_different_nonce_differs(self):
        first, _ = commit(b"value")
        second, _ = commit(b"value")
        self.assertNotEqual(first, second)

    def test_explicit_nonce_is_deterministic(self):
        self.assertEqual(commit(b"v", nonce=b"n" * 16), commit(b"v", nonce=b"n" * 16))

    def test_empty_nonce_rejected(self):
        with self.assertRaises(ValueError):
            commit(b"value", nonce=b"")

    def test_coordinate_commitment(self):
        commitment, nonce = commit_coordinate(12, -34)
        self.assertTrue(verify_opening(commitment, b"12:-34", nonce))

    def test_coordinate_requires_integers(self):
        with self.assertRaises(TypeError):
            commit_coordinate(1.5, 2)


class SchnorrTest(unittest.TestCase):
    def setUp(self):
        self.prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3, randbelow=counter_randbelow())
        self.verifier = SchnorrVerifier(self.prover.public_key, prime=SMALL_PRIME, generator=3)

    def test_public_key_is_generator_power(self):
        self.assertEqual(self.prover.public_key, pow(3, 4321, SMALL_PRIME))

    def test_honest_response_verifies(self):
        commitment = self.prover.new_commitment()
        challenge = 12345
        self.assertTrue(self.verifier.verify(commitment, challenge, self.prover.respond(challenge)))

    def test_tampered_response_fails(self):
        commitment = self.prover.new_commitment()
        challenge = 999
        self.assertFalse(self.verifier.verify(commitment, challenge, self.prover.respond(challenge) + 1))

    def test_wrong_public_key_fails(self):
        commitment = self.prover.new_commitment()
        challenge = 999
        response = self.prover.respond(challenge)
        other = SchnorrVerifier(pow(3, 4322, SMALL_PRIME), prime=SMALL_PRIME, generator=3)
        self.assertFalse(other.verify(commitment, challenge, response))

    def test_respond_before_commitment_is_an_error(self):
        with self.assertRaises(RuntimeError):
            SchnorrProver(secret=7, prime=SMALL_PRIME, generator=3).respond(1)

    def test_each_commitment_uses_a_fresh_nonce(self):
        first = self.prover.new_commitment()
        self.prover.respond(1)
        second = self.prover.new_commitment()
        self.assertNotEqual(first, second)

    def test_secret_bounds(self):
        with self.assertRaises(ValueError):
            SchnorrProver(secret=0, prime=SMALL_PRIME, generator=3)
        with self.assertRaises(ValueError):
            SchnorrProver(secret=SMALL_PRIME, prime=SMALL_PRIME, generator=3)

    def test_public_key_bounds(self):
        with self.assertRaises(ValueError):
            SchnorrVerifier(0, prime=SMALL_PRIME, generator=3)

    def test_default_group_parameters_are_usable(self):
        prover = SchnorrProver(secret=123456789, randbelow=counter_randbelow())
        verifier = SchnorrVerifier(prover.public_key)
        commitment = prover.new_commitment()
        self.assertTrue(verifier.verify(commitment, 42, prover.respond(42)))
        self.assertEqual(DEFAULT_GENERATOR, 3)
        self.assertGreater(DEFAULT_PRIME, 123456789)


class RegionTest(unittest.TestCase):
    def test_inclusive_bounds(self):
        region = Region(0, 10, 0, 10)
        for x, y in ((0, 0), (10, 10), (5, 5)):
            self.assertTrue(region.contains(x, y))

    def test_outside_points(self):
        region = Region(0, 10, 0, 10)
        for x, y in ((-1, 5), (11, 5), (5, -1), (5, 11)):
            self.assertFalse(region.contains(x, y))

    def test_dimensions(self):
        self.assertEqual((Region(0, 9, 0, 4).width(), Region(0, 9, 0, 4).height()), (10, 5))

    def test_inverted_bounds_rejected(self):
        with self.assertRaises(ValueError):
            Region(10, 0, 0, 10)
        with self.assertRaises(ValueError):
            Region(0, 10, 10, 0)

    def test_non_integer_bounds_rejected(self):
        with self.assertRaises(TypeError):
            Region(0.0, 10, 0, 10)

    def test_non_integer_coordinates_rejected(self):
        with self.assertRaises(TypeError):
            Region(0, 10, 0, 10).contains(1.5, 2)


if __name__ == "__main__":
    unittest.main()
