import hashlib
import struct
import unittest
from dataclasses import replace

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    Region,
    SchnorrProof,
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


class SchnorrFiatShamirTest(unittest.TestCase):
    MESSAGE = b"region/42"

    def setUp(self):
        self.prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3, randbelow=counter_randbelow())
        self.verifier = SchnorrVerifier(self.prover.public_key, prime=SMALL_PRIME, generator=3)

    def _challenge(self, commitment, context=b"", message=MESSAGE, prime=SMALL_PRIME, generator=3, public_key=None):
        public_key = pow(generator, 4321, prime) if public_key is None else public_key

        def minimal(value):
            return value.to_bytes((value.bit_length() + 7) // 8, "big")

        digest = hashlib.sha256()
        digest.update(struct.pack(">I", len(b"zkregion/schnorr-fs/v1")) + b"zkregion/schnorr-fs/v1")
        for value in (prime, generator, public_key, commitment):
            data = minimal(value)
            digest.update(struct.pack(">I", len(data)) + data)
        digest.update(struct.pack(">I", len(context)) + context)
        digest.update(struct.pack(">I", len(message)) + message)
        return int.from_bytes(digest.digest(), "big") % prime

    def test_returns_a_schnorr_proof(self):
        proof = self.prover.prove(self.MESSAGE)
        self.assertIsInstance(proof, SchnorrProof)
        self.assertIsInstance(proof.commitment, int)
        self.assertIsInstance(proof.response, int)

    def test_honest_proof_verifies(self):
        proof = self.prover.prove(self.MESSAGE)
        self.assertTrue(self.verifier.verify_proof(self.MESSAGE, proof))

    def test_context_binds_the_proof(self):
        proof = self.prover.prove(self.MESSAGE, context=b"session-7")
        self.assertTrue(self.verifier.verify_proof(self.MESSAGE, proof, context=b"session-7"))
        self.assertFalse(self.verifier.verify_proof(self.MESSAGE, proof, context=b"session-8"))
        self.assertFalse(self.verifier.verify_proof(self.MESSAGE, proof))

    def test_wrong_message_fails(self):
        proof = self.prover.prove(self.MESSAGE)
        self.assertFalse(self.verifier.verify_proof(b"region/43", proof))

    def test_tampered_proof_fails(self):
        proof = self.prover.prove(self.MESSAGE)
        self.assertFalse(self.verifier.verify_proof(self.MESSAGE, replace(proof, response=proof.response + 1)))
        self.assertFalse(self.verifier.verify_proof(self.MESSAGE, replace(proof, commitment=proof.commitment + 1)))

    def test_wrong_public_key_fails(self):
        proof = self.prover.prove(self.MESSAGE)
        other = SchnorrVerifier(pow(3, 4322, SMALL_PRIME), prime=SMALL_PRIME, generator=3)
        self.assertFalse(other.verify_proof(self.MESSAGE, proof))

    def test_transcript_matches_spec(self):
        k = counter_randbelow()(SMALL_PRIME - 1) + 1
        prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3, randbelow=lambda upper: k - 1)
        proof = prover.prove(self.MESSAGE, context=b"ctx")
        commitment = pow(3, k, SMALL_PRIME)
        challenge = self._challenge(commitment, context=b"ctx")
        self.assertEqual(proof, SchnorrProof(commitment, k + challenge * 4321))

    def test_response_is_not_reduced_modulo_group_order(self):
        proof = self.prover.prove(self.MESSAGE)
        self.assertGreaterEqual(proof.response, SMALL_PRIME)

    def test_proof_is_frozen(self):
        proof = self.prover.prove(self.MESSAGE)
        with self.assertRaises(Exception):
            proof.commitment = 0

    def test_prove_uses_independent_nonce(self):
        prover = SchnorrProver(secret=7, prime=SMALL_PRIME, generator=3)
        verifier = SchnorrVerifier(prover.public_key, prime=SMALL_PRIME, generator=3)
        prover.prove(self.MESSAGE)
        self.assertIsNone(prover._nonce)
        with self.assertRaises(RuntimeError):
            prover.respond(1)
        commitment = prover.new_commitment()
        prover.respond(1)
        interactive_nonce = prover._nonce
        prover.prove(self.MESSAGE)
        self.assertEqual(prover._nonce, interactive_nonce)
        self.assertTrue(verifier.verify(commitment, 1, prover.respond(1)))

    def test_non_bytes_message_or_context_rejected(self):
        for bad in ("message", 1, bytearray(b"x"), None):
            with self.assertRaises(TypeError):
                self.prover.prove(bad)
            with self.assertRaises(TypeError):
                self.verifier.verify_proof(bad, self.prover.prove(self.MESSAGE))
            with self.assertRaises(TypeError):
                self.prover.prove(self.MESSAGE, context=bad)

    def test_proof_must_be_schnorr_proof(self):
        proof = self.prover.prove(self.MESSAGE)
        for bad in ((proof.commitment, proof.response), [proof.commitment, proof.response], None, object()):
            with self.assertRaises(TypeError):
                self.verifier.verify_proof(self.MESSAGE, bad)

    def test_proof_fields_must_be_integers(self):
        proof = self.prover.prove(self.MESSAGE)
        for bad_commitment, bad_response in (
            ("1", proof.response),
            (proof.commitment, 1.0),
            (None, proof.response),
            (proof.commitment, b"1"),
        ):
            with self.assertRaises(TypeError):
                self.verifier.verify_proof(self.MESSAGE, SchnorrProof(bad_commitment, bad_response))

    def test_commitment_out_of_range_returns_false(self):
        proof = self.prover.prove(self.MESSAGE)
        for commitment in (0, -1, SMALL_PRIME, SMALL_PRIME + 1):
            self.assertFalse(
                self.verifier.verify_proof(self.MESSAGE, replace(proof, commitment=commitment))
            )

    def test_negative_response_returns_false(self):
        proof = self.prover.prove(self.MESSAGE)
        self.assertFalse(self.verifier.verify_proof(self.MESSAGE, replace(proof, response=-1)))

    def test_default_group_parameters(self):
        prover = SchnorrProver(secret=123456789)
        verifier = SchnorrVerifier(prover.public_key)
        proof = prover.prove(self.MESSAGE, context=b"ctx")
        self.assertTrue(verifier.verify_proof(self.MESSAGE, proof, context=b"ctx"))
        self.assertFalse(verifier.verify_proof(b"other", proof, context=b"ctx"))


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
