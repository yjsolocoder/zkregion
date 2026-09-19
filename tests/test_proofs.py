import dataclasses
import hashlib
import unittest

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    MerkleMultiProof,
    MerkleProof,
    PedersenCommitment,
    RangeProof,
    Region,
    SchnorrBatchEntry,
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
    commit,
    commit_coordinate,
    merkle_root,
    pedersen_commit,
    prove_inclusion,
    prove_multi_inclusion,
    prove_range,
    verify_inclusion,
    verify_multi_inclusion,
    verify_opening,
    verify_pedersen_opening,
    verify_range,
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


class PedersenCommitmentTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5  # independent-looking small base; log_3(5) mod 104729 is not obvious

    def commit(self, value=50, lower=0, upper=100, blinding=1234, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    # ---- honest round trip -------------------------------------------------

    def test_honest_opening_verifies(self):
        commitment, blinding = self.commit()
        self.assertIsInstance(commitment, PedersenCommitment)
        self.assertTrue(verify_pedersen_opening(commitment, 50, blinding))

    def test_commitment_is_frozen(self):
        commitment, _ = self.commit()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            commitment.element = commitment.element + 1
        with self.assertRaises(dataclasses.FrozenInstanceError):
            commitment.lower = 1

    def test_element_is_g_to_the_offset_times_h_to_the_blinding(self):
        lower, value, blinding = 10, 73, 4242
        commitment, returned = self.commit(value=value, lower=lower, upper=100, blinding=blinding)
        self.assertEqual(returned, blinding)
        m = value - lower
        self.assertEqual(commitment.element, (pow(self.G, m, self.PRIME) * pow(self.H, blinding, self.PRIME)) % self.PRIME)
        self.assertEqual((commitment.lower, commitment.upper), (lower, 100))
        self.assertEqual((commitment.prime, commitment.generator, commitment.h), (self.PRIME, self.G, self.H))

    def test_inclusive_range_endpoints(self):
        low, _ = self.commit(value=0, lower=0, upper=100, blinding=7)
        high, high_r = self.commit(value=100, lower=0, upper=100, blinding=7)
        self.assertTrue(verify_pedersen_opening(low, 0, 7))
        self.assertTrue(verify_pedersen_opening(high, 100, high_r))
        # m = 0 at the lower endpoint: element reduces to h**r
        self.assertEqual(low.element, pow(self.H, 7, self.PRIME))

    def test_negative_coordinates_supported(self):
        commitment, blinding = self.commit(value=-250, lower=-500, upper=-100, blinding=99)
        self.assertTrue(verify_pedersen_opening(commitment, -250, blinding))

    def test_wrong_value_and_blinding_fail(self):
        commitment, blinding = self.commit()
        self.assertFalse(verify_pedersen_opening(commitment, 51, blinding))
        self.assertFalse(verify_pedersen_opening(commitment, 50, blinding + 1))
        self.assertFalse(verify_pedersen_opening(commitment, 49, blinding - 1))

    def test_wrong_element_fails_but_other_fields_pass_through(self):
        commitment, blinding = self.commit()
        tampered = dataclasses.replace(commitment, element=(commitment.element + 1) % self.PRIME)
        self.assertFalse(verify_pedersen_opening(tampered, 50, blinding))

    # ---- blinding generation ----------------------------------------------

    def test_random_blinding_is_drawn_from_randbelow(self):
        calls = []

        def recording(upper):
            calls.append(upper)
            return 555

        commitment, blinding = pedersen_commit(
            50, 0, 100, prime=self.PRIME, generator=self.G, h=self.H, randbelow=recording
        )
        self.assertEqual(calls, [self.PRIME - 2])
        self.assertEqual(blinding, 556)  # r = randbelow(prime - 2) + 1
        self.assertTrue(verify_pedersen_opening(commitment, 50, blinding))

    def test_blinding_is_in_required_range(self):
        seen = set()
        for _ in range(20):
            commitment, blinding = pedersen_commit(
                50, 0, 100, prime=self.PRIME, generator=self.G, h=self.H
            )
            self.assertTrue(1 <= blinding < self.PRIME - 1)
            seen.add(blinding)
        self.assertGreater(len(seen), 1)

    def test_explicit_blinding_endpoints(self):
        for blinding in (1, self.PRIME - 2):
            commitment, returned = self.commit(blinding=blinding)
            self.assertEqual(returned, blinding)
            self.assertTrue(verify_pedersen_opening(commitment, 50, blinding))

    def test_randbelow_not_called_when_blinding_given(self):
        def boom(upper):
            raise AssertionError("randbelow must not be called")

        self.commit(randbelow=boom)

    # ---- defaults ----------------------------------------------------------

    def test_default_group_parameters(self):
        commitment, blinding = pedersen_commit(10, 0, 100, blinding=987654321)
        self.assertEqual(commitment.prime, DEFAULT_PRIME)
        self.assertEqual(commitment.generator, DEFAULT_GENERATOR)
        self.assertEqual(commitment.h, pow(DEFAULT_GENERATOR, 2, DEFAULT_PRIME))
        self.assertTrue(verify_pedersen_opening(commitment, 10, blinding))

    def test_default_h_is_g_squared_and_breaks_binding(self):
        # h = g**2 => C = g**m * g**(2r): (value + 2, r - 1) is a second opening
        commitment, blinding = pedersen_commit(40, 0, 100, blinding=1000)
        self.assertEqual(commitment.h, 9)
        self.assertTrue(verify_pedersen_opening(commitment, 40, 1000))
        self.assertTrue(verify_pedersen_opening(commitment, 42, 999))
        self.assertTrue(verify_pedersen_opening(commitment, 38, 1001))

    # ---- parameter validation at commit time ------------------------------

    def test_commit_type_errors(self):
        for bad in (1.5, "50", True, False, None):
            with self.assertRaises(TypeError):
                self.commit(value=bad)
            with self.assertRaises(TypeError):
                self.commit(lower=bad)
            with self.assertRaises(TypeError):
                self.commit(upper=bad)
        for bad in (1.5, str(self.PRIME), True, None):
            with self.assertRaises(TypeError):
                self.commit(prime=bad)
            with self.assertRaises(TypeError):
                self.commit(generator=bad)
        # None for h/blinding explicitly selects the default, like omission
        for bad in (1.5, str(self.PRIME), True):
            with self.assertRaises(TypeError):
                self.commit(h=bad)
            with self.assertRaises(TypeError):
                self.commit(blinding=bad)
        default_h, _ = self.commit(h=None)
        self.assertEqual(default_h.h, pow(self.G, 2, self.PRIME))  # default h = g**2
        self.assertTrue(1 <= self.commit(blinding=None)[1] < self.PRIME - 1)

    def test_randbelow_must_be_callable(self):
        for bad in (7, 1.5, None, "randbelow"):
            with self.assertRaises(TypeError):
                pedersen_commit(50, 0, 100, prime=self.PRIME, generator=self.G, h=self.H, randbelow=bad)

    def test_randbelow_must_return_an_integer(self):
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                pedersen_commit(
                    50, 0, 100, prime=self.PRIME, generator=self.G, h=self.H,
                    randbelow=lambda upper, bad=bad: bad,
                )

    def test_randbelow_out_of_range_value_is_a_value_error(self):
        for bad in (-1, self.PRIME - 2, self.PRIME):
            with self.assertRaises(ValueError):
                pedersen_commit(
                    50, 0, 100, prime=self.PRIME, generator=self.G, h=self.H,
                    randbelow=lambda upper, bad=bad: bad,
                )

    def test_commit_value_errors(self):
        # inverted range
        with self.assertRaises(ValueError):
            self.commit(value=5, lower=100, upper=0)
        # value outside the range
        with self.assertRaises(ValueError):
            self.commit(value=-1, lower=0, upper=100)
        with self.assertRaises(ValueError):
            self.commit(value=101, lower=0, upper=100)
        # width >= prime - 1 (the offsets cannot all be represented distinctly)
        with self.assertRaises(ValueError):
            self.commit(value=0, lower=0, upper=self.PRIME - 1)
        with self.assertRaises(ValueError):
            self.commit(value=0, lower=0, upper=self.PRIME + 10)
        # prime must exceed 3
        with self.assertRaises(ValueError):
            self.commit(prime=3)
        with self.assertRaises(ValueError):
            self.commit(prime=2)
        # generator and h must lie strictly inside (1, prime)
        with self.assertRaises(ValueError):
            self.commit(generator=1)
        with self.assertRaises(ValueError):
            self.commit(generator=self.PRIME)
        with self.assertRaises(ValueError):
            self.commit(h=1)
        with self.assertRaises(ValueError):
            self.commit(h=self.PRIME)
        # blinding outside [1, prime - 1)
        with self.assertRaises(ValueError):
            self.commit(blinding=0)
        with self.assertRaises(ValueError):
            self.commit(blinding=-1)
        with self.assertRaises(ValueError):
            self.commit(blinding=self.PRIME - 1)
        with self.assertRaises(ValueError):
            self.commit(blinding=self.PRIME)

    def test_maximum_width_just_under_prime_minus_one_is_accepted(self):
        commitment, blinding = self.commit(value=1, lower=0, upper=self.PRIME - 2, blinding=2)
        self.assertTrue(verify_pedersen_opening(commitment, 1, blinding))

    def test_default_h_is_also_validated(self):
        # 6**2 % 7 == 1: the derived default h falls outside (1, prime)
        with self.assertRaises(ValueError):
            pedersen_commit(0, 0, 4, prime=7, generator=6, blinding=1)
        # 3**2 % 9 == 0: composite modulus can drive the default h to zero
        with self.assertRaises(ValueError):
            pedersen_commit(0, 0, 4, prime=9, generator=3, blinding=1)
        # a usable default h still works
        commitment, blinding = pedersen_commit(0, 0, 4, prime=7, generator=3, blinding=1)
        self.assertEqual(commitment.h, 2)
        self.assertTrue(verify_pedersen_opening(commitment, 0, blinding))

    # ---- verification validation ------------------------------------------

    def test_verify_type_errors(self):
        commitment, blinding = self.commit()
        with self.assertRaises(TypeError):
            verify_pedersen_opening((commitment.element, 0, 100), 50, blinding)
        with self.assertRaises(TypeError):
            verify_pedersen_opening("commitment", 50, blinding)
        for field in ("element", "lower", "upper", "prime", "generator", "h"):
            bad = dataclasses.replace(commitment, **{field: 1.5})
            with self.assertRaises(TypeError):
                verify_pedersen_opening(bad, 50, blinding)
            bad = dataclasses.replace(commitment, **{field: True})
            with self.assertRaises(TypeError):
                verify_pedersen_opening(bad, 50, blinding)
        for bad in (1.5, "50", True, False, None):
            with self.assertRaises(TypeError):
                verify_pedersen_opening(commitment, bad, blinding)
            with self.assertRaises(TypeError):
                verify_pedersen_opening(commitment, 50, bad)

    def test_verify_returns_false_for_bad_embedded_parameters(self):
        commitment, blinding = self.commit()
        # element outside the field
        for bad_element in (0, self.PRIME, self.PRIME + 1, -1):
            bad = dataclasses.replace(commitment, element=bad_element)
            self.assertFalse(verify_pedersen_opening(bad, 50, blinding))
        # bad group parameters embedded in the object
        for field, bad_value in (
            ("prime", 3),
            ("prime", 2),
            ("generator", 1),
            ("generator", self.PRIME),
            ("h", 1),
            ("h", self.PRIME),
        ):
            bad = dataclasses.replace(commitment, **{field: bad_value})
            self.assertFalse(verify_pedersen_opening(bad, 50, blinding), f"{field}={bad_value}")
        # inverted or too-wide embedded range
        self.assertFalse(
            verify_pedersen_opening(dataclasses.replace(commitment, lower=101), 50, blinding)
        )
        wide = dataclasses.replace(commitment, upper=self.PRIME - 1)
        self.assertFalse(verify_pedersen_opening(wide, 50, blinding))
        # blinding outside [1, prime - 1)
        for bad_blinding in (0, -1, self.PRIME - 1, self.PRIME):
            self.assertFalse(verify_pedersen_opening(commitment, 50, bad_blinding))

    def test_verify_value_outside_embedded_range_returns_false(self):
        commitment, blinding = self.commit()
        for bad_value in (-1, 101):
            self.assertFalse(verify_pedersen_opening(commitment, bad_value, blinding))

    def test_verify_uses_parameters_from_the_object(self):
        # a commitment under a second group must not verify against mismatched fields
        other_prime, other_g, other_h = 104723, 3, 7
        other, other_r = pedersen_commit(
            50, 0, 100, prime=other_prime, generator=other_g, h=other_h, blinding=1234
        )
        self.assertTrue(verify_pedersen_opening(other, 50, other_r))
        self.assertFalse(verify_pedersen_opening(other, 51, other_r))
        # swapping the element of the two groups invalidates the opening
        crossed = dataclasses.replace(other, element=self.commit()[0].element)
        self.assertFalse(verify_pedersen_opening(crossed, 50, other_r))

    def test_inputs_are_not_mutated(self):
        commitment, blinding = self.commit()
        snapshot = dataclasses.replace(commitment)
        value = 50
        verify_pedersen_opening(commitment, value, blinding)
        self.assertEqual(commitment, snapshot)
        self.assertEqual(value, 50)
        self.assertEqual(blinding, 1234)


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
    def setUp(self):
        self.prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3, randbelow=counter_randbelow())
        self.verifier = SchnorrVerifier(self.prover.public_key, prime=SMALL_PRIME, generator=3)

    def test_honest_proof_verifies(self):
        proof = self.prover.prove(b"message")
        self.assertIsInstance(proof, SchnorrProof)
        self.assertTrue(self.verifier.verify_proof(b"message", proof))

    def test_proof_is_immutable(self):
        proof = self.prover.prove(b"message")
        with self.assertRaises(AttributeError):
            proof.response = proof.response + 1

    def test_wrong_message_fails(self):
        proof = self.prover.prove(b"message")
        self.assertFalse(self.verifier.verify_proof(b"other", proof))

    def test_context_binds_proof(self):
        proof = self.prover.prove(b"message", context=b"ctx")
        self.assertTrue(self.verifier.verify_proof(b"message", proof, context=b"ctx"))
        self.assertFalse(self.verifier.verify_proof(b"message", proof))
        self.assertFalse(self.verifier.verify_proof(b"message", proof, context=b"other"))

    def test_tampered_response_fails(self):
        proof = self.prover.prove(b"message")
        tampered = SchnorrProof(commitment=proof.commitment, response=proof.response + 1)
        self.assertFalse(self.verifier.verify_proof(b"message", tampered))

    def test_wrong_public_key_fails(self):
        proof = self.prover.prove(b"message")
        other = SchnorrVerifier(pow(3, 4322, SMALL_PRIME), prime=SMALL_PRIME, generator=3)
        self.assertFalse(other.verify_proof(b"message", proof))

    def test_prove_does_not_touch_interactive_nonce(self):
        commitment = self.prover.new_commitment()
        self.prover.prove(b"message")
        self.assertTrue(self.verifier.verify(commitment, 7, self.prover.respond(7)))

    def test_response_matches_transcript_challenge(self):
        # recompute c from the transcript and confirm s == k + c * secret
        import hashlib

        draws = []
        base = counter_randbelow()

        def recording(upper):
            value = base(upper)
            draws.append(value)
            return value

        secret = 4321
        prover = SchnorrProver(secret=secret, prime=SMALL_PRIME, generator=3, randbelow=recording)
        proof = prover.prove(b"m", context=b"c")
        k = draws[0] + 1

        def encode(value):
            return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

        transcript = hashlib.sha256()
        for item in (
            b"zkregion/schnorr-fs/v1",
            encode(SMALL_PRIME),
            encode(3),
            encode(prover.public_key),
            encode(proof.commitment),
            b"c",
            b"m",
        ):
            transcript.update(len(item).to_bytes(4, "big"))
            transcript.update(item)
        c = int.from_bytes(transcript.digest(), "big") % SMALL_PRIME
        self.assertEqual(proof.response, k + c * secret)

    def test_out_of_range_commitment_returns_false(self):
        proof = self.prover.prove(b"message")
        for bad in (0, SMALL_PRIME, SMALL_PRIME + 1, -1):
            self.assertFalse(self.verifier.verify_proof(b"message", SchnorrProof(bad, proof.response)))

    def test_negative_response_returns_false(self):
        proof = self.prover.prove(b"message")
        self.assertFalse(self.verifier.verify_proof(b"message", SchnorrProof(proof.commitment, -1)))

    def test_type_checks(self):
        proof = self.prover.prove(b"message")
        with self.assertRaises(TypeError):
            self.prover.prove("message")
        with self.assertRaises(TypeError):
            self.prover.prove(b"message", context="ctx")
        with self.assertRaises(TypeError):
            self.verifier.verify_proof("message", proof)
        with self.assertRaises(TypeError):
            self.verifier.verify_proof(b"message", proof, context="ctx")
        with self.assertRaises(TypeError):
            self.verifier.verify_proof(b"message", (proof.commitment, proof.response))
        with self.assertRaises(TypeError):
            self.verifier.verify_proof(b"message", SchnorrProof(1.5, proof.response))
        with self.assertRaises(TypeError):
            self.verifier.verify_proof(b"message", SchnorrProof(proof.commitment, "s"))

    def test_default_group_parameters_are_usable(self):
        prover = SchnorrProver(secret=123456789, randbelow=counter_randbelow())
        verifier = SchnorrVerifier(prover.public_key)
        proof = prover.prove(b"offline", context=b"demo")
        self.assertTrue(verifier.verify_proof(b"offline", proof, context=b"demo"))


class SchnorrBatchTest(unittest.TestCase):
    def setUp(self):
        self.prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3, randbelow=counter_randbelow())
        self.verifier = SchnorrVerifier(self.prover.public_key, prime=SMALL_PRIME, generator=3)

    def entry(self, message=b"message", *, context=b"ctx"):
        return SchnorrBatchEntry(message, self.prover.prove(message, context=context), context)

    def test_entry_defaults_and_immutability(self):
        proof = self.prover.prove(b"m")
        entry = SchnorrBatchEntry(b"m", proof)
        self.assertEqual(entry.context, b"")
        self.assertEqual((entry.message, entry.proof), (b"m", proof))
        with self.assertRaises(AttributeError):
            entry.message = b"other"

    def test_honest_batch_verifies(self):
        entries = [self.entry(b"alpha"), self.entry(b"beta"), self.entry(b"gamma")]
        self.assertTrue(self.verifier.verify_batch(entries, randbelow=counter_randbelow()))
        self.assertTrue(self.verifier.verify_batch(entries))  # default secrets.randbelow
        self.assertTrue(self.verifier.verify_batch(tuple(entries), randbelow=counter_randbelow()))

    def test_single_entry_agrees_with_verify_proof(self):
        entry = self.entry()
        self.assertTrue(self.verifier.verify_batch([entry], randbelow=counter_randbelow()))
        self.assertTrue(self.verifier.verify_proof(entry.message, entry.proof, context=entry.context))

    def test_empty_batch_returns_false(self):
        self.assertFalse(self.verifier.verify_batch([]))
        self.assertFalse(self.verifier.verify_batch(()))

    def test_duplicate_entries_each_draw_a_coefficient(self):
        entry = self.entry()
        calls = []

        def recording(upper):
            calls.append(upper)
            return counter_randbelow()(upper)

        self.assertTrue(self.verifier.verify_batch([entry, entry, entry], randbelow=recording))
        self.assertEqual(calls, [SMALL_PRIME - 1] * 3)

    def test_randbelow_called_once_per_entry_with_prime_minus_one(self):
        entries = [self.entry(b"a"), self.entry(b"b")]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(self.verifier.verify_batch(entries, randbelow=recording))
        self.assertEqual(calls, [SMALL_PRIME - 1, SMALL_PRIME - 1])

    def test_fixed_coefficient_source_is_reproducible(self):
        entries = [self.entry(b"a"), self.entry(b"b")]
        first = self.verifier.verify_batch(entries, randbelow=counter_randbelow(9))
        second = self.verifier.verify_batch(entries, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_random_linear_combination_not_per_item_summary(self):
        # coefficients all 1: two individually invalid proofs whose response
        # errors cancel must still satisfy the aggregate equation
        first, second = self.entry(b"a"), self.entry(b"b")
        forged = [
            SchnorrBatchEntry(b"a", SchnorrProof(first.proof.commitment, first.proof.response + 1), b"ctx"),
            SchnorrBatchEntry(b"b", SchnorrProof(second.proof.commitment, second.proof.response - 1), b"ctx"),
        ]
        for entry in forged:
            self.assertFalse(self.verifier.verify_proof(entry.message, entry.proof, context=b"ctx"))
        self.assertTrue(self.verifier.verify_batch(forged, randbelow=lambda upper: 0))

    def test_tampering_fails(self):
        entries = [self.entry(b"alpha"), self.entry(b"beta")]
        good = entries[1]
        forged = SchnorrProof(good.proof.commitment, good.proof.response + 1)
        cases = [
            [entries[0], SchnorrBatchEntry(b"beta", forged, b"ctx")],          # tampered response
            [entries[0], SchnorrBatchEntry(b"beta", SchnorrProof(entries[0].proof.commitment, good.proof.response), b"ctx")],  # foreign commitment
            [entries[0], SchnorrBatchEntry(b"other", good.proof, b"ctx")],     # wrong message
            [entries[0], SchnorrBatchEntry(b"beta", good.proof, b"other")],    # wrong context
            [entries[0], SchnorrBatchEntry(b"beta", good.proof)],              # missing context
        ]
        for batch in cases:
            self.assertFalse(
                self.verifier.verify_batch(batch, randbelow=counter_randbelow()),
                f"batch accepted: {batch!r}",
            )

    def test_wrong_public_key_fails(self):
        entries = [self.entry(b"a"), self.entry(b"b")]
        other = SchnorrVerifier(pow(3, 4322, SMALL_PRIME), prime=SMALL_PRIME, generator=3)
        self.assertFalse(other.verify_batch(entries, randbelow=counter_randbelow()))

    def test_structurally_invalid_proofs_return_false(self):
        entry = self.entry()
        for bad_commitment in (0, SMALL_PRIME, SMALL_PRIME + 1, -1):
            bad = SchnorrBatchEntry(entry.message, SchnorrProof(bad_commitment, entry.proof.response), entry.context)
            self.assertFalse(self.verifier.verify_batch([bad], randbelow=counter_randbelow()))
        negative = SchnorrBatchEntry(entry.message, SchnorrProof(entry.proof.commitment, -1), entry.context)
        self.assertFalse(self.verifier.verify_batch([negative], randbelow=counter_randbelow()))

    def test_invalid_proof_short_circuits(self):
        valid, invalid = self.entry(b"a"), self.entry()
        invalid = SchnorrBatchEntry(invalid.message, SchnorrProof(0, invalid.proof.response), invalid.context)
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertFalse(self.verifier.verify_batch([invalid, valid], randbelow=recording))
        self.assertEqual(calls, [])  # no coefficient drawn before the invalid entry
        self.assertFalse(self.verifier.verify_batch([valid, invalid], randbelow=recording))
        self.assertEqual(calls, [SMALL_PRIME - 1])  # one call per valid entry

    def test_type_errors(self):
        entry = self.entry()
        for bad in ("entries", b"entries", bytearray(b"x"), 42, None):
            with self.assertRaises(TypeError):
                self.verifier.verify_batch(bad)
        with self.assertRaises(TypeError):
            self.verifier.verify_batch([(entry.message, entry.proof)])
        with self.assertRaises(TypeError):
            self.verifier.verify_batch([SchnorrBatchEntry("message", entry.proof)])
        with self.assertRaises(TypeError):
            self.verifier.verify_batch([SchnorrBatchEntry(b"m", entry.proof, "ctx")])
        with self.assertRaises(TypeError):
            self.verifier.verify_batch([SchnorrBatchEntry(b"m", (entry.proof.commitment, entry.proof.response))])
        for bad_proof in (
            SchnorrProof(1.5, entry.proof.response),
            SchnorrProof(entry.proof.commitment, "s"),
            SchnorrProof(True, entry.proof.response),
            SchnorrProof(entry.proof.commitment, False),
        ):
            with self.assertRaises(TypeError):
                self.verifier.verify_batch([SchnorrBatchEntry(b"m", bad_proof)])
        with self.assertRaises(TypeError):
            self.verifier.verify_batch([entry], randbelow=7)

    def test_coefficient_source_errors(self):
        entries = [self.entry()]
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                self.verifier.verify_batch(entries, randbelow=lambda upper, bad=bad: bad)
        for bad in (-1, SMALL_PRIME - 1, SMALL_PRIME):
            with self.assertRaises(ValueError):
                self.verifier.verify_batch(entries, randbelow=lambda upper, bad=bad: bad)

    def test_batch_verification_does_not_touch_interactive_nonce(self):
        commitment = self.prover.new_commitment()
        self.assertTrue(self.verifier.verify_batch([self.entry()], randbelow=counter_randbelow()))
        self.assertTrue(self.verifier.verify(commitment, 7, self.prover.respond(7)))

    def test_inputs_are_not_mutated(self):
        entries = [self.entry(b"a"), self.entry(b"b")]
        snapshot = list(entries)
        self.verifier.verify_batch(entries, randbelow=counter_randbelow())
        self.assertEqual(entries, snapshot)

    def test_default_group_parameters_are_usable(self):
        prover = SchnorrProver(secret=123456789, randbelow=counter_randbelow())
        verifier = SchnorrVerifier(prover.public_key)
        entries = [
            SchnorrBatchEntry(b"one", prover.prove(b"one", context=b"demo"), context=b"demo"),
            SchnorrBatchEntry(b"two", prover.prove(b"two", context=b"demo"), context=b"demo"),
        ]
        self.assertTrue(verifier.verify_batch(entries, randbelow=counter_randbelow()))


def leaf_digest(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + len(leaf).to_bytes(4, "big") + leaf).digest()


def node_digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTest(unittest.TestCase):
    LEAVES = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]

    def test_single_leaf_root_is_leaf_digest_with_empty_path(self):
        self.assertEqual(merkle_root([b"only"]), leaf_digest(b"only"))
        proof = prove_inclusion([b"only"], 0)
        self.assertEqual(proof, MerkleProof(index=0, siblings=()))
        self.assertTrue(verify_inclusion(b"only", proof, merkle_root([b"only"])))

    def test_root_matches_manual_two_layer_construction(self):
        h01 = node_digest(leaf_digest(b"alpha"), leaf_digest(b"beta"))
        h23 = node_digest(leaf_digest(b"gamma"), leaf_digest(b"delta"))
        self.assertEqual(merkle_root(self.LEAVES[:4]), node_digest(h01, h23))

    def test_odd_layer_duplicates_last_node(self):
        ha = leaf_digest(b"a")
        hb = leaf_digest(b"b")
        hc = leaf_digest(b"c")
        expected = node_digest(node_digest(ha, hb), node_digest(hc, hc))
        self.assertEqual(merkle_root([b"a", b"b", b"c"]), expected)

    def test_leaf_length_prefix_is_four_byte_big_endian(self):
        leaf = b"x" * 300
        expected = hashlib.sha256(b"\x00" + (300).to_bytes(4, "big") + leaf).digest()
        self.assertEqual(merkle_root([leaf]), expected)

    def test_every_leaf_proves_against_the_root(self):
        root = merkle_root(self.LEAVES)
        for index, leaf in enumerate(self.LEAVES):
            proof = prove_inclusion(self.LEAVES, index)
            self.assertIsInstance(proof.siblings, tuple)
            self.assertEqual(proof.index, index)
            self.assertEqual(len(proof.siblings), 3)  # 5 leaves -> 3 levels
            self.assertTrue(verify_inclusion(leaf, proof, root))

    def test_duplicate_leaves_are_located_by_index(self):
        leaves = [b"same", b"other", b"same"]
        root = merkle_root(leaves)
        first = prove_inclusion(leaves, 0)
        second = prove_inclusion(leaves, 2)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_inclusion(b"same", first, root))
        self.assertTrue(verify_inclusion(b"same", second, root))
        # each proof only works at its own index
        self.assertFalse(verify_inclusion(b"same", MerkleProof(2, first.siblings), root))

    def test_proof_is_immutable(self):
        proof = prove_inclusion(self.LEAVES, 1)
        with self.assertRaises(AttributeError):
            proof.index = 3

    def test_empty_tree_rejected(self):
        with self.assertRaises(ValueError):
            merkle_root([])
        with self.assertRaises(ValueError):
            prove_inclusion([], 0)

    def test_leaf_type_errors(self):
        for bad in (b"not-a-sequence-of-leaves", "text", 42, None):
            with self.assertRaises(TypeError):
                merkle_root(bad)
        for bad_item in ("text", 7, None, bytearray(b"x")):
            with self.assertRaises(TypeError):
                merkle_root([b"ok", bad_item])
        with self.assertRaises(TypeError):
            prove_inclusion([b"ok", 7], 0)

    def test_index_errors(self):
        with self.assertRaises(IndexError):
            prove_inclusion(self.LEAVES, len(self.LEAVES))
        with self.assertRaises(IndexError):
            prove_inclusion(self.LEAVES, -1)
        for bad in (1.0, "0", None):
            with self.assertRaises(TypeError):
                prove_inclusion(self.LEAVES, bad)

    def test_tampered_leaf_index_path_and_root_all_fail(self):
        root = merkle_root(self.LEAVES)
        proof = prove_inclusion(self.LEAVES, 2)
        self.assertFalse(verify_inclusion(b"other", proof, root))
        self.assertFalse(verify_inclusion(b"gamma", MerkleProof(3, proof.siblings), root))
        swapped = MerkleProof(2, (proof.siblings[1], proof.siblings[0], proof.siblings[2]))
        self.assertFalse(verify_inclusion(b"gamma", swapped, root))
        flipped = MerkleProof(2, proof.siblings[:-1] + (proof.siblings[-1][::-1],))
        self.assertFalse(verify_inclusion(b"gamma", flipped, root))
        self.assertFalse(verify_inclusion(b"gamma", proof, merkle_root(self.LEAVES[:4])))

    def test_verify_type_and_shape_checks(self):
        root = merkle_root(self.LEAVES)
        proof = prove_inclusion(self.LEAVES, 2)
        with self.assertRaises(TypeError):
            verify_inclusion("gamma", proof, root)
        with self.assertRaises(TypeError):
            verify_inclusion(b"gamma", proof, "root")
        with self.assertRaises(TypeError):
            verify_inclusion(b"gamma", (2, proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_inclusion(b"gamma", MerkleProof(2.0, proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_inclusion(b"gamma", MerkleProof(2, list(proof.siblings)), root)
        with self.assertRaises(TypeError):
            verify_inclusion(b"gamma", MerkleProof(2, (proof.siblings[0], "x", proof.siblings[2])), root)
        # wrong digest lengths and negative index return False, not exceptions
        self.assertFalse(verify_inclusion(b"gamma", proof, root[:-1]))
        self.assertFalse(verify_inclusion(b"gamma", proof, root + b"\x00"))
        self.assertFalse(verify_inclusion(b"gamma", MerkleProof(-1, proof.siblings), root))
        short = MerkleProof(2, (proof.siblings[0][:16],) + proof.siblings[1:])
        self.assertFalse(verify_inclusion(b"gamma", short, root))
        # index deeper than the path allows
        self.assertFalse(verify_inclusion(b"gamma", MerkleProof(8, proof.siblings), root))

    def test_inputs_are_not_mutated(self):
        leaves = list(self.LEAVES)
        snapshot = list(leaves)
        root = merkle_root(leaves)
        proof = prove_inclusion(leaves, 1)
        verify_inclusion(leaves[1], proof, root)
        self.assertEqual(leaves, snapshot)
        self.assertEqual(proof.siblings, prove_inclusion(snapshot, 1).siblings)

    def test_tuple_leaves_accepted(self):
        self.assertEqual(merkle_root(tuple(self.LEAVES)), merkle_root(self.LEAVES))


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


class MerkleMultiProofTest(unittest.TestCase):
    LEAVES = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]

    def entries(self, leaves, indices):
        return [(index, leaves[index]) for index in indices]

    def test_roundtrip_for_every_subset(self):
        # exhaustive over all non-empty subsets of a 5-leaf (odd) tree
        root = merkle_root(self.LEAVES)
        for mask in range(1, 1 << len(self.LEAVES)):
            indices = tuple(i for i in range(len(self.LEAVES)) if mask & (1 << i))
            proof = prove_multi_inclusion(self.LEAVES, indices)
            self.assertIsInstance(proof, MerkleMultiProof)
            self.assertEqual(proof.leaf_count, len(self.LEAVES))
            self.assertEqual(proof.indices, indices)
            self.assertIsInstance(proof.siblings, tuple)
            self.assertTrue(
                verify_multi_inclusion(self.entries(self.LEAVES, indices), proof, root),
                f"subset {indices} failed",
            )

    def test_roundtrip_across_tree_sizes(self):
        for size in range(1, 10):
            leaves = [f"leaf-{i}".encode() for i in range(size)]
            root = merkle_root(leaves)
            for indices in ((0,), (size - 1,), tuple(sorted({0, size - 1})), tuple(range(size))):
                proof = prove_multi_inclusion(leaves, indices)
                self.assertTrue(
                    verify_multi_inclusion(self.entries(leaves, indices), proof, root),
                    f"size={size} indices={indices}",
                )

    def test_single_leaf_tree(self):
        proof = prove_multi_inclusion([b"only"], (0,))
        self.assertEqual(proof, MerkleMultiProof(leaf_count=1, indices=(0,), siblings=()))
        self.assertTrue(verify_multi_inclusion([(0, b"only")], proof, merkle_root([b"only"])))

    def test_full_leaf_proof_has_empty_siblings(self):
        for size in range(1, 9):
            leaves = [f"leaf-{i}".encode() for i in range(size)]
            proof = prove_multi_inclusion(leaves, range(size))
            self.assertEqual(proof.siblings, ())
            self.assertTrue(
                verify_multi_inclusion(list(enumerate(leaves)), proof, merkle_root(leaves))
            )

    def test_proof_is_deterministic(self):
        first = prove_multi_inclusion(self.LEAVES, (0, 2, 4))
        second = prove_multi_inclusion(self.LEAVES, (0, 2, 4))
        self.assertEqual(first, second)

    def test_proof_is_minimal_and_matches_manual_layout(self):
        # three leaves: prove indices 0 and 2; only H(beta) is needed,
        # index 2 duplicates itself at the first level
        leaves = [b"a", b"b", b"c"]
        proof = prove_multi_inclusion(leaves, (0, 2))
        self.assertEqual(proof.siblings, (leaf_digest(b"b"),))
        self.assertTrue(
            verify_multi_inclusion([(0, b"a"), (2, b"c")], proof, merkle_root(leaves))
        )

    def test_shared_sibling_is_collected_once(self):
        # adjacent pair shares its parent: only the other subtree root is needed
        leaves = [b"a", b"b", b"c", b"d"]
        proof = prove_multi_inclusion(leaves, (0, 1))
        self.assertEqual(
            proof.siblings,
            (node_digest(leaf_digest(b"c"), leaf_digest(b"d")),),
        )

    def test_multi_proof_agrees_with_single_proofs(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, (1, 3))
        self.assertTrue(verify_multi_inclusion(self.entries(self.LEAVES, (1, 3)), proof, root))
        for index in (1, 3):
            single = prove_inclusion(self.LEAVES, index)
            self.assertTrue(verify_inclusion(self.LEAVES[index], single, root))

    def test_proof_is_immutable(self):
        proof = prove_multi_inclusion(self.LEAVES, (1, 3))
        with self.assertRaises(AttributeError):
            proof.indices = (0,)

    def test_prove_type_errors(self):
        with self.assertRaises(TypeError):
            prove_multi_inclusion(b"not-a-sequence", (0,))
        with self.assertRaises(TypeError):
            prove_multi_inclusion([b"ok", 7], (0,))
        for bad in (b"\x00", "0", 1, None):
            with self.assertRaises(TypeError):
                prove_multi_inclusion(self.LEAVES, bad)
        for bad_index in (1.0, "0", None, True):
            with self.assertRaises(TypeError):
                prove_multi_inclusion(self.LEAVES, (0, bad_index))

    def test_prove_value_errors(self):
        with self.assertRaises(ValueError):
            prove_multi_inclusion(self.LEAVES, ())
        with self.assertRaises(ValueError):
            prove_multi_inclusion(self.LEAVES, [])
        with self.assertRaises(ValueError):
            prove_multi_inclusion(self.LEAVES, (1, 1))
        with self.assertRaises(ValueError):
            prove_multi_inclusion(self.LEAVES, (2, 0))
        with self.assertRaises(ValueError):
            prove_multi_inclusion([], (0,))

    def test_prove_index_errors(self):
        with self.assertRaises(IndexError):
            prove_multi_inclusion(self.LEAVES, (len(self.LEAVES),))
        with self.assertRaises(IndexError):
            prove_multi_inclusion(self.LEAVES, (-1,))
        with self.assertRaises(IndexError):
            prove_multi_inclusion(self.LEAVES, (0, len(self.LEAVES)))

    def test_verify_type_errors(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, (1, 3))
        entries = self.entries(self.LEAVES, (1, 3))
        with self.assertRaises(TypeError):
            verify_multi_inclusion("entries", proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([(1, "beta"), (3, "delta")], proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([(1.0, b"beta"), (3, b"delta")], proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([(True, b"beta"), (3, b"delta")], proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([(1, b"beta", b"extra"), (3, b"delta")], proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, proof, "root")
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, (1, 3), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(True, (1, 3), proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5, [1, 3], proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 3.0), proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 3), list(proof.siblings)), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(
                entries, MerkleMultiProof(5, (1, 3), proof.siblings + ("x",)), root
            )

    def test_verify_shape_errors_return_false(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, (1, 3))
        entries = self.entries(self.LEAVES, (1, 3))
        # empty or mismatched entries
        self.assertFalse(verify_multi_inclusion([], proof, root))
        self.assertFalse(verify_multi_inclusion(entries[:1], proof, root))
        self.assertFalse(verify_multi_inclusion(entries + [(4, b"epsilon")], proof, root))
        self.assertFalse(verify_multi_inclusion([(1, b"beta"), (2, b"gamma")], proof, root))
        self.assertFalse(verify_multi_inclusion([entries[1], entries[0]], proof, root))
        # malformed proof fields
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(0, (1, 3), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(-2, (1, 3), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (3, 1), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 1), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 5), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (-1, 3), proof.siblings), root))
        # digest length errors
        self.assertFalse(verify_multi_inclusion(entries, proof, root[:-1]))
        self.assertFalse(verify_multi_inclusion(entries, proof, root + b"\x00"))
        short = MerkleMultiProof(5, (1, 3), (proof.siblings[0][:16],) + proof.siblings[1:])
        self.assertFalse(verify_multi_inclusion(entries, short, root))
        # sibling count mismatch in either direction
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 3), proof.siblings[:-1]), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 3), proof.siblings + (root,)), root))

    def test_verify_tampering_fails(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, (1, 3))
        entries = self.entries(self.LEAVES, (1, 3))
        self.assertFalse(verify_multi_inclusion([(1, b"beta"), (3, b"other")], proof, root))
        flipped = MerkleMultiProof(5, (1, 3), proof.siblings[:-1] + (proof.siblings[-1][::-1],))
        self.assertFalse(verify_multi_inclusion(entries, flipped, root))
        self.assertFalse(verify_multi_inclusion(entries, proof, merkle_root(self.LEAVES[:4])))
        # a proof for a different subset must not validate these entries
        other = prove_multi_inclusion(self.LEAVES, (1, 2))
        self.assertFalse(verify_multi_inclusion(entries, other, root))

    def test_inputs_are_not_mutated(self):
        leaves = list(self.LEAVES)
        indices = [1, 3]
        entries = self.entries(leaves, indices)
        snapshot = (list(leaves), list(indices), list(entries))
        proof = prove_multi_inclusion(leaves, indices)
        verify_multi_inclusion(entries, proof, merkle_root(leaves))
        self.assertEqual((leaves, indices, entries), snapshot)


def range_transcript_challenge(commitment, size, t, context):
    """Independent recomputation of the range-proof Fiat-Shamir challenge."""
    items = [b"zkregion/pedersen-range/v1"]
    items += [
        str(field).encode("ascii")
        for field in (
            commitment.element,
            commitment.lower,
            commitment.upper,
            commitment.prime,
            commitment.generator,
            commitment.h,
        )
    ]
    items.append(context)
    items.append(str(size).encode("ascii"))
    items += [str(item).encode("ascii") for item in t]
    transcript = hashlib.sha256()
    for item in items:
        transcript.update(len(item).to_bytes(4, "big"))
        transcript.update(item)
    return int.from_bytes(transcript.digest(), "big") % commitment.prime


class RangeProofTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def commit(self, value=50, lower=0, upper=100, blinding=1234, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def prove(self, value=50, lower=0, upper=100, blinding=1234, context=b"", **kwargs):
        commitment, returned = self.commit(value, lower, upper, blinding, **kwargs)
        proof = prove_range(
            commitment, value, returned, context, randbelow=counter_randbelow()
        )
        return commitment, returned, proof

    # ---- honest round trip -------------------------------------------------

    def test_honest_proof_verifies(self):
        commitment, _, proof = self.prove()
        self.assertIsInstance(proof, RangeProof)
        self.assertTrue(verify_range(commitment, proof))

    def test_every_value_in_range_proves(self):
        for value in (0, 1, 50, 99, 100):
            commitment, blinding = self.commit(value=value)
            proof = prove_range(commitment, value, blinding, randbelow=counter_randbelow())
            self.assertTrue(verify_range(commitment, proof), f"value={value}")

    def test_single_integer_range(self):
        commitment, _, proof = self.prove(value=7, lower=7, upper=7)
        self.assertEqual(len(proof.t), 1)
        self.assertTrue(verify_range(commitment, proof))

    def test_maximum_256_integers_accepted(self):
        commitment, _, proof = self.prove(value=100, lower=0, upper=255)
        self.assertEqual(len(proof.t), 256)
        self.assertTrue(verify_range(commitment, proof))

    def test_257_integers_rejected(self):
        commitment, blinding = self.commit(value=0, lower=0, upper=256)
        with self.assertRaises(ValueError):
            prove_range(commitment, 0, blinding, randbelow=counter_randbelow())
        # verification of an oversized range returns False, never raises
        self.assertFalse(verify_range(commitment, RangeProof((), (), ())))

    def test_proof_shape_and_field_types(self):
        commitment, _, proof = self.prove()
        self.assertEqual(len(proof.t), len(proof.e), 101)
        self.assertEqual(len(proof.s), 101)
        for field in (proof.t, proof.e, proof.s):
            self.assertIsInstance(field, tuple)
            self.assertTrue(all(isinstance(item, int) for item in field))
        self.assertTrue(all(1 <= item < self.PRIME for item in proof.t))
        self.assertTrue(all(0 <= item < self.PRIME for item in proof.e))
        self.assertTrue(all(item >= 0 for item in proof.s))

    def test_proof_is_immutable(self):
        _, _, proof = self.prove()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.s = proof.s

    def test_challenge_shares_sum_to_transcript_challenge(self):
        commitment, _, proof = self.prove(context=b"ctx")
        c = range_transcript_challenge(commitment, 101, proof.t, b"ctx")
        self.assertEqual(sum(proof.e) % self.PRIME, c)

    def test_fixed_randbelow_is_reproducible(self):
        commitment, blinding = self.commit()
        first = prove_range(commitment, 50, blinding, randbelow=counter_randbelow())
        second = prove_range(commitment, 50, blinding, randbelow=counter_randbelow())
        self.assertEqual(first, second)

    def test_default_group_parameters_are_usable(self):
        commitment, blinding = pedersen_commit(10, 0, 20, blinding=987654321)
        proof = prove_range(commitment, 10, blinding, randbelow=counter_randbelow())
        self.assertTrue(verify_range(commitment, proof))

    # ---- prover validation -------------------------------------------------

    def test_prove_requires_a_valid_opening(self):
        commitment, blinding = self.commit()
        with self.assertRaises(ValueError):
            prove_range(commitment, 51, blinding)  # wrong value
        with self.assertRaises(ValueError):
            prove_range(commitment, 50, blinding + 1)  # wrong blinding

    def test_prove_type_errors(self):
        commitment, blinding = self.commit()
        with self.assertRaises(TypeError):
            prove_range((commitment.element, 0, 100), 50, blinding)
        for bad in (1.5, "50", True, None):
            with self.assertRaises(TypeError):
                prove_range(commitment, bad, blinding)
            with self.assertRaises(TypeError):
                prove_range(commitment, 50, bad)
        with self.assertRaises(TypeError):
            prove_range(commitment, 50, blinding, context="ctx")
        with self.assertRaises(TypeError):
            prove_range(commitment, 50, blinding, randbelow=7)
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                prove_range(
                    commitment, 50, blinding, randbelow=lambda upper, bad=bad: bad
                )
        for bad in (-1, self.PRIME):
            with self.assertRaises(ValueError):
                prove_range(
                    commitment, 50, blinding, randbelow=lambda upper, bad=bad: bad
                )

    # ---- verification failures ---------------------------------------------

    def test_tampering_fails(self):
        commitment, _, proof = self.prove(context=b"ctx")
        cases = [
            RangeProof((proof.t[0] % (self.PRIME - 1) + 1,) + proof.t[1:], proof.e, proof.s),
            RangeProof(proof.t, (proof.e[0] + 1,) + proof.e[1:], proof.s),
            RangeProof(proof.t, proof.e, (proof.s[0] + 1,) + proof.s[1:]),
            RangeProof(proof.t[::-1], proof.e, proof.s),
        ]
        for tampered in cases:
            self.assertFalse(verify_range(commitment, tampered, context=b"ctx"))

    def test_context_binds_proof(self):
        commitment, _, proof = self.prove(context=b"ctx")
        self.assertTrue(verify_range(commitment, proof, context=b"ctx"))
        self.assertFalse(verify_range(commitment, proof))
        self.assertFalse(verify_range(commitment, proof, context=b"other"))

    def test_proof_does_not_transfer_to_other_commitments(self):
        _, _, proof = self.prove()
        other, _ = self.commit(value=50, blinding=4321)
        self.assertFalse(verify_range(other, proof))
        shifted, _ = self.commit(value=51)
        self.assertFalse(verify_range(shifted, proof))

    def test_structural_failures_return_false(self):
        commitment, _, proof = self.prove()
        # wrong branch counts
        self.assertFalse(verify_range(commitment, RangeProof((), (), ())))
        self.assertFalse(
            verify_range(commitment, RangeProof(proof.t[:-1], proof.e, proof.s))
        )
        self.assertFalse(
            verify_range(commitment, RangeProof(proof.t, proof.e, proof.s + (0,)))
        )
        # t outside [1, prime)
        for bad in (0, self.PRIME, -1):
            tampered = RangeProof((bad,) + proof.t[1:], proof.e, proof.s)
            self.assertFalse(verify_range(commitment, tampered))
        # e outside [0, prime)
        for bad in (-1, self.PRIME):
            tampered = RangeProof(proof.t, (bad,) + proof.e[1:], proof.s)
            self.assertFalse(verify_range(commitment, tampered))
        # negative response
        tampered = RangeProof(proof.t, proof.e, (-1,) + proof.s[1:])
        self.assertFalse(verify_range(commitment, tampered))
        # bad embedded commitment fields
        for field, bad_value in (
            ("element", 0),
            ("element", self.PRIME),
            ("prime", 3),
            ("generator", 1),
            ("h", self.PRIME),
            ("lower", 101),
        ):
            bad = dataclasses.replace(commitment, **{field: bad_value})
            self.assertFalse(verify_range(bad, proof), f"{field}={bad_value}")

    def test_verify_type_errors(self):
        commitment, _, proof = self.prove()
        with self.assertRaises(TypeError):
            verify_range("commitment", proof)
        with self.assertRaises(TypeError):
            verify_range(commitment, (proof.t, proof.e, proof.s))
        with self.assertRaises(TypeError):
            verify_range(commitment, proof, context="ctx")
        for field in ("element", "lower", "upper", "prime", "generator", "h"):
            bad = dataclasses.replace(commitment, **{field: True})
            with self.assertRaises(TypeError):
                verify_range(bad, proof)
        with self.assertRaises(TypeError):
            verify_range(commitment, RangeProof(list(proof.t), proof.e, proof.s))
        with self.assertRaises(TypeError):
            verify_range(commitment, RangeProof(proof.t, proof.e, list(proof.s)))
        for bad_item in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_range(
                    commitment, RangeProof((bad_item,) + proof.t[1:], proof.e, proof.s)
                )
            with self.assertRaises(TypeError):
                verify_range(
                    commitment, RangeProof(proof.t, (bad_item,) + proof.e[1:], proof.s)
                )
            with self.assertRaises(TypeError):
                verify_range(
                    commitment, RangeProof(proof.t, proof.e, (bad_item,) + proof.s[1:])
                )

    def test_inputs_are_not_mutated(self):
        commitment, blinding = self.commit()
        snapshot = dataclasses.replace(commitment)
        proof = prove_range(commitment, 50, blinding, randbelow=counter_randbelow())
        proof_snapshot = RangeProof(proof.t, proof.e, proof.s)
        verify_range(commitment, proof)
        self.assertEqual(commitment, snapshot)
        self.assertEqual(proof, proof_snapshot)
        self.assertEqual(blinding, 1234)


if __name__ == "__main__":
    unittest.main()
