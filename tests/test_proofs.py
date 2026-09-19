import hashlib
import unittest

from dataclasses import fields, replace

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    MerkleMultiProof,
    MerkleProof,
    PedersenCommitment,
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
    verify_inclusion,
    verify_multi_inclusion,
    verify_opening,
    verify_pedersen_opening,
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
    P = SMALL_PRIME  # 104729
    G = 3
    LOWER = 0
    UPPER = 1000

    def commit(self, value=500, lower=None, upper=None, **kwargs):
        params = dict(prime=self.P, generator=self.G, blinding=12345)
        params.update(kwargs)
        return pedersen_commit(
            value,
            self.LOWER if lower is None else lower,
            self.UPPER if upper is None else upper,
            **params,
        )

    def test_honest_opening_verifies(self):
        pc, blinding = self.commit()
        self.assertIsInstance(pc, PedersenCommitment)
        self.assertEqual(pc.element, 500)
        self.assertEqual((pc.lower, pc.upper, pc.prime, pc.generator), (0, 1000, self.P, self.G))
        self.assertEqual(pc.h, pow(self.G, 2, self.P))  # default h = g**2 mod prime
        self.assertTrue(verify_pedersen_opening(pc, 500, blinding))

    def test_commitment_matches_formula(self):
        pc, blinding = self.commit()
        m = 500 - self.LOWER
        self.assertEqual(pc.commitment, pow(self.G, m, self.P) * pow(pc.h, blinding, self.P) % self.P)

    def test_object_is_frozen_and_keeps_no_blinding(self):
        pc, _ = self.commit()
        with self.assertRaises(AttributeError):
            pc.commitment = 1
        self.assertNotIn("blinding", {f.name for f in fields(pc)})

    def test_inclusive_bounds(self):
        for value in (self.LOWER, self.UPPER, 500):
            pc, blinding = self.commit(value=value)
            self.assertTrue(verify_pedersen_opening(pc, value, blinding))

    def test_negative_offsets_encode_value_minus_lower(self):
        pc, blinding = pedersen_commit(-500, -1000, 0, prime=self.P, generator=self.G, blinding=7)
        self.assertEqual(pc.commitment, pow(self.G, 500, self.P) * pow(pc.h, 7, self.P) % self.P)
        self.assertTrue(verify_pedersen_opening(pc, -500, 7))

    def test_explicit_h_used(self):
        h = pow(self.G, 65537, self.P)
        pc, blinding = pedersen_commit(10, 0, 100, prime=self.P, generator=self.G, h=h, blinding=9)
        self.assertEqual(pc.h, h)
        self.assertTrue(verify_pedersen_opening(pc, 10, 9))

    def test_wrong_value_or_blinding_fails(self):
        pc, blinding = self.commit()
        self.assertFalse(verify_pedersen_opening(pc, 501, blinding))
        self.assertFalse(verify_pedersen_opening(pc, 499, blinding))
        self.assertFalse(verify_pedersen_opening(pc, 500, blinding + 1))
        self.assertFalse(verify_pedersen_opening(pc, 501, blinding + 1))

    def test_verifier_value_out_of_range_fails(self):
        pc, blinding = self.commit()
        self.assertFalse(verify_pedersen_opening(pc, self.UPPER + 1, blinding))
        self.assertFalse(verify_pedersen_opening(pc, self.LOWER - 1, blinding))

    def test_known_trapdoor_allows_reopening(self):
        # default h = g**2: C = g**m * h**r = g**(m-2) * h**(r+1)
        pc, blinding = self.commit()
        self.assertTrue(verify_pedersen_opening(pc, 498, blinding + 1))
        self.assertTrue(verify_pedersen_opening(pc, 400, blinding + 50))

    def test_default_group_parameters_are_usable(self):
        pc, blinding = pedersen_commit(50, 0, 100)
        self.assertEqual((pc.prime, pc.generator), (DEFAULT_PRIME, DEFAULT_GENERATOR))
        self.assertEqual(pc.h, pow(DEFAULT_GENERATOR, 2, DEFAULT_PRIME))
        self.assertTrue(verify_pedersen_opening(pc, 50, blinding))

    def test_random_blinding_drawn_with_prime_minus_two(self):
        calls = []

        def recording(upper):
            calls.append(upper)
            return 41

        pc, blinding = pedersen_commit(5, 0, 10, prime=self.P, randbelow=recording)
        self.assertEqual(calls, [self.P - 2])
        self.assertEqual(blinding, 42)
        self.assertTrue(verify_pedersen_opening(pc, 5, blinding))

    def test_random_blinding_is_in_range(self):
        for _ in range(20):
            pc, blinding = pedersen_commit(5, 0, 10, prime=self.P)
            self.assertTrue(1 <= blinding < self.P - 1)
            self.assertTrue(verify_pedersen_opening(pc, 5, blinding))

    def test_blinding_boundary_values(self):
        for blinding in (1, self.P - 2):
            pc, _ = self.commit(blinding=blinding)
            self.assertTrue(verify_pedersen_opening(pc, 500, blinding))

    def test_interval_width_boundary(self):
        # width == prime - 2 is the largest legal width
        pc, blinding = pedersen_commit(1, 0, self.P - 2, prime=self.P, generator=self.G, blinding=3)
        self.assertTrue(verify_pedersen_opening(pc, 1, 3))

    def test_inputs_not_mutated_and_no_blinding_on_object(self):
        pc, _ = self.commit()
        snapshot = replace(pc)
        verify_pedersen_opening(pc, 501, 999)
        self.assertEqual(pc, snapshot)

    # --- ValueError: invalid interval / out-of-range value / parameters ---

    def test_inverted_interval_rejected(self):
        with self.assertRaises(ValueError):
            self.commit(value=5, lower=10, upper=0)

    def test_value_out_of_range_rejected(self):
        for value in (-1, 1001):
            with self.assertRaises(ValueError):
                self.commit(value=value)

    def test_interval_width_too_large_rejected(self):
        with self.assertRaises(ValueError):
            pedersen_commit(0, 0, self.P - 1, prime=self.P, generator=self.G, blinding=1)
        with self.assertRaises(ValueError):
            pedersen_commit(0, 0, self.P, prime=self.P, generator=self.G, blinding=1)

    def test_prime_must_exceed_three(self):
        for prime in (2, 3, 0, -5):
            with self.assertRaises(ValueError):
                pedersen_commit(0, 0, 1, prime=prime, generator=2, blinding=1)

    def test_generator_out_of_range_rejected(self):
        for generator in (0, 1, self.P, self.P + 1, -1):
            with self.assertRaises(ValueError):
                pedersen_commit(0, 0, 1, prime=self.P, generator=generator, blinding=1)
        # 2 satisfies 1 < g < prime; the default h = g**2 = 4 is in range too
        pc, _ = pedersen_commit(0, 0, 1, prime=self.P, generator=2, blinding=1)
        self.assertTrue(verify_pedersen_opening(pc, 0, 1))
        # g = prime - 1 makes the default h = 1, so pass an explicit in-range h
        pc, _ = pedersen_commit(
            0, 0, 1, prime=self.P, generator=self.P - 1, h=self.P - 1, blinding=1
        )
        self.assertTrue(verify_pedersen_opening(pc, 0, 1))

    def test_h_out_of_range_rejected(self):
        for bad_h in (0, 1, self.P, self.P + 1, -1):
            with self.assertRaises(ValueError):
                pedersen_commit(0, 0, 1, prime=self.P, generator=3, h=bad_h, blinding=1)
        for good_h in (2, self.P - 1):  # both satisfy 1 < h < prime
            pc, _ = pedersen_commit(0, 0, 1, prime=self.P, generator=3, h=good_h, blinding=1)
            self.assertTrue(verify_pedersen_opening(pc, 0, 1))

    def test_blinding_out_of_range_rejected(self):
        for blinding in (0, -1, self.P - 1, self.P):
            with self.assertRaises(ValueError):
                self.commit(blinding=blinding)

    # --- TypeError: non-integer (bool excluded) / non-callable randbelow ---

    def test_numeric_arguments_reject_non_integers(self):
        # value/lower/upper/prime/generator have no None default; blinding and h
        # treat None as "generate / use default", so None is legal only there
        required = dict(value=5, lower=0, upper=10, prime=self.P, generator=3)
        for name in ("value", "lower", "upper", "prime", "generator"):
            for bad in (1.5, "5", None, [5]):
                kwargs = dict(required)
                kwargs["blinding"] = 1
                kwargs[name] = bad
                with self.assertRaises(TypeError, msg=f"{name}={bad!r}"):
                    pedersen_commit(**kwargs)
        for name in ("blinding", "h"):
            for bad in (1.5, "5", [5]):
                kwargs = dict(required)
                kwargs[name] = bad
                with self.assertRaises(TypeError, msg=f"{name}={bad!r}"):
                    pedersen_commit(**kwargs)

    def test_bool_is_not_an_integer(self):
        for name in ("value", "lower", "upper", "prime", "generator"):
            with self.assertRaises(TypeError):
                self.commit(**{name: True})
        with self.assertRaises(TypeError):
            self.commit(h=False)
        with self.assertRaises(TypeError):
            self.commit(blinding=True)

    def test_randbelow_not_callable_rejected(self):
        for bad in (7, "randbelow", None, 1.5):
            with self.assertRaises(TypeError):
                pedersen_commit(5, 0, 10, prime=self.P, randbelow=bad)

    def test_randbelow_non_integer_return_rejected(self):
        for bad in (1.5, "1", None, True):
            with self.assertRaises(TypeError):
                pedersen_commit(5, 0, 10, prime=self.P, randbelow=lambda upper, bad=bad: bad)

    def test_randbelow_out_of_range_integer_rejected(self):
        # r = drawn + 1 must stay in [1, prime - 1): drawn in [0, prime - 2)
        for drawn in (-1, self.P - 2, self.P):
            with self.assertRaises(ValueError):
                pedersen_commit(5, 0, 10, prime=self.P, randbelow=lambda upper, d=drawn: d)

    # --- verify_pedersen_opening type errors ---

    def test_verify_type_errors(self):
        pc, blinding = self.commit()
        with self.assertRaises(TypeError):
            verify_pedersen_opening((pc.commitment,), 500, blinding)
        with self.assertRaises(TypeError):
            verify_pedersen_opening(pc, 500.0, blinding)
        with self.assertRaises(TypeError):
            verify_pedersen_opening(pc, 500, "1")
        with self.assertRaises(TypeError):
            verify_pedersen_opening(pc, True, blinding)
        with self.assertRaises(TypeError):
            verify_pedersen_opening(pc, 500, False)
        for name in ("commitment", "element", "lower", "upper", "prime", "generator", "h"):
            tampered = replace(pc, **{name: 1.5})
            with self.assertRaises(TypeError, msg=f"field {name} float"):
                verify_pedersen_opening(tampered, 500, blinding)
            tampered = replace(pc, **{name: True})
            with self.assertRaises(TypeError, msg=f"field {name} bool"):
                verify_pedersen_opening(tampered, 500, blinding)

    # --- verify_pedersen_opening structural failures return False ---

    def test_verify_out_of_range_element_returns_false(self):
        pc, blinding = self.commit()
        for element in (-1, 1001):
            tampered = replace(pc, element=element)
            self.assertFalse(verify_pedersen_opening(tampered, 500, blinding))

    def test_verify_bad_group_parameters_return_false(self):
        pc, blinding = self.commit()
        self.assertFalse(verify_pedersen_opening(replace(pc, prime=3), 500, blinding))
        self.assertFalse(verify_pedersen_opening(replace(pc, generator=1), 500, blinding))
        self.assertFalse(verify_pedersen_opening(replace(pc, h=pc.prime), 500, blinding))
        self.assertFalse(verify_pedersen_opening(replace(pc, lower=1, upper=0), 0, blinding))
        self.assertFalse(verify_pedersen_opening(replace(pc, lower=0, upper=pc.prime - 1), 0, blinding))

    def test_verify_bad_commitment_range_returns_false(self):
        pc, blinding = self.commit()
        self.assertFalse(verify_pedersen_opening(replace(pc, commitment=pc.prime), 500, blinding))
        self.assertFalse(verify_pedersen_opening(replace(pc, commitment=-1), 500, blinding))

    def test_verify_blinding_range_returns_false(self):
        pc, _ = self.commit()
        self.assertFalse(verify_pedersen_opening(pc, 500, 0))
        self.assertFalse(verify_pedersen_opening(pc, 500, pc.prime - 1))
        self.assertFalse(verify_pedersen_opening(pc, 500, -1))

    def test_verify_tampered_commitment_returns_false(self):
        pc, blinding = self.commit()
        self.assertFalse(verify_pedersen_opening(replace(pc, commitment=pc.commitment + 1), 500, blinding))
        self.assertFalse(verify_pedersen_opening(replace(pc, generator=5), 500, blinding))
        self.assertFalse(verify_pedersen_opening(replace(pc, h=pc.h + 1), 500, blinding))


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


if __name__ == "__main__":
    unittest.main()
