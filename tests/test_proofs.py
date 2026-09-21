import dataclasses
import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    BoundRangeBatch,
    BoundRegionBatch,
    BoundRegionReplayGuard,
    BoundRangeReplayGuard,
    BoundSchnorrBatch,
    BoundSchnorrReplayGuard,
    MerkleConsistencyChain,
    MerkleConsistencyProof,
    MerkleMultiProof,
    MerkleProof,
    MultiSchnorrEntry,
    PedersenCommitment,
    RangeBatchEntry,
    RangeProof,
    RangeReplayGuard,
    Region,
    RegionBatchEntry,
    RegionProof,
    RegionReplayGuard,
    ReplayBinding,
    ReplayGuard,
    SQLiteReplayStore,
    SchnorrBatchEntry,
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
    commit,
    commit_coordinate,
    merkle_root,
    pedersen_commit,
    prove_consistency,
    prove_consistency_chain,
    prove_inclusion,
    prove_multi_inclusion,
    prove_range,
    prove_region,
    verify_bound,
    verify_consistency,
    verify_consistency_chain,
    verify_inclusion,
    verify_multi_inclusion,
    verify_opening,
    verify_pedersen_opening,
    verify_range,
    verify_range_batch,
    verify_range_bound,
    verify_region,
    verify_region_batch,
    verify_region_bound,
    verify_schnorr_batch,
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

    def test_default_h_is_also_validated(self):
        # generator of order 2: the default h = g**2 mod prime collapses to 1
        with self.assertRaises(ValueError):
            pedersen_commit(1, 0, 2, prime=5, generator=4, blinding=1)
        # composite modulus where g**2 == 0 (mod prime)
        with self.assertRaises(ValueError):
            pedersen_commit(1, 0, 2, prime=9, generator=3, blinding=1)
        # an explicit h equal to what the default would compute is rejected too
        with self.assertRaises(ValueError):
            pedersen_commit(1, 0, 2, prime=5, generator=4, h=1, blinding=1)

    def test_maximum_width_just_under_prime_minus_one_is_accepted(self):
        commitment, blinding = self.commit(value=1, lower=0, upper=self.PRIME - 2, blinding=2)
        self.assertTrue(verify_pedersen_opening(commitment, 1, blinding))

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


class RangeProofTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def commit(self, value=50, lower=0, upper=100, blinding=1234, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def prove(self, value=50, lower=0, upper=100, blinding=1234, context=b"ctx", **kwargs):
        commitment, returned = self.commit(value, lower, upper, blinding, **kwargs)
        proof = prove_range(
            commitment, value, returned, context, randbelow=counter_randbelow()
        )
        return commitment, returned, proof

    # ---- honest round trip -------------------------------------------------

    def test_honest_proof_verifies(self):
        commitment, _, proof = self.prove()
        self.assertIsInstance(proof, RangeProof)
        self.assertTrue(verify_range(commitment, proof, b"ctx"))
        self.assertTrue(verify_range(commitment, proof, context=b"ctx"))

    def test_proof_shape_and_immutability(self):
        commitment, _, proof = self.prove(lower=10, upper=20, value=15)
        self.assertEqual(len(proof.t), len(proof.e), )
        self.assertEqual(len(proof.t), 11)  # one branch per integer in [10, 20]
        self.assertEqual(len(proof.e), len(proof.s))
        for field in (proof.t, proof.e, proof.s):
            self.assertIsInstance(field, tuple)
            for item in field:
                self.assertIsInstance(item, int)
                self.assertNotIsInstance(item, bool)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.t = proof.t + (1,)

    def test_every_value_in_range_proves(self):
        for value in (0, 1, 50, 99, 100):
            commitment, blinding, proof = self.prove(value=value)
            self.assertTrue(verify_range(commitment, proof, b"ctx"), f"value={value}")

    def test_negative_range_supported(self):
        commitment, _, proof = self.prove(value=-400, lower=-500, upper=-300)
        self.assertTrue(verify_range(commitment, proof, b"ctx"))

    def test_maximum_size_256_accepted(self):
        commitment, _, proof = self.prove(value=100, lower=0, upper=255)
        self.assertEqual(len(proof.t), 256)
        self.assertTrue(verify_range(commitment, proof, b"ctx"))

    def test_size_over_256_rejected(self):
        commitment, blinding = self.commit(value=0, lower=0, upper=256)
        with self.assertRaises(ValueError):
            prove_range(commitment, 0, blinding, randbelow=counter_randbelow())
        # verification of an oversized range returns False, whatever the proof
        self.assertFalse(verify_range(commitment, RangeProof((), (), ()), b"ctx"))

    def test_fixed_randbelow_is_reproducible(self):
        commitment, blinding = self.commit()
        first = prove_range(commitment, 50, blinding, b"c", randbelow=counter_randbelow())
        second = prove_range(commitment, 50, blinding, b"c", randbelow=counter_randbelow())
        self.assertEqual(first, second)

    def test_default_group_parameters_are_usable(self):
        commitment, blinding = pedersen_commit(40, 0, 100, blinding=987654321)
        proof = prove_range(commitment, 40, blinding, b"demo")
        self.assertTrue(verify_range(commitment, proof, b"demo"))

    # ---- transcript --------------------------------------------------------

    def test_challenge_matches_transcript(self):
        commitment, _, proof = self.prove()
        items = [b"zkregion/pedersen-range/v1"]
        for field in (
            commitment.element,
            commitment.lower,
            commitment.upper,
            commitment.prime,
            commitment.generator,
            commitment.h,
        ):
            items.append(str(field).encode("ascii"))
        items.append(b"ctx")
        items.append(b"101")
        items.extend(str(t).encode("ascii") for t in proof.t)
        transcript = hashlib.sha256()
        for item in items:
            transcript.update(len(item).to_bytes(4, "big"))
            transcript.update(item)
        c = int.from_bytes(transcript.digest(), "big") % self.PRIME
        self.assertEqual(sum(proof.e) % self.PRIME, c)
        for share in proof.e:
            self.assertTrue(0 <= share < self.PRIME)
        for response in proof.s:
            self.assertGreaterEqual(response, 0)

    def test_each_branch_satisfies_the_schnorr_equation(self):
        commitment, _, proof = self.prove()
        for i, (t, e, s) in enumerate(zip(proof.t, proof.e, proof.s)):
            offset = commitment.element * pow(self.G, -i, self.PRIME) % self.PRIME
            self.assertEqual(
                pow(self.H, s, self.PRIME),
                t * pow(offset, e, self.PRIME) % self.PRIME,
                f"branch {i}",
            )

    # ---- prove-time validation ----------------------------------------------

    def test_prove_requires_a_valid_opening(self):
        commitment, blinding = self.commit()
        with self.assertRaises(ValueError):
            prove_range(commitment, 51, blinding, randbelow=counter_randbelow())
        with self.assertRaises(ValueError):
            prove_range(commitment, 50, blinding + 1, randbelow=counter_randbelow())

    def test_prove_type_errors(self):
        commitment, blinding = self.commit()
        with self.assertRaises(TypeError):
            prove_range("commitment", 50, blinding)
        bad = dataclasses.replace(commitment, element=1.5)
        with self.assertRaises(TypeError):
            prove_range(bad, 50, blinding)
        for bad_value in (1.5, "50", True, None):
            with self.assertRaises(TypeError):
                prove_range(commitment, bad_value, blinding)
            with self.assertRaises(TypeError):
                prove_range(commitment, 50, bad_value)
        with self.assertRaises(TypeError):
            prove_range(commitment, 50, blinding, "ctx")
        with self.assertRaises(TypeError):
            prove_range(commitment, 50, blinding, randbelow=7)

    def test_prove_randbelow_draws_are_validated(self):
        commitment, blinding = self.commit()
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

    # ---- verify-time rejection ----------------------------------------------

    def test_tampering_fails(self):
        commitment, _, proof = self.prove()
        self.assertFalse(
            verify_range(commitment, RangeProof(proof.t, proof.e, proof.s[:-1] + (proof.s[-1] + 1,)), b"ctx")
        )
        self.assertFalse(
            verify_range(commitment, RangeProof(proof.t, proof.e[:-1] + ((proof.e[-1] + 1) % self.PRIME,), proof.s), b"ctx")
        )
        self.assertFalse(
            verify_range(commitment, RangeProof(proof.t[:-1] + ((proof.t[-1] % (self.PRIME - 1)) + 1,), proof.e, proof.s), b"ctx")
        )

    def test_context_binds_proof(self):
        commitment, _, proof = self.prove(context=b"ctx")
        self.assertFalse(verify_range(commitment, proof))
        self.assertFalse(verify_range(commitment, proof, b"other"))

    def test_foreign_commitment_fails(self):
        commitment, _, proof = self.prove()
        other, _ = self.commit(value=51, blinding=4321)
        self.assertFalse(verify_range(other, proof, b"ctx"))
        shifted = dataclasses.replace(commitment, element=(commitment.element + 1) % self.PRIME)
        self.assertFalse(verify_range(shifted, proof, b"ctx"))

    def test_structural_errors_return_false(self):
        commitment, _, proof = self.prove()
        n = len(proof.t)
        # wrong tuple lengths
        self.assertFalse(verify_range(commitment, RangeProof(proof.t[:-1], proof.e, proof.s), b"ctx"))
        self.assertFalse(verify_range(commitment, RangeProof(proof.t, proof.e, proof.s + (1,)), b"ctx"))
        self.assertFalse(verify_range(commitment, RangeProof((), (), ()), b"ctx"))
        # t outside [1, prime)
        for bad_t in (0, self.PRIME, self.PRIME + 1, -1):
            bad = RangeProof(proof.t[:-1] + (bad_t,), proof.e, proof.s)
            self.assertFalse(verify_range(commitment, bad, b"ctx"), f"t={bad_t}")
        # e outside [0, prime)
        for bad_e in (-1, self.PRIME, self.PRIME + 1):
            bad = RangeProof(proof.t, proof.e[:-1] + (bad_e,), proof.s)
            self.assertFalse(verify_range(commitment, bad, b"ctx"), f"e={bad_e}")
        # negative response
        bad = RangeProof(proof.t, proof.e, proof.s[:-1] + (-1,))
        self.assertFalse(verify_range(commitment, bad, b"ctx"))
        # challenge shares that do not sum to c
        bad = RangeProof(proof.t, (proof.e[0] + 1,) + proof.e[1:], proof.s)
        self.assertFalse(verify_range(commitment, bad, b"ctx"))
        self.assertEqual(n, 101)

    def test_bad_embedded_parameters_return_false(self):
        commitment, _, proof = self.prove()
        for field, bad_value in (
            ("prime", 3),
            ("generator", 1),
            ("generator", self.PRIME),
            ("h", 1),
            ("h", self.PRIME),
            ("element", 0),
            ("element", self.PRIME),
            ("lower", 101),
        ):
            bad = dataclasses.replace(commitment, **{field: bad_value})
            self.assertFalse(verify_range(bad, proof, b"ctx"), f"{field}={bad_value}")

    def test_verify_type_errors(self):
        commitment, _, proof = self.prove()
        with self.assertRaises(TypeError):
            verify_range("commitment", proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_range(commitment, (proof.t, proof.e, proof.s), b"ctx")
        with self.assertRaises(TypeError):
            verify_range(commitment, proof, "ctx")
        with self.assertRaises(TypeError):
            verify_range(commitment, RangeProof(list(proof.t), proof.e, proof.s), b"ctx")
        with self.assertRaises(TypeError):
            verify_range(commitment, RangeProof(proof.t, proof.e, list(proof.s)), b"ctx")
        for bad_item in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_range(commitment, RangeProof(proof.t[:-1] + (bad_item,), proof.e, proof.s), b"ctx")
            with self.assertRaises(TypeError):
                verify_range(commitment, RangeProof(proof.t, proof.e[:-1] + (bad_item,), proof.s), b"ctx")
            with self.assertRaises(TypeError):
                verify_range(commitment, RangeProof(proof.t, proof.e, proof.s[:-1] + (bad_item,)), b"ctx")
        bad_commitment = dataclasses.replace(commitment, h=True)
        with self.assertRaises(TypeError):
            verify_range(bad_commitment, proof, b"ctx")

    def test_inputs_are_not_mutated(self):
        commitment, blinding, proof = self.prove()
        snapshot = (dataclasses.replace(commitment), RangeProof(*map(tuple, (proof.t, proof.e, proof.s))))
        verify_range(commitment, proof, b"ctx")
        self.assertEqual((commitment, proof), snapshot)
        self.assertEqual(blinding, 1234)


class RangeBatchTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def commit(self, value=5, lower=0, upper=10, blinding=1234, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def entry(self, value=5, lower=0, upper=10, context=b"ctx", blinding=1234, **kwargs):
        commitment, returned = self.commit(value, lower, upper, blinding, **kwargs)
        proof = prove_range(
            commitment, value, returned, context, randbelow=counter_randbelow()
        )
        return RangeBatchEntry(commitment, proof, context)

    # ---- entry object -------------------------------------------------------

    def test_entry_positional_defaults_equality_and_immutability(self):
        commitment, blinding = self.commit()
        proof = prove_range(commitment, 5, blinding, b"", randbelow=counter_randbelow())
        entry = RangeBatchEntry(commitment, proof)
        self.assertEqual(entry.context, b"")
        self.assertEqual(RangeBatchEntry(commitment, proof, b""), entry)
        self.assertEqual(
            tuple(getattr(entry, name) for name in ("commitment", "proof", "context")),
            (commitment, proof, b""),
        )
        other = RangeBatchEntry(commitment, proof, b"other")
        self.assertNotEqual(entry, other)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.context = b"other"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.proof = proof

    def test_entry_field_types(self):
        entry = self.entry()
        self.assertIsInstance(entry.commitment, PedersenCommitment)
        self.assertIsInstance(entry.proof, RangeProof)
        self.assertIsInstance(entry.context, bytes)

    # ---- honest round trip --------------------------------------------------

    def test_honest_batch_verifies(self):
        entries = [self.entry(value=value) for value in (1, 5, 10)]
        self.assertTrue(verify_range_batch(entries, randbelow=counter_randbelow()))
        self.assertTrue(verify_range_batch(tuple(entries)))  # default secrets.randbelow

    def test_single_entry_agrees_with_verify_range(self):
        entry = self.entry()
        self.assertTrue(verify_range_batch([entry], randbelow=counter_randbelow()))
        self.assertTrue(verify_range(entry.commitment, entry.proof, entry.context))

    def test_empty_batch_returns_false(self):
        self.assertFalse(verify_range_batch([], randbelow=counter_randbelow()))
        self.assertFalse(verify_range_batch(()))

    def test_duplicate_entries_are_legal(self):
        entry = self.entry()
        self.assertTrue(verify_range_batch([entry, entry, entry], randbelow=counter_randbelow()))

    def test_distinct_ranges_share_one_group(self):
        entries = [
            self.entry(value=5, lower=0, upper=10),
            self.entry(value=25, lower=20, upper=30, blinding=4321),
        ]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_range_batch(entries, randbelow=recording))
        # 11 branches per entry, two entries
        self.assertEqual(calls, [self.PRIME - 1] * 22)

    def test_mixed_groups_each_checked_under_its_own_parameters(self):
        small = self.entry()
        commitment, blinding = pedersen_commit(40, 0, 100, blinding=987654321)
        proof = prove_range(commitment, 40, blinding, b"ctx")
        default_entry = RangeBatchEntry(commitment, proof, b"ctx")
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_range_batch([small, default_entry], randbelow=recording))
        self.assertEqual(sorted(set(calls)), sorted({self.PRIME - 1, DEFAULT_PRIME - 1}))
        self.assertEqual(len(calls), 112)  # 11 + 101 branches

    # ---- randomness ----------------------------------------------------------

    def test_randbelow_called_once_per_branch_with_prime_minus_one(self):
        entries = [self.entry(), self.entry(blinding=4321)]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_range_batch(entries, randbelow=recording))
        self.assertEqual(calls, [self.PRIME - 1] * 22)

    def test_fixed_coefficient_source_is_reproducible(self):
        entries = [self.entry(), self.entry(blinding=4321)]
        first = verify_range_batch(entries, randbelow=counter_randbelow(9))
        second = verify_range_batch(entries, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_random_linear_combination_not_per_proof_summary(self):
        # coefficients all 1: +1 and -1 response deltas cancel in the single
        # aggregate exponent sum, even though neither proof verifies alone
        first, second = self.entry(blinding=1234), self.entry(blinding=5555)
        first_tampered = RangeProof(
            first.proof.t, first.proof.e,
            first.proof.s[:-1] + (first.proof.s[-1] + 1,),
        )
        second_tampered = RangeProof(
            second.proof.t, second.proof.e,
            second.proof.s[:-1] + (second.proof.s[-1] - 1,),
        )
        self.assertFalse(verify_range(first.commitment, first_tampered, b"ctx"))
        self.assertFalse(verify_range(second.commitment, second_tampered, b"ctx"))
        forged = [
            RangeBatchEntry(first.commitment, first_tampered, b"ctx"),
            RangeBatchEntry(second.commitment, second_tampered, b"ctx"),
        ]
        self.assertTrue(verify_range_batch(forged, randbelow=lambda upper: 0))

    # ---- rejection -----------------------------------------------------------

    def test_tampering_fails(self):
        entry = self.entry()
        proof = entry.proof
        cases = [
            RangeProof(proof.t, proof.e, proof.s[:-1] + (proof.s[-1] + 1,)),
            RangeProof(
                proof.t,
                proof.e[:-1] + ((proof.e[-1] + 1) % self.PRIME,),
                proof.s,
            ),
            RangeProof(
                proof.t[:-1] + ((proof.t[-1] % (self.PRIME - 1)) + 1,),
                proof.e,
                proof.s,
            ),
        ]
        for forged in cases:
            self.assertFalse(
                verify_range_batch(
                    [RangeBatchEntry(entry.commitment, forged, entry.context)],
                    randbelow=counter_randbelow(),
                ),
                f"batch accepted: {forged!r}",
            )

    def test_context_binds_proof(self):
        entry = self.entry(context=b"ctx")
        for bad_context in (b"", b"other"):
            bad = RangeBatchEntry(entry.commitment, entry.proof, bad_context)
            self.assertFalse(verify_range_batch([bad], randbelow=counter_randbelow()))

    def test_foreign_commitment_fails(self):
        entry = self.entry()
        other, _ = self.commit(value=6, blinding=4321)
        self.assertFalse(
            verify_range_batch(
                [RangeBatchEntry(other, entry.proof, entry.context)],
                randbelow=counter_randbelow(),
            )
        )
        shifted = dataclasses.replace(
            entry.commitment, element=(entry.commitment.element + 1) % self.PRIME
        )
        self.assertFalse(
            verify_range_batch(
                [RangeBatchEntry(shifted, entry.proof, entry.context)],
                randbelow=counter_randbelow(),
            )
        )

    def test_cancellation_does_not_cross_group_boundaries(self):
        # same prime/generator, different h: an s delta of +1 in one group and
        # a delta of -1 in the other cannot cancel
        first = self.entry(blinding=1234)
        commitment, blinding = self.commit(5, 0, 10, 333, h=7)
        other_proof = prove_range(
            commitment, 5, blinding, b"ctx", randbelow=counter_randbelow()
        )
        first_tampered = RangeProof(
            first.proof.t, first.proof.e,
            first.proof.s[:-1] + (first.proof.s[-1] + 1,),
        )
        other_tampered = RangeProof(
            other_proof.t, other_proof.e,
            other_proof.s[:-1] + (other_proof.s[-1] - 1,),
        )
        forged = [
            RangeBatchEntry(first.commitment, first_tampered, b"ctx"),
            RangeBatchEntry(commitment, other_tampered, b"ctx"),
        ]
        self.assertFalse(verify_range_batch(forged, randbelow=lambda upper: 0))

    def test_structural_errors_return_false(self):
        entry = self.entry()
        proof = entry.proof
        cases = [
            RangeProof(proof.t[:-1], proof.e, proof.s),
            RangeProof(proof.t, proof.e, proof.s + (1,)),
            RangeProof((), (), ()),
        ]
        for forged in cases:
            self.assertFalse(
                verify_range_batch(
                    [RangeBatchEntry(entry.commitment, forged, b"ctx")],
                    randbelow=counter_randbelow(),
                )
            )
        # oversized declared range returns False whatever the proof
        wide_commitment, wide_blinding = self.commit(value=0, lower=0, upper=256, blinding=7)
        self.assertFalse(
            verify_range_batch(
                [RangeBatchEntry(wide_commitment, RangeProof((), (), ()), b"ctx")],
                randbelow=counter_randbelow(),
            )
        )

    def test_bad_embedded_commitment_parameters_return_false(self):
        entry = self.entry()
        for name, value in (
            ("element", 0),
            ("prime", 3),
            ("generator", 1),
            ("h", self.PRIME),
            ("lower", 11),
        ):
            broken = dataclasses.replace(entry.commitment, **{name: value})
            bad = RangeBatchEntry(broken, entry.proof, entry.context)
            self.assertFalse(
                verify_range_batch([bad], randbelow=counter_randbelow()), name
            )

    def test_invalid_entry_short_circuits_before_drawing(self):
        entry = self.entry()
        short = RangeProof(entry.proof.t[:-1], entry.proof.e, entry.proof.s)
        invalid = RangeBatchEntry(entry.commitment, short, entry.context)
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertFalse(verify_range_batch([invalid, entry], randbelow=recording))
        self.assertEqual(calls, [])  # the invalid entry is rejected before any draw
        self.assertFalse(verify_range_batch([entry, invalid], randbelow=recording))
        self.assertEqual(calls, [self.PRIME - 1] * 11)  # one draw per branch of entry 1

    # ---- type errors ---------------------------------------------------------

    def test_type_errors(self):
        entry = self.entry()
        for bad in ("entries", b"entries", bytearray(b"x"), 42, None):
            with self.assertRaises(TypeError):
                verify_range_batch(bad)
        with self.assertRaises(TypeError):
            verify_range_batch([(entry.commitment, entry.proof)])
        with self.assertRaises(TypeError):
            verify_range_batch([
                RangeBatchEntry(entry.commitment, entry.proof, "ctx")
            ])
        with self.assertRaises(TypeError):
            verify_range_batch([
                RangeBatchEntry(entry.commitment, (entry.proof.t, entry.proof.e, entry.proof.s), b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_range_batch([
                RangeBatchEntry("commitment", entry.proof, b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_range_batch([
                RangeBatchEntry(
                    (entry.commitment.element, 0, 10, self.PRIME, self.G, self.H),
                    entry.proof, b"ctx",
                )
            ])
        bool_proof = RangeProof(
            (True,) * len(entry.proof.t), entry.proof.e, entry.proof.s
        )
        with self.assertRaises(TypeError):
            verify_range_batch([
                RangeBatchEntry(entry.commitment, bool_proof, b"ctx")
            ])
        list_proof = RangeProof(list(entry.proof.t), entry.proof.e, entry.proof.s)
        with self.assertRaises(TypeError):
            verify_range_batch([
                RangeBatchEntry(entry.commitment, list_proof, b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_range_batch([entry], randbelow=7)

    def test_coefficient_source_errors(self):
        entry = self.entry()
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_range_batch([entry], randbelow=lambda upper, bad=bad: bad)
        for bad in (-1, self.PRIME - 1, self.PRIME):
            with self.assertRaises(ValueError):
                verify_range_batch([entry], randbelow=lambda upper, bad=bad: bad)

    # ---- hygiene -------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = [self.entry(), self.entry(blinding=4321)]
        snapshot = [dataclasses.replace(entry) for entry in entries]
        verify_range_batch(entries, randbelow=counter_randbelow())
        self.assertEqual(entries, snapshot)

    def test_default_group_parameters_are_usable(self):
        commitment, blinding = pedersen_commit(40, 0, 100, blinding=987654321)
        proof = prove_range(commitment, 40, blinding, b"demo")
        entry = RangeBatchEntry(commitment, proof, b"demo")
        self.assertTrue(verify_range_batch([entry], randbelow=counter_randbelow()))


class RegionProofTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def commit(self, value, lower, upper, blinding, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def prove(self, x=40, y=60, region=None, context=b"ctx", x_blinding=1234, y_blinding=4321):
        region = Region(0, 100, 0, 100) if region is None else region
        x_commitment, x_r = self.commit(x, region.min_x, region.max_x, x_blinding)
        y_commitment, y_r = self.commit(y, region.min_y, region.max_y, y_blinding)
        proof = prove_region(
            x_commitment, y_commitment, x, y, x_r, y_r, region, context,
            randbelow=counter_randbelow(),
        )
        return x_commitment, y_commitment, region, proof

    @staticmethod
    def sub_context(axis, context, region, x_commitment, y_commitment):
        items = [b"zkregion/region/v1", axis, context]
        items.extend(
            str(bound).encode("ascii")
            for bound in (region.min_x, region.max_x, region.min_y, region.max_y)
        )
        for commitment in (x_commitment, y_commitment):
            items.extend(
                str(getattr(commitment, name)).encode("ascii")
                for name in ("element", "lower", "upper", "prime", "generator", "h")
            )
        transcript = b""
        for item in items:
            transcript += len(item).to_bytes(4, "big") + item
        return transcript

    # ---- honest round trip -------------------------------------------------

    def test_honest_proof_verifies(self):
        x_commitment, y_commitment, region, proof = self.prove()
        self.assertIsInstance(proof, RegionProof)
        self.assertIsInstance(proof.x_proof, RangeProof)
        self.assertIsInstance(proof.y_proof, RangeProof)
        self.assertTrue(verify_region(x_commitment, y_commitment, region, proof, b"ctx"))
        self.assertTrue(verify_region(x_commitment, y_commitment, region, proof, context=b"ctx"))

    def test_proof_is_immutable(self):
        _, _, _, proof = self.prove()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.x_proof = proof.y_proof
        with self.assertRaises(dataclasses.FrozenInstanceError):
            proof.y_proof = proof.x_proof

    def test_region_corners_and_center_prove(self):
        region = Region(0, 10, 20, 30)
        for x, y in ((0, 20), (10, 30), (0, 30), (10, 20), (5, 25)):
            x_commitment, y_commitment, region, proof = self.prove(x=x, y=y, region=region)
            self.assertTrue(
                verify_region(x_commitment, y_commitment, region, proof, b"ctx"),
                f"({x}, {y})",
            )

    def test_negative_region_supported(self):
        region = Region(-100, -50, -30, -10)
        x_commitment, y_commitment, region, proof = self.prove(x=-75, y=-20, region=region)
        self.assertTrue(verify_region(x_commitment, y_commitment, region, proof, b"ctx"))

    def test_fixed_randbelow_is_reproducible(self):
        region = Region(0, 100, 0, 100)
        x_commitment, x_r = self.commit(40, 0, 100, 1234)
        y_commitment, y_r = self.commit(60, 0, 100, 4321)
        first = prove_region(
            x_commitment, y_commitment, 40, 60, x_r, y_r, region, b"c",
            randbelow=counter_randbelow(),
        )
        second = prove_region(
            x_commitment, y_commitment, 40, 60, x_r, y_r, region, b"c",
            randbelow=counter_randbelow(),
        )
        self.assertEqual(first, second)

    def test_default_group_parameters_are_usable(self):
        region = Region(0, 100, 0, 100)
        x_commitment, x_r = pedersen_commit(40, 0, 100, blinding=987654321)
        y_commitment, y_r = pedersen_commit(60, 0, 100, blinding=123456789)
        proof = prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, region, b"demo")
        self.assertTrue(verify_region(x_commitment, y_commitment, region, proof, b"demo"))

    # ---- transcript ----------------------------------------------------------

    def test_sub_proofs_use_the_specified_context(self):
        x_commitment, y_commitment, region, proof = self.prove()
        x_context = self.sub_context(b"x", b"ctx", region, x_commitment, y_commitment)
        y_context = self.sub_context(b"y", b"ctx", region, x_commitment, y_commitment)
        self.assertTrue(verify_range(x_commitment, proof.x_proof, x_context))
        self.assertTrue(verify_range(y_commitment, proof.y_proof, y_context))
        # axes are not interchangeable
        self.assertFalse(verify_range(x_commitment, proof.x_proof, y_context))
        self.assertFalse(verify_range(y_commitment, proof.y_proof, x_context))
        # the plain external context alone does not verify a sub-proof
        self.assertFalse(verify_range(x_commitment, proof.x_proof, b"ctx"))

    # ---- prove-time validation ----------------------------------------------

    def test_commitment_range_must_match_region(self):
        x_commitment, x_r = self.commit(40, 0, 100, 1234)
        y_commitment, y_r = self.commit(60, 0, 100, 4321)
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, Region(0, 99, 0, 100))
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, Region(1, 100, 0, 100))
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, Region(0, 100, 0, 101))
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, Region(0, 100, -1, 100))

    def test_invalid_opening_rejected(self):
        x_commitment, x_r = self.commit(40, 0, 100, 1234)
        y_commitment, y_r = self.commit(60, 0, 100, 4321)
        region = Region(0, 100, 0, 100)
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 41, 60, x_r, y_r, region)
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r + 1, y_r, region)
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 59, x_r, y_r, region)
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r + 1, region)

    def test_axis_over_256_rejected(self):
        region = Region(0, 256, 0, 100)
        x_commitment, x_r = self.commit(40, 0, 256, 1234)
        y_commitment, y_r = self.commit(60, 0, 100, 4321)
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, region)
        region = Region(0, 100, 0, 256)
        x_commitment, x_r = self.commit(40, 0, 100, 1234)
        y_commitment, y_r = self.commit(60, 0, 256, 4321)
        with self.assertRaises(ValueError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, region)

    def test_prove_type_errors(self):
        x_commitment, y_commitment, region, proof = self.prove()
        x_r, y_r = 1234, 4321
        with self.assertRaises(TypeError):
            prove_region("commitment", y_commitment, 40, 60, x_r, y_r, region)
        with self.assertRaises(TypeError):
            prove_region(x_commitment, "commitment", 40, 60, x_r, y_r, region)
        bad = dataclasses.replace(x_commitment, element=1.5)
        with self.assertRaises(TypeError):
            prove_region(bad, y_commitment, 40, 60, x_r, y_r, region)
        bad = dataclasses.replace(y_commitment, h=True)
        with self.assertRaises(TypeError):
            prove_region(x_commitment, bad, 40, 60, x_r, y_r, region)
        for bad_value in (1.5, "40", True, False, None):
            with self.assertRaises(TypeError):
                prove_region(x_commitment, y_commitment, bad_value, 60, x_r, y_r, region)
            with self.assertRaises(TypeError):
                prove_region(x_commitment, y_commitment, 40, bad_value, x_r, y_r, region)
            with self.assertRaises(TypeError):
                prove_region(x_commitment, y_commitment, 40, 60, bad_value, y_r, region)
            with self.assertRaises(TypeError):
                prove_region(x_commitment, y_commitment, 40, 60, x_r, bad_value, region)
        with self.assertRaises(TypeError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, "region")
        with self.assertRaises(TypeError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, (0, 100, 0, 100))
        with self.assertRaises(TypeError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, region, "ctx")
        with self.assertRaises(TypeError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, region, randbelow=7)
        # bool region bounds are rejected even though Region itself allows them
        bool_region = Region(True, 100, 0, 100)
        with self.assertRaises(TypeError):
            prove_region(x_commitment, y_commitment, 40, 60, x_r, y_r, bool_region)

    # ---- verify-time rejection ------------------------------------------------

    def test_tampering_fails(self):
        x_commitment, y_commitment, region, proof = self.prove()
        tampered_x = RangeProof(
            proof.x_proof.t, proof.x_proof.e,
            proof.x_proof.s[:-1] + (proof.x_proof.s[-1] + 1,),
        )
        self.assertFalse(
            verify_region(x_commitment, y_commitment, region, RegionProof(tampered_x, proof.y_proof), b"ctx")
        )
        tampered_y = RangeProof(
            proof.y_proof.t[:-1] + ((proof.y_proof.t[-1] % (self.PRIME - 1)) + 1,),
            proof.y_proof.e, proof.y_proof.s,
        )
        self.assertFalse(
            verify_region(x_commitment, y_commitment, region, RegionProof(proof.x_proof, tampered_y), b"ctx")
        )

    def test_context_binds_proof(self):
        x_commitment, y_commitment, region, proof = self.prove(context=b"ctx")
        self.assertFalse(verify_region(x_commitment, y_commitment, region, proof))
        self.assertFalse(verify_region(x_commitment, y_commitment, region, proof, b"other"))

    def test_region_binds_proof(self):
        x_commitment, y_commitment, region, proof = self.prove()
        # same x bounds, different y bounds: the y commitment no longer matches
        self.assertFalse(verify_region(x_commitment, y_commitment, Region(0, 100, 0, 99), proof, b"ctx"))
        self.assertFalse(verify_region(x_commitment, y_commitment, Region(0, 100, 1, 100), proof, b"ctx"))
        self.assertFalse(verify_region(x_commitment, y_commitment, Region(0, 99, 0, 100), proof, b"ctx"))
        self.assertFalse(verify_region(x_commitment, y_commitment, Region(1, 100, 0, 100), proof, b"ctx"))

    def test_foreign_commitment_fails(self):
        x_commitment, y_commitment, region, proof = self.prove()
        other, _ = self.commit(41, 0, 100, 777)
        self.assertFalse(verify_region(other, y_commitment, region, proof, b"ctx"))
        self.assertFalse(verify_region(x_commitment, other, region, proof, b"ctx"))
        shifted = dataclasses.replace(x_commitment, element=(x_commitment.element + 1) % self.PRIME)
        self.assertFalse(verify_region(shifted, y_commitment, region, proof, b"ctx"))

    def test_swapped_axes_fail(self):
        region = Region(0, 100, 0, 100)  # square: ranges alone cannot catch the swap
        x_commitment, y_commitment, region, proof = self.prove(x=40, y=60, region=region)
        # swapped sub-proofs
        swapped = RegionProof(x_proof=proof.y_proof, y_proof=proof.x_proof)
        self.assertFalse(verify_region(x_commitment, y_commitment, region, swapped, b"ctx"))
        # swapped commitments
        self.assertFalse(verify_region(y_commitment, x_commitment, region, proof, b"ctx"))
        # both swapped together
        self.assertFalse(verify_region(y_commitment, x_commitment, region, swapped, b"ctx"))

    def test_structural_errors_return_false(self):
        x_commitment, y_commitment, region, proof = self.prove()
        short = RangeProof(proof.x_proof.t[:-1], proof.x_proof.e, proof.x_proof.s)
        self.assertFalse(verify_region(x_commitment, y_commitment, region, RegionProof(short, proof.y_proof), b"ctx"))
        empty = RangeProof((), (), ())
        self.assertFalse(verify_region(x_commitment, y_commitment, region, RegionProof(empty, proof.y_proof), b"ctx"))
        # oversized axis range on verify returns False, whatever the proof
        wide_region = Region(0, 256, 0, 100)
        wide_x, _ = self.commit(40, 0, 256, 1234)
        self.assertFalse(verify_region(wide_x, y_commitment, wide_region, proof, b"ctx"))

    def test_verify_type_errors(self):
        x_commitment, y_commitment, region, proof = self.prove()
        with self.assertRaises(TypeError):
            verify_region("commitment", y_commitment, region, proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_region(x_commitment, (y_commitment.element, 0, 100), region, proof, b"ctx")
        bad = dataclasses.replace(x_commitment, lower=1.5)
        with self.assertRaises(TypeError):
            verify_region(bad, y_commitment, region, proof, b"ctx")
        bad = dataclasses.replace(y_commitment, generator=False)
        with self.assertRaises(TypeError):
            verify_region(x_commitment, bad, region, proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_region(x_commitment, y_commitment, "region", proof, b"ctx")
        with self.assertRaises(TypeError):
            verify_region(x_commitment, y_commitment, region, (proof.x_proof, proof.y_proof), b"ctx")
        with self.assertRaises(TypeError):
            verify_region(x_commitment, y_commitment, region, RegionProof("proof", proof.y_proof), b"ctx")
        with self.assertRaises(TypeError):
            verify_region(x_commitment, y_commitment, region, RegionProof(proof.x_proof, None), b"ctx")
        with self.assertRaises(TypeError):
            verify_region(x_commitment, y_commitment, region, proof, "ctx")
        with self.assertRaises(TypeError):
            verify_region(x_commitment, y_commitment, Region(0, 100, 0, True), proof, b"ctx")
        # malformed sub-proof fields raise TypeError through verify_range
        bad_proof = RegionProof(RangeProof(list(proof.x_proof.t), proof.x_proof.e, proof.x_proof.s), proof.y_proof)
        with self.assertRaises(TypeError):
            verify_region(x_commitment, y_commitment, region, bad_proof, b"ctx")

    def test_inputs_are_not_mutated(self):
        x_commitment, y_commitment, region, proof = self.prove()
        snapshot = (
            dataclasses.replace(x_commitment),
            dataclasses.replace(y_commitment),
            RegionProof(
                RangeProof(*map(tuple, (proof.x_proof.t, proof.x_proof.e, proof.x_proof.s))),
                RangeProof(*map(tuple, (proof.y_proof.t, proof.y_proof.e, proof.y_proof.s))),
            ),
        )
        verify_region(x_commitment, y_commitment, region, proof, b"ctx")
        self.assertEqual((x_commitment, y_commitment, proof), snapshot)


class RegionBatchTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def commit(self, value, lower, upper, blinding, **kwargs):
        kwargs.setdefault("prime", self.PRIME)
        kwargs.setdefault("generator", self.G)
        kwargs.setdefault("h", self.H)
        return pedersen_commit(value, lower, upper, blinding=blinding, **kwargs)

    def entry(self, x=5, y=25, region=None, context=b"ctx", x_blinding=1234, y_blinding=4321):
        region = Region(0, 10, 20, 30) if region is None else region
        x_commitment, x_r = self.commit(x, region.min_x, region.max_x, x_blinding)
        y_commitment, y_r = self.commit(y, region.min_y, region.max_y, y_blinding)
        proof = prove_region(
            x_commitment, y_commitment, x, y, x_r, y_r, region, context,
            randbelow=counter_randbelow(),
        )
        return RegionBatchEntry(x_commitment, y_commitment, region, proof, context)

    # ---- entry object -------------------------------------------------------

    def test_entry_defaults_equality_and_immutability(self):
        entry = self.entry(context=b"")
        self.assertEqual(entry.context, b"")
        self.assertEqual(
            RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region, entry.proof),
            entry,
        )
        other = self.entry(context=b"other")
        self.assertNotEqual(entry, other)
        self.assertEqual(
            tuple(getattr(entry, name) for name in (
                "x_commitment", "y_commitment", "region", "proof", "context")),
            (entry.x_commitment, entry.y_commitment, entry.region, entry.proof, b""),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.context = b"other"

    # ---- honest round trip --------------------------------------------------

    def test_honest_batch_verifies(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b"), self.entry(context=b"c")]
        self.assertTrue(verify_region_batch(entries, randbelow=counter_randbelow()))
        self.assertTrue(verify_region_batch(tuple(entries)))  # default secrets.randbelow

    def test_single_entry_agrees_with_verify_region(self):
        entry = self.entry()
        self.assertTrue(verify_region_batch([entry], randbelow=counter_randbelow()))
        self.assertTrue(
            verify_region(
                entry.x_commitment, entry.y_commitment, entry.region, entry.proof, entry.context
            )
        )

    def test_empty_batch_returns_false(self):
        self.assertFalse(verify_region_batch([], randbelow=counter_randbelow()))
        self.assertFalse(verify_region_batch(()))

    def test_duplicate_entries_are_legal(self):
        entry = self.entry()
        self.assertTrue(verify_region_batch([entry, entry, entry], randbelow=counter_randbelow()))

    def test_distinct_ranges_share_one_group(self):
        entries = [
            self.entry(region=Region(0, 10, 20, 30)),
            self.entry(x=25, y=25, region=Region(20, 30, 20, 30)),
        ]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_region_batch(entries, randbelow=recording))
        # 11 + 11 branches per entry, two entries
        self.assertEqual(calls, [self.PRIME - 1] * 44)

    def test_mixed_groups_each_checked_under_its_own_parameters(self):
        small = self.entry()
        region = Region(0, 10, 20, 30)
        x_commitment, x_r = pedersen_commit(5, 0, 10, blinding=987654321)
        y_commitment, y_r = pedersen_commit(25, 20, 30, blinding=123456789)
        proof = prove_region(x_commitment, y_commitment, 5, 25, x_r, y_r, region, b"ctx")
        default_entry = RegionBatchEntry(x_commitment, y_commitment, region, proof, b"ctx")
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_region_batch([small, default_entry], randbelow=recording))
        self.assertEqual(sorted(set(calls)), sorted({self.PRIME - 1, DEFAULT_PRIME - 1}))
        self.assertEqual(len(calls), 44)  # 22 branches per entry

    # ---- randomness ----------------------------------------------------------

    def test_randbelow_called_once_per_branch_with_prime_minus_one(self):
        entries = [self.entry(), self.entry()]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_region_batch(entries, randbelow=recording))
        self.assertEqual(calls, [self.PRIME - 1] * 44)

    def test_fixed_coefficient_source_is_reproducible(self):
        entries = [self.entry(), self.entry()]
        first = verify_region_batch(entries, randbelow=counter_randbelow(9))
        second = verify_region_batch(entries, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_random_linear_combination_not_per_branch_summary(self):
        # coefficients all 1: +1 and -1 response deltas cancel in the single
        # aggregate exponent sum, even though neither sub-proof verifies alone
        entry = self.entry()
        x_proof, y_proof = entry.proof.x_proof, entry.proof.y_proof
        x_tampered = RangeProof(
            x_proof.t, x_proof.e, x_proof.s[:-1] + (x_proof.s[-1] + 1,)
        )
        y_tampered = RangeProof(
            y_proof.t, y_proof.e, y_proof.s[:-1] + (y_proof.s[-1] - 1,)
        )
        forged = RegionProof(x_tampered, y_tampered)
        self.assertFalse(
            verify_range(
                entry.x_commitment,
                x_tampered,
                RegionProofTest.sub_context(
                    b"x", entry.context, entry.region, entry.x_commitment, entry.y_commitment
                ),
            )
        )
        forged_entry = RegionBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.region, forged, entry.context
        )
        self.assertTrue(verify_region_batch([forged_entry], randbelow=lambda upper: 0))

    # ---- rejection -----------------------------------------------------------

    def test_tampering_fails(self):
        entry = self.entry()
        x_proof, y_proof = entry.proof.x_proof, entry.proof.y_proof
        tampered_x = RangeProof(
            x_proof.t, x_proof.e, x_proof.s[:-1] + (x_proof.s[-1] + 1,)
        )
        tampered_y = RangeProof(
            y_proof.t, y_proof.e, y_proof.s[:-1] + (y_proof.s[-1] + 1,)
        )
        cases = [
            RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region,
                             RegionProof(tampered_x, y_proof), entry.context),
            RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region,
                             RegionProof(x_proof, tampered_y), entry.context),
            RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region,
                             entry.proof, b"other"),
            RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region, entry.proof),
            RegionBatchEntry(entry.x_commitment, entry.y_commitment,
                             Region(0, 9, 20, 30), entry.proof, entry.context),
            RegionBatchEntry(entry.x_commitment, entry.y_commitment,
                             Region(0, 10, 21, 30), entry.proof, entry.context),
        ]
        for batch in cases:
            self.assertFalse(
                verify_region_batch([batch], randbelow=counter_randbelow()),
                f"batch accepted: {batch!r}",
            )

    def test_foreign_commitment_and_swapped_axes_fail(self):
        entry = self.entry()
        other, _ = self.commit(6, 0, 10, 777)
        cases = [
            RegionBatchEntry(other, entry.y_commitment, entry.region, entry.proof, entry.context),
            RegionBatchEntry(entry.x_commitment, other, entry.region, entry.proof, entry.context),
            RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region,
                             RegionProof(entry.proof.y_proof, entry.proof.x_proof), entry.context),
            RegionBatchEntry(entry.y_commitment, entry.x_commitment, entry.region,
                             entry.proof, entry.context),
        ]
        for batch in cases:
            self.assertFalse(
                verify_region_batch([batch], randbelow=counter_randbelow()),
                f"batch accepted: {batch!r}",
            )

    def test_cross_item_recombination_fails(self):
        first = self.entry(context=b"a")
        second = self.entry(context=b"b", x_blinding=5555, y_blinding=6666)
        assert first.x_commitment != second.x_commitment  # distinct blinding factors
        # second's commitments paired with first's region proof
        recombined = RegionBatchEntry(
            second.x_commitment, second.y_commitment, second.region, first.proof, first.context
        )
        self.assertFalse(verify_region_batch([recombined], randbelow=counter_randbelow()))
        # proof from one item replayed with another item's context entry
        replayed = RegionBatchEntry(
            first.x_commitment, first.y_commitment, first.region, first.proof, second.context
        )
        self.assertFalse(verify_region_batch([replayed], randbelow=counter_randbelow()))

    def test_cancellation_does_not_cross_group_boundaries(self):
        # same prime/generator, different h: an x delta of +1 in one group and
        # a y delta of -1 in the other cannot cancel
        first = self.entry()
        xc, xr = self.commit(5, 0, 10, 333, h=7)
        yc, yr = self.commit(25, 20, 30, 444, h=7)
        proof = prove_region(xc, yc, 5, 25, xr, yr, first.region, b"ctx")
        second = RegionBatchEntry(xc, yc, first.region, proof, b"ctx")
        x_delta = RangeProof(
            first.proof.x_proof.t, first.proof.x_proof.e,
            first.proof.x_proof.s[:-1] + (first.proof.x_proof.s[-1] + 1,),
        )
        y_delta = RangeProof(
            proof.y_proof.t, proof.y_proof.e,
            proof.y_proof.s[:-1] + (proof.y_proof.s[-1] - 1,),
        )
        forged_first = RegionBatchEntry(
            first.x_commitment, first.y_commitment, first.region,
            RegionProof(x_delta, first.proof.y_proof), first.context,
        )
        forged_second = RegionBatchEntry(
            xc, yc, first.region, RegionProof(proof.x_proof, y_delta), b"ctx"
        )
        self.assertFalse(
            verify_region_batch([forged_first, forged_second], randbelow=lambda upper: 0)
        )

    def test_sub_proof_count_errors_return_false(self):
        entry = self.entry()
        short_x = RangeProof(entry.proof.x_proof.t[:-1], entry.proof.x_proof.e, entry.proof.x_proof.s)
        cases = [
            RegionProof(short_x, entry.proof.y_proof),
            RegionProof(entry.proof.x_proof, RangeProof((), (), ())),
        ]
        for forged in cases:
            bad = RegionBatchEntry(
                entry.x_commitment, entry.y_commitment, entry.region, forged, entry.context
            )
            self.assertFalse(verify_region_batch([bad], randbelow=counter_randbelow()))

    def test_oversized_axis_range_returns_false(self):
        entry = self.entry()
        wide_region = Region(0, 256, 20, 30)
        wide_x, _ = self.commit(5, 0, 256, 1234)
        bad = RegionBatchEntry(wide_x, entry.y_commitment, wide_region, entry.proof, entry.context)
        self.assertFalse(verify_region_batch([bad], randbelow=counter_randbelow()))

    def test_bad_embedded_commitment_parameters_return_false(self):
        entry = self.entry()
        for name, value in (("element", 0), ("prime", 7), ("generator", 1), ("h", self.PRIME)):
            broken_x = dataclasses.replace(entry.x_commitment, **{name: value})
            bad = RegionBatchEntry(
                broken_x, entry.y_commitment, entry.region, entry.proof, entry.context
            )
            self.assertFalse(
                verify_region_batch([bad], randbelow=counter_randbelow()), name
            )

    def test_invalid_entry_short_circuits_before_drawing(self):
        entry = self.entry()
        short_x = RangeProof(entry.proof.x_proof.t[:-1], entry.proof.x_proof.e, entry.proof.x_proof.s)
        invalid = RegionBatchEntry(
            entry.x_commitment, entry.y_commitment, entry.region,
            RegionProof(short_x, entry.proof.y_proof), entry.context,
        )
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertFalse(verify_region_batch([invalid, entry], randbelow=recording))
        self.assertEqual(calls, [])  # the invalid entry is rejected before any draw
        self.assertFalse(verify_region_batch([entry, invalid], randbelow=recording))
        self.assertEqual(calls, [self.PRIME - 1] * 22)  # one draw per branch of entry 1

    # ---- type errors ---------------------------------------------------------

    def test_type_errors(self):
        entry = self.entry()
        for bad in ("entries", b"entries", bytearray(b"x"), 42, None):
            with self.assertRaises(TypeError):
                verify_region_batch(bad)
        with self.assertRaises(TypeError):
            verify_region_batch([(entry.x_commitment, entry.y_commitment)])
        with self.assertRaises(TypeError):
            verify_region_batch([
                RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region, entry.proof, "ctx")
            ])
        with self.assertRaises(TypeError):
            verify_region_batch([
                RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region,
                                 (entry.proof.x_proof, entry.proof.y_proof), b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_region_batch([
                RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region,
                                 RegionProof("proof", entry.proof.y_proof), b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_region_batch([
                RegionBatchEntry(entry.x_commitment, entry.y_commitment,
                                 (0, 10, 20, 30), entry.proof, b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_region_batch([
                RegionBatchEntry((entry.x_commitment.element, 0, 10, self.PRIME, self.G, self.H),
                                 entry.y_commitment, entry.region, entry.proof, b"ctx")
            ])
        bool_proof = RegionProof(
            RangeProof((True,) * len(entry.proof.x_proof.t), entry.proof.x_proof.e, entry.proof.x_proof.s),
            entry.proof.y_proof,
        )
        with self.assertRaises(TypeError):
            verify_region_batch([
                RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region, bool_proof, b"ctx")
            ])
        list_proof = RegionProof(
            RangeProof(list(entry.proof.x_proof.t), entry.proof.x_proof.e, entry.proof.x_proof.s),
            entry.proof.y_proof,
        )
        with self.assertRaises(TypeError):
            verify_region_batch([
                RegionBatchEntry(entry.x_commitment, entry.y_commitment, entry.region, list_proof, b"ctx")
            ])
        with self.assertRaises(TypeError):
            verify_region_batch([entry], randbelow=7)

    def test_coefficient_source_errors(self):
        entry = self.entry()
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_region_batch([entry], randbelow=lambda upper, bad=bad: bad)
        for bad in (-1, self.PRIME - 1, self.PRIME):
            with self.assertRaises(ValueError):
                verify_region_batch([entry], randbelow=lambda upper, bad=bad: bad)

    # ---- hygiene -------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = [self.entry(), self.entry()]
        snapshot = [dataclasses.replace(entry) for entry in entries]
        verify_region_batch(entries, randbelow=counter_randbelow())
        self.assertEqual(entries, snapshot)

    def test_default_group_parameters_are_usable(self):
        region = Region(0, 10, 20, 30)
        x_commitment, x_r = pedersen_commit(5, 0, 10, blinding=987654321)
        y_commitment, y_r = pedersen_commit(25, 20, 30, blinding=123456789)
        proof = prove_region(x_commitment, y_commitment, 5, 25, x_r, y_r, region, b"demo")
        entry = RegionBatchEntry(x_commitment, y_commitment, region, proof, b"demo")
        self.assertTrue(verify_region_batch([entry], randbelow=counter_randbelow()))


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


class MultiSchnorrBatchTest(unittest.TestCase):
    G_PRIME = SMALL_PRIME
    G2_PRIME = 104723

    def prover(self, secret, prime, generator):
        return SchnorrProver(
            secret=secret, prime=prime, generator=generator, randbelow=counter_randbelow()
        )

    def setUp(self):
        self.alice = self.prover(4321, self.G_PRIME, 3)
        self.bob = self.prover(7777, self.G_PRIME, 3)
        self.carol = self.prover(5566, self.G2_PRIME, 3)

    def entry(self, prover, message, *, prime, generator, context=b"ctx"):
        return MultiSchnorrEntry(
            public_key=prover.public_key,
            message=message,
            proof=prover.prove(message, context=context),
            context=context,
            prime=prime,
            generator=generator,
        )

    # ---- entry object -------------------------------------------------------

    def test_entry_positional_defaults_equality_and_immutability(self):
        proof = self.alice.prove(b"m")
        entry = MultiSchnorrEntry(self.alice.public_key, b"m", proof)
        self.assertEqual(entry.context, b"")
        self.assertEqual(entry.prime, DEFAULT_PRIME)
        self.assertEqual(entry.generator, DEFAULT_GENERATOR)
        self.assertEqual(
            tuple(getattr(entry, name) for name in (
                "public_key", "message", "proof", "context", "prime", "generator")),
            (self.alice.public_key, b"m", proof, b"", DEFAULT_PRIME, DEFAULT_GENERATOR),
        )
        self.assertEqual(
            MultiSchnorrEntry(self.alice.public_key, b"m", proof, b"",
                              DEFAULT_PRIME, DEFAULT_GENERATOR),
            entry,
        )
        self.assertNotEqual(
            MultiSchnorrEntry(self.alice.public_key, b"other", proof), entry
        )
        self.assertNotEqual(
            MultiSchnorrEntry(self.alice.public_key, b"m", proof, b"c"), entry
        )
        self.assertNotEqual(
            MultiSchnorrEntry(self.bob.public_key, b"m", proof), entry
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.message = b"other"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.prime = 5

    def test_entry_field_types(self):
        entry = self.entry(self.alice, b"m", prime=self.G_PRIME, generator=3)
        self.assertIsInstance(entry.public_key, int)
        self.assertIsInstance(entry.message, bytes)
        self.assertIsInstance(entry.proof, SchnorrProof)
        self.assertIsInstance(entry.context, bytes)
        self.assertIsInstance(entry.prime, int)
        self.assertIsInstance(entry.generator, int)

    # ---- honest round trip --------------------------------------------------

    def test_honest_batch_verifies(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
        ]
        self.assertTrue(verify_schnorr_batch(entries, randbelow=counter_randbelow()))
        self.assertTrue(verify_schnorr_batch(tuple(entries)))  # default secrets.randbelow

    def test_single_entry_agrees_with_verify_proof(self):
        entry = self.entry(self.alice, b"m", prime=self.G_PRIME, generator=3)
        self.assertTrue(verify_schnorr_batch([entry], randbelow=counter_randbelow()))
        self.assertTrue(
            SchnorrVerifier(self.alice.public_key, prime=self.G_PRIME, generator=3)
            .verify_proof(b"m", entry.proof, context=b"ctx")
        )

    def test_empty_batch_returns_false(self):
        self.assertFalse(verify_schnorr_batch([], randbelow=counter_randbelow()))
        self.assertFalse(verify_schnorr_batch(()))

    def test_duplicate_entries_are_legal(self):
        entry = self.entry(self.alice, b"m", prime=self.G_PRIME, generator=3)
        self.assertTrue(
            verify_schnorr_batch([entry, entry, entry], randbelow=counter_randbelow())
        )

    def test_mixed_groups_each_checked_under_its_own_parameters(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.carol, b"gamma", prime=self.G2_PRIME, generator=3),
        ]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_schnorr_batch(entries, randbelow=recording))
        self.assertEqual(sorted(calls), sorted([self.G_PRIME - 1, self.G2_PRIME - 1]))

    def test_default_group_entries_usable(self):
        prover = SchnorrProver(secret=123456789, randbelow=counter_randbelow())
        entry = MultiSchnorrEntry(
            prover.public_key, b"demo", prover.prove(b"demo", context=b"c"), b"c"
        )
        self.assertEqual((entry.prime, entry.generator), (DEFAULT_PRIME, DEFAULT_GENERATOR))
        self.assertTrue(verify_schnorr_batch([entry], randbelow=counter_randbelow()))

    # ---- randomness ----------------------------------------------------------

    def test_randbelow_called_once_per_entry_with_prime_minus_one(self):
        entries = [
            self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3),
            self.entry(self.carol, b"c", prime=self.G2_PRIME, generator=3),
        ]
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_schnorr_batch(entries, randbelow=recording))
        self.assertEqual(sorted(calls), sorted([self.G_PRIME - 1, self.G2_PRIME - 1]))

    def test_fixed_coefficient_source_is_reproducible(self):
        entries = [
            self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"b", prime=self.G_PRIME, generator=3),
        ]
        first = verify_schnorr_batch(entries, randbelow=counter_randbelow(9))
        second = verify_schnorr_batch(entries, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_random_linear_combination_not_per_item_summary(self):
        # coefficients all 1: two individually invalid proofs under different
        # keys, in the same group, whose response errors cancel
        first = self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3)
        second = self.entry(self.bob, b"b", prime=self.G_PRIME, generator=3)
        forged = [
            MultiSchnorrEntry(first.public_key, b"a",
                              SchnorrProof(first.proof.commitment, first.proof.response + 1),
                              b"ctx", self.G_PRIME, 3),
            MultiSchnorrEntry(second.public_key, b"b",
                              SchnorrProof(second.proof.commitment, second.proof.response - 1),
                              b"ctx", self.G_PRIME, 3),
        ]
        for entry in forged:
            self.assertFalse(
                SchnorrVerifier(entry.public_key, prime=self.G_PRIME, generator=3)
                .verify_proof(entry.message, entry.proof, context=b"ctx")
            )
        self.assertTrue(verify_schnorr_batch(forged, randbelow=lambda upper: 0))

    # ---- rejection -----------------------------------------------------------

    def test_tampering_fails(self):
        good_first = self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3)
        second = self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3)
        forged = [
            MultiSchnorrEntry(
                good_first.public_key, b"alpha",
                SchnorrProof(good_first.proof.commitment, good_first.proof.response + 1),
                b"ctx", self.G_PRIME, 3,
            ),
            second,
        ]
        self.assertFalse(verify_schnorr_batch(forged, randbelow=counter_randbelow()))
        # wrong message / context / public key all break the transcript binding
        for bad in (
            MultiSchnorrEntry(good_first.public_key, b"other", good_first.proof,
                              b"ctx", self.G_PRIME, 3),
            MultiSchnorrEntry(good_first.public_key, b"alpha", good_first.proof,
                              b"other", self.G_PRIME, 3),
            MultiSchnorrEntry(self.bob.public_key, b"alpha", good_first.proof,
                              b"ctx", self.G_PRIME, 3),
            MultiSchnorrEntry(good_first.public_key, b"alpha", good_first.proof,
                              b"ctx", self.G_PRIME, 5),
        ):
            self.assertFalse(
                verify_schnorr_batch([bad, second], randbelow=counter_randbelow())
            )

    def test_entry_group_fields_bind_the_proof(self):
        # proof made under generator 3 verified under generator 5
        entry = self.entry(self.alice, b"m", prime=self.G_PRIME, generator=3)
        crossed = MultiSchnorrEntry(
            entry.public_key, b"m", entry.proof, b"ctx", self.G_PRIME, 5
        )
        self.assertFalse(verify_schnorr_batch([crossed], randbelow=counter_randbelow()))

    def test_cancellation_does_not_cross_group_boundaries(self):
        # response deltas of +1 and -1 in two different (prime, generator)
        # groups cannot cancel
        first = self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3)
        second = self.entry(self.carol, b"c", prime=self.G2_PRIME, generator=3)
        forged = [
            MultiSchnorrEntry(first.public_key, b"a",
                              SchnorrProof(first.proof.commitment, first.proof.response + 1),
                              b"ctx", self.G_PRIME, 3),
            MultiSchnorrEntry(second.public_key, b"c",
                              SchnorrProof(second.proof.commitment, second.proof.response - 1),
                              b"ctx", self.G2_PRIME, 3),
        ]
        self.assertFalse(verify_schnorr_batch(forged, randbelow=lambda upper: 0))

    def test_structural_errors_return_false(self):
        entry = self.entry(self.alice, b"m", prime=self.G_PRIME, generator=3)
        for bad_commitment in (0, self.G_PRIME, self.G_PRIME + 1, -1):
            bad = MultiSchnorrEntry(
                entry.public_key, b"m",
                SchnorrProof(bad_commitment, entry.proof.response),
                b"ctx", self.G_PRIME, 3,
            )
            self.assertFalse(
                verify_schnorr_batch([bad], randbelow=counter_randbelow()),
                f"commitment={bad_commitment}",
            )
        negative = MultiSchnorrEntry(
            entry.public_key, b"m", SchnorrProof(entry.proof.commitment, -1),
            b"ctx", self.G_PRIME, 3,
        )
        self.assertFalse(verify_schnorr_batch([negative], randbelow=counter_randbelow()))
        for bad_pk in (0, self.G_PRIME, -1):
            bad = MultiSchnorrEntry(
                bad_pk, b"m", entry.proof, b"ctx", self.G_PRIME, 3
            )
            self.assertFalse(verify_schnorr_batch([bad], randbelow=counter_randbelow()))
        for prime, generator in ((3, 2), (self.G_PRIME, 1), (self.G_PRIME, self.G_PRIME)):
            bad = MultiSchnorrEntry(
                entry.public_key, b"m", entry.proof, b"ctx", prime, generator
            )
            self.assertFalse(verify_schnorr_batch([bad], randbelow=counter_randbelow()))

    def test_invalid_entry_short_circuits_before_drawing(self):
        valid = self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3)
        invalid = MultiSchnorrEntry(
            valid.public_key, b"a", SchnorrProof(0, valid.proof.response),
            b"ctx", self.G_PRIME, 3,
        )
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertFalse(verify_schnorr_batch([invalid, valid], randbelow=recording))
        self.assertEqual(calls, [])
        self.assertFalse(verify_schnorr_batch([valid, invalid], randbelow=recording))
        self.assertEqual(calls, [self.G_PRIME - 1])

    # ---- type errors ---------------------------------------------------------

    def test_type_errors(self):
        entry = self.entry(self.alice, b"m", prime=self.G_PRIME, generator=3)
        for bad in ("entries", b"entries", bytearray(b"x"), 42, None):
            with self.assertRaises(TypeError):
                verify_schnorr_batch(bad)
        with self.assertRaises(TypeError):
            verify_schnorr_batch([(entry.public_key, entry.message, entry.proof)])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry("pk", b"m", entry.proof, b"ctx", self.G_PRIME, 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(True, b"m", entry.proof, b"ctx", self.G_PRIME, 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(entry.public_key, "m", entry.proof, b"ctx", self.G_PRIME, 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(entry.public_key, b"m", entry.proof, "ctx", self.G_PRIME, 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(entry.public_key, b"m",
                                  (entry.proof.commitment, entry.proof.response),
                                  b"ctx", self.G_PRIME, 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(entry.public_key, b"m",
                                  SchnorrProof(1.5, entry.proof.response),
                                  b"ctx", self.G_PRIME, 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(entry.public_key, b"m",
                                  SchnorrProof(entry.proof.commitment, False),
                                  b"ctx", self.G_PRIME, 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(entry.public_key, b"m", entry.proof, b"ctx",
                                  str(self.G_PRIME), 3)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([
                MultiSchnorrEntry(entry.public_key, b"m", entry.proof, b"ctx",
                                  self.G_PRIME, True)
            ])
        with self.assertRaises(TypeError):
            verify_schnorr_batch([entry], randbelow=7)

    def test_coefficient_source_errors(self):
        entry = self.entry(self.alice, b"m", prime=self.G_PRIME, generator=3)
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_schnorr_batch([entry], randbelow=lambda upper, bad=bad: bad)
        for bad in (-1, self.G_PRIME - 1, self.G_PRIME):
            with self.assertRaises(ValueError):
                verify_schnorr_batch([entry], randbelow=lambda upper, bad=bad: bad)

    # ---- hygiene -------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        entries = [
            self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"b", prime=self.G_PRIME, generator=3),
        ]
        snapshot = [dataclasses.replace(entry) for entry in entries]
        verify_schnorr_batch(entries, randbelow=counter_randbelow())
        self.assertEqual(entries, snapshot)


def leaf_digest(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + len(leaf).to_bytes(4, "big") + leaf).digest()


def node_digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def encode_uint(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def bound_schnorr_leaf(entry: MultiSchnorrEntry) -> bytes:
    items = (
        b"zkregion/schnorr-fs/v1",
        encode_uint(entry.prime),
        encode_uint(entry.generator),
        encode_uint(entry.public_key),
        encode_uint(entry.proof.commitment),
        entry.context,
        entry.message,
        encode_uint(entry.proof.response),
    )
    return b"".join(len(item).to_bytes(4, "big") + item for item in items)


class BoundSchnorrBatchTest(unittest.TestCase):
    G_PRIME = SMALL_PRIME
    G2_PRIME = 104723

    def prover(self, secret, prime, generator):
        return SchnorrProver(
            secret=secret, prime=prime, generator=generator, randbelow=counter_randbelow()
        )

    def setUp(self):
        self.alice = self.prover(4321, self.G_PRIME, 3)
        self.bob = self.prover(7777, self.G_PRIME, 3)
        self.carol = self.prover(5566, self.G2_PRIME, 3)

    def entry(self, prover, message, *, prime, generator, context=b"ctx"):
        return MultiSchnorrEntry(
            public_key=prover.public_key,
            message=message,
            proof=prover.prove(message, context=context),
            context=context,
            prime=prime,
            generator=generator,
        )

    def build(self, entries):
        leaves = [bound_schnorr_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundSchnorrBatch(tuple(entries), len(entries), proof)
        return batch, root

    def honest(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
            self.entry(self.carol, b"gamma", prime=self.G2_PRIME, generator=3),
        ]
        return self.build(entries)

    # ---- batch object -------------------------------------------------------

    def test_batch_positional_equality_and_immutability(self):
        batch, root = self.honest()
        proof = batch.proof
        rebuilt = BoundSchnorrBatch(batch.entries, 3, proof)
        self.assertEqual(rebuilt, batch)
        self.assertEqual(hash(rebuilt), hash(batch))
        self.assertEqual(
            tuple(getattr(batch, name) for name in ("entries", "leaf_count", "proof")),
            (batch.entries, 3, proof),
        )
        self.assertIsInstance(batch.entries, tuple)
        self.assertNotEqual(
            BoundSchnorrBatch(batch.entries, 4, proof), batch
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 4
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.entries = ()

    def test_field_types(self):
        batch, _ = self.honest()
        self.assertIsInstance(batch.entries, tuple)
        for entry in batch.entries:
            self.assertIsInstance(entry, MultiSchnorrEntry)
        self.assertIsInstance(batch.leaf_count, int)
        self.assertNotIsInstance(batch.leaf_count, bool)
        self.assertIsInstance(batch.proof, MerkleMultiProof)

    # ---- honest round trip --------------------------------------------------

    def test_honest_batch_verifies(self):
        batch, root = self.honest()
        self.assertTrue(verify_bound(batch, root, randbelow=counter_randbelow()))
        self.assertTrue(verify_bound(batch, root))  # default secrets.randbelow

    def test_single_entry_batch_verifies(self):
        entries = [self.entry(self.alice, b"only", prime=self.G_PRIME, generator=3)]
        batch, root = self.build(entries)
        self.assertTrue(verify_bound(batch, root, randbelow=counter_randbelow()))
        self.assertTrue(
            verify_schnorr_batch(entries, randbelow=counter_randbelow())
        )

    def test_full_leaf_proof_has_empty_siblings(self):
        batch, root = self.honest()
        self.assertEqual(batch.proof.siblings, ())

    def test_leaf_is_the_seven_transcript_items_plus_response(self):
        from zkregion import _fs_challenge

        batch, _ = self.honest()
        entry = batch.entries[0]
        leaf = bound_schnorr_leaf(entry)
        offset = 0
        items = []
        for _ in range(8):
            length = int.from_bytes(leaf[offset:offset + 4], "big")
            offset += 4
            items.append(leaf[offset:offset + length])
            offset += length
        self.assertEqual(offset, len(leaf))  # exactly eight framed items, nothing trailing
        self.assertEqual(items[0], b"zkregion/schnorr-fs/v1")
        self.assertEqual(items[1], encode_uint(entry.prime))
        self.assertEqual(items[2], encode_uint(entry.generator))
        self.assertEqual(items[3], encode_uint(entry.public_key))
        self.assertEqual(items[4], encode_uint(entry.proof.commitment))
        self.assertEqual(items[5], entry.context)
        self.assertEqual(items[6], entry.message)
        self.assertEqual(items[7], encode_uint(entry.proof.response))
        # shortest unsigned big-endian: no leading zero bytes
        self.assertFalse(items[1].startswith(b"\x00"))
        self.assertFalse(items[7].startswith(b"\x00"))
        # the same seven items drive the Fiat-Shamir challenge, in order
        fs = hashlib.sha256()
        for item in items[:7]:
            fs.update(len(item).to_bytes(4, "big"))
            fs.update(item)
        self.assertEqual(
            int.from_bytes(fs.digest(), "big") % entry.prime,
            _fs_challenge(
                entry.prime, entry.generator, entry.public_key,
                entry.proof.commitment, entry.context, entry.message,
            ),
        )

    def test_leaf_uses_merkle_leaf_domain(self):
        batch, root = self.honest()
        # root recomputed with the library's leaf framing must match
        self.assertEqual(
            merkle_root([bound_schnorr_leaf(entry) for entry in batch.entries]), root
        )

    def test_empty_context_and_message_are_framed_as_zero_length(self):
        entry = self.entry(self.alice, b"", prime=self.G_PRIME, generator=3, context=b"")
        leaf = bound_schnorr_leaf(entry)
        # offset of the context item (index 5): five prior 4-byte prefixes + bodies
        offset = 0
        for _ in range(5):
            length = int.from_bytes(leaf[offset:offset + 4], "big")
            offset += 4 + length
        self.assertEqual(leaf[offset:offset + 4], b"\x00\x00\x00\x00")  # empty context
        offset += 4
        self.assertEqual(leaf[offset:offset + 4], b"\x00\x00\x00\x00")  # empty message

    # ---- completeness / count checks ---------------------------------------

    def test_empty_batch_returns_false(self):
        proof = MerkleMultiProof(1, (), ())
        batch = BoundSchnorrBatch((), 0, proof)
        self.assertFalse(verify_bound(batch, bytes(32), randbelow=counter_randbelow()))

    def test_leaf_count_must_equal_entry_count(self):
        entries = [
            self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"b", prime=self.G_PRIME, generator=3),
        ]
        leaves = [bound_schnorr_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, (0, 1))
        for count in (1, 3, 0):
            batch = BoundSchnorrBatch(tuple(entries), count, proof)
            self.assertFalse(
                verify_bound(batch, root, randbelow=counter_randbelow()), count
            )

    def test_leaf_count_must_equal_proof_leaf_count(self):
        entries = [
            self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"b", prime=self.G_PRIME, generator=3),
        ]
        leaves = [bound_schnorr_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, (0, 1))
        for claimed in (1, 3):
            bad_proof = dataclasses.replace(proof, leaf_count=claimed)
            batch = BoundSchnorrBatch(tuple(entries), 2, bad_proof)
            self.assertFalse(
                verify_bound(batch, root, randbelow=counter_randbelow()), claimed
            )

    def test_indices_must_cover_zero_to_n_without_gaps(self):
        batch, root = self.honest()
        good_indices = batch.proof.indices
        for bad_indices in (
            (0, 1),          # missing one
            (0, 1, 1),       # duplicate
            (0, 0, 2),       # duplicate with gap
            (2, 1, 0),       # reversed
            (0, 2, 1),       # reordered
            (1, 2, 3),       # starts at 1
            (-1, 1, 2),      # negative
            (0, 1, 3),       # gap at the end
            (),              # empty
        ):
            bad_proof = MerkleMultiProof(3, bad_indices, batch.proof.siblings)
            bad_batch = BoundSchnorrBatch(batch.entries, 3, bad_proof)
            self.assertFalse(
                verify_bound(bad_batch, root, randbelow=counter_randbelow()),
                bad_indices,
            )
        self.assertEqual(good_indices, (0, 1, 2))

    def test_missing_entry_returns_false(self):
        entries = [
            self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"b", prime=self.G_PRIME, generator=3),
        ]
        leaves = [bound_schnorr_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        # proof claims three leaves covering 0..2 but only two entries exist
        proof = MerkleMultiProof(3, (0, 1, 2), ())
        batch = BoundSchnorrBatch(tuple(entries), 3, proof)
        self.assertFalse(verify_bound(batch, root, randbelow=counter_randbelow()))

    # ---- Merkle binding rejection -------------------------------------------

    def test_wrong_root_returns_false(self):
        batch, _ = self.honest()
        self.assertFalse(verify_bound(batch, bytes(32), randbelow=counter_randbelow()))
        other = merkle_root([b"alpha", b"beta", b"gamma"])
        self.assertFalse(verify_bound(batch, other, randbelow=counter_randbelow()))

    def test_tampered_leaf_returns_false_even_with_matching_proof(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
        ]
        batch, root = self.build(entries)
        # tamper the message but keep a structurally valid proof for the old leaves
        tampered = dataclasses.replace(entries[0], message=b"other")
        bad_batch = BoundSchnorrBatch((tampered, entries[1]), 2, batch.proof)
        self.assertFalse(verify_bound(bad_batch, root, randbelow=counter_randbelow()))
        # wrong public key / context / group likewise change the leaf
        for tampered in (
            dataclasses.replace(entries[0], public_key=self.bob.public_key),
            dataclasses.replace(entries[0], context=b"other"),
            dataclasses.replace(entries[0], prime=self.G2_PRIME),
            dataclasses.replace(entries[0], generator=5),
        ):
            bad_batch = BoundSchnorrBatch((tampered, entries[1]), 2, batch.proof)
            self.assertFalse(
                verify_bound(bad_batch, root, randbelow=counter_randbelow()),
                tampered,
            )

    def test_response_is_committed_by_the_leaf(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
        ]
        batch, root = self.build(entries)
        tampered = dataclasses.replace(
            entries[0],
            proof=SchnorrProof(entries[0].proof.commitment, entries[0].proof.response + 1),
        )
        bad_batch = BoundSchnorrBatch((tampered, entries[1]), 2, batch.proof)
        self.assertFalse(verify_bound(bad_batch, root, randbelow=counter_randbelow()))

    def test_committed_but_forged_signature_fails_at_signature_step(self):
        # the forged batch is honestly committed to its own (modified) leaves,
        # so the Merkle step passes; signature verification must still fail
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
        ]
        forged_entry = dataclasses.replace(
            entries[0],
            proof=SchnorrProof(entries[0].proof.commitment, entries[0].proof.response + 1),
        )
        forged_entries = [forged_entry, entries[1]]
        bad_batch, forged_root = self.build(forged_entries)
        self.assertTrue(  # Merkle step alone passes against the forged root
            verify_multi_inclusion(
                [(i, bound_schnorr_leaf(e)) for i, e in enumerate(forged_entries)],
                bad_batch.proof,
                forged_root,
            )
        )
        self.assertFalse(
            verify_bound(bad_batch, forged_root, randbelow=counter_randbelow())
        )

    def test_tampered_siblings_return_false(self):
        batch, root = self.honest()
        # a complete-coverage proof consumes no siblings: any supplied
        # sibling must be rejected as leftover/structural garbage
        self.assertEqual(batch.proof.siblings, ())
        bogus = MerkleMultiProof(3, batch.proof.indices, (root,))
        bad_batch = BoundSchnorrBatch(batch.entries, 3, bogus)
        self.assertFalse(verify_bound(bad_batch, root, randbelow=counter_randbelow()))
        # and a wrong root digest length fails the Merkle step
        self.assertFalse(
            verify_bound(batch, root + b"\x00", randbelow=counter_randbelow())
        )

    # ---- randomness contract ------------------------------------------------

    def test_randbelow_passed_unchanged_and_called_once_per_entry(self):
        batch, root = self.honest()
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_bound(batch, root, randbelow=recording))
        self.assertEqual(sorted(calls), sorted([self.G_PRIME - 1, self.G_PRIME - 1, self.G2_PRIME - 1]))

    def test_no_randomness_consumed_before_the_root_check(self):
        batch, _ = self.honest()

        def boom(upper):
            raise AssertionError("randbelow must not be called before the root checks")

        self.assertFalse(verify_bound(batch, bytes(32), randbelow=boom))

    def test_fixed_randbelow_is_reproducible(self):
        batch, root = self.honest()
        first = verify_bound(batch, root, randbelow=counter_randbelow(9))
        second = verify_bound(batch, root, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_non_random_source_invalidates_or_raises_per_schnorr_contract(self):
        batch, root = self.honest()
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_bound(batch, root, randbelow=lambda upper, bad=bad: bad)
        for bad in (-1, self.G_PRIME - 1, self.G_PRIME):
            with self.assertRaises(ValueError):
                verify_bound(batch, root, randbelow=lambda upper, bad=bad: bad)

    def test_structurally_invalid_integer_fields_return_false_without_encoding_error(self):
        # unsigned leaf framing cannot represent negatives and verify_bound
        # must report False rather than raise OverflowError, before drawing
        entries = [
            self.entry(self.alice, b"a", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"b", prime=self.G_PRIME, generator=3),
        ]
        batch, root = self.build(entries)
        good = entries[0]
        cases = [
            dataclasses.replace(good, prime=-5),
            dataclasses.replace(good, generator=-1),
            dataclasses.replace(good, public_key=-1),
            dataclasses.replace(good, proof=SchnorrProof(-1, good.proof.response)),
            dataclasses.replace(good, proof=SchnorrProof(good.proof.commitment, -1)),
        ]
        for bad_entry in cases:
            bad_batch = BoundSchnorrBatch((bad_entry, entries[1]), 2, batch.proof)

            def boom(upper):
                raise AssertionError("randbelow must not be called")

            self.assertFalse(
                verify_bound(bad_batch, root, randbelow=counter_randbelow()), bad_entry
            )
            self.assertFalse(verify_bound(bad_batch, bytes(32), randbelow=boom))

    # ---- type errors ---------------------------------------------------------

    def test_type_errors(self):
        batch, root = self.honest()
        with self.assertRaises(TypeError):
            verify_bound("batch", root)
        with self.assertRaises(TypeError):
            verify_bound(None, root)
        with self.assertRaises(TypeError):
            verify_bound(BoundSchnorrBatch(list(batch.entries), 3, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_bound(BoundSchnorrBatch(("x",) * 3, 3, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_bound(BoundSchnorrBatch(batch.entries, True, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_bound(BoundSchnorrBatch(batch.entries, 3.0, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_bound(BoundSchnorrBatch(batch.entries, "3", batch.proof), root)
        with self.assertRaises(TypeError):
            verify_bound(BoundSchnorrBatch(batch.entries, 3, "proof"), root)
        with self.assertRaises(TypeError):
            verify_bound(batch, "root")
        with self.assertRaises(TypeError):
            verify_bound(batch, bytearray(root))
        with self.assertRaises(TypeError):
            verify_bound(batch, root, randbelow=7)
        # malformed nested entry fields
        good = batch.entries[0]
        cases = [
            dataclasses.replace(good, public_key="pk"),
            dataclasses.replace(good, public_key=True),
            dataclasses.replace(good, message="m"),
            dataclasses.replace(good, context="ctx"),
            dataclasses.replace(good, prime=str(self.G_PRIME)),
            dataclasses.replace(good, prime=True),
            dataclasses.replace(good, generator=True),
            dataclasses.replace(good, proof=(good.proof.commitment, good.proof.response)),
        ]
        for bad_entry in cases:
            entries = (bad_entry,) + batch.entries[1:]
            bad_batch = BoundSchnorrBatch(entries, 3, batch.proof)
            with self.assertRaises(TypeError):
                verify_bound(bad_batch, root, randbelow=counter_randbelow())
        for bad_proof in (
            SchnorrProof(1.5, good.proof.response),
            SchnorrProof(good.proof.commitment, "s"),
            SchnorrProof(True, good.proof.response),
            SchnorrProof(good.proof.commitment, False),
        ):
            entries = (dataclasses.replace(good, proof=bad_proof),) + batch.entries[1:]
            bad_batch = BoundSchnorrBatch(entries, 3, batch.proof)
            with self.assertRaises(TypeError):
                verify_bound(bad_batch, root, randbelow=counter_randbelow())
        # malformed MerkleMultiProof fields
        with self.assertRaises(TypeError):
            verify_bound(
                BoundSchnorrBatch(batch.entries, 3,
                                  MerkleMultiProof(True, (0, 1, 2), ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_bound(
                BoundSchnorrBatch(batch.entries, 3,
                                  MerkleMultiProof(3, [0, 1, 2], ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_bound(
                BoundSchnorrBatch(batch.entries, 3,
                                  MerkleMultiProof(3, (0, 1, 2.0), ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_bound(
                BoundSchnorrBatch(batch.entries, 3,
                                  MerkleMultiProof(3, (0, 1, 2), ["x"])),
                root,
            )

    # ---- hygiene -------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        batch, root = self.honest()
        snapshot = BoundSchnorrBatch(
            tuple(dataclasses.replace(entry) for entry in batch.entries),
            batch.leaf_count,
            dataclasses.replace(batch.proof),
        )
        verify_bound(batch, root, randbelow=counter_randbelow())
        self.assertEqual(batch, snapshot)


def bound_range_leaf(entry: RangeBatchEntry) -> bytes:
    items = [b"zkregion/range-bound/v1"]
    commitment = entry.commitment
    items += [
        str(value).encode("ascii")
        for value in (
            commitment.element,
            commitment.lower,
            commitment.upper,
            commitment.prime,
            commitment.generator,
            commitment.h,
        )
    ]
    items.append(entry.context)
    for sequence in (entry.proof.t, entry.proof.e, entry.proof.s):
        items.append(str(len(sequence)).encode("ascii"))
        items += [str(value).encode("ascii") for value in sequence]
    return b"".join(len(item).to_bytes(4, "big") + item for item in items)


def bound_region_leaf(entry: RegionBatchEntry) -> bytes:
    items = [b"zkregion/region-bound/v1"]
    for commitment in (entry.x_commitment, entry.y_commitment):
        items += [
            str(value).encode("ascii")
            for value in (
                commitment.element,
                commitment.lower,
                commitment.upper,
                commitment.prime,
                commitment.generator,
                commitment.h,
            )
        ]
    region = entry.region
    items += [
        str(value).encode("ascii")
        for value in (region.min_x, region.max_x, region.min_y, region.max_y)
    ]
    items.append(entry.context)
    for sub_proof in (entry.proof.x_proof, entry.proof.y_proof):
        for sequence in (sub_proof.t, sub_proof.e, sub_proof.s):
            items.append(str(len(sequence)).encode("ascii"))
            items += [str(value).encode("ascii") for value in sequence]
    return b"".join(len(item).to_bytes(4, "big") + item for item in items)


def frame_items(leaf: bytes) -> list:
    items = []
    offset = 0
    while offset < len(leaf):
        length = int.from_bytes(leaf[offset:offset + 4], "big")
        offset += 4
        items.append(leaf[offset:offset + length])
        offset += length
    return items


class BoundRangeBatchTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def entry(self, value=5, lower=0, upper=10, context=b"ctx", blinding=1234):
        commitment, r = pedersen_commit(
            value, lower, upper, blinding=blinding,
            prime=self.PRIME, generator=self.G, h=self.H,
        )
        proof = prove_range(
            commitment, value, r, context, randbelow=counter_randbelow()
        )
        return RangeBatchEntry(commitment, proof, context)

    def build(self, entries):
        leaves = [bound_range_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundRangeBatch(tuple(entries), len(entries), proof)
        return batch, root

    def honest(self):
        entries = [
            self.entry(value=5, context=b"a"),
            self.entry(value=7, context=b"b"),
            self.entry(value=0, context=b"c"),
        ]
        return self.build(entries)

    # ---- batch object -------------------------------------------------------

    def test_batch_positional_equality_and_immutability(self):
        batch, root = self.honest()
        proof = batch.proof
        rebuilt = BoundRangeBatch(batch.entries, 3, proof)
        self.assertEqual(rebuilt, batch)
        self.assertEqual(hash(rebuilt), hash(batch))
        self.assertEqual(
            tuple(getattr(batch, name) for name in ("entries", "leaf_count", "proof")),
            (batch.entries, 3, proof),
        )
        self.assertIsInstance(batch.entries, tuple)
        self.assertNotEqual(
            BoundRangeBatch(batch.entries, 4, proof), batch
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 4
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.entries = ()

    def test_entries_must_be_tuple(self):
        batch, root = self.honest()
        # the dataclass stores whatever it is given; verification rejects a
        # non-tuple entries field with TypeError
        loose = BoundRangeBatch(list(batch.entries), 3, batch.proof)
        self.assertNotIsInstance(loose.entries, tuple)
        with self.assertRaises(TypeError):
            verify_range_bound(loose, root, randbelow=counter_randbelow())

    def test_field_types(self):
        batch, _ = self.honest()
        self.assertIsInstance(batch.entries, tuple)
        for entry in batch.entries:
            self.assertIsInstance(entry, RangeBatchEntry)
        self.assertIsInstance(batch.leaf_count, int)
        self.assertNotIsInstance(batch.leaf_count, bool)
        self.assertIsInstance(batch.proof, MerkleMultiProof)

    # ---- honest round trip --------------------------------------------------

    def test_honest_batch_verifies(self):
        batch, root = self.honest()
        self.assertTrue(verify_range_bound(batch, root, randbelow=counter_randbelow()))
        self.assertTrue(verify_range_bound(batch, root))  # default secrets.randbelow

    def test_single_entry_batch_verifies(self):
        entries = [self.entry()]
        batch, root = self.build(entries)
        self.assertTrue(verify_range_bound(batch, root, randbelow=counter_randbelow()))
        self.assertTrue(
            verify_range_batch(entries, randbelow=counter_randbelow())
        )

    def test_full_leaf_proof_has_empty_siblings(self):
        batch, root = self.honest()
        self.assertEqual(batch.proof.siblings, ())

    def test_leaf_layout(self):
        batch, _ = self.honest()
        entry = batch.entries[0]
        items = frame_items(bound_range_leaf(entry))
        size = entry.commitment.upper - entry.commitment.lower + 1
        expected_count = 1 + 6 + 1 + 3 * (1 + size)
        self.assertEqual(len(items), expected_count)
        self.assertEqual(items[0], b"zkregion/range-bound/v1")
        cursor = 1
        for value in (
            entry.commitment.element, entry.commitment.lower, entry.commitment.upper,
            entry.commitment.prime, entry.commitment.generator, entry.commitment.h,
        ):
            self.assertEqual(items[cursor], str(value).encode("ascii"))
            cursor += 1
        self.assertEqual(items[cursor], entry.context)
        cursor += 1
        for sequence in (entry.proof.t, entry.proof.e, entry.proof.s):
            self.assertEqual(items[cursor], str(len(sequence)).encode("ascii"))
            cursor += 1
            for value in sequence:
                self.assertEqual(items[cursor], str(value).encode("ascii"))
                cursor += 1
        self.assertEqual(cursor, len(items))

    def test_leaf_uses_merkle_leaf_domain(self):
        batch, root = self.honest()
        self.assertEqual(
            merkle_root([bound_range_leaf(entry) for entry in batch.entries]), root
        )

    def test_empty_context_is_framed_as_zero_length(self):
        entry = self.entry(context=b"")
        items = frame_items(bound_range_leaf(entry))
        self.assertEqual(items[1 + 6], b"")  # context item

    def test_negative_bounds_are_framed_with_their_sign(self):
        entry = self.entry(value=-5, lower=-10, upper=10)
        items = frame_items(bound_range_leaf(entry))
        self.assertIn(b"-10", items)
        batch, root = self.build([entry])
        self.assertTrue(verify_range_bound(batch, root, randbelow=counter_randbelow()))

    # ---- completeness / count checks ---------------------------------------

    def test_empty_batch_returns_false(self):
        proof = MerkleMultiProof(1, (), ())
        batch = BoundRangeBatch((), 0, proof)
        self.assertFalse(verify_range_bound(batch, bytes(32), randbelow=counter_randbelow()))

    def test_leaf_count_must_equal_entry_count(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        leaves = [bound_range_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, (0, 1))
        for count in (1, 3, 0):
            batch = BoundRangeBatch(tuple(entries), count, proof)
            self.assertFalse(
                verify_range_bound(batch, root, randbelow=counter_randbelow()), count
            )

    def test_leaf_count_must_equal_proof_leaf_count(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        leaves = [bound_range_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, (0, 1))
        for claimed in (1, 3):
            bad_proof = dataclasses.replace(proof, leaf_count=claimed)
            batch = BoundRangeBatch(tuple(entries), 2, bad_proof)
            self.assertFalse(
                verify_range_bound(batch, root, randbelow=counter_randbelow()), claimed
            )

    def test_indices_must_cover_zero_to_n_without_gaps(self):
        batch, root = self.honest()
        good_indices = batch.proof.indices
        for bad_indices in (
            (0, 1),          # missing one
            (0, 1, 1),       # duplicate
            (0, 0, 2),       # duplicate with gap
            (2, 1, 0),       # reversed
            (0, 2, 1),       # reordered
            (1, 2, 3),       # starts at 1
            (-1, 1, 2),      # negative
            (0, 1, 3),       # gap at the end
            (),              # empty
        ):
            bad_proof = MerkleMultiProof(3, bad_indices, batch.proof.siblings)
            bad_batch = BoundRangeBatch(batch.entries, 3, bad_proof)
            self.assertFalse(
                verify_range_bound(bad_batch, root, randbelow=counter_randbelow()),
                bad_indices,
            )
        self.assertEqual(good_indices, (0, 1, 2))

    def test_missing_entry_returns_false(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        leaves = [bound_range_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        # proof claims three leaves covering 0..2 but only two entries exist
        proof = MerkleMultiProof(3, (0, 1, 2), ())
        batch = BoundRangeBatch(tuple(entries), 3, proof)
        self.assertFalse(verify_range_bound(batch, root, randbelow=counter_randbelow()))

    # ---- Merkle binding rejection -------------------------------------------

    def test_wrong_root_returns_false(self):
        batch, _ = self.honest()
        self.assertFalse(verify_range_bound(batch, bytes(32), randbelow=counter_randbelow()))
        other = merkle_root([b"alpha", b"beta", b"gamma"])
        self.assertFalse(verify_range_bound(batch, other, randbelow=counter_randbelow()))

    def test_tampered_leaf_returns_false_even_with_matching_proof(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        batch, root = self.build(entries)
        good = entries[0]
        # every committed field change must change the leaf
        tampered_commitment = dataclasses.replace(
            good.commitment, element=good.commitment.element + 1
        )
        tampered_proof = RangeProof(
            good.proof.t[:-1] + (good.proof.t[-1] + 1,),
            good.proof.e,
            good.proof.s,
        )
        for tampered in (
            dataclasses.replace(good, context=b"other"),
            dataclasses.replace(good, commitment=tampered_commitment),
            dataclasses.replace(good, proof=tampered_proof),
        ):
            bad_batch = BoundRangeBatch((tampered, entries[1]), 2, batch.proof)
            self.assertFalse(
                verify_range_bound(bad_batch, root, randbelow=counter_randbelow()),
                tampered,
            )

    def test_committed_but_forged_proof_fails_at_batch_step(self):
        # the forged batch is honestly committed to its own (modified) leaves,
        # so the Merkle step passes; range batch verification must still fail
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        good = entries[0]
        forged_entry = dataclasses.replace(
            good,
            proof=RangeProof(
                good.proof.t,
                good.proof.e,
                good.proof.s[:-1] + (good.proof.s[-1] + 1,),
            ),
        )
        forged_entries = [forged_entry, entries[1]]
        bad_batch, forged_root = self.build(forged_entries)
        self.assertTrue(  # Merkle step alone passes against the forged root
            verify_multi_inclusion(
                [(i, bound_range_leaf(e)) for i, e in enumerate(forged_entries)],
                bad_batch.proof,
                forged_root,
            )
        )
        self.assertFalse(
            verify_range_bound(bad_batch, forged_root, randbelow=counter_randbelow())
        )

    def test_tampered_siblings_return_false(self):
        batch, root = self.honest()
        # a complete-coverage proof consumes no siblings: any supplied
        # sibling must be rejected as leftover/structural garbage
        self.assertEqual(batch.proof.siblings, ())
        bogus = MerkleMultiProof(3, batch.proof.indices, (root,))
        bad_batch = BoundRangeBatch(batch.entries, 3, bogus)
        self.assertFalse(verify_range_bound(bad_batch, root, randbelow=counter_randbelow()))
        # and a wrong root digest length fails the Merkle step
        self.assertFalse(
            verify_range_bound(bad_batch, root + b"\x00", randbelow=counter_randbelow())
        )

    # ---- randomness contract ------------------------------------------------

    def test_randbelow_passed_unchanged_and_called_once_per_branch(self):
        batch, root = self.honest()
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_range_bound(batch, root, randbelow=recording))
        branches = sum(
            entry.commitment.upper - entry.commitment.lower + 1
            for entry in batch.entries
        )
        self.assertEqual(calls, [self.PRIME - 1] * branches)

    def test_no_randomness_consumed_before_the_root_check(self):
        batch, _ = self.honest()

        def boom(upper):
            raise AssertionError("randbelow must not be called before the root checks")

        self.assertFalse(verify_range_bound(batch, bytes(32), randbelow=boom))
        # a root check that fails structurally still draws nothing
        bad_proof = MerkleMultiProof(3, (0, 1), batch.proof.siblings)
        bad_batch = BoundRangeBatch(batch.entries, 3, bad_proof)
        self.assertFalse(verify_range_bound(bad_batch, bytes(32), randbelow=boom))

    def test_fixed_randbelow_is_reproducible(self):
        batch, root = self.honest()
        first = verify_range_bound(batch, root, randbelow=counter_randbelow(9))
        second = verify_range_bound(batch, root, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_non_random_source_invalidates_or_raises_per_range_batch_contract(self):
        batch, root = self.honest()
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_range_bound(batch, root, randbelow=lambda upper, bad=bad: bad)
        for bad in (-1, self.PRIME - 1, self.PRIME):
            with self.assertRaises(ValueError):
                verify_range_bound(batch, root, randbelow=lambda upper, bad=bad: bad)

    # ---- type errors ---------------------------------------------------------

    def test_type_errors(self):
        batch, root = self.honest()
        with self.assertRaises(TypeError):
            verify_range_bound("batch", root)
        with self.assertRaises(TypeError):
            verify_range_bound(None, root)
        with self.assertRaises(TypeError):
            verify_range_bound(BoundRangeBatch(list(batch.entries), 3, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_range_bound(BoundRangeBatch(("x",) * 3, 3, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_range_bound(BoundRangeBatch(batch.entries, True, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_range_bound(BoundRangeBatch(batch.entries, 3.0, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_range_bound(BoundRangeBatch(batch.entries, "3", batch.proof), root)
        with self.assertRaises(TypeError):
            verify_range_bound(BoundRangeBatch(batch.entries, 3, "proof"), root)
        with self.assertRaises(TypeError):
            verify_range_bound(batch, "root")
        with self.assertRaises(TypeError):
            verify_range_bound(batch, bytearray(root))
        with self.assertRaises(TypeError):
            verify_range_bound(batch, root, randbelow=7)
        # malformed nested entry fields
        good = batch.entries[0]
        bad_commitment = dataclasses.replace(good.commitment, element=True)
        cases = [
            dataclasses.replace(good, commitment="c"),
            dataclasses.replace(good, commitment=bad_commitment),
            dataclasses.replace(good, proof="p"),
            dataclasses.replace(good, context="ctx"),
            dataclasses.replace(
                good,
                proof=RangeProof(
                    list(good.proof.t), good.proof.e, good.proof.s
                ),
            ),
            dataclasses.replace(
                good,
                proof=RangeProof(
                    good.proof.t, good.proof.e[:-1] + (True,), good.proof.s
                ),
            ),
        ]
        for bad_entry in cases:
            entries = (bad_entry,) + batch.entries[1:]
            bad_batch = BoundRangeBatch(entries, 3, batch.proof)
            with self.assertRaises(TypeError):
                verify_range_bound(bad_batch, root, randbelow=counter_randbelow())
        # malformed MerkleMultiProof fields
        with self.assertRaises(TypeError):
            verify_range_bound(
                BoundRangeBatch(batch.entries, 3,
                                MerkleMultiProof(True, (0, 1, 2), ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_range_bound(
                BoundRangeBatch(batch.entries, 3,
                                MerkleMultiProof(3, [0, 1, 2], ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_range_bound(
                BoundRangeBatch(batch.entries, 3,
                                MerkleMultiProof(3, (0, 1, 2.0), ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_range_bound(
                BoundRangeBatch(batch.entries, 3,
                                MerkleMultiProof(3, (0, 1, 2), ["x"])),
                root,
            )

    # ---- hygiene -------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        batch, root = self.honest()
        snapshot = BoundRangeBatch(
            tuple(dataclasses.replace(entry) for entry in batch.entries),
            batch.leaf_count,
            dataclasses.replace(batch.proof),
        )
        verify_range_bound(batch, root, randbelow=counter_randbelow())
        self.assertEqual(batch, snapshot)


class BoundRegionBatchTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def entry(self, x=5, y=25, region=None, context=b"ctx",
              x_blinding=1234, y_blinding=4321):
        region = Region(0, 10, 20, 30) if region is None else region
        x_commitment, x_r = pedersen_commit(
            x, region.min_x, region.max_x, blinding=x_blinding,
            prime=self.PRIME, generator=self.G, h=self.H,
        )
        y_commitment, y_r = pedersen_commit(
            y, region.min_y, region.max_y, blinding=y_blinding,
            prime=self.PRIME, generator=self.G, h=self.H,
        )
        proof = prove_region(
            x_commitment, y_commitment, x, y, x_r, y_r, region, context,
            randbelow=counter_randbelow(),
        )
        return RegionBatchEntry(x_commitment, y_commitment, region, proof, context)

    def build(self, entries):
        leaves = [bound_region_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundRegionBatch(tuple(entries), len(entries), proof)
        return batch, root

    def honest(self):
        entries = [
            self.entry(context=b"a"),
            self.entry(x=7, y=22, context=b"b"),
            self.entry(x=0, y=30, context=b"c"),
        ]
        return self.build(entries)

    # ---- batch object -------------------------------------------------------

    def test_batch_positional_equality_and_immutability(self):
        batch, root = self.honest()
        proof = batch.proof
        rebuilt = BoundRegionBatch(batch.entries, 3, proof)
        self.assertEqual(rebuilt, batch)
        self.assertEqual(hash(rebuilt), hash(batch))
        self.assertEqual(
            tuple(getattr(batch, name) for name in ("entries", "leaf_count", "proof")),
            (batch.entries, 3, proof),
        )
        self.assertIsInstance(batch.entries, tuple)
        self.assertNotEqual(
            BoundRegionBatch(batch.entries, 4, proof), batch
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.leaf_count = 4
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.entries = ()

    def test_field_types(self):
        batch, _ = self.honest()
        self.assertIsInstance(batch.entries, tuple)
        for entry in batch.entries:
            self.assertIsInstance(entry, RegionBatchEntry)
        self.assertIsInstance(batch.leaf_count, int)
        self.assertNotIsInstance(batch.leaf_count, bool)
        self.assertIsInstance(batch.proof, MerkleMultiProof)

    # ---- honest round trip --------------------------------------------------

    def test_honest_batch_verifies(self):
        batch, root = self.honest()
        self.assertTrue(verify_region_bound(batch, root, randbelow=counter_randbelow()))
        self.assertTrue(verify_region_bound(batch, root))  # default secrets.randbelow

    def test_single_entry_batch_verifies(self):
        entries = [self.entry()]
        batch, root = self.build(entries)
        self.assertTrue(verify_region_bound(batch, root, randbelow=counter_randbelow()))
        self.assertTrue(
            verify_region_batch(entries, randbelow=counter_randbelow())
        )

    def test_full_leaf_proof_has_empty_siblings(self):
        batch, root = self.honest()
        self.assertEqual(batch.proof.siblings, ())

    def test_leaf_layout(self):
        batch, _ = self.honest()
        entry = batch.entries[0]
        items = frame_items(bound_region_leaf(entry))
        x_size = entry.region.max_x - entry.region.min_x + 1
        y_size = entry.region.max_y - entry.region.min_y + 1
        expected_count = 1 + 6 + 6 + 4 + 1 + 3 * (1 + x_size) + 3 * (1 + y_size)
        self.assertEqual(len(items), expected_count)
        self.assertEqual(items[0], b"zkregion/region-bound/v1")
        cursor = 1
        for commitment in (entry.x_commitment, entry.y_commitment):
            for value in (
                commitment.element, commitment.lower, commitment.upper,
                commitment.prime, commitment.generator, commitment.h,
            ):
                self.assertEqual(items[cursor], str(value).encode("ascii"))
                cursor += 1
        for value in (
            entry.region.min_x, entry.region.max_x,
            entry.region.min_y, entry.region.max_y,
        ):
            self.assertEqual(items[cursor], str(value).encode("ascii"))
            cursor += 1
        self.assertEqual(items[cursor], entry.context)
        cursor += 1
        for sub_proof in (entry.proof.x_proof, entry.proof.y_proof):
            for sequence in (sub_proof.t, sub_proof.e, sub_proof.s):
                self.assertEqual(items[cursor], str(len(sequence)).encode("ascii"))
                cursor += 1
                for value in sequence:
                    self.assertEqual(items[cursor], str(value).encode("ascii"))
                    cursor += 1
        self.assertEqual(cursor, len(items))

    def test_leaf_uses_merkle_leaf_domain(self):
        batch, root = self.honest()
        # root recomputed with the library's leaf framing must match
        self.assertEqual(
            merkle_root([bound_region_leaf(entry) for entry in batch.entries]), root
        )

    def test_empty_context_is_framed_as_zero_length(self):
        entry = self.entry(context=b"")
        items = frame_items(bound_region_leaf(entry))
        self.assertEqual(items[1 + 6 + 6 + 4], b"")  # context item

    def test_negative_integers_are_framed_with_their_sign(self):
        region = Region(-10, 10, -30, 30)
        entry = self.entry(x=-5, y=-25, region=region)
        items = frame_items(bound_region_leaf(entry))
        self.assertIn(b"-10", items)
        self.assertIn(b"-30", items)
        batch, root = self.build([entry])
        self.assertTrue(verify_region_bound(batch, root, randbelow=counter_randbelow()))

    # ---- completeness / count checks ---------------------------------------

    def test_empty_batch_returns_false(self):
        proof = MerkleMultiProof(1, (), ())
        batch = BoundRegionBatch((), 0, proof)
        self.assertFalse(verify_region_bound(batch, bytes(32), randbelow=counter_randbelow()))

    def test_leaf_count_must_equal_entry_count(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        leaves = [bound_region_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, (0, 1))
        for count in (1, 3, 0):
            batch = BoundRegionBatch(tuple(entries), count, proof)
            self.assertFalse(
                verify_region_bound(batch, root, randbelow=counter_randbelow()), count
            )

    def test_leaf_count_must_equal_proof_leaf_count(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        leaves = [bound_region_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, (0, 1))
        for claimed in (1, 3):
            bad_proof = dataclasses.replace(proof, leaf_count=claimed)
            batch = BoundRegionBatch(tuple(entries), 2, bad_proof)
            self.assertFalse(
                verify_region_bound(batch, root, randbelow=counter_randbelow()), claimed
            )

    def test_indices_must_cover_zero_to_n_without_gaps(self):
        batch, root = self.honest()
        good_indices = batch.proof.indices
        for bad_indices in (
            (0, 1),          # missing one
            (0, 1, 1),       # duplicate
            (0, 0, 2),       # duplicate with gap
            (2, 1, 0),       # reversed
            (0, 2, 1),       # reordered
            (1, 2, 3),       # starts at 1
            (-1, 1, 2),      # negative
            (0, 1, 3),       # gap at the end
            (),              # empty
        ):
            bad_proof = MerkleMultiProof(3, bad_indices, batch.proof.siblings)
            bad_batch = BoundRegionBatch(batch.entries, 3, bad_proof)
            self.assertFalse(
                verify_region_bound(bad_batch, root, randbelow=counter_randbelow()),
                bad_indices,
            )
        self.assertEqual(good_indices, (0, 1, 2))

    def test_missing_entry_returns_false(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        leaves = [bound_region_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        # proof claims three leaves covering 0..2 but only two entries exist
        proof = MerkleMultiProof(3, (0, 1, 2), ())
        batch = BoundRegionBatch(tuple(entries), 3, proof)
        self.assertFalse(verify_region_bound(batch, root, randbelow=counter_randbelow()))

    # ---- Merkle binding rejection -------------------------------------------

    def test_wrong_root_returns_false(self):
        batch, _ = self.honest()
        self.assertFalse(verify_region_bound(batch, bytes(32), randbelow=counter_randbelow()))
        other = merkle_root([b"alpha", b"beta", b"gamma"])
        self.assertFalse(verify_region_bound(batch, other, randbelow=counter_randbelow()))

    def test_tampered_leaf_returns_false_even_with_matching_proof(self):
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        batch, root = self.build(entries)
        good = entries[0]
        # every committed field change must change the leaf
        tampered_commitment = dataclasses.replace(
            good.x_commitment, element=good.x_commitment.element + 1
        )
        tampered_proof = RegionProof(
            RangeProof(
                good.proof.x_proof.t[:-1] + (good.proof.x_proof.t[-1] + 1,),
                good.proof.x_proof.e,
                good.proof.x_proof.s,
            ),
            good.proof.y_proof,
        )
        for tampered in (
            dataclasses.replace(good, context=b"other"),
            dataclasses.replace(good, region=Region(0, 9, 20, 30)),
            dataclasses.replace(good, x_commitment=tampered_commitment),
            dataclasses.replace(good, proof=tampered_proof),
        ):
            bad_batch = BoundRegionBatch((tampered, entries[1]), 2, batch.proof)
            self.assertFalse(
                verify_region_bound(bad_batch, root, randbelow=counter_randbelow()),
                tampered,
            )

    def test_committed_but_forged_sub_proof_fails_at_batch_step(self):
        # the forged batch is honestly committed to its own (modified) leaves,
        # so the Merkle step passes; sub-proof verification must still fail
        entries = [self.entry(context=b"a"), self.entry(context=b"b")]
        good = entries[0]
        forged_entry = dataclasses.replace(
            good,
            proof=RegionProof(
                RangeProof(
                    good.proof.x_proof.t,
                    good.proof.x_proof.e,
                    good.proof.x_proof.s[:-1] + (good.proof.x_proof.s[-1] + 1,),
                ),
                good.proof.y_proof,
            ),
        )
        forged_entries = [forged_entry, entries[1]]
        bad_batch, forged_root = self.build(forged_entries)
        self.assertTrue(  # Merkle step alone passes against the forged root
            verify_multi_inclusion(
                [(i, bound_region_leaf(e)) for i, e in enumerate(forged_entries)],
                bad_batch.proof,
                forged_root,
            )
        )
        self.assertFalse(
            verify_region_bound(bad_batch, forged_root, randbelow=counter_randbelow())
        )

    def test_tampered_siblings_return_false(self):
        batch, root = self.honest()
        # a complete-coverage proof consumes no siblings: any supplied
        # sibling must be rejected as leftover/structural garbage
        self.assertEqual(batch.proof.siblings, ())
        bogus = MerkleMultiProof(3, batch.proof.indices, (root,))
        bad_batch = BoundRegionBatch(batch.entries, 3, bogus)
        self.assertFalse(verify_region_bound(bad_batch, root, randbelow=counter_randbelow()))
        # and a wrong root digest length fails the Merkle step
        self.assertFalse(
            verify_region_bound(batch, root + b"\x00", randbelow=counter_randbelow())
        )

    # ---- randomness contract ------------------------------------------------

    def test_randbelow_passed_unchanged_and_called_once_per_branch(self):
        batch, root = self.honest()
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        self.assertTrue(verify_region_bound(batch, root, randbelow=recording))
        branches = sum(
            (entry.region.max_x - entry.region.min_x + 1)
            + (entry.region.max_y - entry.region.min_y + 1)
            for entry in batch.entries
        )
        self.assertEqual(calls, [self.PRIME - 1] * branches)

    def test_no_randomness_consumed_before_the_root_check(self):
        batch, _ = self.honest()

        def boom(upper):
            raise AssertionError("randbelow must not be called before the root checks")

        self.assertFalse(verify_region_bound(batch, bytes(32), randbelow=boom))

    def test_fixed_randbelow_is_reproducible(self):
        batch, root = self.honest()
        first = verify_region_bound(batch, root, randbelow=counter_randbelow(9))
        second = verify_region_bound(batch, root, randbelow=counter_randbelow(9))
        self.assertEqual(first, second)

    def test_non_random_source_invalidates_or_raises_per_region_batch_contract(self):
        batch, root = self.honest()
        for bad in (1.5, "0", True, None):
            with self.assertRaises(TypeError):
                verify_region_bound(batch, root, randbelow=lambda upper, bad=bad: bad)
        for bad in (-1, self.PRIME - 1, self.PRIME):
            with self.assertRaises(ValueError):
                verify_region_bound(batch, root, randbelow=lambda upper, bad=bad: bad)

    # ---- type errors ---------------------------------------------------------

    def test_type_errors(self):
        batch, root = self.honest()
        with self.assertRaises(TypeError):
            verify_region_bound("batch", root)
        with self.assertRaises(TypeError):
            verify_region_bound(None, root)
        with self.assertRaises(TypeError):
            verify_region_bound(BoundRegionBatch(list(batch.entries), 3, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_region_bound(BoundRegionBatch(("x",) * 3, 3, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_region_bound(BoundRegionBatch(batch.entries, True, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_region_bound(BoundRegionBatch(batch.entries, 3.0, batch.proof), root)
        with self.assertRaises(TypeError):
            verify_region_bound(BoundRegionBatch(batch.entries, "3", batch.proof), root)
        with self.assertRaises(TypeError):
            verify_region_bound(BoundRegionBatch(batch.entries, 3, "proof"), root)
        with self.assertRaises(TypeError):
            verify_region_bound(batch, "root")
        with self.assertRaises(TypeError):
            verify_region_bound(batch, bytearray(root))
        with self.assertRaises(TypeError):
            verify_region_bound(batch, root, randbelow=7)
        # malformed nested entry fields
        good = batch.entries[0]
        bad_commitment = dataclasses.replace(good.x_commitment, element=True)
        bad_region = dataclasses.replace(good.region, min_x=True)
        cases = [
            dataclasses.replace(good, x_commitment="c"),
            dataclasses.replace(good, y_commitment="c"),
            dataclasses.replace(good, x_commitment=bad_commitment),
            dataclasses.replace(good, region="r"),
            dataclasses.replace(good, region=bad_region),
            dataclasses.replace(good, proof="p"),
            dataclasses.replace(good, context="ctx"),
            dataclasses.replace(
                good, proof=RegionProof("x", good.proof.y_proof)
            ),
            dataclasses.replace(
                good, proof=RegionProof(good.proof.x_proof, "y")
            ),
            dataclasses.replace(
                good,
                proof=RegionProof(
                    RangeProof(list(good.proof.x_proof.t),
                               good.proof.x_proof.e, good.proof.x_proof.s),
                    good.proof.y_proof,
                ),
            ),
            dataclasses.replace(
                good,
                proof=RegionProof(
                    RangeProof(good.proof.x_proof.t,
                               good.proof.x_proof.e[:-1] + (True,),
                               good.proof.x_proof.s),
                    good.proof.y_proof,
                ),
            ),
        ]
        for bad_entry in cases:
            entries = (bad_entry,) + batch.entries[1:]
            bad_batch = BoundRegionBatch(entries, 3, batch.proof)
            with self.assertRaises(TypeError):
                verify_region_bound(bad_batch, root, randbelow=counter_randbelow())
        # malformed MerkleMultiProof fields
        with self.assertRaises(TypeError):
            verify_region_bound(
                BoundRegionBatch(batch.entries, 3,
                                 MerkleMultiProof(True, (0, 1, 2), ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_region_bound(
                BoundRegionBatch(batch.entries, 3,
                                 MerkleMultiProof(3, [0, 1, 2], ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_region_bound(
                BoundRegionBatch(batch.entries, 3,
                                 MerkleMultiProof(3, (0, 1, 2.0), ())),
                root,
            )
        with self.assertRaises(TypeError):
            verify_region_bound(
                BoundRegionBatch(batch.entries, 3,
                                 MerkleMultiProof(3, (0, 1, 2), ["x"])),
                root,
            )

    # ---- hygiene -------------------------------------------------------------

    def test_inputs_are_not_mutated(self):
        batch, root = self.honest()
        snapshot = BoundRegionBatch(
            tuple(dataclasses.replace(entry) for entry in batch.entries),
            batch.leaf_count,
            dataclasses.replace(batch.proof),
        )
        verify_region_bound(batch, root, randbelow=counter_randbelow())
        self.assertEqual(batch, snapshot)


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


class ReplayBindingTest(unittest.TestCase):
    def test_positional_construction_defaults_equality_and_immutability(self):
        digest = b"\x00" * 32
        binding = ReplayBinding(b"session", digest)
        self.assertEqual(binding.session_id, b"session")
        self.assertEqual(binding.digest, digest)
        self.assertIsNone(binding.expires_at)
        self.assertEqual(ReplayBinding(b"session", digest, None), binding)
        self.assertEqual(
            tuple(getattr(binding, name) for name in ("session_id", "digest", "expires_at")),
            (b"session", digest, None),
        )
        self.assertNotEqual(binding, ReplayBinding(b"other", digest))
        self.assertNotEqual(binding, ReplayBinding(b"session", b"\x01" * 32))
        self.assertNotEqual(binding, ReplayBinding(b"session", digest, 1))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            binding.session_id = b"other"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            binding.digest = digest

    def test_type_errors(self):
        digest = b"\x00" * 32
        for bad in ("session", b"session".decode(), 7, None, bytearray(b"x")):
            with self.assertRaises(TypeError):
                ReplayBinding(bad, digest)
        for bad in ("digest", 7, None, bytearray(32)):
            with self.assertRaises(TypeError):
                ReplayBinding(b"s", bad)
        for bad in (True, False, 1.5, "1000"):
            with self.assertRaises(TypeError):
                ReplayBinding(b"s", digest, bad)

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            ReplayBinding(b"", b"\x00" * 32)
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                ReplayBinding(b"s", b"\x00" * 32, bad)

    def test_digest_accepts_any_bytes_length(self):
        # the digest length is no longer constrained to 32 bytes
        for length in (0, 1, 16, 31, 32, 33, 64):
            binding = ReplayBinding(b"s", b"\x00" * length)
            self.assertEqual(binding.digest, b"\x00" * length)
        self.assertNotEqual(ReplayBinding(b"s", b"\x00"), ReplayBinding(b"s", b"\x00" * 2))


class ReplayGuardTest(unittest.TestCase):
    def setUp(self):
        self.prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3,
                                    randbelow=counter_randbelow())
        self.entry = MultiSchnorrEntry(
            self.prover.public_key, b"spend",
            self.prover.prove(b"spend", context=b"ctx"),
            b"ctx", SMALL_PRIME, 3,
        )

    def entry_with(self, **changes):
        return dataclasses.replace(self.entry, **changes)

    def bound_leaf(self, entry):
        def enc(value):
            return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

        items = (
            b"zkregion/schnorr-fs/v1",
            enc(entry.prime), enc(entry.generator), enc(entry.public_key),
            enc(entry.proof.commitment), entry.context, entry.message,
            enc(entry.proof.response),
        )
        return b"".join(len(item).to_bytes(4, "big") + item for item in items)

    def expected_digest(self, entry, session_id, expires_at=None):
        def frame(item):
            return len(item).to_bytes(4, "big") + item

        expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
        material = frame(b"zr/r/v1") + frame(session_id) + self.bound_leaf(entry) + frame(expiry)
        return hashlib.sha256(material).digest()

    # ---- binding ------------------------------------------------------------

    def test_bind_once_returns_spec_digest(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s1")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"s1")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(binding.digest, self.expected_digest(self.entry, b"s1"))
        self.assertEqual(len(binding.digest), 32)
        binding = guard.bind_once(self.entry, b"s2", expires_at=1000)
        self.assertEqual(binding.expires_at, 1000)
        self.assertEqual(binding.digest, self.expected_digest(self.entry, b"s2", 1000))

    def test_digest_binds_every_component(self):
        guard = ReplayGuard()
        base = guard.bind_once(self.entry, b"s")
        self.assertNotEqual(base.digest, self.expected_digest(self.entry, b"other"))
        self.assertNotEqual(base.digest, self.expected_digest(self.entry, b"s", 1))
        self.assertNotEqual(
            base.digest,
            self.expected_digest(self.entry_with(message=b"other"), b"s"),
        )
        self.assertNotEqual(
            base.digest,
            self.expected_digest(self.entry_with(context=b"other"), b"s"),
        )
        self.assertNotEqual(
            base.digest,
            self.expected_digest(self.entry_with(generator=5), b"s"),
        )

    def test_expiry_encodings_distinguish_presence_and_value(self):
        no_expiry = ReplayGuard().bind_once(self.entry, b"s")
        with_expiry = ReplayGuard().bind_once(self.entry, b"s", expires_at=0)
        later = ReplayGuard().bind_once(self.entry, b"s", expires_at=1)
        self.assertNotEqual(no_expiry.digest, with_expiry.digest)
        self.assertNotEqual(with_expiry.digest, later.digest)

    def test_pending_id_cannot_be_rebound(self):
        guard = ReplayGuard()
        guard.bind_once(self.entry, b"s")
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_consumed_id_cannot_be_rebound(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_distinct_session_ids_are_independent(self):
        guard = ReplayGuard()
        first = guard.bind_once(self.entry, b"s1")
        second = guard.bind_once(self.entry, b"s2")
        self.assertNotEqual(first, second)
        self.assertTrue(guard.check(self.entry, first, now=1))
        self.assertTrue(guard.check(self.entry, second, now=1))

    def test_bind_once_type_errors(self):
        guard = ReplayGuard()
        for bad in ("entry", 7, None, self.entry.proof):
            with self.assertRaises(TypeError):
                guard.bind_once(bad, b"s")
        for bad in ("s", 7, None, bytearray(b"s")):
            with self.assertRaises(TypeError):
                guard.bind_once(self.entry, bad)
        for bad in (True, False, 1.5, "1000"):
            with self.assertRaises(TypeError):
                guard.bind_once(self.entry, b"s", expires_at=bad)

    def test_bind_once_value_errors(self):
        guard = ReplayGuard()
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"")
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError):
                guard.bind_once(self.entry, b"s", expires_at=bad)

    def test_negative_entry_integers_rejected(self):
        # the BoundSchnorr leaf is unsigned, so a negative field cannot bind
        guard = ReplayGuard()
        for field in ("public_key", "prime", "generator"):
            broken = self.entry_with(**{field: -1})
            with self.assertRaises(ValueError):
                guard.bind_once(broken, b"s")
        for field in ("commitment", "response"):
            broken = self.entry_with(
                proof=SchnorrProof(
                    -1 if field == "commitment" else self.entry.proof.commitment,
                    -1 if field == "response" else self.entry.proof.response,
                )
            )
            with self.assertRaises(ValueError):
                guard.bind_once(broken, b"s")

    # ---- honest check and single use ----------------------------------------

    def test_check_accepts_then_consumes(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=1000)
        self.assertTrue(guard.check(self.entry, binding, now=999))
        # the consumed id is rejected and cannot be replayed
        self.assertFalse(guard.check(self.entry, binding, now=999))
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_check_without_expiry_ignores_now(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=0))
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=2**64 - 1))

    def test_check_with_default_now(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding))
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=10**12)
        self.assertTrue(guard.check(self.entry, binding))

    def test_expiry_boundary_is_inclusive(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s1", expires_at=1000)
        self.assertTrue(guard.check(self.entry, binding, now=999))
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s2", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=1000))
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s3", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=1001))

    # ---- rejection never consumes -------------------------------------------

    def test_expired_rejection_does_not_consume(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=2000))
        # still pending: an earlier clock succeeds and consumes it
        self.assertTrue(guard.check(self.entry, binding, now=999))
        self.assertFalse(guard.check(self.entry, binding, now=999))

    def test_bad_proof_rejection_does_not_consume(self):
        forged = self.entry_with(
            proof=SchnorrProof(self.entry.proof.commitment,
                               self.entry.proof.response + 1)
        )
        guard = ReplayGuard()
        binding = guard.bind_once(forged, b"s")
        self.assertFalse(guard.check(forged, binding, now=1))
        # id still pending — rebinding is still refused while it waits
        with self.assertRaises(ValueError):
            guard.bind_once(forged, b"s")

    def test_entry_mismatch_rejection_does_not_consume(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        for changed in (
            self.entry_with(message=b"other"),
            self.entry_with(context=b"other"),
            self.entry_with(
                proof=SchnorrProof(self.entry.proof.commitment,
                                   self.entry.proof.response + 1),
            ),
        ):
            self.assertFalse(guard.check(changed, binding, now=1))
        # the originally bound entry still verifies once
        self.assertTrue(guard.check(self.entry, binding, now=1))

    def test_bad_group_parameters_return_false(self):
        guard = ReplayGuard()
        broken = self.entry_with(prime=3)
        binding = guard.bind_once(broken, b"s")
        self.assertFalse(guard.check(broken, binding, now=1))
        self.assertTrue(b"s" in guard._pending)

    def test_unknown_or_foreign_binding_rejected(self):
        guard = ReplayGuard()
        guard.bind_once(self.entry, b"local")
        # an equal binding built elsewhere verifies (bindings compare by
        # value), but an id never registered in this guard does not
        foreign = ReplayGuard().bind_once(self.entry, b"elsewhere")
        self.assertFalse(guard.check(self.entry, foreign, now=1))
        equal = ReplayGuard().bind_once(self.entry, b"local")
        self.assertTrue(guard.check(self.entry, equal, now=1))
        unknown = ReplayBinding(b"never-bound", b"\x00" * 32)
        self.assertFalse(guard.check(self.entry, unknown, now=1))

    def test_unequal_binding_rejected_without_consuming(self):
        guard = ReplayGuard()
        guard.bind_once(self.entry, b"s")
        forged_digest = ReplayBinding(b"s", b"\x01" * 32)
        self.assertFalse(guard.check(self.entry, forged_digest, now=1))
        forged_expiry = ReplayBinding(
            b"s", self.expected_digest(self.entry, b"s", 1), 1
        )
        self.assertFalse(guard.check(self.entry, forged_expiry, now=0))

    # ---- argument validation ------------------------------------------------

    def test_check_type_errors(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        for bad in ("entry", 7, None, self.entry.proof):
            with self.assertRaises(TypeError):
                guard.check(bad, binding, now=1)
        for bad in ("binding", 7, None, (b"s", binding.digest)):
            with self.assertRaises(TypeError):
                guard.check(self.entry, bad, now=1)
        for bad in (True, False, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                guard.check(self.entry, binding, now=bad)

    def test_check_now_out_of_range_is_a_value_error(self):
        guard = ReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                guard.check(self.entry, binding, now=bad)

    def test_instances_are_independent(self):
        first = ReplayGuard()
        second = ReplayGuard()
        binding = first.bind_once(self.entry, b"s")
        self.assertFalse(second.check(self.entry, binding, now=1))
        # the rejected foreign check did not touch the first guard
        self.assertTrue(first.check(self.entry, binding, now=1))

    def test_inputs_are_not_mutated(self):
        guard = ReplayGuard()
        snapshot = dataclasses.replace(self.entry)
        binding = guard.bind_once(self.entry, b"s")
        binding_snapshot = dataclasses.replace(binding)
        guard.check(self.entry, binding, now=1)
        self.assertEqual(self.entry, snapshot)
        self.assertEqual(binding, binding_snapshot)


class SQLiteReplayStoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "replay.db")
        self.prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3,
                                    randbelow=counter_randbelow())
        self.entry = MultiSchnorrEntry(
            self.prover.public_key, b"spend",
            self.prover.prove(b"spend", context=b"ctx"),
            b"ctx", SMALL_PRIME, 3,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def make_store(self, *args, **kwargs):
        return SQLiteReplayStore(self.path, *args, **kwargs)

    def raw_rows(self):
        conn = sqlite3.connect(self.path)
        try:
            return conn.execute(
                "SELECT namespace, domain, session_id, state, digest, "
                "expires_at, token, claim_expires FROM replay_sessions_v1"
            ).fetchall()
        finally:
            conn.close()

    # ---- construction -------------------------------------------------------

    def test_construction_validation(self):
        with self.assertRaises(TypeError):
            SQLiteReplayStore(123)
        with self.assertRaises(TypeError):
            SQLiteReplayStore(self.path, namespace="default")
        with self.assertRaises(TypeError):
            SQLiteReplayStore(self.path, namespace=b"default", lease_seconds="30")
        with self.assertRaises(TypeError):
            SQLiteReplayStore(self.path, lease_seconds=True)
        with self.assertRaises(TypeError):
            SQLiteReplayStore(self.path, clock=123)
        for bad in (0, -1, -100):
            with self.assertRaises(ValueError):
                SQLiteReplayStore(self.path, lease_seconds=bad)

    def test_defaults(self):
        store = self.make_store()
        self.assertEqual(store._namespace, b"default")
        now = store._clock()
        self.assertIsInstance(now, int)
        self.assertNotIsInstance(now, bool)
        self.assertGreater(now, 10**9)

    def test_guard_rejects_non_store(self):
        for bad in (object(), "path", 1, True, b"ns", {}):
            with self.assertRaises(TypeError):
                ReplayGuard(store=bad)

    # ---- sharing, persistence, isolation ------------------------------------

    def test_independent_instances_share_pending_and_consumed(self):
        store = self.make_store()
        first = ReplayGuard(store=store)
        second = ReplayGuard(store=store)
        binding = first.bind_once(self.entry, b"s")
        self.assertIn(b"s", second._pending)
        self.assertTrue(second.check(self.entry, binding, now=1))
        self.assertIn(b"s", first._consumed)
        self.assertFalse(first.check(self.entry, binding, now=1))
        with self.assertRaises(ValueError):
            second.bind_once(self.entry, b"s")

    def test_state_survives_store_reopen(self):
        store = self.make_store()
        with_expiry = ReplayGuard(store=store).bind_once(
            self.entry, b"a", expires_at=1000
        )
        ReplayGuard(store=store).bind_once(self.entry, b"b")
        store.close()
        store = self.make_store()
        guard = ReplayGuard(store=store)
        pending = guard._pending
        self.assertEqual(pending[b"a"], with_expiry)
        self.assertEqual(pending[b"b"].session_id, b"b")
        self.assertTrue(guard.check(self.entry, with_expiry, now=999))
        store.close()
        store = self.make_store()
        guard = ReplayGuard(store=store)
        self.assertEqual(guard._consumed, {b"a"})
        self.assertNotIn(b"a", guard._pending)
        self.assertFalse(
            guard.check(self.entry, with_expiry, now=999)
        )

    def test_namespaces_in_one_file_are_independent(self):
        a = self.make_store(namespace=b"alpha")
        b = self.make_store(namespace=b"beta")
        binding_a = ReplayGuard(store=a).bind_once(self.entry, b"s")
        self.assertFalse(ReplayGuard(store=b).check(self.entry, binding_a, now=1))
        binding_b = ReplayGuard(store=b).bind_once(self.entry, b"s")
        self.assertTrue(ReplayGuard(store=b).check(self.entry, binding_b, now=1))
        self.assertTrue(ReplayGuard(store=a).check(self.entry, binding_a, now=1))

    def test_in_memory_default_remains_isolated(self):
        first, second = ReplayGuard(), ReplayGuard()
        binding = first.bind_once(self.entry, b"s")
        self.assertFalse(second.check(self.entry, binding, now=1))
        self.assertTrue(first.check(self.entry, binding, now=1))

    # ---- database contents --------------------------------------------------

    def test_row_key_and_value_use_spec_segments_and_e_encoding(self):
        store = self.make_store(namespace=b"ns1")
        guard = ReplayGuard(store=store)
        no_expiry = guard.bind_once(self.entry, b"s0")
        with_expiry = guard.bind_once(self.entry, b"s1", expires_at=12345)
        rows = {row[2]: row for row in self.raw_rows()}
        for binding, expected_expiry in (
            (no_expiry, b"\x00"),
            (with_expiry, b"\x01" + (12345).to_bytes(8, "big")),
        ):
            namespace, domain, session_id, state, digest, expiry, token, deadline = rows[
                binding.session_id
            ]
            self.assertEqual(namespace, b"ns1")
            self.assertEqual(domain, b"zr/r/v1")
            self.assertEqual(session_id, binding.session_id)
            self.assertEqual(state, "pending")
            self.assertEqual(digest, binding.digest)
            self.assertEqual(expiry, expected_expiry)
            self.assertIsNone(token)
            self.assertIsNone(deadline)

    def test_persisted_binding_digest_matches_spec(self):
        store = self.make_store()
        binding = ReplayGuard(store=store).bind_once(self.entry, b"s")

        def enc(value):
            return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

        items = (
            b"zkregion/schnorr-fs/v1",
            enc(self.entry.prime), enc(self.entry.generator),
            enc(self.entry.public_key),
            enc(self.entry.proof.commitment), self.entry.context,
            self.entry.message, enc(self.entry.proof.response),
        )
        leaf = b"".join(len(x).to_bytes(4, "big") + x for x in items)

        def frame(item):
            return len(item).to_bytes(4, "big") + item

        expected = hashlib.sha256(
            frame(b"zr/r/v1") + frame(b"s") + leaf + frame(b"\x00")
        ).digest()
        self.assertEqual(binding.digest, expected)

    # ---- bind_once ----------------------------------------------------------

    def test_bind_once_rejects_pending_claimed_expired_claim_and_consumed(self):
        clock = {"t": 1000}
        store = self.make_store(lease_seconds=10, clock=lambda: clock["t"])
        guard = ReplayGuard(store=store)
        binding = guard.bind_once(self.entry, b"s")
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")
        token = store.claim(b"s", binding)
        self.assertIsNotNone(token)
        with self.assertRaises(ValueError):  # live claim cannot be rebound
            guard.bind_once(self.entry, b"s")
        clock["t"] = 2000  # let the claim lease expire
        with self.assertRaises(ValueError):  # expired claim still cannot be rebound
            guard.bind_once(self.entry, b"s")
        new_token = store.claim(b"s", binding)
        self.assertTrue(store.commit(b"s", new_token))
        with self.assertRaises(ValueError):  # consumed id can never be rebound
            guard.bind_once(self.entry, b"s")

    def test_bind_once_validation_matches_memory_guard(self):
        store = self.make_store()
        guard = ReplayGuard(store=store)
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"")
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s", expires_at=-1)
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry, "s")
        with self.assertRaises(TypeError):
            guard.bind_once("entry", b"s")

    # ---- check: accept, reject, consume -------------------------------------

    def test_check_accepts_then_consumes_across_instances(self):
        store = self.make_store()
        binder = ReplayGuard(store=store)
        binding = binder.bind_once(self.entry, b"s", expires_at=1000)
        checker = ReplayGuard(store=store)
        self.assertTrue(checker.check(self.entry, binding, now=999))
        self.assertFalse(checker.check(self.entry, binding, now=999))
        state = {row[2]: row[3] for row in self.raw_rows()}
        self.assertEqual(state[b"s"], "consumed")

    def test_expired_binding_rejection_leaves_pending(self):
        store = self.make_store()
        guard = ReplayGuard(store=store)
        binding = guard.bind_once(self.entry, b"s", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=1000))
        self.assertIn(b"s", guard._pending)
        self.assertTrue(guard.check(self.entry, binding, now=999))

    def test_bad_proof_and_unequal_binding_rejected_without_consuming(self):
        store = self.make_store()
        guard = ReplayGuard(store=store)
        forged_entry = MultiSchnorrEntry(
            self.entry.public_key, b"spend",
            SchnorrProof(self.entry.proof.commitment,
                         self.entry.proof.response + 1),
            b"ctx", SMALL_PRIME, 3,
        )
        binding = guard.bind_once(forged_entry, b"s")
        self.assertFalse(guard.check(forged_entry, binding, now=1))
        self.assertIn(b"s", guard._pending)
        # an unequal binding cannot even take the pending claim
        forged_binding = ReplayBinding(b"s", b"\x01" * 32)
        self.assertIsNone(store.claim(b"s", forged_binding))
        # other session ids remain fully usable on the same store
        other_guard = ReplayGuard(store=store)
        fresh = other_guard.bind_once(self.entry, b"t")
        self.assertTrue(other_guard.check(self.entry, fresh, now=1))

    def test_unknown_and_consumed_ids_rejected(self):
        store = self.make_store()
        guard = ReplayGuard(store=store)
        self.assertFalse(
            guard.check(self.entry, ReplayBinding(b"never", b"\x00" * 32), now=1)
        )
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=1))
        self.assertFalse(guard.check(self.entry, binding, now=1))

    # ---- claim tokens and lease takeover ------------------------------------

    def test_only_current_token_consumes_stale_token_loses(self):
        clock = {"t": 1000}
        store = self.make_store(lease_seconds=10, clock=lambda: clock["t"])
        binding = ReplayGuard(store=store).bind_once(self.entry, b"s")
        old_token = store.claim(b"s", binding)
        self.assertIsNotNone(old_token)
        self.assertIsNone(store.claim(b"s", binding))  # a live claim blocks takeover
        clock["t"] = 1010
        new_token = store.claim(b"s", binding)
        self.assertIsNotNone(new_token)
        self.assertNotEqual(old_token, new_token)
        # the stale claim can neither consume nor restore
        self.assertFalse(store.commit(b"s", old_token))
        self.assertFalse(store.release(b"s", old_token))
        self.assertTrue(store.commit(b"s", new_token))
        self.assertEqual(
            {row[2]: row[3] for row in self.raw_rows()}[b"s"], "consumed"
        )

    def test_takeover_check_must_equal_stored_binding(self):
        clock = {"t": 1000}
        store = self.make_store(lease_seconds=10, clock=lambda: clock["t"])
        binding = ReplayGuard(store=store).bind_once(self.entry, b"s")
        self.assertIsNotNone(store.claim(b"s", binding))
        clock["t"] = 1010
        forged = ReplayBinding(b"s", b"\x01" * 32)
        self.assertIsNone(store.claim(b"s", forged))

    def test_check_releases_claim_after_rejection(self):
        store = self.make_store()
        guard = ReplayGuard(store=store)
        forged_entry = MultiSchnorrEntry(
            self.entry.public_key, b"spend",
            SchnorrProof(self.entry.proof.commitment,
                         self.entry.proof.response + 1),
            b"ctx", SMALL_PRIME, 3,
        )
        binding = guard.bind_once(forged_entry, b"s")
        self.assertFalse(guard.check(forged_entry, binding, now=1))
        rows = {row[2]: row for row in self.raw_rows()}
        self.assertEqual(rows[b"s"][3], "pending")
        self.assertIsNone(rows[b"s"][6])
        self.assertIsNone(rows[b"s"][7])

    def test_exception_during_verification_restores_pending(self):
        import zkregion

        class BoomVerifier:
            def __init__(self, *args, **kwargs):
                pass

            def verify_proof(self, *args, **kwargs):
                raise RuntimeError("boom")

        store = self.make_store()
        guard = ReplayGuard(store=store)
        binding = guard.bind_once(self.entry, b"s")
        original = zkregion.SchnorrVerifier
        zkregion.SchnorrVerifier = BoomVerifier
        try:
            with self.assertRaises(RuntimeError):
                guard.check(self.entry, binding, now=1)
        finally:
            zkregion.SchnorrVerifier = original
        self.assertEqual(
            {row[2]: row[3] for row in self.raw_rows()}[b"s"], "pending"
        )

    def test_concurrent_checks_have_exactly_one_winner(self):
        store = self.make_store()
        guard = ReplayGuard(store=store)
        binding = guard.bind_once(self.entry, b"s")
        results = []
        lock = threading.Lock()

        def attempt():
            won = ReplayGuard(store=store).check(self.entry, binding, now=1)
            with lock:
                results.append(won)

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(results), 1)

    def test_bind_refused_while_claim_is_live(self):
        import zkregion

        started = threading.Event()

        class SlowVerifier:
            def __init__(self, *args, **kwargs):
                pass

            def verify_proof(self, *args, **kwargs):
                started.set()
                event.wait(0.5)
                return True

        store = self.make_store(lease_seconds=60)
        binding = ReplayGuard(store=store).bind_once(self.entry, b"s")
        event = threading.Event()
        original = zkregion.SchnorrVerifier
        zkregion.SchnorrVerifier = SlowVerifier
        try:
            thread = threading.Thread(
                target=lambda: ReplayGuard(store=store).check(
                    self.entry, binding, now=1
                )
            )
            thread.start()
            started.wait(2)
            with self.assertRaises(ValueError):
                ReplayGuard(store=store).bind_once(self.entry, b"s")
            event.set()
            thread.join()
        finally:
            zkregion.SchnorrVerifier = original
        self.assertEqual(
            {row[2]: row[3] for row in self.raw_rows()}[b"s"], "consumed"
        )

    # ---- clock / lease boundaries -------------------------------------------

    def test_check_clock_validation(self):
        for i, (bad, error) in enumerate((
            (-1, ValueError), (2**64, ValueError),
            (1.5, TypeError), (True, TypeError),
        )):
            store = self.make_store(clock=lambda b=bad: b)
            guard = ReplayGuard(store=store)
            binding = guard.bind_once(self.entry, f"s{i}".encode())
            with self.assertRaises(error):
                guard.check(self.entry, binding)

    def test_lease_deadline_overflow_is_value_error(self):
        store = self.make_store(
            lease_seconds=10, clock=lambda: 2**64 - 5
        )
        guard = ReplayGuard(store=store)
        binding = guard.bind_once(self.entry, b"s")
        with self.assertRaises(ValueError):
            guard.check(self.entry, binding)
        # an overflow must not have consumed the id
        self.assertIn(b"s", guard._pending)

    def test_deadline_uses_full_uint64_range_in_database(self):
        # SQLite integers are signed 64-bit, so the uint64 deadline must
        # survive as an 8-byte big-endian value even in the top half.
        store = self.make_store(
            lease_seconds=1, clock=lambda: 2**64 - 2
        )
        binding = ReplayGuard(store=store).bind_once(self.entry, b"s")
        token = store.claim(b"s", binding)
        self.assertIsNotNone(token)
        deadline = {row[2]: row[7] for row in self.raw_rows()}[b"s"]
        self.assertEqual(deadline, (2**64 - 1).to_bytes(8, "big"))

    # ---- database errors ----------------------------------------------------

    def test_sqlite_errors_propagate(self):
        store = self.make_store()
        store._connection.execute("DROP TABLE replay_sessions_v1")
        guard = ReplayGuard(store=store)
        with self.assertRaises(sqlite3.Error):
            guard.bind_once(self.entry, b"s")


class RangeReplayGuardTest(unittest.TestCase):
    def setUp(self):
        self.commitment, self.blinding = pedersen_commit(
            4, 0, 10, prime=SMALL_PRIME, generator=3, blinding=1000,
        )
        self.proof = prove_range(
            self.commitment, 4, self.blinding, context=b"ctx",
            randbelow=counter_randbelow(),
        )
        self.entry = RangeBatchEntry(self.commitment, self.proof, b"ctx")

    def entry_with(self, **changes):
        return dataclasses.replace(self.entry, **changes)

    def bound_leaf(self, entry):
        c = entry.commitment
        items = [b"zkregion/range-bound/v1"]
        items += [str(v).encode("ascii")
                  for v in (c.element, c.lower, c.upper, c.prime, c.generator, c.h)]
        items.append(entry.context)
        for seq in (entry.proof.t, entry.proof.e, entry.proof.s):
            items.append(str(len(seq)).encode("ascii"))
            items += [str(v).encode("ascii") for v in seq]
        return b"".join(len(item).to_bytes(4, "big") + item for item in items)

    def expected_digest(self, entry, session_id, expires_at=None):
        def frame(item):
            return len(item).to_bytes(4, "big") + item

        expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
        material = frame(b"zr/rr/v1") + frame(session_id) + self.bound_leaf(entry) + frame(expiry)
        return hashlib.sha256(material).digest()

    # ---- binding ------------------------------------------------------------

    def test_bind_once_returns_spec_digest(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s1")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"s1")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(binding.digest, self.expected_digest(self.entry, b"s1"))
        self.assertEqual(len(binding.digest), 32)
        binding = guard.bind_once(self.entry, b"s2", expires_at=1000)
        self.assertEqual(binding.expires_at, 1000)
        self.assertEqual(binding.digest, self.expected_digest(self.entry, b"s2", 1000))

    def test_digest_binds_every_component(self):
        guard = RangeReplayGuard()
        base = guard.bind_once(self.entry, b"s")
        self.assertNotEqual(base.digest, self.expected_digest(self.entry, b"other"))
        self.assertNotEqual(base.digest, self.expected_digest(self.entry, b"s", 1))
        self.assertNotEqual(
            base.digest,
            self.expected_digest(self.entry_with(context=b"other"), b"s"),
        )
        self.assertNotEqual(
            base.digest,
            self.expected_digest(
                self.entry_with(commitment=dataclasses.replace(self.commitment, lower=1)),
                b"s",
            ),
        )
        tampered = RangeProof(self.proof.t, self.proof.e, self.proof.s[:-1] + (self.proof.s[-1] + 1,))
        self.assertNotEqual(
            base.digest,
            self.expected_digest(self.entry_with(proof=tampered), b"s"),
        )

    def test_expiry_encodings_distinguish_presence_and_value(self):
        no_expiry = RangeReplayGuard().bind_once(self.entry, b"s")
        with_expiry = RangeReplayGuard().bind_once(self.entry, b"s", expires_at=0)
        later = RangeReplayGuard().bind_once(self.entry, b"s", expires_at=1)
        self.assertNotEqual(no_expiry.digest, with_expiry.digest)
        self.assertNotEqual(with_expiry.digest, later.digest)

    def test_pending_id_cannot_be_rebound(self):
        guard = RangeReplayGuard()
        guard.bind_once(self.entry, b"s")
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_consumed_id_cannot_be_rebound(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_distinct_session_ids_are_independent(self):
        guard = RangeReplayGuard()
        first = guard.bind_once(self.entry, b"s1")
        second = guard.bind_once(self.entry, b"s2")
        self.assertNotEqual(first, second)
        self.assertTrue(guard.check(self.entry, first, now=1))
        self.assertTrue(guard.check(self.entry, second, now=1))

    def test_bind_once_type_errors(self):
        guard = RangeReplayGuard()
        for bad in ("entry", 7, None, self.proof, self.commitment):
            with self.assertRaises(TypeError):
                guard.bind_once(bad, b"s")
        for bad in ("s", 7, None, bytearray(b"s")):
            with self.assertRaises(TypeError):
                guard.bind_once(self.entry, bad)
        for bad in (True, False, 1.5, "1000"):
            with self.assertRaises(TypeError):
                guard.bind_once(self.entry, b"s", expires_at=bad)

    def test_bind_once_nested_type_errors(self):
        guard = RangeReplayGuard()
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(commitment="c"), b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                self.entry_with(commitment=dataclasses.replace(self.commitment, h=True)), b"s"
            )
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(proof="p"), b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                self.entry_with(proof=RangeProof(list(self.proof.t), self.proof.e, self.proof.s)),
                b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                self.entry_with(
                    proof=RangeProof(self.proof.t, self.proof.e + (True,), self.proof.s)
                ),
                b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(context="ctx"), b"s")

    def test_bind_once_value_errors(self):
        guard = RangeReplayGuard()
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"")
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError):
                guard.bind_once(self.entry, b"s", expires_at=bad)

    def test_negative_entry_integers_bind(self):
        # the BoundRange leaf encodes integers as decimal ASCII, so negative
        # fields are encodable and bind_once does not reject them
        guard = RangeReplayGuard()
        broken = self.entry_with(
            commitment=dataclasses.replace(self.commitment, lower=-5)
        )
        binding = guard.bind_once(broken, b"s")
        self.assertEqual(binding.digest, self.expected_digest(broken, b"s"))

    # ---- honest check and single use ----------------------------------------

    def test_check_accepts_then_consumes(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=1000)
        self.assertTrue(guard.check(self.entry, binding, now=999))
        # the consumed id is rejected and cannot be replayed
        self.assertFalse(guard.check(self.entry, binding, now=999))
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_check_without_expiry_ignores_now(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=0))
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=2**64 - 1))

    def test_check_with_default_now(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding))
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=10**12)
        self.assertTrue(guard.check(self.entry, binding))

    def test_expiry_boundary_is_inclusive(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s1", expires_at=1000)
        self.assertTrue(guard.check(self.entry, binding, now=999))
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s2", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=1000))
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s3", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=1001))

    # ---- rejection never consumes -------------------------------------------

    def test_expired_rejection_does_not_consume(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=2000))
        # still pending: an earlier clock succeeds and consumes it
        self.assertTrue(guard.check(self.entry, binding, now=999))
        self.assertFalse(guard.check(self.entry, binding, now=999))

    def test_bad_proof_rejection_does_not_consume(self):
        forged = self.entry_with(
            proof=RangeProof(
                self.proof.t, self.proof.e, self.proof.s[:-1] + (self.proof.s[-1] + 1,)
            )
        )
        guard = RangeReplayGuard()
        binding = guard.bind_once(forged, b"s")
        self.assertFalse(guard.check(forged, binding, now=1))
        # id still pending — rebinding is still refused while it waits
        with self.assertRaises(ValueError):
            guard.bind_once(forged, b"s")

    def test_entry_mismatch_rejection_does_not_consume(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        changed_commitment = self.entry_with(
            commitment=dataclasses.replace(self.commitment, upper=11)
        )
        for changed in (
            self.entry_with(context=b"other"),
            changed_commitment,
            self.entry_with(
                proof=RangeProof(
                    self.proof.t, self.proof.e,
                    self.proof.s[:-1] + (self.proof.s[-1] + 1,),
                )
            ),
        ):
            self.assertFalse(guard.check(changed, binding, now=1))
        # the originally bound entry still verifies once
        self.assertTrue(guard.check(self.entry, binding, now=1))

    def test_unknown_or_foreign_binding_rejected(self):
        guard = RangeReplayGuard()
        guard.bind_once(self.entry, b"local")
        # an equal binding built elsewhere verifies (bindings compare by
        # value), but an id never registered in this guard does not
        foreign = RangeReplayGuard().bind_once(self.entry, b"elsewhere")
        self.assertFalse(guard.check(self.entry, foreign, now=1))
        equal = RangeReplayGuard().bind_once(self.entry, b"local")
        self.assertTrue(guard.check(self.entry, equal, now=1))
        unknown = ReplayBinding(b"never-bound", b"\x00" * 32)
        self.assertFalse(guard.check(self.entry, unknown, now=1))

    def test_unequal_binding_rejected_without_consuming(self):
        guard = RangeReplayGuard()
        guard.bind_once(self.entry, b"s")
        forged_digest = ReplayBinding(b"s", b"\x01" * 32)
        self.assertFalse(guard.check(self.entry, forged_digest, now=1))
        forged_expiry = ReplayBinding(
            b"s", self.expected_digest(self.entry, b"s", 1), 1
        )
        self.assertFalse(guard.check(self.entry, forged_expiry, now=0))

    def test_cross_guard_binding_rejected(self):
        # a Schnorr-guard binding for the same id is not a range-guard binding
        prover = SchnorrProver(secret=4321, prime=SMALL_PRIME, generator=3,
                               randbelow=counter_randbelow())
        schnorr_entry = MultiSchnorrEntry(
            prover.public_key, b"spend", prover.prove(b"spend", context=b"ctx"), b"ctx",
            SMALL_PRIME, 3,
        )
        schnorr_binding = ReplayGuard().bind_once(schnorr_entry, b"s")
        guard = RangeReplayGuard()
        guard.bind_once(self.entry, b"s")
        self.assertFalse(guard.check(self.entry, schnorr_binding, now=1))
        # and the range digests differ from the Schnorr ones for equal input
        range_binding = RangeReplayGuard().bind_once(self.entry, b"s")
        self.assertNotEqual(schnorr_binding.digest, range_binding.digest)

    # ---- argument validation ------------------------------------------------

    def test_check_type_errors(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        for bad in ("entry", 7, None, self.proof, self.commitment):
            with self.assertRaises(TypeError):
                guard.check(bad, binding, now=1)
        for bad in ("binding", 7, None, (b"s", binding.digest)):
            with self.assertRaises(TypeError):
                guard.check(self.entry, bad, now=1)
        for bad in (True, False, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                guard.check(self.entry, binding, now=bad)

    def test_check_now_out_of_range_is_a_value_error(self):
        guard = RangeReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                guard.check(self.entry, binding, now=bad)

    def test_instances_are_independent(self):
        first = RangeReplayGuard()
        second = RangeReplayGuard()
        binding = first.bind_once(self.entry, b"s")
        self.assertFalse(second.check(self.entry, binding, now=1))
        # the rejected foreign check did not touch the first guard
        self.assertTrue(first.check(self.entry, binding, now=1))

    def test_inputs_are_not_mutated(self):
        guard = RangeReplayGuard()
        snapshot = dataclasses.replace(self.entry)
        binding = guard.bind_once(self.entry, b"s")
        binding_snapshot = dataclasses.replace(binding)
        guard.check(self.entry, binding, now=1)
        self.assertEqual(self.entry, snapshot)
        self.assertEqual(binding, binding_snapshot)


class RegionReplayGuardTest(unittest.TestCase):
    def setUp(self):
        self.region = Region(0, 10, 20, 30)
        self.x_commitment, self.x_blinding = pedersen_commit(
            5, 0, 10, prime=SMALL_PRIME, generator=3, blinding=1234,
        )
        self.y_commitment, self.y_blinding = pedersen_commit(
            25, 20, 30, prime=SMALL_PRIME, generator=3, blinding=4321,
        )
        self.proof = prove_region(
            self.x_commitment, self.y_commitment,
            5, 25, self.x_blinding, self.y_blinding,
            self.region, context=b"ctx", randbelow=counter_randbelow(),
        )
        self.entry = RegionBatchEntry(
            self.x_commitment, self.y_commitment, self.region, self.proof, b"ctx"
        )

    def entry_with(self, **changes):
        return dataclasses.replace(self.entry, **changes)

    def bound_leaf(self, entry):
        items = [b"zkregion/region-bound/v1"]
        for c in (entry.x_commitment, entry.y_commitment):
            items += [str(v).encode("ascii")
                      for v in (c.element, c.lower, c.upper, c.prime, c.generator, c.h)]
        r = entry.region
        items += [str(v).encode("ascii") for v in (r.min_x, r.max_x, r.min_y, r.max_y)]
        items.append(entry.context)
        for sub in (entry.proof.x_proof, entry.proof.y_proof):
            for seq in (sub.t, sub.e, sub.s):
                items.append(str(len(seq)).encode("ascii"))
                items += [str(v).encode("ascii") for v in seq]
        return b"".join(len(item).to_bytes(4, "big") + item for item in items)

    def expected_digest(self, entry, session_id, expires_at=None):
        def frame(item):
            return len(item).to_bytes(4, "big") + item

        expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
        material = frame(b"zr/rg/v1") + frame(session_id) + self.bound_leaf(entry) + frame(expiry)
        return hashlib.sha256(material).digest()

    # ---- binding ------------------------------------------------------------

    def test_bind_once_returns_spec_digest(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s1")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"s1")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(binding.digest, self.expected_digest(self.entry, b"s1"))
        self.assertEqual(len(binding.digest), 32)
        binding = guard.bind_once(self.entry, b"s2", expires_at=1000)
        self.assertEqual(binding.expires_at, 1000)
        self.assertEqual(binding.digest, self.expected_digest(self.entry, b"s2", 1000))

    def test_domain_separator_is_distinct(self):
        self.assertEqual(
            RegionReplayGuard().bind_once(self.entry, b"s").digest,
            self.expected_digest(self.entry, b"s"),
        )
        self.assertNotEqual(
            RegionReplayGuard().bind_once(self.entry, b"s").digest,
            hashlib.sha256(
                len(b"zr/rr/v1").to_bytes(4, "big") + b"zr/rr/v1"
                + len(b"s").to_bytes(4, "big") + b"s" + self.bound_leaf(self.entry)
                + len(b"\x00").to_bytes(4, "big") + b"\x00"
            ).digest(),
        )

    def test_digest_binds_every_component(self):
        guard = RegionReplayGuard()
        base = guard.bind_once(self.entry, b"s")
        self.assertNotEqual(base.digest, self.expected_digest(self.entry, b"other"))
        self.assertNotEqual(base.digest, self.expected_digest(self.entry, b"s", 1))
        self.assertNotEqual(
            base.digest,
            self.expected_digest(self.entry_with(context=b"other"), b"s"),
        )
        self.assertNotEqual(
            base.digest,
            self.expected_digest(
                self.entry_with(
                    x_commitment=dataclasses.replace(
                        self.x_commitment,
                        element=(self.x_commitment.element + 1) % SMALL_PRIME,
                    )
                ),
                b"s",
            ),
        )
        self.assertNotEqual(
            base.digest,
            self.expected_digest(
                self.entry_with(region=Region(0, 10, 20, 29)), b"s"
            ),
        )
        tampered_x = RangeProof(
            self.proof.x_proof.t, self.proof.x_proof.e,
            self.proof.x_proof.s[:-1] + (self.proof.x_proof.s[-1] + 1,),
        )
        self.assertNotEqual(
            base.digest,
            self.expected_digest(
                self.entry_with(proof=RegionProof(tampered_x, self.proof.y_proof)), b"s"
            ),
        )
        swapped = RegionProof(x_proof=self.proof.y_proof, y_proof=self.proof.x_proof)
        self.assertNotEqual(
            base.digest,
            self.expected_digest(self.entry_with(proof=swapped), b"s"),
        )

    def test_expiry_encodings_distinguish_presence_and_value(self):
        no_expiry = RegionReplayGuard().bind_once(self.entry, b"s")
        with_expiry = RegionReplayGuard().bind_once(self.entry, b"s", expires_at=0)
        later = RegionReplayGuard().bind_once(self.entry, b"s", expires_at=1)
        self.assertNotEqual(no_expiry.digest, with_expiry.digest)
        self.assertNotEqual(with_expiry.digest, later.digest)

    def test_pending_id_cannot_be_rebound(self):
        guard = RegionReplayGuard()
        guard.bind_once(self.entry, b"s")
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_consumed_id_cannot_be_rebound(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_distinct_session_ids_are_independent(self):
        guard = RegionReplayGuard()
        first = guard.bind_once(self.entry, b"s1")
        second = guard.bind_once(self.entry, b"s2")
        self.assertNotEqual(first, second)
        self.assertTrue(guard.check(self.entry, first, now=1))
        self.assertTrue(guard.check(self.entry, second, now=1))

    def test_bind_once_type_errors(self):
        guard = RegionReplayGuard()
        for bad in ("entry", 7, None, self.proof, self.x_commitment, self.region):
            with self.assertRaises(TypeError):
                guard.bind_once(bad, b"s")
        for bad in ("s", 7, None, bytearray(b"s")):
            with self.assertRaises(TypeError):
                guard.bind_once(self.entry, bad)
        for bad in (True, False, 1.5, "1000"):
            with self.assertRaises(TypeError):
                guard.bind_once(self.entry, b"s", expires_at=bad)

    def test_bind_once_nested_type_errors(self):
        guard = RegionReplayGuard()
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(x_commitment="c"), b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                self.entry_with(x_commitment=dataclasses.replace(self.x_commitment, h=True)),
                b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(y_commitment=self.proof), b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(region="r"), b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                self.entry_with(region=Region(0, 10, True, 30)), b"s"
            )
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(proof="p"), b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                self.entry_with(
                    proof=RegionProof(
                        RangeProof(
                            list(self.proof.x_proof.t),
                            self.proof.x_proof.e,
                            self.proof.x_proof.s,
                        ),
                        self.proof.y_proof,
                    )
                ),
                b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                self.entry_with(
                    proof=RegionProof(
                        RangeProof(
                            self.proof.x_proof.t,
                            self.proof.x_proof.e + (True,),
                            self.proof.x_proof.s,
                        ),
                        self.proof.y_proof,
                    )
                ),
                b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(self.entry_with(context="ctx"), b"s")

    def test_bind_once_value_errors(self):
        guard = RegionReplayGuard()
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"")
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError):
                guard.bind_once(self.entry, b"s", expires_at=bad)

    def test_negative_entry_integers_bind(self):
        # the BoundRegion leaf encodes integers as decimal ASCII, so negative
        # region bounds and commitment fields are encodable and bind_once does
        # not reject them
        guard = RegionReplayGuard()
        region = Region(-10, -1, -20, -11)
        xc, xr = pedersen_commit(
            -5, -10, -1, prime=SMALL_PRIME, generator=3, blinding=2222
        )
        yc, yr = pedersen_commit(
            -15, -20, -11, prime=SMALL_PRIME, generator=3, blinding=3333
        )
        proof = prove_region(
            xc, yc, -5, -15, xr, yr, region, context=b"ctx",
            randbelow=counter_randbelow(),
        )
        broken = RegionBatchEntry(xc, yc, region, proof, b"ctx")
        binding = guard.bind_once(broken, b"s")
        self.assertEqual(binding.digest, self.expected_digest(broken, b"s"))

    # ---- honest check and single use ----------------------------------------

    def test_check_accepts_then_consumes(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=1000)
        self.assertTrue(guard.check(self.entry, binding, now=999))
        # the consumed id is rejected and cannot be replayed
        self.assertFalse(guard.check(self.entry, binding, now=999))
        with self.assertRaises(ValueError):
            guard.bind_once(self.entry, b"s")

    def test_check_without_expiry_ignores_now(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=0))
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding, now=2**64 - 1))

    def test_check_with_default_now(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        self.assertTrue(guard.check(self.entry, binding))
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=10**12)
        self.assertTrue(guard.check(self.entry, binding))

    def test_expiry_boundary_is_inclusive(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s1", expires_at=1000)
        self.assertTrue(guard.check(self.entry, binding, now=999))
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s2", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=1000))
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s3", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=1001))

    # ---- rejection never consumes -------------------------------------------

    def test_expired_rejection_does_not_consume(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s", expires_at=1000)
        self.assertFalse(guard.check(self.entry, binding, now=2000))
        # still pending: an earlier clock succeeds and consumes it
        self.assertTrue(guard.check(self.entry, binding, now=999))
        self.assertFalse(guard.check(self.entry, binding, now=999))

    def test_bad_proof_rejection_does_not_consume(self):
        forged = self.entry_with(
            proof=RegionProof(
                RangeProof(
                    self.proof.x_proof.t, self.proof.x_proof.e,
                    self.proof.x_proof.s[:-1] + (self.proof.x_proof.s[-1] + 1,),
                ),
                self.proof.y_proof,
            )
        )
        guard = RegionReplayGuard()
        binding = guard.bind_once(forged, b"s")
        self.assertFalse(guard.check(forged, binding, now=1))
        # id still pending — rebinding is still refused while it waits
        with self.assertRaises(ValueError):
            guard.bind_once(forged, b"s")

    def test_entry_mismatch_rejection_does_not_consume(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        tampered_x = RangeProof(
            self.proof.x_proof.t, self.proof.x_proof.e,
            self.proof.x_proof.s[:-1] + (self.proof.x_proof.s[-1] + 1,),
        )
        for changed in (
            self.entry_with(context=b"other"),
            self.entry_with(
                x_commitment=dataclasses.replace(
                    self.x_commitment,
                    element=(self.x_commitment.element + 1) % SMALL_PRIME,
                )
            ),
            self.entry_with(region=Region(0, 10, 20, 29)),
            self.entry_with(proof=RegionProof(tampered_x, self.proof.y_proof)),
            self.entry_with(
                proof=RegionProof(self.proof.y_proof, self.proof.x_proof)
            ),
        ):
            self.assertFalse(guard.check(changed, binding, now=1))
        # the originally bound entry still verifies once
        self.assertTrue(guard.check(self.entry, binding, now=1))

    def test_unknown_or_foreign_binding_rejected(self):
        guard = RegionReplayGuard()
        guard.bind_once(self.entry, b"local")
        # an equal binding built elsewhere verifies (bindings compare by
        # value), but an id never registered in this guard does not
        foreign = RegionReplayGuard().bind_once(self.entry, b"elsewhere")
        self.assertFalse(guard.check(self.entry, foreign, now=1))
        equal = RegionReplayGuard().bind_once(self.entry, b"local")
        self.assertTrue(guard.check(self.entry, equal, now=1))
        unknown = ReplayBinding(b"never-bound", b"\x00" * 32)
        self.assertFalse(guard.check(self.entry, unknown, now=1))

    def test_unequal_binding_rejected_without_consuming(self):
        guard = RegionReplayGuard()
        guard.bind_once(self.entry, b"s")
        forged_digest = ReplayBinding(b"s", b"\x01" * 32)
        self.assertFalse(guard.check(self.entry, forged_digest, now=1))
        forged_expiry = ReplayBinding(
            b"s", self.expected_digest(self.entry, b"s", 1), 1
        )
        self.assertFalse(guard.check(self.entry, forged_expiry, now=0))

    def test_cross_guard_binding_rejected(self):
        # a range-guard binding for the same id is not a region-guard binding
        commitment, blinding = pedersen_commit(
            4, 0, 10, prime=SMALL_PRIME, generator=3, blinding=1000,
        )
        proof = prove_range(
            commitment, 4, blinding, context=b"ctx",
            randbelow=counter_randbelow(),
        )
        range_entry = RangeBatchEntry(commitment, proof, b"ctx")
        range_binding = RangeReplayGuard().bind_once(range_entry, b"s")
        guard = RegionReplayGuard()
        guard.bind_once(self.entry, b"s")
        self.assertFalse(guard.check(self.entry, range_binding, now=1))
        # and the region digest differs from the range one for a shared id
        region_binding = RegionReplayGuard().bind_once(self.entry, b"s")
        self.assertNotEqual(range_binding.digest, region_binding.digest)

    # ---- argument validation ------------------------------------------------

    def test_check_type_errors(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        for bad in ("entry", 7, None, self.proof, self.x_commitment, self.region):
            with self.assertRaises(TypeError):
                guard.check(bad, binding, now=1)
        for bad in ("binding", 7, None, (b"s", binding.digest)):
            with self.assertRaises(TypeError):
                guard.check(self.entry, bad, now=1)
        for bad in (True, False, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                guard.check(self.entry, binding, now=bad)

    def test_check_now_out_of_range_is_a_value_error(self):
        guard = RegionReplayGuard()
        binding = guard.bind_once(self.entry, b"s")
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                guard.check(self.entry, binding, now=bad)

    def test_instances_are_independent(self):
        first = RegionReplayGuard()
        second = RegionReplayGuard()
        binding = first.bind_once(self.entry, b"s")
        self.assertFalse(second.check(self.entry, binding, now=1))
        # the rejected foreign check did not touch the first guard
        self.assertTrue(first.check(self.entry, binding, now=1))

    def test_inputs_are_not_mutated(self):
        guard = RegionReplayGuard()
        snapshot = dataclasses.replace(self.entry)
        binding = guard.bind_once(self.entry, b"s")
        binding_snapshot = dataclasses.replace(binding)
        guard.check(self.entry, binding, now=1)
        self.assertEqual(self.entry, snapshot)
        self.assertEqual(binding, binding_snapshot)


class BoundRegionReplayGuardTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def entry(self, x=5, y=25, region=None, context=b"ctx",
              x_blinding=1234, y_blinding=4321):
        region = Region(0, 10, 20, 30) if region is None else region
        x_commitment, x_r = pedersen_commit(
            x, region.min_x, region.max_x, blinding=x_blinding,
            prime=self.PRIME, generator=self.G, h=self.H,
        )
        y_commitment, y_r = pedersen_commit(
            y, region.min_y, region.max_y, blinding=y_blinding,
            prime=self.PRIME, generator=self.G, h=self.H,
        )
        proof = prove_region(
            x_commitment, y_commitment, x, y, x_r, y_r, region, context,
            randbelow=counter_randbelow(),
        )
        return RegionBatchEntry(x_commitment, y_commitment, region, proof, context)

    def build(self, entries):
        leaves = [bound_region_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundRegionBatch(tuple(entries), len(entries), proof)
        return batch, root

    def honest(self):
        entries = [
            self.entry(context=b"a"),
            self.entry(x=7, y=22, context=b"b"),
            self.entry(x=0, y=30, context=b"c"),
        ]
        return self.build(entries)

    @staticmethod
    def expected_digest(batch, root, session_id, expires_at=None):
        def F(item):
            return len(item).to_bytes(4, "big") + item

        def U(value):
            return value.to_bytes(8, "big")

        def S(sequence, transform):
            return F(U(len(sequence))) + b"".join(F(transform(item)) for item in sequence)

        expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
        proof = batch.proof
        material = F(b"zr/brg/v1") + F(session_id) + F(root) + F(U(batch.leaf_count))
        material += b"".join(F(bound_region_leaf(entry)) for entry in batch.entries)
        material += (
            F(U(proof.leaf_count)) + S(proof.indices, U)
            + S(proof.siblings, lambda sibling: sibling) + F(expiry)
        )
        return hashlib.sha256(material).digest()

    # ---- binding / digest wire format ---------------------------------------

    def test_bind_once_returns_spec_digest(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s1")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"s1")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(len(binding.digest), 32)
        self.assertEqual(
            binding.digest, self.expected_digest(batch, root, b"s1")
        )
        binding = guard.bind_once(batch, root, b"s2", expires_at=1000)
        self.assertEqual(binding.expires_at, 1000)
        self.assertEqual(
            binding.digest, self.expected_digest(batch, root, b"s2", 1000)
        )

    def test_domain_separator_is_distinct(self):
        batch, root = self.honest()
        binding = BoundRegionReplayGuard().bind_once(batch, root, b"s")
        self.assertEqual(binding.digest, self.expected_digest(batch, root, b"s"))
        # the single-entry RegionReplayGuard domain must produce another digest
        proof = batch.proof
        material = (
            len(b"zr/rg/v1").to_bytes(4, "big") + b"zr/rg/v1"
            + len(b"s").to_bytes(4, "big") + b"s"
            + bound_region_leaf(batch.entries[0])
            + len(b"\x00").to_bytes(4, "big") + b"\x00"
        )
        self.assertNotEqual(binding.digest, hashlib.sha256(material).digest())

    def test_digest_binds_every_component(self):
        entries = [
            self.entry(context=b"a"),
            self.entry(x=7, y=22, context=b"b"),
            self.entry(x=0, y=30, context=b"c"),
        ]
        batch, root = self.build(entries)
        guard = BoundRegionReplayGuard()
        base = guard.bind_once(batch, root, b"s")
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, root, b"other")
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, root, b"s", 1)
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, hashlib.sha256(root).digest(), b"s")
        )
        # leaf_count and the per-entry leaves (entry order) participate
        single, single_root = self.build(entries[:1])
        self.assertNotEqual(
            base.digest, self.expected_digest(single, single_root, b"s")
        )
        reordered, reordered_root = self.build(
            [entries[1], entries[0], entries[2]]
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(reordered, reordered_root, b"s")
        )
        # proof indices and siblings participate: a partial multi proof differs
        leaves = [bound_region_leaf(entry) for entry in entries]
        partial = prove_multi_inclusion(leaves, (0, 1))
        partial_batch = BoundRegionBatch(tuple(entries), len(entries), partial)
        self.assertNotEqual(
            base.digest, self.expected_digest(partial_batch, root, b"s")
        )

    def test_expiry_encodings_distinguish_presence_and_value(self):
        batch, root = self.honest()
        none = BoundRegionReplayGuard().bind_once(batch, root, b"s")
        zero = BoundRegionReplayGuard().bind_once(batch, root, b"s", expires_at=0)
        one = BoundRegionReplayGuard().bind_once(batch, root, b"s", expires_at=1)
        self.assertNotEqual(none.digest, zero.digest)
        self.assertNotEqual(zero.digest, one.digest)

    def test_pending_id_cannot_be_rebound(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        guard.bind_once(batch, root, b"s")
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_consumed_id_cannot_be_rebound(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_distinct_session_ids_are_independent(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        first = guard.bind_once(batch, root, b"s1")
        second = guard.bind_once(batch, root, b"s2")
        self.assertNotEqual(first, second)
        self.assertTrue(guard.check(batch, root, first, now=1))
        self.assertTrue(guard.check(batch, root, second, now=1))

    # ---- bind argument validation -------------------------------------------

    def test_bind_type_errors(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        for bad in ("batch", 7, None, batch.entries, batch.proof):
            with self.assertRaises(TypeError):
                guard.bind_once(bad, root, b"s")
        for bad in (bytearray(root), None, 7, "root"):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, bad, b"s")
        for bad in ("s", 7, None, bytearray(b"s")):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, root, bad)
        for bad in (True, False, 1.5, "1000"):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, root, b"s", expires_at=bad)

    def test_bind_nested_type_errors(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        entries = batch.entries
        proof = batch.proof
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRegionBatch(list(entries), 3, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRegionBatch(("x",) * 3, 3, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRegionBatch(entries, True, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRegionBatch(entries, 3.0, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRegionBatch(entries, 3, "proof"), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundRegionBatch(
                    entries, 3,
                    MerkleMultiProof(3, [0, 1, 2], ()),
                ), root, b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundRegionBatch(
                    entries, 3,
                    MerkleMultiProof(3, (0, 1, True), ()),
                ), root, b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundRegionBatch(
                    entries, 3,
                    MerkleMultiProof(3, (0, 1, 2), (b"ok", 7)),
                ), root, b"s",
            )
        entry = entries[0]
        bad_entry_cases = [
            dataclasses.replace(entry, x_commitment="c"),
            dataclasses.replace(
                entry,
                x_commitment=dataclasses.replace(entry.x_commitment, h=True),
            ),
            dataclasses.replace(entry, y_commitment=entry.proof),
            dataclasses.replace(entry, region="r"),
            dataclasses.replace(entry, region=Region(0, 10, True, 30)),
            dataclasses.replace(entry, proof="p"),
            dataclasses.replace(
                entry,
                proof=RegionProof(
                    RangeProof(
                        list(entry.proof.x_proof.t),
                        entry.proof.x_proof.e,
                        entry.proof.x_proof.s,
                    ),
                    entry.proof.y_proof,
                ),
            ),
            dataclasses.replace(
                entry,
                proof=RegionProof(
                    RangeProof(
                        entry.proof.x_proof.t,
                        entry.proof.x_proof.e + (True,),
                        entry.proof.x_proof.s,
                    ),
                    entry.proof.y_proof,
                ),
            ),
            dataclasses.replace(entry, context="ctx"),
        ]
        for bad_entry in bad_entry_cases:
            with self.assertRaises(TypeError):
                guard.bind_once(
                    BoundRegionBatch((bad_entry,) + entries[1:], 3, proof),
                    root, b"s",
                )

    def test_bind_value_errors(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"")
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError):
                guard.bind_once(batch, root, b"s", expires_at=bad)
        with self.assertRaises(ValueError):
            guard.bind_once(
                BoundRegionBatch(batch.entries, 2**64, batch.proof), root, b"t"
            )
        negative = MerkleMultiProof(1, (-1,), ())
        with self.assertRaises(ValueError):
            guard.bind_once(
                BoundRegionBatch(batch.entries[:1], 1, negative), root, b"t"
            )

    # ---- honest check and single use ----------------------------------------

    def test_check_accepts_then_consumes(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s", expires_at=1000)
        self.assertTrue(guard.check(batch, root, binding, now=999))
        self.assertFalse(guard.check(batch, root, binding, now=999))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_check_with_default_now_and_randbelow(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding))

    def test_check_without_expiry_ignores_now(self):
        batch, root = self.honest()
        for now in (0, 2**64 - 1):
            guard = BoundRegionReplayGuard()
            binding = guard.bind_once(batch, root, b"s")
            self.assertTrue(guard.check(batch, root, binding, now=now))

    def test_expiry_boundary_is_inclusive(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s1", expires_at=1000)
        self.assertTrue(guard.check(batch, root, binding, now=999))
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s2", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=1000))
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s3", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=1001))

    # ---- random source passthrough ------------------------------------------

    def test_randbelow_is_passed_through_to_delegation(self):
        batch, root = self.honest()
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding, now=1, randbelow=recording))
        # 3 entries * 2 axes * 11 range values, one draw per branch
        self.assertEqual(calls, [self.PRIME - 1] * 66)

    def test_no_randomness_drawn_for_a_replayed_id(self):
        batch, root = self.honest()

        def boom(upper):
            raise AssertionError("randbelow must not be called")

        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )
        self.assertFalse(guard.check(batch, root, binding, now=1, randbelow=boom))

    def test_delegated_randomness_errors_propagate(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        with self.assertRaises(TypeError):
            guard.check(batch, root, binding, now=1, randbelow=lambda upper: True)
        # the failed check did not consume the id
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s2")
        with self.assertRaises(ValueError):
            guard.check(batch, root, binding, now=1, randbelow=lambda upper: -1)

    # ---- rejection never consumes -------------------------------------------

    def test_expired_rejection_does_not_consume(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=2000))
        self.assertTrue(guard.check(batch, root, binding, now=999))
        self.assertFalse(guard.check(batch, root, binding, now=999))

    def test_wrong_root_rejection_does_not_consume(self):
        batch, root = self.honest()
        leaves = [bound_region_leaf(entry) for entry in batch.entries]
        wrong_root = merkle_root(leaves[:1])
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertFalse(guard.check(batch, wrong_root, binding, now=1))
        # the original binding still verifies once
        self.assertTrue(guard.check(batch, root, binding, now=1))

    def test_bad_proof_rejection_does_not_consume(self):
        entries = [
            self.entry(context=b"a"),
            self.entry(x=7, y=22, context=b"b"),
            self.entry(x=0, y=30, context=b"c"),
        ]
        tampered_x = RangeProof(
            entries[0].proof.x_proof.t,
            entries[0].proof.x_proof.e,
            entries[0].proof.x_proof.s[:-1]
            + (entries[0].proof.x_proof.s[-1] + 1,),
        )
        forged_entries = [
            dataclasses.replace(
                entries[0],
                proof=RegionProof(tampered_x, entries[0].proof.y_proof),
            ),
            entries[1],
            entries[2],
        ]
        forged_batch, forged_root = self.build(forged_entries)
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(forged_batch, forged_root, b"s")
        self.assertFalse(guard.check(forged_batch, forged_root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(forged_batch, forged_root, b"s")

    def test_short_sibling_rejection_does_not_consume(self):
        batch, root = self.honest()
        bogus_proof = MerkleMultiProof(
            batch.proof.leaf_count, batch.proof.indices, (b"short",)
        )
        bogus_batch = BoundRegionBatch(batch.entries, batch.leaf_count, bogus_proof)
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(bogus_batch, root, b"s")
        self.assertFalse(guard.check(bogus_batch, root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(bogus_batch, root, b"s")

    def test_short_root_rejection_does_not_consume(self):
        batch, root = self.honest()
        short_root = root[:-1]
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, short_root, b"s")
        self.assertFalse(guard.check(batch, short_root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, short_root, b"s")

    def test_unknown_or_foreign_binding_rejected(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        guard.bind_once(batch, root, b"local")
        foreign = BoundRegionReplayGuard().bind_once(batch, root, b"elsewhere")
        self.assertFalse(guard.check(batch, root, foreign, now=1))
        equal = BoundRegionReplayGuard().bind_once(batch, root, b"local")
        self.assertTrue(guard.check(batch, root, equal, now=1))
        unknown = ReplayBinding(b"never-bound", b"\x00" * 32)
        self.assertFalse(guard.check(batch, root, unknown, now=1))

    def test_unequal_binding_rejected_without_consuming(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        guard.bind_once(batch, root, b"s")
        forged_digest = ReplayBinding(b"s", b"\x01" * 32)
        self.assertFalse(guard.check(batch, root, forged_digest, now=1))
        forged_expiry = ReplayBinding(
            b"s", self.expected_digest(batch, root, b"s", 1), 1
        )
        self.assertFalse(guard.check(batch, root, forged_expiry, now=0))

    def test_instances_are_independent(self):
        batch, root = self.honest()
        first = BoundRegionReplayGuard()
        second = BoundRegionReplayGuard()
        binding = first.bind_once(batch, root, b"s")
        self.assertFalse(second.check(batch, root, binding, now=1))
        self.assertTrue(first.check(batch, root, binding, now=1))

    # ---- check argument validation ------------------------------------------

    def test_check_type_errors(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        for bad in ("batch", 7, None, batch.entries):
            with self.assertRaises(TypeError):
                guard.check(bad, root, binding, now=1)
        for bad in (None, 7, "root", bytearray(root)):
            with self.assertRaises(TypeError):
                guard.check(batch, bad, binding, now=1)
        for bad in ("binding", 7, None, (b"s", binding.digest)):
            with self.assertRaises(TypeError):
                guard.check(batch, root, bad, now=1)
        for bad in (True, False, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                guard.check(batch, root, binding, now=bad)
        with self.assertRaises(TypeError):
            guard.check(batch, root, binding, now=1, randbelow=7)

    def test_check_now_out_of_range_is_a_value_error(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                guard.check(batch, root, binding, now=bad)

    def test_inputs_are_not_mutated(self):
        batch, root = self.honest()
        guard = BoundRegionReplayGuard()
        batch_snapshot = BoundRegionBatch(batch.entries, batch.leaf_count, batch.proof)
        binding = guard.bind_once(batch, root, b"s")
        binding_snapshot = dataclasses.replace(binding)
        held_root = bytes(root)
        guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        self.assertEqual(batch, batch_snapshot)
        self.assertEqual(binding, binding_snapshot)
        self.assertEqual(root, held_root)


class BoundRangeReplayGuardTest(unittest.TestCase):
    PRIME = SMALL_PRIME
    G = 3
    H = 5

    def entry(self, value=5, lower=0, upper=10, context=b"ctx", blinding=1234):
        commitment, r = pedersen_commit(
            value, lower, upper, blinding=blinding,
            prime=self.PRIME, generator=self.G, h=self.H,
        )
        proof = prove_range(
            commitment, value, r, context, randbelow=counter_randbelow()
        )
        return RangeBatchEntry(commitment, proof, context)

    def build(self, entries):
        leaves = [bound_range_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundRangeBatch(tuple(entries), len(entries), proof)
        return batch, root

    def honest(self):
        entries = [
            self.entry(value=5, context=b"a"),
            self.entry(value=7, context=b"b"),
            self.entry(value=0, context=b"c"),
        ]
        return self.build(entries)

    @staticmethod
    def expected_digest(batch, root, session_id, expires_at=None):
        def F(item):
            return len(item).to_bytes(4, "big") + item

        def U(value):
            return value.to_bytes(8, "big")

        def S(sequence, transform):
            return F(U(len(sequence))) + b"".join(F(transform(item)) for item in sequence)

        expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
        proof = batch.proof
        material = F(b"zr/brr/v1") + F(session_id) + F(root) + F(U(batch.leaf_count))
        material += b"".join(F(bound_range_leaf(entry)) for entry in batch.entries)
        material += (
            F(U(proof.leaf_count)) + S(proof.indices, U)
            + S(proof.siblings, lambda sibling: sibling) + F(expiry)
        )
        return hashlib.sha256(material).digest()

    # ---- binding / digest wire format ---------------------------------------

    def test_bind_once_returns_spec_digest(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s1")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"s1")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(len(binding.digest), 32)
        self.assertEqual(
            binding.digest, self.expected_digest(batch, root, b"s1")
        )
        binding = guard.bind_once(batch, root, b"s2", expires_at=1000)
        self.assertEqual(binding.expires_at, 1000)
        self.assertEqual(
            binding.digest, self.expected_digest(batch, root, b"s2", 1000)
        )

    def test_domain_separator_is_distinct(self):
        batch, root = self.honest()
        binding = BoundRangeReplayGuard().bind_once(batch, root, b"s")
        self.assertEqual(binding.digest, self.expected_digest(batch, root, b"s"))
        # the single-entry RangeReplayGuard domain must produce another digest
        material = (
            len(b"zr/rr/v1").to_bytes(4, "big") + b"zr/rr/v1"
            + len(b"s").to_bytes(4, "big") + b"s"
            + bound_range_leaf(batch.entries[0])
            + len(b"\x00").to_bytes(4, "big") + b"\x00"
        )
        self.assertNotEqual(binding.digest, hashlib.sha256(material).digest())
        # the same framing with the bound-region domain differs as well
        proof = batch.proof

        def F(item):
            return len(item).to_bytes(4, "big") + item

        def U(value):
            return value.to_bytes(8, "big")

        region_domain_material = F(b"zr/brg/v1") + F(b"s") + F(root) + F(U(3))
        region_domain_material += b"".join(
            F(bound_range_leaf(entry)) for entry in batch.entries
        )
        region_domain_material += (
            F(U(proof.leaf_count))
            + F(U(len(proof.indices)))
            + b"".join(F(U(index)) for index in proof.indices)
            + F(U(len(proof.siblings)))
            + b"".join(F(sibling) for sibling in proof.siblings)
            + F(b"\x00")
        )
        self.assertNotEqual(
            binding.digest, hashlib.sha256(region_domain_material).digest()
        )

    def test_digest_binds_every_component(self):
        entries = [
            self.entry(value=5, context=b"a"),
            self.entry(value=7, context=b"b"),
            self.entry(value=0, context=b"c"),
        ]
        batch, root = self.build(entries)
        guard = BoundRangeReplayGuard()
        base = guard.bind_once(batch, root, b"s")
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, root, b"other")
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, root, b"s", 1)
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, hashlib.sha256(root).digest(), b"s")
        )
        # leaf_count and the per-entry leaves (entry order) participate
        single, single_root = self.build(entries[:1])
        self.assertNotEqual(
            base.digest, self.expected_digest(single, single_root, b"s")
        )
        reordered, reordered_root = self.build(
            [entries[1], entries[0], entries[2]]
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(reordered, reordered_root, b"s")
        )
        # proof indices and siblings participate: a partial multi proof differs
        leaves = [bound_range_leaf(entry) for entry in entries]
        partial = prove_multi_inclusion(leaves, (0, 1))
        partial_batch = BoundRangeBatch(tuple(entries), len(entries), partial)
        self.assertNotEqual(
            base.digest, self.expected_digest(partial_batch, root, b"s")
        )

    def test_expiry_encodings_distinguish_presence_and_value(self):
        batch, root = self.honest()
        none = BoundRangeReplayGuard().bind_once(batch, root, b"s")
        zero = BoundRangeReplayGuard().bind_once(batch, root, b"s", expires_at=0)
        one = BoundRangeReplayGuard().bind_once(batch, root, b"s", expires_at=1)
        self.assertNotEqual(none.digest, zero.digest)
        self.assertNotEqual(zero.digest, one.digest)

    def test_pending_id_cannot_be_rebound(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        guard.bind_once(batch, root, b"s")
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_consumed_id_cannot_be_rebound(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_distinct_session_ids_are_independent(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        first = guard.bind_once(batch, root, b"s1")
        second = guard.bind_once(batch, root, b"s2")
        self.assertNotEqual(first, second)
        self.assertTrue(guard.check(batch, root, first, now=1))
        self.assertTrue(guard.check(batch, root, second, now=1))

    # ---- bind argument validation -------------------------------------------

    def test_bind_type_errors(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        for bad in ("batch", 7, None, batch.entries, batch.proof):
            with self.assertRaises(TypeError):
                guard.bind_once(bad, root, b"s")
        for bad in (bytearray(root), None, 7, "root"):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, bad, b"s")
        for bad in ("s", 7, None, bytearray(b"s")):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, root, bad)
        for bad in (True, False, 1.5, "1000"):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, root, b"s", expires_at=bad)

    def test_bind_nested_type_errors(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        entries = batch.entries
        proof = batch.proof
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRangeBatch(list(entries), 3, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRangeBatch(("x",) * 3, 3, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRangeBatch(entries, True, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRangeBatch(entries, 3.0, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundRangeBatch(entries, 3, "proof"), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundRangeBatch(
                    entries, 3,
                    MerkleMultiProof(3, [0, 1, 2], ()),
                ), root, b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundRangeBatch(
                    entries, 3,
                    MerkleMultiProof(3, (0, 1, True), ()),
                ), root, b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundRangeBatch(
                    entries, 3,
                    MerkleMultiProof(3, (0, 1, 2), (b"ok", 7)),
                ), root, b"s",
            )
        entry = entries[0]
        bad_entry_cases = [
            dataclasses.replace(entry, commitment="c"),
            dataclasses.replace(
                entry,
                commitment=dataclasses.replace(entry.commitment, element=True),
            ),
            dataclasses.replace(entry, proof="p"),
            dataclasses.replace(
                entry,
                proof=RangeProof(
                    list(entry.proof.t), entry.proof.e, entry.proof.s
                ),
            ),
            dataclasses.replace(
                entry,
                proof=RangeProof(
                    entry.proof.t, entry.proof.e[:-1] + (True,), entry.proof.s
                ),
            ),
            dataclasses.replace(entry, context="ctx"),
        ]
        for bad_entry in bad_entry_cases:
            with self.assertRaises(TypeError):
                guard.bind_once(
                    BoundRangeBatch((bad_entry,) + entries[1:], 3, proof),
                    root, b"s",
                )

    def test_bind_value_errors(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"")
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError):
                guard.bind_once(batch, root, b"s", expires_at=bad)
        with self.assertRaises(ValueError):
            guard.bind_once(
                BoundRangeBatch(batch.entries, 2**64, batch.proof), root, b"t"
            )
        negative = MerkleMultiProof(1, (-1,), ())
        with self.assertRaises(ValueError):
            guard.bind_once(
                BoundRangeBatch(batch.entries[:1], 1, negative), root, b"t"
            )

    # ---- honest check and single use ----------------------------------------

    def test_check_accepts_then_consumes(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s", expires_at=1000)
        self.assertTrue(guard.check(batch, root, binding, now=999))
        self.assertFalse(guard.check(batch, root, binding, now=999))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_check_with_default_now_and_randbelow(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding))

    def test_check_without_expiry_ignores_now(self):
        batch, root = self.honest()
        for now in (0, 2**64 - 1):
            guard = BoundRangeReplayGuard()
            binding = guard.bind_once(batch, root, b"s")
            self.assertTrue(guard.check(batch, root, binding, now=now))

    def test_expiry_boundary_is_inclusive(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s1", expires_at=1000)
        self.assertTrue(guard.check(batch, root, binding, now=999))
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s2", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=1000))
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s3", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=1001))

    # ---- random source passthrough ------------------------------------------

    def test_randbelow_is_passed_through_to_delegation(self):
        batch, root = self.honest()
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding, now=1, randbelow=recording))
        # 3 entries * 11 range values, one draw per structurally valid branch
        branches = sum(
            entry.commitment.upper - entry.commitment.lower + 1
            for entry in batch.entries
        )
        self.assertEqual(calls, [self.PRIME - 1] * branches)

    def test_no_randomness_drawn_for_a_replayed_id(self):
        batch, root = self.honest()

        def boom(upper):
            raise AssertionError("randbelow must not be called")

        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )
        self.assertFalse(guard.check(batch, root, binding, now=1, randbelow=boom))

    def test_delegated_randomness_errors_propagate(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        with self.assertRaises(TypeError):
            guard.check(batch, root, binding, now=1, randbelow=lambda upper: True)
        # the failed check did not consume the id
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s2")
        with self.assertRaises(ValueError):
            guard.check(batch, root, binding, now=1, randbelow=lambda upper: -1)

    # ---- rejection never consumes -------------------------------------------

    def test_expired_rejection_does_not_consume(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=2000))
        self.assertTrue(guard.check(batch, root, binding, now=999))
        self.assertFalse(guard.check(batch, root, binding, now=999))

    def test_wrong_root_rejection_does_not_consume(self):
        batch, root = self.honest()
        leaves = [bound_range_leaf(entry) for entry in batch.entries]
        wrong_root = merkle_root(leaves[:1])
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertFalse(guard.check(batch, wrong_root, binding, now=1))
        # the original binding still verifies once
        self.assertTrue(guard.check(batch, root, binding, now=1))

    def test_bad_proof_rejection_does_not_consume(self):
        entries = [
            self.entry(value=5, context=b"a"),
            self.entry(value=7, context=b"b"),
            self.entry(value=0, context=b"c"),
        ]
        tampered = RangeProof(
            entries[0].proof.t,
            entries[0].proof.e,
            entries[0].proof.s[:-1] + (entries[0].proof.s[-1] + 1,),
        )
        forged_entries = [
            dataclasses.replace(entries[0], proof=tampered),
            entries[1],
            entries[2],
        ]
        forged_batch, forged_root = self.build(forged_entries)
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(forged_batch, forged_root, b"s")
        self.assertFalse(guard.check(forged_batch, forged_root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(forged_batch, forged_root, b"s")

    def test_short_sibling_rejection_does_not_consume(self):
        batch, root = self.honest()
        bogus_proof = MerkleMultiProof(
            batch.proof.leaf_count, batch.proof.indices, (b"short",)
        )
        bogus_batch = BoundRangeBatch(batch.entries, batch.leaf_count, bogus_proof)
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(bogus_batch, root, b"s")
        self.assertFalse(guard.check(bogus_batch, root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(bogus_batch, root, b"s")

    def test_short_root_rejection_does_not_consume(self):
        batch, root = self.honest()
        short_root = root[:-1]
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, short_root, b"s")
        self.assertFalse(guard.check(batch, short_root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, short_root, b"s")

    def test_unknown_or_foreign_binding_rejected(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        guard.bind_once(batch, root, b"local")
        foreign = BoundRangeReplayGuard().bind_once(batch, root, b"elsewhere")
        self.assertFalse(guard.check(batch, root, foreign, now=1))
        equal = BoundRangeReplayGuard().bind_once(batch, root, b"local")
        self.assertTrue(guard.check(batch, root, equal, now=1))
        unknown = ReplayBinding(b"never-bound", b"\x00" * 32)
        self.assertFalse(guard.check(batch, root, unknown, now=1))

    def test_unequal_binding_rejected_without_consuming(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        guard.bind_once(batch, root, b"s")
        forged_digest = ReplayBinding(b"s", b"\x01" * 32)
        self.assertFalse(guard.check(batch, root, forged_digest, now=1))
        forged_expiry = ReplayBinding(
            b"s", self.expected_digest(batch, root, b"s", 1), 1
        )
        self.assertFalse(guard.check(batch, root, forged_expiry, now=0))

    def test_replaced_proof_mismatches_digest_without_consuming(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        # same entries and counts, but a different (invalid) multi proof
        replaced = BoundRangeBatch(
            batch.entries, batch.leaf_count,
            MerkleMultiProof(3, (0, 1, 2), (b"\x00" * 32,)),
        )
        self.assertFalse(guard.check(replaced, root, binding, now=1))
        # the untouched registration still verifies once
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )

    def test_instances_are_independent(self):
        batch, root = self.honest()
        first = BoundRangeReplayGuard()
        second = BoundRangeReplayGuard()
        binding = first.bind_once(batch, root, b"s")
        self.assertFalse(second.check(batch, root, binding, now=1))
        self.assertTrue(first.check(batch, root, binding, now=1))

    # ---- check argument validation ------------------------------------------

    def test_check_type_errors(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        for bad in ("batch", 7, None, batch.entries):
            with self.assertRaises(TypeError):
                guard.check(bad, root, binding, now=1)
        for bad in (None, 7, "root", bytearray(root)):
            with self.assertRaises(TypeError):
                guard.check(batch, bad, binding, now=1)
        for bad in ("binding", 7, None, (b"s", binding.digest)):
            with self.assertRaises(TypeError):
                guard.check(batch, root, bad, now=1)
        for bad in (True, False, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                guard.check(batch, root, binding, now=bad)
        with self.assertRaises(TypeError):
            guard.check(batch, root, binding, now=1, randbelow=7)

    def test_check_now_out_of_range_is_a_value_error(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                guard.check(batch, root, binding, now=bad)

    def test_inputs_are_not_mutated(self):
        batch, root = self.honest()
        guard = BoundRangeReplayGuard()
        batch_snapshot = BoundRangeBatch(batch.entries, batch.leaf_count, batch.proof)
        binding = guard.bind_once(batch, root, b"s")
        binding_snapshot = dataclasses.replace(binding)
        held_root = bytes(root)
        guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        self.assertEqual(batch, batch_snapshot)
        self.assertEqual(binding, binding_snapshot)
        self.assertEqual(root, held_root)


class BoundSchnorrReplayGuardTest(unittest.TestCase):
    G_PRIME = SMALL_PRIME
    G2_PRIME = 104723

    def prover(self, secret, prime, generator):
        return SchnorrProver(
            secret=secret, prime=prime, generator=generator,
            randbelow=counter_randbelow(),
        )

    def setUp(self):
        self.alice = self.prover(4321, self.G_PRIME, 3)
        self.bob = self.prover(7777, self.G_PRIME, 3)
        self.carol = self.prover(5566, self.G2_PRIME, 3)

    def entry(self, prover, message, *, prime, generator, context=b"ctx"):
        return MultiSchnorrEntry(
            public_key=prover.public_key,
            message=message,
            proof=prover.prove(message, context=context),
            context=context,
            prime=prime,
            generator=generator,
        )

    def build(self, entries):
        leaves = [bound_schnorr_leaf(entry) for entry in entries]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(entries))))
        batch = BoundSchnorrBatch(tuple(entries), len(entries), proof)
        return batch, root

    def honest(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
            self.entry(self.carol, b"gamma", prime=self.G2_PRIME, generator=3),
        ]
        return self.build(entries)

    @staticmethod
    def expected_digest(batch, root, session_id, expires_at=None):
        def F(item):
            return len(item).to_bytes(4, "big") + item

        def U(value):
            return value.to_bytes(8, "big")

        def S(sequence, transform):
            return F(U(len(sequence))) + b"".join(F(transform(item)) for item in sequence)

        expiry = b"\x00" if expires_at is None else b"\x01" + expires_at.to_bytes(8, "big")
        proof = batch.proof
        material = F(b"zr/bsr/v1") + F(session_id) + F(root) + F(U(batch.leaf_count))
        material += b"".join(F(bound_schnorr_leaf(entry)) for entry in batch.entries)
        material += (
            F(U(proof.leaf_count)) + S(proof.indices, U)
            + S(proof.siblings, lambda sibling: sibling) + F(expiry)
        )
        return hashlib.sha256(material).digest()

    # ---- binding / digest wire format ---------------------------------------

    def test_bind_once_returns_spec_digest(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s1")
        self.assertIsInstance(binding, ReplayBinding)
        self.assertEqual(binding.session_id, b"s1")
        self.assertIsNone(binding.expires_at)
        self.assertEqual(len(binding.digest), 32)
        self.assertEqual(
            binding.digest, self.expected_digest(batch, root, b"s1")
        )
        binding = guard.bind_once(batch, root, b"s2", expires_at=1000)
        self.assertEqual(binding.expires_at, 1000)
        self.assertEqual(
            binding.digest, self.expected_digest(batch, root, b"s2", 1000)
        )

    def test_domain_separator_is_distinct(self):
        batch, root = self.honest()
        binding = BoundSchnorrReplayGuard().bind_once(batch, root, b"s")
        self.assertEqual(binding.digest, self.expected_digest(batch, root, b"s"))
        # the single-entry ReplayGuard domain and raw-leaf framing must differ
        material = (
            len(b"zr/r/v1").to_bytes(4, "big") + b"zr/r/v1"
            + len(b"s").to_bytes(4, "big") + b"s"
            + bound_schnorr_leaf(batch.entries[0])
            + len(b"\x00").to_bytes(4, "big") + b"\x00"
        )
        self.assertNotEqual(binding.digest, hashlib.sha256(material).digest())
        # the same framing with the bound-region domain differs as well
        proof = batch.proof

        def F(item):
            return len(item).to_bytes(4, "big") + item

        def U(value):
            return value.to_bytes(8, "big")

        region_domain_material = F(b"zr/brg/v1") + F(b"s") + F(root) + F(U(3))
        region_domain_material += b"".join(
            F(bound_schnorr_leaf(entry)) for entry in batch.entries
        )
        region_domain_material += (
            F(U(proof.leaf_count))
            + F(U(len(proof.indices)))
            + b"".join(F(U(index)) for index in proof.indices)
            + F(U(len(proof.siblings)))
            + b"".join(F(sibling) for sibling in proof.siblings)
            + F(b"\x00")
        )
        self.assertNotEqual(
            binding.digest, hashlib.sha256(region_domain_material).digest()
        )

    def test_digest_binds_every_component(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
            self.entry(self.carol, b"gamma", prime=self.G2_PRIME, generator=3),
        ]
        batch, root = self.build(entries)
        guard = BoundSchnorrReplayGuard()
        base = guard.bind_once(batch, root, b"s")
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, root, b"other")
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, root, b"s", 1)
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(batch, hashlib.sha256(root).digest(), b"s")
        )
        # leaf_count and the per-entry leaves (entry order) participate
        single, single_root = self.build(entries[:1])
        self.assertNotEqual(
            base.digest, self.expected_digest(single, single_root, b"s")
        )
        reordered, reordered_root = self.build(
            [entries[1], entries[0], entries[2]]
        )
        self.assertNotEqual(
            base.digest, self.expected_digest(reordered, reordered_root, b"s")
        )
        # proof indices and siblings participate: a partial multi proof differs
        leaves = [bound_schnorr_leaf(entry) for entry in entries]
        partial = prove_multi_inclusion(leaves, (0, 1))
        partial_batch = BoundSchnorrBatch(tuple(entries), len(entries), partial)
        self.assertNotEqual(
            base.digest, self.expected_digest(partial_batch, root, b"s")
        )

    def test_expiry_encodings_distinguish_presence_and_value(self):
        batch, root = self.honest()
        none = BoundSchnorrReplayGuard().bind_once(batch, root, b"s")
        zero = BoundSchnorrReplayGuard().bind_once(batch, root, b"s", expires_at=0)
        one = BoundSchnorrReplayGuard().bind_once(batch, root, b"s", expires_at=1)
        self.assertNotEqual(none.digest, zero.digest)
        self.assertNotEqual(zero.digest, one.digest)

    def test_pending_id_cannot_be_rebound(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        guard.bind_once(batch, root, b"s")
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_consumed_id_cannot_be_rebound(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_distinct_session_ids_are_independent(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        first = guard.bind_once(batch, root, b"s1")
        second = guard.bind_once(batch, root, b"s2")
        self.assertNotEqual(first, second)
        self.assertTrue(guard.check(batch, root, first, now=1))
        self.assertTrue(guard.check(batch, root, second, now=1))

    # ---- bind argument validation -------------------------------------------

    def test_bind_type_errors(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        for bad in ("batch", 7, None, batch.entries, batch.proof):
            with self.assertRaises(TypeError):
                guard.bind_once(bad, root, b"s")
        for bad in (bytearray(root), None, 7, "root"):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, bad, b"s")
        for bad in ("s", 7, None, bytearray(b"s")):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, root, bad)
        for bad in (True, False, 1.5, "1000"):
            with self.assertRaises(TypeError):
                guard.bind_once(batch, root, b"s", expires_at=bad)

    def test_bind_nested_type_errors(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        entries = batch.entries
        proof = batch.proof
        with self.assertRaises(TypeError):
            guard.bind_once(BoundSchnorrBatch(list(entries), 3, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundSchnorrBatch(("x",) * 3, 3, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundSchnorrBatch(entries, True, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundSchnorrBatch(entries, 3.0, proof), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(BoundSchnorrBatch(entries, 3, "proof"), root, b"s")
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundSchnorrBatch(
                    entries, 3,
                    MerkleMultiProof(3, [0, 1, 2], ()),
                ), root, b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundSchnorrBatch(
                    entries, 3,
                    MerkleMultiProof(3, (0, 1, True), ()),
                ), root, b"s",
            )
        with self.assertRaises(TypeError):
            guard.bind_once(
                BoundSchnorrBatch(
                    entries, 3,
                    MerkleMultiProof(3, (0, 1, 2), (b"ok", 7)),
                ), root, b"s",
            )
        entry = entries[0]
        bad_entry_cases = [
            dataclasses.replace(entry, public_key="pk"),
            dataclasses.replace(entry, message="m"),
            dataclasses.replace(entry, proof="p"),
            dataclasses.replace(
                entry,
                proof=SchnorrProof(True, entry.proof.response),
            ),
            dataclasses.replace(entry, context="ctx"),
            dataclasses.replace(entry, prime=True),
        ]
        for bad_entry in bad_entry_cases:
            with self.assertRaises(TypeError):
                guard.bind_once(
                    BoundSchnorrBatch((bad_entry,) + entries[1:], 3, proof),
                    root, b"s",
                )

    def test_bind_value_errors(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"")
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError):
                guard.bind_once(batch, root, b"s", expires_at=bad)
        with self.assertRaises(ValueError):
            guard.bind_once(
                BoundSchnorrBatch(batch.entries, 2**64, batch.proof), root, b"t"
            )
        negative_index = MerkleMultiProof(1, (-1,), ())
        with self.assertRaises(ValueError):
            guard.bind_once(
                BoundSchnorrBatch(batch.entries[:1], 1, negative_index), root, b"t"
            )
        # a negative leaf integer (L is unsigned big-endian) is a ValueError
        negative_entries = self._negative_response_entries()
        negative_batch = BoundSchnorrBatch(tuple(negative_entries), 3, batch.proof)
        with self.assertRaises(ValueError):
            guard.bind_once(negative_batch, root, b"t")

    # ---- honest check and single use ----------------------------------------

    def test_check_accepts_then_consumes(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s", expires_at=1000)
        self.assertTrue(guard.check(batch, root, binding, now=999))
        self.assertFalse(guard.check(batch, root, binding, now=999))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, root, b"s")

    def test_check_with_default_now_and_randbelow(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding))

    def test_check_without_expiry_ignores_now(self):
        batch, root = self.honest()
        for now in (0, 2**64 - 1):
            guard = BoundSchnorrReplayGuard()
            binding = guard.bind_once(batch, root, b"s")
            self.assertTrue(guard.check(batch, root, binding, now=now))

    def test_expiry_boundary_is_inclusive(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s1", expires_at=1000)
        self.assertTrue(guard.check(batch, root, binding, now=999))
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s2", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=1000))
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s3", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=1001))

    # ---- random source passthrough ------------------------------------------

    def test_randbelow_is_passed_through_to_delegation(self):
        batch, root = self.honest()
        calls = []

        def recording(upper):
            calls.append(upper)
            return 0

        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(guard.check(batch, root, binding, now=1, randbelow=recording))
        # one draw per structurally valid entry, each at its own prime - 1
        self.assertEqual(
            calls,
            [self.G_PRIME - 1, self.G_PRIME - 1, self.G2_PRIME - 1],
        )

    def test_no_randomness_drawn_for_a_replayed_id(self):
        batch, root = self.honest()

        def boom(upper):
            raise AssertionError("randbelow must not be called")

        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )
        self.assertFalse(guard.check(batch, root, binding, now=1, randbelow=boom))

    def test_delegated_randomness_errors_propagate(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        with self.assertRaises(TypeError):
            guard.check(batch, root, binding, now=1, randbelow=lambda upper: True)
        # the failed check did not consume the id
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s2")
        with self.assertRaises(ValueError):
            guard.check(batch, root, binding, now=1, randbelow=lambda upper: -1)

    # ---- rejection never consumes -------------------------------------------

    def test_expired_rejection_does_not_consume(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s", expires_at=1000)
        self.assertFalse(guard.check(batch, root, binding, now=2000))
        self.assertTrue(guard.check(batch, root, binding, now=999))
        self.assertFalse(guard.check(batch, root, binding, now=999))

    def test_wrong_root_rejection_does_not_consume(self):
        batch, root = self.honest()
        leaves = [bound_schnorr_leaf(entry) for entry in batch.entries]
        wrong_root = merkle_root(leaves[:1])
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        self.assertFalse(guard.check(batch, wrong_root, binding, now=1))
        # the original binding still verifies once
        self.assertTrue(guard.check(batch, root, binding, now=1))

    def test_bad_proof_rejection_does_not_consume(self):
        entries = [
            self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
            self.entry(self.carol, b"gamma", prime=self.G2_PRIME, generator=3),
        ]
        forged_entries = [
            dataclasses.replace(
                entries[0],
                proof=SchnorrProof(
                    entries[0].proof.commitment, entries[0].proof.response + 1
                ),
            ),
            entries[1],
            entries[2],
        ]
        forged_batch, forged_root = self.build(forged_entries)
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(forged_batch, forged_root, b"s")
        self.assertFalse(guard.check(forged_batch, forged_root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(forged_batch, forged_root, b"s")

    def test_short_sibling_rejection_does_not_consume(self):
        batch, root = self.honest()
        bogus_proof = MerkleMultiProof(
            batch.proof.leaf_count, batch.proof.indices, (b"short",)
        )
        bogus_batch = BoundSchnorrBatch(batch.entries, batch.leaf_count, bogus_proof)
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(bogus_batch, root, b"s")
        self.assertFalse(guard.check(bogus_batch, root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(bogus_batch, root, b"s")

    def test_short_root_rejection_does_not_consume(self):
        batch, root = self.honest()
        short_root = root[:-1]
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, short_root, b"s")
        self.assertFalse(guard.check(batch, short_root, binding, now=1))
        with self.assertRaises(ValueError):
            guard.bind_once(batch, short_root, b"s")

    def test_negative_leaf_integer_rejected_without_consuming(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        negative_entries = self._negative_response_entries()
        negative_batch = BoundSchnorrBatch(
            tuple(negative_entries), 3, batch.proof
        )
        # check returns False (never raises) and leaves the id pending
        self.assertFalse(guard.check(negative_batch, root, binding, now=1))
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )

    def test_unknown_or_foreign_binding_rejected(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        guard.bind_once(batch, root, b"local")
        foreign = BoundSchnorrReplayGuard().bind_once(batch, root, b"elsewhere")
        self.assertFalse(guard.check(batch, root, foreign, now=1))
        equal = BoundSchnorrReplayGuard().bind_once(batch, root, b"local")
        self.assertTrue(guard.check(batch, root, equal, now=1))
        unknown = ReplayBinding(b"never-bound", b"\x00" * 32)
        self.assertFalse(guard.check(batch, root, unknown, now=1))

    def test_unequal_binding_rejected_without_consuming(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        guard.bind_once(batch, root, b"s")
        forged_digest = ReplayBinding(b"s", b"\x01" * 32)
        self.assertFalse(guard.check(batch, root, forged_digest, now=1))
        forged_expiry = ReplayBinding(
            b"s", self.expected_digest(batch, root, b"s", 1), 1
        )
        self.assertFalse(guard.check(batch, root, forged_expiry, now=0))

    def test_replaced_proof_mismatches_digest_without_consuming(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        # same entries and counts, but a different (invalid) multi proof
        replaced = BoundSchnorrBatch(
            batch.entries, batch.leaf_count,
            MerkleMultiProof(3, (0, 1, 2), (b"\x00" * 32,)),
        )
        self.assertFalse(guard.check(replaced, root, binding, now=1))
        # the untouched registration still verifies once
        self.assertTrue(
            guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        )

    def test_instances_are_independent(self):
        batch, root = self.honest()
        first = BoundSchnorrReplayGuard()
        second = BoundSchnorrReplayGuard()
        binding = first.bind_once(batch, root, b"s")
        self.assertFalse(second.check(batch, root, binding, now=1))
        self.assertTrue(first.check(batch, root, binding, now=1))

    # ---- check argument validation ------------------------------------------

    def test_check_type_errors(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        for bad in ("batch", 7, None, batch.entries):
            with self.assertRaises(TypeError):
                guard.check(bad, root, binding, now=1)
        for bad in (None, 7, "root", bytearray(root)):
            with self.assertRaises(TypeError):
                guard.check(batch, bad, binding, now=1)
        for bad in ("binding", 7, None, (b"s", binding.digest)):
            with self.assertRaises(TypeError):
                guard.check(batch, root, bad, now=1)
        for bad in (True, False, 1.5, "1", b"1"):
            with self.assertRaises(TypeError):
                guard.check(batch, root, binding, now=bad)
        with self.assertRaises(TypeError):
            guard.check(batch, root, binding, now=1, randbelow=7)

    def test_check_now_out_of_range_is_a_value_error(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        binding = guard.bind_once(batch, root, b"s")
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                guard.check(batch, root, binding, now=bad)

    def test_inputs_are_not_mutated(self):
        batch, root = self.honest()
        guard = BoundSchnorrReplayGuard()
        batch_snapshot = BoundSchnorrBatch(batch.entries, batch.leaf_count, batch.proof)
        binding = guard.bind_once(batch, root, b"s")
        binding_snapshot = dataclasses.replace(binding)
        held_root = bytes(root)
        guard.check(batch, root, binding, now=1, randbelow=counter_randbelow())
        self.assertEqual(batch, batch_snapshot)
        self.assertEqual(binding, binding_snapshot)
        self.assertEqual(root, held_root)

    # ---- helpers -------------------------------------------------------------

    def _negative_response_entries(self):
        entry = self.entry(self.alice, b"alpha", prime=self.G_PRIME, generator=3)
        return [
            dataclasses.replace(
                entry,
                proof=SchnorrProof(entry.proof.commitment, -1),
            ),
            self.entry(self.bob, b"beta", prime=self.G_PRIME, generator=3),
            self.entry(self.carol, b"gamma", prime=self.G2_PRIME, generator=3),
        ]


class MerkleConsistencyTest(unittest.TestCase):
    """Append-only consistency proofs between two Merkle roots."""

    def _leaves(self, count):
        return [f"cons-{i}".encode() for i in range(count)]

    def test_round_trip_all_prefixes(self):
        for size in range(1, 34):
            leaves = self._leaves(size)
            new_root = merkle_root(leaves)
            for old_count in range(1, size + 1):
                old_root = merkle_root(leaves[:old_count])
                proof = prove_consistency(leaves, old_count)
                self.assertEqual(proof.old_count, old_count)
                self.assertEqual(proof.new_count, size)
                self.assertIsInstance(proof.nodes, tuple)
                self.assertTrue(
                    verify_consistency(old_root, new_root, proof),
                    (old_count, size),
                )

    def test_nodes_layout(self):
        # nodes = popcount(old_count) subtree roots + one digest per new leaf
        for size in range(1, 20):
            leaves = self._leaves(size)
            for old_count in range(1, size + 1):
                proof = prove_consistency(leaves, old_count)
                expected = bin(old_count).count("1") + (size - old_count)
                self.assertEqual(len(proof.nodes), expected, (old_count, size))
                appended = proof.nodes[bin(old_count).count("1"):]
                self.assertEqual(
                    appended,
                    tuple(merkle_root([leaf]) for leaf in leaves[old_count:]),
                )

    def test_no_append_keeps_root(self):
        leaves = self._leaves(5)
        root = merkle_root(leaves)
        proof = prove_consistency(leaves, 5)
        self.assertEqual(proof.old_count, proof.new_count)
        self.assertTrue(verify_consistency(root, root, proof))
        self.assertFalse(verify_consistency(root, merkle_root(leaves + [b"x"]), proof))

    def test_proof_is_frozen_positional_and_value_equal(self):
        leaves = self._leaves(6)
        proof = prove_consistency(leaves, 3)
        clone = MerkleConsistencyProof(3, 6, proof.nodes)
        self.assertEqual(proof, clone)
        self.assertTrue(dataclasses.is_dataclass(proof))
        with self.assertRaises(AttributeError):
            proof.old_count = 1

    def test_type_errors(self):
        leaves = self._leaves(4)
        for bad_count in (True, False, 1.5, "2", None, b"2"):
            with self.assertRaises(TypeError, msg=repr(bad_count)):
                prove_consistency(leaves, bad_count)
        with self.assertRaises(TypeError):
            prove_consistency(b"abcd", 1)
        with self.assertRaises(TypeError):
            prove_consistency([b"a", 1], 1)
        proof = prove_consistency(leaves, 2)
        old_root = merkle_root(leaves[:2])
        new_root = merkle_root(leaves)
        with self.assertRaises(TypeError):
            verify_consistency(1, new_root, proof)
        with self.assertRaises(TypeError):
            verify_consistency(old_root, "root", proof)
        with self.assertRaises(TypeError):
            verify_consistency(old_root, new_root, object())
        with self.assertRaises(TypeError):
            verify_consistency(
                old_root, new_root, MerkleConsistencyProof(True, 4, proof.nodes)
            )
        with self.assertRaises(TypeError):
            verify_consistency(
                old_root, new_root, MerkleConsistencyProof(2, False, proof.nodes)
            )
        with self.assertRaises(TypeError):
            verify_consistency(
                old_root, new_root, MerkleConsistencyProof(2, 4, list(proof.nodes))
            )
        with self.assertRaises(TypeError):
            verify_consistency(
                old_root,
                new_root,
                MerkleConsistencyProof(2, 4, proof.nodes[:-1] + (1,)),
            )

    def test_value_errors(self):
        leaves = self._leaves(3)
        for bad_count in (0, -1, 4, 100):
            with self.assertRaises(ValueError, msg=repr(bad_count)):
                prove_consistency(leaves, bad_count)
        with self.assertRaises(ValueError):
            prove_consistency([], 1)

    def test_invalid_proofs_return_false(self):
        leaves = self._leaves(7)
        old_root = merkle_root(leaves[:3])
        new_root = merkle_root(leaves)
        proof = prove_consistency(leaves, 3)
        node = b"\x00" * 32
        cases = [
            # wrong counts
            MerkleConsistencyProof(0, 7, proof.nodes),
            MerkleConsistencyProof(-1, 7, proof.nodes),
            MerkleConsistencyProof(7, 3, proof.nodes),
            MerkleConsistencyProof(3, 8, proof.nodes),
            MerkleConsistencyProof(4, 7, proof.nodes),
            # wrong node count (truncated / extra / missing remainder)
            MerkleConsistencyProof(3, 7, proof.nodes[:-1]),
            MerkleConsistencyProof(3, 7, proof.nodes + (node,)),
            MerkleConsistencyProof(3, 3, proof.nodes),
            # bad digest length
            MerkleConsistencyProof(3, 7, (b"\x00" * 31,) * len(proof.nodes)),
            # tampered node
            MerkleConsistencyProof(3, 7, (node,) + proof.nodes[1:]),
            MerkleConsistencyProof(3, 7, proof.nodes[:-1] + (node,)),
        ]
        for bad in cases:
            self.assertFalse(verify_consistency(old_root, new_root, bad), bad)
        # bad root lengths and swapped / tampered roots
        self.assertFalse(verify_consistency(b"\x00" * 31, new_root, proof))
        self.assertFalse(verify_consistency(old_root, b"\x00" * 31, proof))
        self.assertFalse(verify_consistency(new_root, old_root, proof))
        self.assertFalse(verify_consistency(old_root, merkle_root(leaves[:6]), proof))
        self.assertFalse(verify_consistency(merkle_root(leaves[:2]), new_root, proof))

    def test_inputs_not_mutated(self):
        leaves = self._leaves(9)
        snapshot = list(leaves)
        proof = prove_consistency(leaves, 4)
        nodes_snapshot = proof.nodes
        self.assertEqual(leaves, snapshot)
        self.assertTrue(
            verify_consistency(merkle_root(snapshot[:4]), merkle_root(snapshot), proof)
        )
        self.assertEqual(leaves, snapshot)
        self.assertEqual(proof.nodes, nodes_snapshot)

    def test_existing_merkle_interfaces_unchanged(self):
        leaves = self._leaves(5)
        root = merkle_root(leaves)
        inclusion = prove_inclusion(leaves, 2)
        self.assertTrue(verify_inclusion(leaves[2], inclusion, root))
        multi = prove_multi_inclusion(leaves, (1, 3))
        self.assertTrue(
            verify_multi_inclusion([(1, leaves[1]), (3, leaves[3])], multi, root)
        )


class MerkleConsistencyChainTest(unittest.TestCase):
    """Multi-checkpoint Merkle consistency chains."""

    def _leaves(self, count):
        return [f"chain-{i}".encode() for i in range(count)]

    def test_round_trip_many_checkpoints(self):
        for size in range(2, 34):
            leaves = self._leaves(size)
            counts = tuple(sorted({1, size, (size // 2) or 1}))
            chain = prove_consistency_chain(leaves, counts)
            self.assertIsInstance(chain.roots, tuple)
            self.assertIsInstance(chain.proofs, tuple)
            self.assertEqual(len(chain.roots), len(counts))
            self.assertEqual(len(chain.proofs), len(counts) - 1)
            for count, root in zip(counts, chain.roots):
                self.assertEqual(root, merkle_root(leaves[:count]))
            for index, proof in enumerate(chain.proofs):
                self.assertEqual(proof.old_count, counts[index])
                self.assertEqual(proof.new_count, counts[index + 1])
                self.assertTrue(
                    verify_consistency(
                        chain.roots[index], chain.roots[index + 1], proof
                    )
                )
            self.assertTrue(verify_consistency_chain(chain))

    def test_two_checkpoints_and_full_prefixes(self):
        leaves = self._leaves(10)
        chain = prove_consistency_chain(leaves, (3, 10))
        self.assertEqual(chain.roots, (merkle_root(leaves[:3]), merkle_root(leaves)))
        self.assertEqual(len(chain.proofs), 1)
        self.assertEqual(chain.proofs[0], prove_consistency(leaves, 3))
        self.assertTrue(verify_consistency_chain(chain))
        # every checkpoint count up to the leaf total, including the end
        chain = prove_consistency_chain(leaves, tuple(range(1, 11)))
        self.assertEqual(len(chain.roots), 10)
        self.assertEqual(len(chain.proofs), 9)
        self.assertTrue(verify_consistency_chain(chain))

    def test_chain_is_frozen_positional_and_value_equal(self):
        leaves = self._leaves(8)
        chain = prove_consistency_chain(leaves, (2, 5, 8))
        clone = MerkleConsistencyChain(chain.roots, chain.proofs)
        self.assertEqual(chain, clone)
        self.assertTrue(dataclasses.is_dataclass(chain))
        with self.assertRaises(AttributeError):
            chain.roots = ()
        # differing roots or proofs compare unequal
        other = prove_consistency_chain(
            [f"other-{i}".encode() for i in range(8)], (2, 5, 8)
        )
        self.assertNotEqual(chain, MerkleConsistencyChain(other.roots, chain.proofs))
        self.assertNotEqual(chain, MerkleConsistencyChain(chain.roots, other.proofs))

    def test_prove_type_errors(self):
        leaves = self._leaves(6)
        good_counts = (2, 4)
        with self.assertRaises(TypeError):
            prove_consistency_chain(b"abcdef", good_counts)
        with self.assertRaises(TypeError):
            prove_consistency_chain([b"a", 1], good_counts)
        # counts must be a tuple (lists are rejected), never a bytes/str
        for bad_counts in ([2, 4], b"24", "(2, 4)", None, 2):
            with self.assertRaises(TypeError, msg=repr(bad_counts)):
                prove_consistency_chain(leaves, bad_counts)
        for bad_counts in (
            (True, 4),
            (2, False),
            (1.0, 4),
            (2, "4"),
            (2, None),
        ):
            with self.assertRaises(TypeError, msg=repr(bad_counts)):
                prove_consistency_chain(leaves, bad_counts)

    def test_prove_value_errors(self):
        leaves = self._leaves(6)
        for bad_counts in (
            (),
            (3,),
            (0, 3),
            (-1, 3),
            (3, 7),
            (3, 100),
            (3, 3),
            (4, 3),
            (1, 3, 3),
            (1, 5, 4),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_counts)):
                prove_consistency_chain(leaves, bad_counts)
        with self.assertRaises(ValueError):
            prove_consistency_chain([], (1, 2))

    def test_verify_type_errors(self):
        leaves = self._leaves(6)
        chain = prove_consistency_chain(leaves, (2, 4, 6))
        with self.assertRaises(TypeError):
            verify_consistency_chain(object())
        with self.assertRaises(TypeError):
            verify_consistency_chain(MerkleConsistencyChain(list(chain.roots), chain.proofs))
        with self.assertRaises(TypeError):
            verify_consistency_chain(MerkleConsistencyChain(chain.roots, list(chain.proofs)))
        with self.assertRaises(TypeError):
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots[:-1] + (1,), chain.proofs)
            )
        with self.assertRaises(TypeError):
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, chain.proofs[:-1] + (object(),))
            )
        bad_proof = MerkleConsistencyProof(True, 4, chain.proofs[0].nodes)
        with self.assertRaises(TypeError):
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (bad_proof, chain.proofs[1]))
            )
        bad_proof = MerkleConsistencyProof(2, False, chain.proofs[0].nodes)
        with self.assertRaises(TypeError):
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (bad_proof, chain.proofs[1]))
            )
        bad_proof = MerkleConsistencyProof(2, 4, list(chain.proofs[0].nodes))
        with self.assertRaises(TypeError):
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (bad_proof, chain.proofs[1]))
            )
        bad_proof = MerkleConsistencyProof(
            2, 4, chain.proofs[0].nodes[:-1] + (1,)
        )
        with self.assertRaises(TypeError):
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (bad_proof, chain.proofs[1]))
            )

    def test_verify_invalid_chains_return_false(self):
        leaves = self._leaves(9)
        chain = prove_consistency_chain(leaves, (2, 5, 9))
        node = b"\x00" * 32
        # empty chain, count mismatch, single root, bad digest lengths
        self.assertFalse(
            verify_consistency_chain(MerkleConsistencyChain((), ()))
        )
        self.assertFalse(
            verify_consistency_chain(MerkleConsistencyChain((chain.roots[0],), ()))
        )
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, chain.proofs + chain.proofs[:1])
            )
        )
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, chain.proofs[1:])
            )
        )
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(
                    chain.roots[:-1] + (b"\x00" * 31,), chain.proofs
                )
            )
        )
        # segment counts do not line up between adjacent proofs
        p0, p1 = chain.proofs
        spliced = MerkleConsistencyProof(p0.old_count, 6, p0.nodes)
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (spliced, p1))
            )
        )
        # reordered / replaced proofs fail even if counts look adjacent
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (p1, p0))
            )
        )
        # tampered root
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(
                    (node,) + chain.roots[1:], chain.proofs
                )
            )
        )
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(
                    chain.roots[:-1] + (node,), chain.proofs
                )
            )
        )
        # tampered proof node
        bad_nodes = (node,) + p0.nodes[1:]
        tampered = MerkleConsistencyProof(p0.old_count, p0.new_count, bad_nodes)
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (tampered, p1))
            )
        )
        # structurally malformed proof (zero old count) returns False
        bad = MerkleConsistencyProof(0, 5, p0.nodes)
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain(chain.roots, (bad, p1))
            )
        )

    def test_chain_does_not_accept_unrelated_prefixes(self):
        leaves = self._leaves(9)
        chain = prove_consistency_chain(leaves, (2, 5, 9))
        # a root from a different leaf sequence is rejected
        other = self._leaves(9)
        other[0] = b"different"
        self.assertFalse(
            verify_consistency_chain(
                MerkleConsistencyChain((merkle_root(other[:2]),) + chain.roots[1:],
                                       chain.proofs)
            )
        )

    def test_inputs_not_mutated(self):
        leaves = self._leaves(11)
        counts = (1, 4, 7, 11)
        leaves_snapshot = list(leaves)
        counts_snapshot = counts
        chain = prove_consistency_chain(leaves, counts)
        roots_snapshot = chain.roots
        proofs_snapshot = chain.proofs
        self.assertEqual(leaves, leaves_snapshot)
        self.assertEqual(counts, counts_snapshot)
        self.assertTrue(verify_consistency_chain(chain))
        self.assertEqual(leaves, leaves_snapshot)
        self.assertEqual(counts, counts_snapshot)
        self.assertEqual(chain.roots, roots_snapshot)
        self.assertEqual(chain.proofs, proofs_snapshot)

    def test_existing_merkle_interfaces_still_compatible(self):
        leaves = self._leaves(5)
        root = merkle_root(leaves)
        inclusion = prove_inclusion(leaves, 2)
        self.assertTrue(verify_inclusion(leaves[2], inclusion, root))
        multi = prove_multi_inclusion(leaves, (1, 3))
        self.assertTrue(
            verify_multi_inclusion([(1, leaves[1]), (3, leaves[3])], multi, root)
        )
        consistency = prove_consistency(leaves, 3)
        self.assertTrue(
            verify_consistency(merkle_root(leaves[:3]), root, consistency)
        )


if __name__ == "__main__":
    unittest.main()
