import hashlib
import unittest

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    MerkleMultiProof,
    MerkleProof,
    Region,
    SchnorrBatchEntry,
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
    commit,
    commit_coordinate,
    merkle_root,
    prove_inclusion,
    prove_multi_inclusion,
    verify_inclusion,
    verify_multi_inclusion,
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
        self.messages = [b"alpha", b"beta", b"gamma"]
        self.entries = [
            SchnorrBatchEntry(message, self.prover.prove(message, context=b"batch"), context=b"batch")
            for message in self.messages
        ]

    def test_entry_defaults_to_empty_context(self):
        entry = SchnorrBatchEntry(b"m", self.prover.prove(b"m"))
        self.assertEqual(entry.context, b"")
        self.assertTrue(self.verifier.verify_batch([entry], randbelow=counter_randbelow()))

    def test_entry_is_immutable(self):
        with self.assertRaises(AttributeError):
            self.entries[0].message = b"other"

    def test_honest_batch_verifies(self):
        self.assertTrue(self.verifier.verify_batch(self.entries, randbelow=counter_randbelow()))

    def test_default_randbelow_is_used(self):
        self.assertTrue(self.verifier.verify_batch(self.entries))

    def test_fixed_coefficient_source_is_reproducible(self):
        first = self.verifier.verify_batch(self.entries, randbelow=counter_randbelow())
        second = self.verifier.verify_batch(self.entries, randbelow=counter_randbelow())
        self.assertEqual(first, second)

    def test_single_entry_agrees_with_verify_proof(self):
        entry = self.entries[0]
        self.assertTrue(self.verifier.verify_batch([entry], randbelow=counter_randbelow()))
        self.assertTrue(self.verifier.verify_proof(entry.message, entry.proof, context=entry.context))

    def test_empty_batch_returns_false(self):
        self.assertFalse(self.verifier.verify_batch([], randbelow=counter_randbelow()))
        self.assertFalse(self.verifier.verify_batch((), randbelow=counter_randbelow()))

    def test_tuple_entries_accepted(self):
        self.assertTrue(self.verifier.verify_batch(tuple(self.entries), randbelow=counter_randbelow()))

    def test_duplicate_entries_each_draw_a_coefficient(self):
        doubled = [self.entries[0], self.entries[0], self.entries[1]]
        self.assertTrue(self.verifier.verify_batch(doubled, randbelow=counter_randbelow()))

    def test_randbelow_called_exactly_once_per_entry(self):
        calls = []

        def recording(upper):
            calls.append(upper)
            return counter_randbelow()(upper)

        self.assertTrue(self.verifier.verify_batch(self.entries, randbelow=recording))
        self.assertEqual(calls, [SMALL_PRIME - 1] * len(self.entries))

    def test_tampered_response_fails(self):
        entry = self.entries[1]
        forged = SchnorrBatchEntry(
            entry.message, SchnorrProof(entry.proof.commitment, entry.proof.response + 1), context=entry.context
        )
        batch = [self.entries[0], forged, self.entries[2]]
        self.assertFalse(self.verifier.verify_batch(batch, randbelow=counter_randbelow()))

    def test_tampered_commitment_fails(self):
        entry = self.entries[0]
        forged = SchnorrBatchEntry(
            entry.message,
            SchnorrProof(entry.proof.commitment % (SMALL_PRIME - 1) + 1, entry.proof.response),
            context=entry.context,
        )
        if forged.proof.commitment == entry.proof.commitment:
            forged = SchnorrBatchEntry(
                entry.message, SchnorrProof(entry.proof.commitment + 1, entry.proof.response), context=entry.context
            )
        self.assertFalse(self.verifier.verify_batch([forged], randbelow=counter_randbelow()))

    def test_wrong_message_or_context_fails(self):
        entry = self.entries[0]
        wrong_message = SchnorrBatchEntry(b"other", entry.proof, context=entry.context)
        self.assertFalse(self.verifier.verify_batch([wrong_message], randbelow=counter_randbelow()))
        wrong_context = SchnorrBatchEntry(entry.message, entry.proof, context=b"other")
        self.assertFalse(self.verifier.verify_batch([wrong_context], randbelow=counter_randbelow()))
        missing_context = SchnorrBatchEntry(entry.message, entry.proof)
        self.assertFalse(self.verifier.verify_batch([missing_context], randbelow=counter_randbelow()))

    def test_wrong_public_key_fails(self):
        other = SchnorrVerifier(pow(3, 4322, SMALL_PRIME), prime=SMALL_PRIME, generator=3)
        self.assertFalse(other.verify_batch(self.entries, randbelow=counter_randbelow()))

    def test_out_of_range_commitment_returns_false(self):
        entry = self.entries[0]
        for bad in (0, SMALL_PRIME, SMALL_PRIME + 1, -1):
            forged = SchnorrBatchEntry(entry.message, SchnorrProof(bad, entry.proof.response), context=entry.context)
            self.assertFalse(self.verifier.verify_batch([forged], randbelow=counter_randbelow()))

    def test_negative_response_returns_false(self):
        entry = self.entries[0]
        forged = SchnorrBatchEntry(entry.message, SchnorrProof(entry.proof.commitment, -1), context=entry.context)
        self.assertFalse(self.verifier.verify_batch([forged], randbelow=counter_randbelow()))

    def test_invalid_proof_may_short_circuit(self):
        entry = self.entries[0]
        forged = SchnorrBatchEntry(entry.message, SchnorrProof(0, entry.proof.response), context=entry.context)

        def exploding(upper):
            raise AssertionError("randbelow must not be called for an invalid entry")

        self.assertFalse(self.verifier.verify_batch([forged], randbelow=exploding))

    def test_entries_type_errors(self):
        for bad in ("entries", b"entries", bytearray(b"x"), 42, None, (e for e in self.entries)):
            with self.assertRaises(TypeError):
                self.verifier.verify_batch(bad, randbelow=counter_randbelow())

    def test_entry_and_field_type_errors(self):
        entry = self.entries[0]
        with self.assertRaises(TypeError):
            self.verifier.verify_batch([(entry.message, entry.proof)], randbelow=counter_randbelow())
        with self.assertRaises(TypeError):
            self.verifier.verify_batch([SchnorrBatchEntry("m", entry.proof)], randbelow=counter_randbelow())
        with self.assertRaises(TypeError):
            self.verifier.verify_batch(
                [SchnorrBatchEntry(entry.message, entry.proof, context="ctx")],
                randbelow=counter_randbelow(),
            )
        with self.assertRaises(TypeError):
            self.verifier.verify_batch(
                [SchnorrBatchEntry(entry.message, (entry.proof.commitment, entry.proof.response))],
                randbelow=counter_randbelow(),
            )
        with self.assertRaises(TypeError):
            self.verifier.verify_batch(
                [SchnorrBatchEntry(entry.message, SchnorrProof(1.5, entry.proof.response))],
                randbelow=counter_randbelow(),
            )
        with self.assertRaises(TypeError):
            self.verifier.verify_batch(
                [SchnorrBatchEntry(entry.message, SchnorrProof(entry.proof.commitment, "s"))],
                randbelow=counter_randbelow(),
            )

    def test_randbelow_type_errors(self):
        with self.assertRaises(TypeError):
            self.verifier.verify_batch(self.entries, randbelow=7)
        for bad_value in ("1", 1.5, None, True):
            with self.assertRaises(TypeError):
                self.verifier.verify_batch(self.entries, randbelow=lambda upper: bad_value)

    def test_coefficient_out_of_range_raises_value_error(self):
        for bad_value in (-1, SMALL_PRIME - 1, SMALL_PRIME):
            with self.assertRaises(ValueError):
                self.verifier.verify_batch(self.entries, randbelow=lambda upper: bad_value)

    def test_boundary_coefficients_accepted(self):
        self.assertTrue(self.verifier.verify_batch(self.entries, randbelow=lambda upper: 0))
        self.assertTrue(self.verifier.verify_batch(self.entries, randbelow=lambda upper: SMALL_PRIME - 2))

    def test_inputs_are_not_mutated(self):
        entries = list(self.entries)
        snapshot = list(entries)
        self.verifier.verify_batch(entries, randbelow=counter_randbelow())
        self.assertEqual(entries, snapshot)

    def test_does_not_touch_interactive_nonce(self):
        commitment = self.prover.new_commitment()
        self.verifier.verify_batch(self.entries, randbelow=counter_randbelow())
        self.assertTrue(self.verifier.verify(commitment, 7, self.prover.respond(7)))

    def test_default_group_parameters_are_usable(self):
        prover = SchnorrProver(secret=123456789, randbelow=counter_randbelow())
        verifier = SchnorrVerifier(prover.public_key)
        entries = [
            SchnorrBatchEntry(b"m1", prover.prove(b"m1", context=b"demo"), context=b"demo"),
            SchnorrBatchEntry(b"m2", prover.prove(b"m2", context=b"demo"), context=b"demo"),
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
