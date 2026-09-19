import unittest

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    MerkleProof,
    Region,
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
    commit,
    commit_coordinate,
    merkle_root,
    prove_inclusion,
    verify_inclusion,
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


def _leaf_digest(leaf: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(b"\x00" + len(leaf).to_bytes(4, "big") + leaf).digest()


def _node_digest(left: bytes, right: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleRootTest(unittest.TestCase):
    def test_single_leaf_root_is_leaf_digest(self):
        self.assertEqual(merkle_root([b"only"]), _leaf_digest(b"only"))

    def test_two_leaves_pair_directly(self):
        h0, h1 = _leaf_digest(b"a"), _leaf_digest(b"b")
        self.assertEqual(merkle_root([b"a", b"b"]), _node_digest(h0, h1))

    def test_odd_level_duplicates_last_node(self):
        h0, h1, h2 = map(_leaf_digest, (b"a", b"b", b"c"))
        n01 = _node_digest(h0, h1)
        n22 = _node_digest(h2, h2)
        self.assertEqual(merkle_root([b"a", b"b", b"c"]), _node_digest(n01, n22))

    def test_root_is_deterministic_and_order_sensitive(self):
        leaves = [b"a", b"b", b"c", b"d"]
        self.assertEqual(merkle_root(leaves), merkle_root(list(leaves)))
        self.assertNotEqual(merkle_root(leaves), merkle_root([b"a", b"c", b"b", b"d"]))

    def test_accepts_tuples(self):
        self.assertEqual(merkle_root((b"a", b"b")), merkle_root([b"a", b"b"]))

    def test_empty_tree_rejected(self):
        with self.assertRaises(ValueError):
            merkle_root([])
        with self.assertRaises(ValueError):
            merkle_root(())

    def test_non_bytes_leaves_rejected(self):
        with self.assertRaises(TypeError):
            merkle_root([b"a", "b"])
        with self.assertRaises(TypeError):
            merkle_root([1])

    def test_non_sequence_rejected(self):
        with self.assertRaises(TypeError):
            merkle_root(123)
        with self.assertRaises(TypeError):
            merkle_root(iter([b"a", b"b"]))

    def test_inputs_are_not_mutated(self):
        leaves = [b"a", b"b", b"c", b"d", b"e"]
        snapshot = list(leaves)
        merkle_root(leaves)
        self.assertEqual(leaves, snapshot)


class MerkleProofTest(unittest.TestCase):
    def test_proof_is_frozen_tuple_path(self):
        proof = prove_inclusion([b"a", b"b"], 0)
        self.assertIsInstance(proof, MerkleProof)
        self.assertIsInstance(proof.siblings, tuple)
        with self.assertRaises(AttributeError):
            proof.index = 1

    def test_single_leaf_has_empty_path(self):
        proof = prove_inclusion([b"only"], 0)
        self.assertEqual((proof.index, proof.siblings), (0, ()))
        self.assertTrue(verify_inclusion(b"only", proof, merkle_root([b"only"])))

    def test_every_index_verifies_for_each_tree_size(self):
        for size in range(1, 9):
            leaves = [f"leaf-{i}".encode() for i in range(size)]
            root = merkle_root(leaves)
            for index in range(size):
                with self.subTest(size=size, index=index):
                    proof = prove_inclusion(leaves, index)
                    self.assertEqual(len(proof.siblings), (size - 1).bit_length())
                    self.assertTrue(verify_inclusion(leaves[index], proof, root))

    def test_three_leaf_path_matches_manual_vector(self):
        h0, h1, h2 = map(_leaf_digest, (b"a", b"b", b"c"))
        n01 = _node_digest(h0, h1)
        n22 = _node_digest(h2, h2)
        self.assertEqual(prove_inclusion([b"a", b"b", b"c"], 0).siblings, (h1, n22))
        self.assertEqual(prove_inclusion([b"a", b"b", b"c"], 1).siblings, (h0, n22))
        self.assertEqual(prove_inclusion([b"a", b"b", b"c"], 2).siblings, (h2, n01))

    def test_duplicate_leaves_are_located_by_index(self):
        leaves = [b"same", b"same", b"other", b"same"]
        root = merkle_root(leaves)
        paths = {prove_inclusion(leaves, i).siblings for i in range(4)}
        # duplicate content still yields position-specific sibling paths
        self.assertEqual(len(paths), 3)
        for i in range(4):
            self.assertTrue(verify_inclusion(leaves[i], prove_inclusion(leaves, i), root))
        # a proof for one occurrence does not verify at the wrong index
        first = prove_inclusion(leaves, 0)
        third = MerkleProof(3, first.siblings)
        self.assertFalse(verify_inclusion(b"same", third, root))

    def test_index_out_of_range(self):
        with self.assertRaises(IndexError):
            prove_inclusion([b"a", b"b"], 2)
        with self.assertRaises(IndexError):
            prove_inclusion([b"a"], -1)

    def test_non_integer_index_rejected(self):
        with self.assertRaises(TypeError):
            prove_inclusion([b"a", b"b"], 1.0)
        with self.assertRaises(TypeError):
            prove_inclusion([b"a", b"b"], "0")

    def test_propagates_leaf_validation(self):
        with self.assertRaises(ValueError):
            prove_inclusion([], 0)
        with self.assertRaises(TypeError):
            prove_inclusion([b"a", 1], 0)

    def test_inputs_are_not_mutated(self):
        leaves = [b"a", b"b", b"c"]
        snapshot = list(leaves)
        prove_inclusion(leaves, 2)
        self.assertEqual(leaves, snapshot)


class MerkleVerificationTest(unittest.TestCase):
    def setUp(self):
        self.leaves = [f"leaf-{i}".encode() for i in range(5)]
        self.root = merkle_root(self.leaves)

    def test_tampered_leaf_rejected(self):
        proof = prove_inclusion(self.leaves, 2)
        self.assertFalse(verify_inclusion(b"leaf-X", proof, self.root))

    def test_tampered_index_rejected(self):
        proof = prove_inclusion(self.leaves, 0)
        relocated = MerkleProof(1, proof.siblings)
        self.assertFalse(verify_inclusion(self.leaves[0], relocated, self.root))

    def test_tampered_sibling_rejected(self):
        proof = prove_inclusion(self.leaves, 2)
        broken = (b"\x00" * 32,) + proof.siblings[1:]
        self.assertFalse(verify_inclusion(self.leaves[2], MerkleProof(2, broken), self.root))

    def test_tampered_root_rejected(self):
        proof = prove_inclusion(self.leaves, 2)
        self.assertFalse(verify_inclusion(self.leaves[2], proof, b"\x00" * 32))

    def test_wrong_tree_root_rejected(self):
        proof = prove_inclusion(self.leaves, 2)
        self.assertFalse(verify_inclusion(self.leaves[2], proof, merkle_root([b"other"])))

    def test_truncated_and_extended_paths_rejected(self):
        proof = prove_inclusion(self.leaves, 2)
        leaf = self.leaves[2]
        self.assertFalse(verify_inclusion(leaf, MerkleProof(2, proof.siblings[:-1]), self.root))
        self.assertFalse(
            verify_inclusion(leaf, MerkleProof(2, proof.siblings + (b"\x00" * 32,)), self.root)
        )

    def test_root_must_be_32_bytes(self):
        proof = prove_inclusion(self.leaves, 2)
        for bad_root in (b"", b"\x00" * 31, b"\x00" * 33):
            self.assertFalse(verify_inclusion(self.leaves[2], proof, bad_root))

    def test_siblings_must_be_32_byte_bytes(self):
        proof = prove_inclusion(self.leaves, 2)
        self.assertFalse(
            verify_inclusion(self.leaves[2], MerkleProof(2, ("not-bytes",)), self.root)
        )
        self.assertFalse(
            verify_inclusion(self.leaves[2], MerkleProof(2, (b"\x00" * 31,)), self.root)
        )
        self.assertFalse(
            verify_inclusion(self.leaves[2], MerkleProof(2, [b"\x00" * 32]), self.root)
        )

    def test_negative_index_returns_false(self):
        proof = prove_inclusion(self.leaves, 2)
        self.assertFalse(
            verify_inclusion(self.leaves[2], MerkleProof(-1, proof.siblings), self.root)
        )

    def test_non_integer_index_returns_false(self):
        proof = prove_inclusion(self.leaves, 2)
        self.assertFalse(
            verify_inclusion(self.leaves[2], MerkleProof(2.0, proof.siblings), self.root)
        )

    def test_type_errors(self):
        proof = prove_inclusion(self.leaves, 2)
        with self.assertRaises(TypeError):
            verify_inclusion("leaf-2", proof, self.root)
        with self.assertRaises(TypeError):
            verify_inclusion(self.leaves[2], proof, "root")
        with self.assertRaises(TypeError):
            verify_inclusion(self.leaves[2], (2, proof.siblings), self.root)

    def test_does_not_mutate_proof(self):
        proof = prove_inclusion(self.leaves, 2)
        siblings = proof.siblings
        verify_inclusion(self.leaves[2], proof, self.root)
        self.assertEqual(proof.siblings, siblings)


if __name__ == "__main__":
    unittest.main()
