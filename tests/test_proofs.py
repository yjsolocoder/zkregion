import hashlib
import itertools
import unittest

from zkregion import (
    DEFAULT_GENERATOR,
    DEFAULT_PRIME,
    MerkleMultiProof,
    MerkleProof,
    Region,
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


class MerkleMultiProofTest(unittest.TestCase):
    LEAVES = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]

    def entries(self, indices, leaves=None):
        source = self.LEAVES if leaves is None else leaves
        return [(index, source[index]) for index in indices]

    def test_round_trip_for_every_subset(self):
        root = merkle_root(self.LEAVES)
        for size in range(1, len(self.LEAVES) + 1):
            for indices in itertools.combinations(range(len(self.LEAVES)), size):
                proof = prove_multi_inclusion(self.LEAVES, list(indices))
                self.assertEqual(proof.leaf_count, len(self.LEAVES))
                self.assertEqual(proof.indices, indices)
                self.assertIsInstance(proof.indices, tuple)
                self.assertIsInstance(proof.siblings, tuple)
                self.assertTrue(verify_multi_inclusion(self.entries(indices), proof, root))

    def test_single_leaf_tree(self):
        proof = prove_multi_inclusion([b"only"], [0])
        self.assertEqual(proof, MerkleMultiProof(leaf_count=1, indices=(0,), siblings=()))
        self.assertTrue(verify_multi_inclusion([(0, b"only")], proof, merkle_root([b"only"])))

    def test_all_leaves_needs_no_siblings(self):
        proof = prove_multi_inclusion(self.LEAVES, list(range(len(self.LEAVES))))
        self.assertEqual(proof.siblings, ())
        self.assertTrue(
            verify_multi_inclusion(self.entries(range(len(self.LEAVES))), proof, merkle_root(self.LEAVES))
        )

    def test_proof_is_deterministic_and_minimal(self):
        indices = [1, 2, 4]
        first = prove_multi_inclusion(self.LEAVES, indices)
        second = prove_multi_inclusion(self.LEAVES, tuple(indices))
        self.assertEqual(first, second)
        # hand-computed frontier for indices {1, 2, 4} in a five-leaf tree
        expected = (
            leaf_digest(b"alpha"),
            leaf_digest(b"delta"),
        )
        self.assertEqual(first.siblings, expected)
        # a compact proof never repeats a sibling two single proofs would share
        combined = sum(len(prove_inclusion(self.LEAVES, i).siblings) for i in indices)
        self.assertLess(len(first.siblings), combined)

    def test_odd_last_proven_node_duplicates_itself(self):
        # index 2 in a three-leaf tree is the odd last node: no sibling collected
        leaves = self.LEAVES[:3]
        proof = prove_multi_inclusion(leaves, [2])
        self.assertEqual(len(proof.siblings), 1)
        self.assertTrue(verify_multi_inclusion([(2, b"gamma")], proof, merkle_root(leaves)))

    def test_proof_is_immutable(self):
        proof = prove_multi_inclusion(self.LEAVES, [1, 3])
        with self.assertRaises(AttributeError):
            proof.indices = (0,)

    def test_prove_input_validation(self):
        for bad in ("01", b"01", 1, None):
            with self.assertRaises(TypeError):
                prove_multi_inclusion(self.LEAVES, bad)
        for bad in ([0.0], ["0"], [None], [True], [0, False]):
            with self.assertRaises(TypeError):
                prove_multi_inclusion(self.LEAVES, bad)
        with self.assertRaises(ValueError):
            prove_multi_inclusion(self.LEAVES, [])
        for bad in ([1, 1], [2, 0], [0, 0], [3, 1, 4, 1]):
            with self.assertRaises(ValueError):
                prove_multi_inclusion(self.LEAVES, bad)
        for bad in ([5], [-1], [0, 7]):
            with self.assertRaises(IndexError):
                prove_multi_inclusion(self.LEAVES, bad)
        with self.assertRaises(ValueError):
            prove_multi_inclusion([], [0])
        with self.assertRaises(TypeError):
            prove_multi_inclusion([b"ok", 7], [0])

    def test_tampering_fails(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, [1, 3])
        entries = self.entries([1, 3])
        self.assertFalse(verify_multi_inclusion([(1, b"beta"), (3, b"other")], proof, root))
        self.assertFalse(verify_multi_inclusion(entries, proof, merkle_root(self.LEAVES[:4])))
        swapped = MerkleMultiProof(5, proof.indices, (proof.siblings[1], proof.siblings[0]))
        self.assertFalse(verify_multi_inclusion(entries, swapped, root))
        flipped = MerkleMultiProof(5, proof.indices, proof.siblings[:-1] + (proof.siblings[-1][::-1],))
        self.assertFalse(verify_multi_inclusion(entries, flipped, root))

    def test_sibling_count_must_match_exactly(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, [1, 3])
        entries = self.entries([1, 3])
        extra = MerkleMultiProof(5, proof.indices, proof.siblings + (b"\x00" * 32,))
        self.assertFalse(verify_multi_inclusion(entries, extra, root))
        short = MerkleMultiProof(5, proof.indices, proof.siblings[:-1])
        self.assertFalse(verify_multi_inclusion(entries, short, root))

    def test_entries_must_match_proof_indices(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, [1, 3])
        self.assertFalse(verify_multi_inclusion([], proof, root))
        self.assertFalse(verify_multi_inclusion(self.entries([3, 1]), proof, root))
        self.assertFalse(verify_multi_inclusion(self.entries([1]), proof, root))
        self.assertFalse(verify_multi_inclusion(self.entries([1, 2, 3]), proof, root))
        self.assertFalse(verify_multi_inclusion(self.entries([1, 2]), proof, root))

    def test_verify_structural_checks_return_false(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, [1, 3])
        entries = self.entries([1, 3])
        self.assertFalse(verify_multi_inclusion(entries, proof, root[:-1]))
        self.assertFalse(verify_multi_inclusion(entries, proof, root + b"\x00"))
        short = MerkleMultiProof(5, proof.indices, (proof.siblings[0][:16],) + proof.siblings[1:])
        self.assertFalse(verify_multi_inclusion(entries, short, root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(0, proof.indices, proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(-2, proof.indices, proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 5), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (1, -1), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (3, 1), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 1), proof.siblings), root))
        self.assertFalse(verify_multi_inclusion(entries, MerkleMultiProof(5, (), ()), root))

    def test_verify_type_checks(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(self.LEAVES, [1, 3])
        entries = self.entries([1, 3])
        with self.assertRaises(TypeError):
            verify_multi_inclusion("entries", proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, proof, "root")
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, (5, proof.indices, proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5.0, proof.indices, proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(True, proof.indices, proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5, list(proof.indices), proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5, (1, 3.0), proof.siblings), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5, proof.indices, list(proof.siblings)), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion(entries, MerkleMultiProof(5, proof.indices, (proof.siblings[0], "x")), root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([(1, "beta"), (3, b"delta")], proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([(True, b"beta"), (3, b"delta")], proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([(1, b"beta", b"x"), (3, b"delta")], proof, root)
        with self.assertRaises(TypeError):
            verify_multi_inclusion([b"ab", (3, b"delta")], proof, root)

    def test_inputs_are_not_mutated(self):
        leaves = list(self.LEAVES)
        indices = [1, 3]
        entries = self.entries(indices)
        proof = prove_multi_inclusion(leaves, indices)
        verify_multi_inclusion(entries, proof, merkle_root(leaves))
        self.assertEqual(leaves, self.LEAVES)
        self.assertEqual(indices, [1, 3])
        self.assertEqual(entries, [(1, b"beta"), (3, b"delta")])

    def test_list_entries_and_tuple_indices_accepted(self):
        root = merkle_root(self.LEAVES)
        proof = prove_multi_inclusion(tuple(self.LEAVES), (0, 2, 4))
        entries = [[0, b"alpha"], [2, b"gamma"], [4, b"epsilon"]]
        self.assertTrue(verify_multi_inclusion(entries, proof, root))


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
