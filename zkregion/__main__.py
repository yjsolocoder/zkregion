"""Self-contained demo: python3 -m zkregion"""

from __future__ import annotations

import dataclasses

from . import (
    BoundConsistencyBatch,
    BoundConsistencyChainBatch,
    BoundConsistencyChainReplayGuard,
    BoundConsistencyReplayGuard,
    BoundRangeBatch,
    BoundRegionBatch,
    BoundRegionReplayGuard,
    BoundRangeReplayGuard,
    BoundSchnorrBatch,
    BoundSchnorrReplayGuard,
    MerkleConsistencyBatchEntry,
    MerkleConsistencyBatchReplayGuard,
    MerkleConsistencyChain,
    MerkleConsistencyChainBatchReplayGuard,
    MerkleConsistencyChainReplayGuard,
    MerkleConsistencyReplayGuard,
    MerkleMultiProof,
    MultiSchnorrEntry,
    RangeBatchEntry,
    RangeBatchReplayGuard,
    RangeProof,
    RangeReplayGuard,
    Region,
    RegionBatchEntry,
    RegionBatchReplayGuard,
    RegionProof,
    RegionReplayGuard,
    ReplayBinding,
    ReplayGuard,
    SchnorrBatchEntry,
    SchnorrBatchReplayGuard,
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
    SingleKeyBatchGuard,
    SingleKeyBoundBatch,
    SingleKeyBoundReplayGuard,
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
    verify_consistency_batch,
    verify_consistency_batch_bound,
    verify_consistency_chain_batch,
    verify_consistency_chain_batch_bound,
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


def counter_randbelow():
    state = {"value": 7}

    def randbelow(upper: int) -> int:
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


def main() -> int:
    print("commitment:")
    commitment, nonce = commit(b"payload")
    print(f"  commitment={commitment.hex()[:32]}…  open={verify_opening(commitment, b'payload', nonce)}")
    print(f"  wrong value opens: {verify_opening(commitment, b'other', nonce)}")

    coordinate, coordinate_nonce = commit_coordinate(-73, 40)
    print(f"  coordinate opens: {verify_opening(coordinate, b'-73:40', coordinate_nonce)}")

    print()
    print("Pedersen commitment (quantized range):")
    lower, upper = 0, 100
    commitment, blinding = pedersen_commit(40, lower, upper, blinding=1000)
    print(f"  element={commitment.element}  blinding={blinding}  h={commitment.h}")
    print(f"  honest opening accepted: {verify_pedersen_opening(commitment, 40, blinding)}")
    print(f"  wrong value rejected: {not verify_pedersen_opening(commitment, 41, blinding)}")
    print(f"  wrong blinding rejected: {not verify_pedersen_opening(commitment, 40, blinding + 1)}")
    print(f"  out-of-range value rejected: {not verify_pedersen_opening(commitment, 101, blinding)}")
    # default h = g**2 has a publicly known discrete log: the same commitment
    # opens at (value + 2, blinding - 1), so it is not binding — demo only.
    forged_value, forged_blinding = 42, blinding - 1
    print(
        f"  trapdoor: same element also opens at ({forged_value}, {forged_blinding}): "
        f"{verify_pedersen_opening(commitment, forged_value, forged_blinding)}"
    )
    print("  (default h = g**2 breaks binding; demonstration only, not a range proof)")

    print()
    print("Pedersen non-interactive range proof (Schnorr OR):")
    range_proof = prove_range(commitment, 40, blinding, context=b"demo")
    print(f"  branches={len(range_proof.t)}  (one per integer in [{lower}, {upper}])")
    print(f"  valid proof accepted: {verify_range(commitment, range_proof, context=b'demo')}")
    print(f"  wrong context rejected: {not verify_range(commitment, range_proof)}")
    tampered = RangeProof(
        range_proof.t,
        range_proof.e,
        range_proof.s[:-1] + (range_proof.s[-1] + 1,),
    )
    print(f"  tampered response rejected: {not verify_range(commitment, tampered, context=b'demo')}")
    other, other_r = pedersen_commit(41, lower, upper, blinding=1001)
    print(f"  foreign commitment rejected: {not verify_range(other, range_proof, context=b'demo')}")
    print("  (Schnorr OR over the demo group; demonstration-level security only)")

    print()
    print("batch range verification (random linear combination per (prime, generator, h)):")
    range_entries = []
    for value in (10, 40, 90):
        bc, bc_r = pedersen_commit(value, lower, upper, blinding=1000 + value)
        bp = prove_range(bc, value, bc_r, context=b"batch")
        range_entries.append(RangeBatchEntry(bc, bp, b"batch"))
    print(f"  valid batch of {len(range_entries)} accepted: "
          f"{verify_range_batch(range_entries, randbelow=counter_randbelow())}")
    print(f"  duplicate entries accepted: "
          f"{verify_range_batch(range_entries + range_entries[:1], randbelow=counter_randbelow())}")
    print(f"  empty batch rejected: {not verify_range_batch(())}")
    forged = RangeProof(
        range_entries[0].proof.t,
        range_entries[0].proof.e,
        range_entries[0].proof.s[:-1] + (range_entries[0].proof.s[-1] + 1,),
    )
    tampered = [RangeBatchEntry(range_entries[0].commitment, forged, b"batch")] + range_entries[1:]
    print(f"  tampered batch rejected: {not verify_range_batch(tampered, randbelow=counter_randbelow())}")

    print()
    print("Merkle-committed range batch (root check, then batch verification):")

    def bound_range_leaf(entry: RangeBatchEntry) -> bytes:
        items = [b"zkregion/range-bound/v1"]
        c = entry.commitment
        items += [str(v).encode("ascii")
                  for v in (c.element, c.lower, c.upper, c.prime, c.generator, c.h)]
        items.append(entry.context)
        for seq in (entry.proof.t, entry.proof.e, entry.proof.s):
            items.append(str(len(seq)).encode("ascii"))
            items += [str(v).encode("ascii") for v in seq]
        return b"".join(len(item).to_bytes(4, "big") + item for item in items)

    range_leaves = [bound_range_leaf(entry) for entry in range_entries]
    range_root = merkle_root(range_leaves)
    range_multi = prove_multi_inclusion(range_leaves, tuple(range(len(range_entries))))
    range_bound = BoundRangeBatch(tuple(range_entries), len(range_entries), range_multi)
    print(f"  entries={len(range_entries)}  complete index coverage 0..{len(range_entries) - 1}")
    print(f"  valid bound batch accepted: {verify_range_bound(range_bound, range_root, randbelow=counter_randbelow())}")
    print(f"  wrong root rejected: {not verify_range_bound(range_bound, merkle_root(range_leaves[:1]))}")
    forged_range = RangeProof(
        range_entries[0].proof.t,
        range_entries[0].proof.e,
        range_entries[0].proof.s[:-1] + (range_entries[0].proof.s[-1] + 1,),
    )
    committed_entry = dataclasses.replace(range_entries[0], proof=forged_range)
    forged_entries = [committed_entry, *range_entries[1:]]
    forged_leaves = [bound_range_leaf(entry) for entry in forged_entries]
    forged_proof = prove_multi_inclusion(forged_leaves, tuple(range(len(forged_entries))))
    forged_bound = BoundRangeBatch(tuple(forged_entries), len(forged_entries), forged_proof)
    print(
        "  committed-but-forged proof rejected: "
        f"{not verify_range_bound(forged_bound, merkle_root(forged_leaves), randbelow=counter_randbelow())}"
    )

    print()
    print("2-D region membership proof (two range proofs, one per axis):")
    region = Region(0, 100, 0, 100)
    x_commitment, x_blinding = pedersen_commit(40, region.min_x, region.max_x, blinding=1000)
    y_commitment, y_blinding = pedersen_commit(60, region.min_y, region.max_y, blinding=2000)
    region_proof = prove_region(
        x_commitment, y_commitment, 40, 60, x_blinding, y_blinding, region, context=b"demo"
    )
    print(f"  x branches={len(region_proof.x_proof.t)}  y branches={len(region_proof.y_proof.t)}")
    print(f"  valid proof accepted: {verify_region(x_commitment, y_commitment, region, region_proof, context=b'demo')}")
    print(f"  wrong context rejected: {not verify_region(x_commitment, y_commitment, region, region_proof)}")
    other_region = Region(0, 100, 0, 99)
    print(f"  wrong region rejected: {not verify_region(x_commitment, y_commitment, other_region, region_proof, context=b'demo')}")
    swapped = RegionProof(x_proof=region_proof.y_proof, y_proof=region_proof.x_proof)
    print(f"  swapped axes rejected: {not verify_region(x_commitment, y_commitment, region, swapped, context=b'demo')}")
    print("  (verifier needs only the commitments, the region and the proof)")

    print()
    print("batch region verification (random linear combination per (prime, generator, h)):")
    batch_region = Region(0, 100, 0, 100)
    batch_entries = []
    for x, y in ((40, 60), (10, 90), (100, 0)):
        bx, bx_r = pedersen_commit(x, 0, 100, blinding=1000 + x)
        by, by_r = pedersen_commit(y, 0, 100, blinding=2000 + y)
        bp = prove_region(bx, by, x, y, bx_r, by_r, batch_region, context=b"batch")
        batch_entries.append(RegionBatchEntry(bx, by, batch_region, bp, b"batch"))
    print(f"  valid batch of {len(batch_entries)} accepted: "
          f"{verify_region_batch(batch_entries, randbelow=counter_randbelow())}")
    print(f"  duplicate entries accepted: "
          f"{verify_region_batch(batch_entries + batch_entries[:1], randbelow=counter_randbelow())}")
    print(f"  empty batch rejected: {not verify_region_batch(())}")
    forged = RegionProof(
        RangeProof(
            batch_entries[0].proof.x_proof.t,
            batch_entries[0].proof.x_proof.e,
            batch_entries[0].proof.x_proof.s[:-1]
            + (batch_entries[0].proof.x_proof.s[-1] + 1,),
        ),
        batch_entries[0].proof.y_proof,
    )
    tampered = [RegionBatchEntry(
        batch_entries[0].x_commitment, batch_entries[0].y_commitment,
        batch_region, forged, b"batch",
    )] + batch_entries[1:]
    print(f"  tampered batch rejected: {not verify_region_batch(tampered, randbelow=counter_randbelow())}")
    wrong_context = [RegionBatchEntry(
        e.x_commitment, e.y_commitment, e.region, e.proof, b"other"
    ) for e in batch_entries[:1]]
    print(f"  wrong context rejected: {not verify_region_batch(wrong_context, randbelow=counter_randbelow())}")

    print()
    print("Merkle-committed region batch (root check, then batch sub-proofs):")

    def bound_region_leaf(entry: RegionBatchEntry) -> bytes:
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

    region_leaves = [bound_region_leaf(entry) for entry in batch_entries]
    region_root = merkle_root(region_leaves)
    region_proof = prove_multi_inclusion(region_leaves, tuple(range(len(batch_entries))))
    region_bound = BoundRegionBatch(tuple(batch_entries), len(batch_entries), region_proof)
    print(f"  entries={len(batch_entries)}  complete index coverage 0..{len(batch_entries) - 1}")
    print(f"  valid bound batch accepted: {verify_region_bound(region_bound, region_root, randbelow=counter_randbelow())}")
    print(f"  wrong root rejected: {not verify_region_bound(region_bound, merkle_root(region_leaves[:1]))}")
    committed_entry = dataclasses.replace(
        batch_entries[0],
        proof=RegionProof(
            RangeProof(
                batch_entries[0].proof.x_proof.t,
                batch_entries[0].proof.x_proof.e,
                batch_entries[0].proof.x_proof.s[:-1]
                + (batch_entries[0].proof.x_proof.s[-1] + 1,),
            ),
            batch_entries[0].proof.y_proof,
        ),
    )
    forged_entries = [committed_entry, *batch_entries[1:]]
    forged_leaves = [bound_region_leaf(entry) for entry in forged_entries]
    forged_proof = prove_multi_inclusion(forged_leaves, tuple(range(len(forged_entries))))
    forged_bound = BoundRegionBatch(tuple(forged_entries), len(forged_entries), forged_proof)
    print(
        "  committed-but-forged sub-proof rejected: "
        f"{not verify_region_bound(forged_bound, merkle_root(forged_leaves), randbelow=counter_randbelow())}"
    )

    print()
    print("interactive Schnorr:")
    prover = SchnorrProver(secret=0xDEADBEEF, randbelow=counter_randbelow())
    verifier = SchnorrVerifier(prover.public_key)
    t = prover.new_commitment()
    challenge = 0x123456789
    response = prover.respond(challenge)
    print(f"  public={prover.public_key}  commitment={t}")
    print(f"  valid response accepted: {verifier.verify(t, challenge, response)}")
    print(f"  tampered response rejected: {verifier.verify(t, challenge, response + 1)}")

    print()
    print("non-interactive Schnorr (Fiat-Shamir):")
    proof = prover.prove(b"payload", context=b"demo")
    print(f"  proof commitment={proof.commitment}")
    print(f"  valid proof accepted: {verifier.verify_proof(b'payload', proof, context=b'demo')}")
    print(f"  wrong message rejected: {verifier.verify_proof(b'other', proof, context=b'demo')}")
    print(f"  wrong context rejected: {verifier.verify_proof(b'payload', proof)}")

    print()
    print("batch Fiat-Shamir verification (same public key):")
    batch = [
        SchnorrBatchEntry(b"alpha", prover.prove(b"alpha", context=b"batch"), context=b"batch"),
        SchnorrBatchEntry(b"beta", prover.prove(b"beta", context=b"batch"), context=b"batch"),
    ]
    print(f"  valid batch accepted: {verifier.verify_batch(batch, randbelow=counter_randbelow())}")
    print(f"  duplicate entries accepted: {verifier.verify_batch(batch + batch[:1], randbelow=counter_randbelow())}")
    print(f"  empty batch rejected: {not verifier.verify_batch(())}")
    forged = SchnorrProof(batch[0].proof.commitment, batch[0].proof.response + 1)
    tampered = [SchnorrBatchEntry(b"alpha", forged, context=b"batch"), batch[1]]
    print(f"  tampered batch rejected: {not verifier.verify_batch(tampered, randbelow=counter_randbelow())}")

    print()
    print("multi-key batch Fiat-Shamir verification (entries carry their own key/group):")
    other = SchnorrProver(secret=8888, prime=104729, generator=5, randbelow=counter_randbelow())
    multi_batch = [
        MultiSchnorrEntry(
            prover.public_key, b"alpha", prover.prove(b"alpha", context=b"multi"),
            b"multi",
        ),
        MultiSchnorrEntry(
            other.public_key, b"beta", other.prove(b"beta", context=b"multi"),
            b"multi", 104729, 5,
        ),
    ]
    print(f"  mixed-key/mixed-group batch accepted: "
          f"{verify_schnorr_batch(multi_batch, randbelow=counter_randbelow())}")
    print(f"  duplicate entries accepted: "
          f"{verify_schnorr_batch(multi_batch + multi_batch[:1], randbelow=counter_randbelow())}")
    print(f"  empty batch rejected: {not verify_schnorr_batch(())}")
    forged = SchnorrProof(multi_batch[0].proof.commitment, multi_batch[0].proof.response + 1)
    tampered = [MultiSchnorrEntry(multi_batch[0].public_key, b"alpha", forged, b"multi"),
                multi_batch[1]]
    print(f"  tampered batch rejected: {not verify_schnorr_batch(tampered, randbelow=counter_randbelow())}")

    print()
    print("Merkle-committed Schnorr batch (root check, then batch signatures):")

    def enc(value: int) -> bytes:
        return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

    def bound_leaf(entry: MultiSchnorrEntry) -> bytes:
        items = (
            b"zkregion/schnorr-fs/v1",
            enc(entry.prime),
            enc(entry.generator),
            enc(entry.public_key),
            enc(entry.proof.commitment),
            entry.context,
            entry.message,
            enc(entry.proof.response),
        )
        return b"".join(len(item).to_bytes(4, "big") + item for item in items)

    bound_leaves = [bound_leaf(entry) for entry in multi_batch]
    bound_root = merkle_root(bound_leaves)
    bound_proof = prove_multi_inclusion(bound_leaves, tuple(range(len(multi_batch))))
    bound_batch = BoundSchnorrBatch(tuple(multi_batch), len(multi_batch), bound_proof)
    print(f"  entries={len(multi_batch)}  complete index coverage 0..{len(multi_batch) - 1}")
    print(f"  valid bound batch accepted: {verify_bound(bound_batch, bound_root, randbelow=counter_randbelow())}")
    print(f"  wrong root rejected: {not verify_bound(bound_batch, merkle_root(bound_leaves[:1]))}")
    committed = dataclasses.replace(
        multi_batch[0],
        proof=SchnorrProof(multi_batch[0].proof.commitment, multi_batch[0].proof.response + 1),
    )
    forged_leaves = [bound_leaf(committed)] + bound_leaves[1:]
    forged_proof = prove_multi_inclusion(forged_leaves, tuple(range(len(multi_batch))))
    forged_batch = BoundSchnorrBatch((committed, *multi_batch[1:]), len(multi_batch), forged_proof)
    print(
        "  committed-but-forged response rejected: "
        f"{not verify_bound(forged_batch, merkle_root(forged_leaves), randbelow=counter_randbelow())}"
    )

    print()
    print("Merkle-committed same-key Schnorr batch (verifier fixes the key/group):")
    single_batch = [
        SchnorrBatchEntry(b"alpha", prover.prove(b"alpha", context=b"same"), context=b"same"),
        SchnorrBatchEntry(b"beta", prover.prove(b"beta", context=b"same"), context=b"same"),
    ]
    single_leaves = [
        bound_leaf(
            MultiSchnorrEntry(
                verifier.public_key, entry.message, entry.proof, entry.context
            )
        )
        for entry in single_batch
    ]
    single_root = merkle_root(single_leaves)
    single_proof = prove_multi_inclusion(single_leaves, tuple(range(len(single_batch))))
    single_bound = SingleKeyBoundBatch(
        tuple(single_batch), len(single_batch), single_proof
    )
    print(f"  entries={len(single_batch)}  complete index coverage 0..{len(single_batch) - 1}")
    print(
        "  valid bound batch accepted: "
        f"{verifier.verify_bound_batch(single_bound, single_root, randbelow=counter_randbelow())}"
    )
    print(
        "  wrong root rejected: "
        f"{not verifier.verify_bound_batch(single_bound, merkle_root(single_leaves[:1]))}"
    )
    committed = dataclasses.replace(
        single_batch[0],
        proof=SchnorrProof(single_batch[0].proof.commitment, single_batch[0].proof.response + 1),
    )
    forged_leaves = [
        bound_leaf(MultiSchnorrEntry(verifier.public_key, committed.message, committed.proof, committed.context))
    ] + single_leaves[1:]
    forged_proof = prove_multi_inclusion(forged_leaves, tuple(range(len(single_batch))))
    forged_single = SingleKeyBoundBatch(
        (committed, *single_batch[1:]), len(single_batch), forged_proof
    )
    print(
        "  committed-but-forged response rejected: "
        f"{not verifier.verify_bound_batch(forged_single, merkle_root(forged_leaves), randbelow=counter_randbelow())}"
    )

    print()
    print("merkle inclusion proofs:")
    leaves = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
    root = merkle_root(leaves)
    proof = prove_inclusion(leaves, 2)
    print(f"  root={root.hex()[:32]}…  leaves={len(leaves)}  path depth={len(proof.siblings)}")
    print(f"  valid proof accepted: {verify_inclusion(b'gamma', proof, root)}")
    print(f"  tampered leaf rejected: {not verify_inclusion(b'other', proof, root)}")
    shifted = prove_inclusion(leaves, 3)
    print(f"  wrong index rejected: {not verify_inclusion(b'gamma', shifted, root)}")
    print(f"  wrong root rejected: {not verify_inclusion(b'gamma', proof, merkle_root(leaves[:-1]))}")

    print()
    print("merkle multi-inclusion proofs:")
    indices = (0, 2, 4)
    multi = prove_multi_inclusion(leaves, indices)
    entries = [(index, leaves[index]) for index in indices]
    print(f"  indices={indices}  siblings={len(multi.siblings)}  leaf_count={multi.leaf_count}")
    print(f"  valid proof accepted: {verify_multi_inclusion(entries, multi, root)}")
    tampered = [(0, b"other"), (2, b"gamma"), (4, b"epsilon")]
    print(f"  tampered leaf rejected: {not verify_multi_inclusion(tampered, multi, root)}")
    reordered = [entries[1], entries[0], entries[2]]
    print(f"  misordered entries rejected: {not verify_multi_inclusion(reordered, multi, root)}")
    full = prove_multi_inclusion(leaves, range(len(leaves)))
    print(f"  full-leaf proof needs no siblings: {full.siblings == ()}")
    print(f"  full-leaf proof accepted: {verify_multi_inclusion(list(enumerate(leaves)), full, root)}")

    print()
    print("independent Merkle consistency batch verification:")
    batch_leaves = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon", b"zeta"]
    consistency_entries = []
    for old_count in (1, 3, 5):
        consistency_entries.append(MerkleConsistencyBatchEntry(
            merkle_root(batch_leaves[:old_count]),
            merkle_root(batch_leaves),
            prove_consistency(batch_leaves, old_count),
        ))
    print(f"  valid batch of {len(consistency_entries)} independent pairs accepted: "
          f"{verify_consistency_batch(consistency_entries)}")
    print(f"  tuple and duplicate entries accepted: "
          f"{verify_consistency_batch(tuple(consistency_entries) + tuple(consistency_entries[:1]))}")
    print(f"  empty batch rejected: {not verify_consistency_batch(())}")
    last_node = consistency_entries[0].proof.nodes[-1]
    tampered_node = bytes([last_node[0] ^ 1]) + last_node[1:]
    tampered = [dataclasses.replace(
        consistency_entries[0],
        proof=dataclasses.replace(
            consistency_entries[0].proof,
            nodes=consistency_entries[0].proof.nodes[:-1] + (tampered_node,),
        ),
    )] + consistency_entries[1:]
    print(f"  tampered entry rejected: {not verify_consistency_batch(tampered)}")
    # entries are independent: counts need not chain to their neighbours
    unordered = [consistency_entries[2], consistency_entries[0], consistency_entries[1]]
    print(f"  non-adjacent, reordered counts accepted: {verify_consistency_batch(unordered)}")

    print()
    print("Merkle-committed complete consistency batch verification:")

    def bound_consistency_leaf(entry: MerkleConsistencyBatchEntry) -> bytes:
        proof = entry.proof
        items = [
            b"zkregion/consistency-bound/v1",
            entry.old_root,
            entry.new_root,
            str(proof.old_count).encode("ascii"),
            str(proof.new_count).encode("ascii"),
        ]
        items.extend(proof.nodes)
        return b"".join(len(item).to_bytes(4, "big") + item for item in items)

    consistency_bound_leaves = [
        bound_consistency_leaf(entry) for entry in consistency_entries
    ]
    consistency_bound_root = merkle_root(consistency_bound_leaves)
    consistency_bound_proof = prove_multi_inclusion(
        consistency_bound_leaves, tuple(range(len(consistency_bound_leaves)))
    )
    consistency_bound = BoundConsistencyBatch(
        tuple(consistency_entries), len(consistency_entries), consistency_bound_proof
    )
    print("  valid bound batch accepted: "
          f"{verify_consistency_batch_bound(consistency_bound, consistency_bound_root)}")
    print("  wrong root rejected: "
          f"{not verify_consistency_batch_bound(consistency_bound, merkle_root(consistency_bound_leaves[:1]))}")
    print("  empty batch rejected: "
          f"{not verify_consistency_batch_bound(BoundConsistencyBatch((), 0, MerkleMultiProof(0, (), ())), bytes(32))}")
    gap_proof = MerkleMultiProof(
        len(consistency_entries), (0, 1, 3), consistency_bound_proof.siblings
    )
    print("  incomplete indices rejected: "
          f"{not verify_consistency_batch_bound(BoundConsistencyBatch(tuple(consistency_entries), 3, gap_proof), consistency_bound_root)}")
    forged_leaves = [bound_consistency_leaf(entry) for entry in tampered]
    forged_proof = prove_multi_inclusion(forged_leaves, tuple(range(len(forged_leaves))))
    forged_bound = BoundConsistencyBatch(
        tuple(tampered), len(tampered), forged_proof
    )
    print("  tampered entry rejected: "
          f"{not verify_consistency_batch_bound(forged_bound, merkle_root(forged_leaves))}")

    print()
    print("Merkle-committed complete consistency chain batch verification:")

    def bound_consistency_chain_leaf(chain: MerkleConsistencyChain) -> bytes:
        def frame(item: bytes) -> bytes:
            return len(item).to_bytes(4, "big") + item

        leaf = bytearray(frame(b"zkregion/consistency-chains/v1"))
        leaf += frame(str(len(chain.roots)).encode("ascii"))
        for chain_root in chain.roots:
            leaf += frame(chain_root)
        leaf += frame(str(len(chain.proofs)).encode("ascii"))
        for segment in chain.proofs:
            leaf += frame(str(segment.old_count).encode("ascii"))
            leaf += frame(str(segment.new_count).encode("ascii"))
            leaf += frame(str(len(segment.nodes)).encode("ascii"))
            for node in segment.nodes:
                leaf += frame(node)
        return bytes(leaf)

    consistency_chains = [
        prove_consistency_chain(leaves, (1, 2, 4)),
        prove_consistency_chain(leaves, (2, 4)),
    ]
    chain_bound_leaves = [
        bound_consistency_chain_leaf(chain) for chain in consistency_chains
    ]
    chain_bound_root = merkle_root(chain_bound_leaves)
    chain_bound_proof = prove_multi_inclusion(
        chain_bound_leaves, tuple(range(len(chain_bound_leaves)))
    )
    chain_bound = BoundConsistencyChainBatch(
        tuple(consistency_chains), len(consistency_chains), chain_bound_proof
    )
    print("  valid bound chain batch accepted: "
          f"{verify_consistency_chain_batch_bound(chain_bound, chain_bound_root)}")
    print("  wrong root rejected: "
          f"{not verify_consistency_chain_batch_bound(chain_bound, bytes(32))}")
    print("  empty batch rejected: "
          f"{not verify_consistency_chain_batch_bound(BoundConsistencyChainBatch((), 0, MerkleMultiProof(0, (), ())), bytes(32))}")
    chain_gap_proof = MerkleMultiProof(
        len(consistency_chains), (0, 2), chain_bound_proof.siblings
    )
    print("  incomplete indices rejected: "
          f"{not verify_consistency_chain_batch_bound(BoundConsistencyChainBatch(tuple(consistency_chains), 2, chain_gap_proof), chain_bound_root)}")
    forged_chains = [
        MerkleConsistencyChain(tuple(bytes(32) for _ in chain.roots), chain.proofs)
        for chain in consistency_chains
    ]
    forged_chain_leaves = [
        bound_consistency_chain_leaf(chain) for chain in forged_chains
    ]
    forged_chain_proof = prove_multi_inclusion(
        forged_chain_leaves, tuple(range(len(forged_chain_leaves)))
    )
    forged_chain_bound = BoundConsistencyChainBatch(
        tuple(forged_chains), len(forged_chains), forged_chain_proof
    )
    print("  invalid chain rejected: "
          f"{not verify_consistency_chain_batch_bound(forged_chain_bound, merkle_root(forged_chain_leaves))}")

    print()
    print("independent consistency chain batch verification:")
    chain_batch = [
        prove_consistency_chain(leaves, (1, 2, 4)),
        prove_consistency_chain(leaves, (2, 4)),
    ]
    print("  valid chain batch accepted: "
          f"{verify_consistency_chain_batch(chain_batch)}")
    print("  tuple and duplicate chains accepted: "
          f"{verify_consistency_chain_batch((chain_batch[0],) * 3)}")
    print("  empty batch rejected: "
          f"{not verify_consistency_chain_batch(())}")
    invalid_chain = MerkleConsistencyChain(
        tuple(bytes(32) for _ in chain_batch[0].roots), chain_batch[0].proofs
    )
    print("  invalid chain rejected: "
          f"{not verify_consistency_chain_batch([chain_batch[0], invalid_chain])}")

    print()
    print("per-instance replay protection (bind once, check once):")
    guard = ReplayGuard()
    replay_entry = MultiSchnorrEntry(
        prover.public_key, b"spend", prover.prove(b"spend", context=b"session"),
        b"session",
    )
    binding = guard.bind_once(replay_entry, b"session-id-1", expires_at=10**12)
    print(f"  digest={binding.digest.hex()[:32]}…  expires_at={binding.expires_at}")
    print(f"  valid first check accepted: {guard.check(replay_entry, binding, now=100)}")
    print(f"  replay rejected: {not guard.check(replay_entry, binding, now=101)}")
    print(f"  consumed id cannot be rebound: ", end="")
    try:
        guard.bind_once(replay_entry, b"session-id-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    pending = ReplayGuard()
    pending_binding = pending.bind_once(replay_entry, b"session-id-2", expires_at=1000)
    print(f"  expired binding (now >= expires_at) rejected: "
          f"{not pending.check(replay_entry, pending_binding, now=1000)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{pending.check(replay_entry, pending_binding, now=999)}")
    wrong_proof = dataclasses.replace(replay_entry, proof=SchnorrProof(
        replay_entry.proof.commitment, replay_entry.proof.response + 1,
    ))
    other = ReplayGuard()
    other_binding = other.bind_once(wrong_proof, b"session-id-3")
    print(f"  bad proof rejected without consuming the id: "
          f"{not other.check(wrong_proof, other_binding)}")
    fresh_binding = ReplayGuard().bind_once(replay_entry, b"x")
    print(f"  binding from another guard instance rejected: "
          f"{not other.check(replay_entry, fresh_binding)}")
    timeless_guard = ReplayGuard()
    timeless_binding = timeless_guard.bind_once(replay_entry, b"session-id-4")
    print(f"  binding without expiry (expires_at=None) accepted at any now: "
          f"{timeless_guard.check(replay_entry, timeless_binding, now=(1 << 64) - 1)}")

    print()
    print("per-instance replay protection for multi-key Schnorr batches (bind once, check once):")
    sbr = SchnorrBatchReplayGuard()
    sbr_binding = sbr.bind_once(multi_batch, b"schnorr-batch-session-1", expires_at=10**12)
    print(f"  digest={sbr_binding.digest.hex()[:32]}…  expires_at={sbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{sbr.check(multi_batch, sbr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not sbr.check(multi_batch, sbr_binding, now=101, randbelow=counter_randbelow())}")
    other_sbr = SchnorrBatchReplayGuard()
    other_sbr_binding = other_sbr.bind_once(multi_batch, b"schnorr-batch-session-2")
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_sbr.check(multi_batch[::-1], other_sbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_sbr.check(multi_batch, other_sbr_binding, now=1, randbelow=counter_randbelow())}")
    try:
        sbr.bind_once(multi_batch, b"schnorr-batch-session-1")
    except ValueError:
        print("  rebind of a consumed id rejected: True")
    else:
        print("  rebind of a consumed id rejected: False")
    foreign_sbr = SchnorrBatchReplayGuard()
    foreign_sbr_binding = foreign_sbr.bind_once(multi_batch, b"schnorr-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_sbr.check(multi_batch, foreign_sbr_binding, now=1)}")

    print()
    print("per-instance replay protection for same-key Schnorr batches (bind once, check once):")
    skbr = SingleKeyBatchGuard(prover.public_key)
    skbr_binding = skbr.bind_once(batch, b"single-key-batch-session-1", expires_at=10**12)
    print(f"  digest={skbr_binding.digest.hex()[:32]}…  expires_at={skbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{skbr.check(batch, skbr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not skbr.check(batch, skbr_binding, now=101, randbelow=counter_randbelow())}")
    other_skbr = SingleKeyBatchGuard(prover.public_key)
    other_skbr_binding = other_skbr.bind_once(batch, b"single-key-batch-session-2")
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_skbr.check(batch[::-1], other_skbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_skbr.check(batch, other_skbr_binding, now=1, randbelow=counter_randbelow())}")
    try:
        skbr.bind_once(batch, b"single-key-batch-session-1")
    except ValueError:
        print("  rebind of a consumed id rejected: True")
    else:
        print("  rebind of a consumed id rejected: False")
    wrong_key_skbr = SingleKeyBatchGuard(SchnorrProver(secret=0xC0FFEE).public_key)
    wrong_key_binding = wrong_key_skbr.bind_once(batch, b"single-key-batch-session-3")
    print(f"  batch under the wrong key rejected without consuming the id: "
          f"{not wrong_key_skbr.check(batch, wrong_key_binding, now=1, randbelow=counter_randbelow())}")

    print()
    print("per-instance replay protection for range proofs (bind once, check once):")
    range_guard = RangeReplayGuard()
    range_replay_entry = range_entries[0]
    range_binding = range_guard.bind_once(
        range_replay_entry, b"range-session-1", expires_at=10**12
    )
    print(f"  digest={range_binding.digest.hex()[:32]}…  expires_at={range_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{range_guard.check(range_replay_entry, range_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not range_guard.check(range_replay_entry, range_binding, now=101)}")
    forged_range_entry = dataclasses.replace(
        range_replay_entry,
        proof=RangeProof(
            range_replay_entry.proof.t,
            range_replay_entry.proof.e,
            range_replay_entry.proof.s[:-1] + (range_replay_entry.proof.s[-1] + 1,),
        ),
    )
    other_range = RangeReplayGuard()
    other_range_binding = other_range.bind_once(forged_range_entry, b"range-session-2")
    print(f"  bad range proof rejected without consuming the id: "
          f"{not other_range.check(forged_range_entry, other_range_binding)}")
    print(f"  binding from another guard instance rejected: "
          f"{not other_range.check(range_replay_entry, fresh_binding)}")

    print()
    print("per-instance replay protection for range batches (bind once, check once):")
    rbr = RangeBatchReplayGuard()
    rbr_binding = rbr.bind_once(range_entries, b"range-batch-session-1", expires_at=10**12)
    print(f"  digest={rbr_binding.digest.hex()[:32]}…  expires_at={rbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{rbr.check(range_entries, rbr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not rbr.check(range_entries, rbr_binding, now=101, randbelow=counter_randbelow())}")
    other_rbr = RangeBatchReplayGuard()
    other_rbr_binding = other_rbr.bind_once(range_entries, b"range-batch-session-2")
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_rbr.check(range_entries[::-1], other_rbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_rbr.check(range_entries, other_rbr_binding, now=1, randbelow=counter_randbelow())}")
    try:
        rbr.bind_once(range_entries, b"range-batch-session-1")
    except ValueError:
        print("  rebind of a consumed id rejected: True")
    else:
        print("  rebind of a consumed id rejected: False")
    foreign_rbr = RangeBatchReplayGuard()
    foreign_rbr_binding = foreign_rbr.bind_once(range_entries, b"range-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_rbr.check(range_entries, foreign_rbr_binding, now=1)}")

    print()
    print("per-instance replay protection for region batches (bind once, check once):")
    rgbr = RegionBatchReplayGuard()
    rgbr_binding = rgbr.bind_once(batch_entries, b"region-batch-session-1", expires_at=10**12)
    print(f"  digest={rgbr_binding.digest.hex()[:32]}…  expires_at={rgbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{rgbr.check(batch_entries, rgbr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not rgbr.check(batch_entries, rgbr_binding, now=101, randbelow=counter_randbelow())}")
    other_rgbr = RegionBatchReplayGuard()
    other_rgbr_binding = other_rgbr.bind_once(batch_entries, b"region-batch-session-2")
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_rgbr.check(batch_entries[::-1], other_rgbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_rgbr.check(batch_entries, other_rgbr_binding, now=1, randbelow=counter_randbelow())}")
    try:
        rgbr.bind_once(batch_entries, b"region-batch-session-1")
    except ValueError:
        print("  rebind of a consumed id rejected: True")
    else:
        print("  rebind of a consumed id rejected: False")
    foreign_rgbr = RegionBatchReplayGuard()
    foreign_rgbr_binding = foreign_rgbr.bind_once(batch_entries, b"region-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_rgbr.check(batch_entries, foreign_rgbr_binding, now=1)}")

    print()
    print("per-instance replay protection for region proofs (bind once, check once):")
    region_guard = RegionReplayGuard()
    region_replay_entry = batch_entries[0]
    region_binding = region_guard.bind_once(
        region_replay_entry, b"region-session-1", expires_at=10**12
    )
    print(f"  digest={region_binding.digest.hex()[:32]}…  expires_at={region_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{region_guard.check(region_replay_entry, region_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not region_guard.check(region_replay_entry, region_binding, now=101)}")
    other_region = RegionReplayGuard()
    bound_entry = batch_entries[1]
    other_region_binding = other_region.bind_once(bound_entry, b"region-session-2")
    forged_region_entry = dataclasses.replace(
        bound_entry,
        region=Region(0, 100, 1, 100),
    )
    print(f"  replaced region field rejected without consuming the id: "
          f"{not other_region.check(forged_region_entry, other_region_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_region.check(bound_entry, other_region_binding, now=1)}")
    print(f"  binding from another guard instance rejected: "
          f"{not other_region.check(region_replay_entry, fresh_binding)}")

    print()
    print("per-instance replay protection for bound region batches (bind once, check once):")
    brg = BoundRegionReplayGuard()
    brg_binding = brg.bind_once(region_bound, region_root, b"bound-region-session-1", expires_at=10**12)
    print(f"  digest={brg_binding.digest.hex()[:32]}…  expires_at={brg_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{brg.check(region_bound, region_root, brg_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not brg.check(region_bound, region_root, brg_binding, now=101, randbelow=counter_randbelow())}")
    other_brg = BoundRegionReplayGuard()
    other_brg_binding = other_brg.bind_once(region_bound, region_root, b"bound-region-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_brg.check(region_bound, merkle_root(region_leaves[:1]), other_brg_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_brg.check(region_bound, region_root, other_brg_binding, now=1, randbelow=counter_randbelow())}")
    foreign_brg = BoundRegionReplayGuard()
    foreign_binding = foreign_brg.bind_once(region_bound, region_root, b"bound-region-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_brg.check(region_bound, region_root, foreign_binding, now=1)}")

    print()
    print("per-instance replay protection for bound range batches (bind once, check once):")
    brr = BoundRangeReplayGuard()
    brr_binding = brr.bind_once(range_bound, range_root, b"bound-range-session-1", expires_at=10**12)
    print(f"  digest={brr_binding.digest.hex()[:32]}…  expires_at={brr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{brr.check(range_bound, range_root, brr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not brr.check(range_bound, range_root, brr_binding, now=101, randbelow=counter_randbelow())}")
    other_brr = BoundRangeReplayGuard()
    other_brr_binding = other_brr.bind_once(range_bound, range_root, b"bound-range-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_brr.check(range_bound, merkle_root(range_leaves[:1]), other_brr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_brr.check(range_bound, range_root, other_brr_binding, now=1, randbelow=counter_randbelow())}")
    foreign_brr = BoundRangeReplayGuard()
    foreign_brr_binding = foreign_brr.bind_once(range_bound, range_root, b"bound-range-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_brr.check(range_bound, range_root, foreign_brr_binding, now=1)}")

    print()
    print("per-instance replay protection for bound Schnorr batches (bind once, check once):")
    bsr = BoundSchnorrReplayGuard()
    bsr_binding = bsr.bind_once(bound_batch, bound_root, b"bound-schnorr-session-1", expires_at=10**12)
    print(f"  digest={bsr_binding.digest.hex()[:32]}…  expires_at={bsr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{bsr.check(bound_batch, bound_root, bsr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not bsr.check(bound_batch, bound_root, bsr_binding, now=101, randbelow=counter_randbelow())}")
    other_bsr = BoundSchnorrReplayGuard()
    other_bsr_binding = other_bsr.bind_once(bound_batch, bound_root, b"bound-schnorr-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_bsr.check(bound_batch, merkle_root(bound_leaves[:1]), other_bsr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_bsr.check(bound_batch, bound_root, other_bsr_binding, now=1, randbelow=counter_randbelow())}")
    foreign_bsr = BoundSchnorrReplayGuard()
    foreign_bsr_binding = foreign_bsr.bind_once(bound_batch, bound_root, b"bound-schnorr-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_bsr.check(bound_batch, bound_root, foreign_bsr_binding, now=1)}")

    print()
    print("per-instance replay protection for same-key bound Schnorr batches:")
    skbbr = SingleKeyBoundReplayGuard(verifier.public_key)
    skbbr_binding = skbbr.bind_once(single_bound, single_root, b"single-key-bound-session-1", expires_at=10**12)
    print(f"  digest={skbbr_binding.digest.hex()[:32]}…  expires_at={skbbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{skbbr.check(single_bound, single_root, skbbr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not skbbr.check(single_bound, single_root, skbbr_binding, now=101, randbelow=counter_randbelow())}")
    other_skbbr = SingleKeyBoundReplayGuard(verifier.public_key)
    other_skbbr_binding = other_skbbr.bind_once(single_bound, single_root, b"single-key-bound-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_skbbr.check(single_bound, merkle_root(single_leaves[:1]), other_skbbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_skbbr.check(single_bound, single_root, other_skbbr_binding, now=1, randbelow=counter_randbelow())}")
    foreign_skbbr = SingleKeyBoundReplayGuard(verifier.public_key)
    foreign_skbbr_binding = foreign_skbbr.bind_once(single_bound, single_root, b"single-key-bound-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_skbbr.check(single_bound, single_root, foreign_skbbr_binding, now=1)}")

    print()
    print("per-instance replay protection for consistency chains (bind once, check once):")
    chain = prove_consistency_chain(leaves, (1, 2, 4))
    mccr = MerkleConsistencyChainReplayGuard()
    mccr_binding = mccr.bind_once(chain, b"chain-session-1", expires_at=10**12)
    print(f"  digest={mccr_binding.digest.hex()[:32]}…  expires_at={mccr_binding.expires_at}")
    print(f"  valid first check accepted: {mccr.check(chain, mccr_binding, now=100)}")
    print(f"  replay rejected: {not mccr.check(chain, mccr_binding, now=101)}")
    other_mccr = MerkleConsistencyChainReplayGuard()
    other_mccr_binding = other_mccr.bind_once(chain, b"chain-session-2")
    tampered_chain = prove_consistency_chain(leaves, (1, 2, 3))
    print(f"  different chain rejected without consuming the id: "
          f"{not other_mccr.check(tampered_chain, other_mccr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mccr.check(chain, other_mccr_binding, now=1)}")
    foreign_mccr = MerkleConsistencyChainReplayGuard()
    foreign_mccr_binding = foreign_mccr.bind_once(chain, b"chain-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mccr.check(chain, foreign_mccr_binding, now=1)}")

    print()
    print("per-instance replay protection for consistency chain batches (bind once, check once):")
    mccbr = MerkleConsistencyChainBatchReplayGuard()
    mccbr_binding = mccbr.bind_once(chain_batch, b"chain-batch-session-1", expires_at=10**12)
    print(f"  digest={mccbr_binding.digest.hex()[:32]}…  expires_at={mccbr_binding.expires_at}")
    print(f"  valid first check accepted: {mccbr.check(chain_batch, mccbr_binding, now=100)}")
    print(f"  replay rejected: {not mccbr.check(chain_batch, mccbr_binding, now=101)}")
    other_mccbr = MerkleConsistencyChainBatchReplayGuard()
    other_mccbr_binding = other_mccbr.bind_once(chain_batch, b"chain-batch-session-2")
    print(f"  shortened batch rejected without consuming the id: "
          f"{not other_mccbr.check(chain_batch[:-1], other_mccbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mccbr.check(chain_batch, other_mccbr_binding, now=1)}")
    try:
        mccbr.bind_once(chain_batch, b"chain-batch-session-1")
    except ValueError:
        print("  rebind of a consumed id rejected: True")
    else:
        print("  rebind of a consumed id rejected: False")
    foreign_mccbr = MerkleConsistencyChainBatchReplayGuard()
    foreign_mccbr_binding = foreign_mccbr.bind_once(chain_batch, b"chain-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mccbr.check(chain_batch, foreign_mccbr_binding, now=1)}")

    print()
    print("per-instance replay protection for single consistency proofs (bind once, check once):")
    old_root = merkle_root(leaves[:2])
    new_root = merkle_root(leaves)
    consistency = prove_consistency(leaves, 2)
    mcr = MerkleConsistencyReplayGuard()
    mcr_binding = mcr.bind_once(old_root, new_root, consistency, b"consistency-session-1", expires_at=10**12)
    print(f"  digest={mcr_binding.digest.hex()[:32]}…  expires_at={mcr_binding.expires_at}")
    print(f"  valid first check accepted: {mcr.check(old_root, new_root, consistency, mcr_binding, now=100)}")
    print(f"  replay rejected: {not mcr.check(old_root, new_root, consistency, mcr_binding, now=101)}")
    other_mcr = MerkleConsistencyReplayGuard()
    other_mcr_binding = other_mcr.bind_once(old_root, new_root, consistency, b"consistency-session-2")
    wrong_root = merkle_root(leaves[:3])
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_mcr.check(old_root, wrong_root, consistency, other_mcr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mcr.check(old_root, new_root, consistency, other_mcr_binding, now=1)}")
    foreign_mcr = MerkleConsistencyReplayGuard()
    foreign_mcr_binding = foreign_mcr.bind_once(old_root, new_root, consistency, b"consistency-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mcr.check(old_root, new_root, consistency, foreign_mcr_binding, now=1)}")

    print()
    print("per-instance replay protection for consistency batches (bind once, check once):")
    mcbr = MerkleConsistencyBatchReplayGuard()
    mcbr_binding = mcbr.bind_once(consistency_entries, b"consistency-batch-session-1", expires_at=10**12)
    print(f"  digest={mcbr_binding.digest.hex()[:32]}…  expires_at={mcbr_binding.expires_at}")
    print(f"  valid first check accepted: {mcbr.check(consistency_entries, mcbr_binding, now=100)}")
    print(f"  replay rejected: {not mcbr.check(consistency_entries, mcbr_binding, now=101)}")
    other_mcbr = MerkleConsistencyBatchReplayGuard()
    other_mcbr_binding = other_mcbr.bind_once(consistency_entries, b"consistency-batch-session-2")
    print(f"  shortened batch rejected without consuming the id: "
          f"{not other_mcbr.check(consistency_entries[:-1], other_mcbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mcbr.check(consistency_entries, other_mcbr_binding, now=1)}")
    try:
        mcbr.bind_once(consistency_entries, b"consistency-batch-session-1")
    except ValueError:
        print("  rebind of a consumed id rejected: True")
    else:
        print("  rebind of a consumed id rejected: False")
    foreign_mcbr = MerkleConsistencyBatchReplayGuard()
    foreign_mcbr_binding = foreign_mcbr.bind_once(consistency_entries, b"consistency-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mcbr.check(consistency_entries, foreign_mcbr_binding, now=1)}")

    print()
    print("per-instance replay protection for bound consistency batches (bind once, check once):")
    bcbr = BoundConsistencyReplayGuard()
    bcbr_binding = bcbr.bind_once(consistency_bound, consistency_bound_root, b"bound-consistency-session-1", expires_at=10**12)
    print(f"  digest={bcbr_binding.digest.hex()[:32]}…  expires_at={bcbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{bcbr.check(consistency_bound, consistency_bound_root, bcbr_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not bcbr.check(consistency_bound, consistency_bound_root, bcbr_binding, now=101)}")
    other_bcbr = BoundConsistencyReplayGuard()
    other_bcbr_binding = other_bcbr.bind_once(consistency_bound, consistency_bound_root, b"bound-consistency-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_bcbr.check(consistency_bound, merkle_root(consistency_bound_leaves[:1]), other_bcbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_bcbr.check(consistency_bound, consistency_bound_root, other_bcbr_binding, now=1)}")
    foreign_bcbr = BoundConsistencyReplayGuard()
    foreign_bcbr_binding = foreign_bcbr.bind_once(consistency_bound, consistency_bound_root, b"bound-consistency-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_bcbr.check(consistency_bound, consistency_bound_root, foreign_bcbr_binding, now=1)}")

    print()
    print("per-instance replay protection for bound consistency chain batches (bind once, check once):")
    bccbr = BoundConsistencyChainReplayGuard()
    bccbr_binding = bccbr.bind_once(chain_bound, chain_bound_root, b"bound-consistency-chain-session-1", expires_at=10**12)
    print(f"  digest={bccbr_binding.digest.hex()[:32]}…  expires_at={bccbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{bccbr.check(chain_bound, chain_bound_root, bccbr_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not bccbr.check(chain_bound, chain_bound_root, bccbr_binding, now=101)}")
    other_bccbr = BoundConsistencyChainReplayGuard()
    other_bccbr_binding = other_bccbr.bind_once(chain_bound, chain_bound_root, b"bound-consistency-chain-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_bccbr.check(chain_bound, bytes(32), other_bccbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_bccbr.check(chain_bound, chain_bound_root, other_bccbr_binding, now=1)}")
    foreign_bccbr = BoundConsistencyChainReplayGuard()
    foreign_bccbr_binding = foreign_bccbr.bind_once(chain_bound, chain_bound_root, b"bound-consistency-chain-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_bccbr.check(chain_bound, chain_bound_root, foreign_bccbr_binding, now=1)}")

    print()
    print("region membership:")
    region = Region(0, 100, 0, 100)
    print(f"  region size {region.width()}x{region.height()}")
    for x, y in ((50, 50), (0, 0), (100, 100), (101, 50), (-1, 50)):
        print(f"  contains({x:>4}, {y:>4}) = {region.contains(x, y)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
