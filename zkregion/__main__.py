"""Self-contained demo: python3 -m zkregion"""

from __future__ import annotations

import dataclasses
import os
import tempfile
import threading

from . import (
    BoundConsistencyBatch,
    BoundConsistencyChainBatch,
    BoundConsistencyChainReplayGuard,
    BoundConsistencyReplayGuard,
    BoundMerkleInclusionBatch,
    BoundMerkleInclusionBatchReplayGuard,
    BoundMerkleMultiBatch,
    BoundMerkleMultiBatchReplayGuard,
    BoundRangeBatch,
    BoundRegionBatch,
    BoundRegionReplayGuard,
    BoundRegionWideReplayGuard,
    BoundRangeReplayGuard,
    BoundSchnorrBatch,
    BoundSchnorrReplayGuard,
    BoundWideRangeReplayGuard,
    MerkleConsistencyBatchEntry,
    MerkleConsistencyBatchReplayGuard,
    MerkleConsistencyChain,
    MerkleConsistencyChainBatchReplayGuard,
    MerkleConsistencyChainReplayGuard,
    MerkleConsistencyReplayGuard,
    MerkleInclusionBatchEntry,
    MerkleInclusionBatchReplayGuard,
    MerkleMultiBatchEntry,
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
    RegionWideBatchEntry,
    RegionWideBatchReplayGuard,
    RegionWideReplayGuard,
    ReplayBinding,
    ReplayGuard,
    SchnorrBatchEntry,
    SchnorrBatchReplayGuard,
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
    SQLiteReplayStore,
    SingleKeyBatchGuard,
    SingleKeyBoundBatch,
    SingleKeyBoundReplayGuard,
    WideRangeBatchEntry,
    WideRangeBatchReplayGuard,
    WideRangeProof,
    WideRangeReplayGuard,
    commit,
    commit_coordinate,
    merkle_root,
    pedersen_commit,
    prove_consistency,
    prove_consistency_chain,
    prove_inclusion,
    prove_multi_inclusion,
    prove_range,
    prove_range_wide,
    prove_range_wide_batch_bound,
    prove_region,
    prove_region_wide,
    prove_region_wide_batch_bound,
    verify_bound,
    verify_consistency_batch,
    verify_consistency_batch_bound,
    verify_consistency_chain_batch,
    verify_consistency_chain_batch_bound,
    verify_inclusion,
    verify_inclusion_batch,
    verify_inclusion_batch_bound,
    verify_multi_inclusion,
    verify_multi_inclusion_batch_bound,
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
    commitment, nonce = commit(b"payload", nonce=b"zkregion-demo-01")
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
    range_proof = prove_range(commitment, 40, blinding, context=b"demo", randbelow=counter_randbelow())
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
        bp = prove_range(bc, value, bc_r, context=b"batch", randbelow=counter_randbelow())
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
        x_commitment, y_commitment, 40, 60, x_blinding, y_blinding, region, context=b"demo",
        randbelow=counter_randbelow(),
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
        bp = prove_region(bx, by, x, y, bx_r, by_r, batch_region, context=b"batch",
                          randbelow=counter_randbelow())
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
    print(f"  tampered response rejected: {not verifier.verify(t, challenge, response + 1)}")

    print()
    print("non-interactive Schnorr (Fiat-Shamir):")
    proof = prover.prove(b"payload", context=b"demo")
    print(f"  proof commitment={proof.commitment}")
    print(f"  valid proof accepted: {verifier.verify_proof(b'payload', proof, context=b'demo')}")
    print(f"  wrong message rejected: {not verifier.verify_proof(b'other', proof, context=b'demo')}")
    print(f"  wrong context rejected: {not verifier.verify_proof(b'payload', proof)}")

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
    print("independent single-leaf Merkle inclusion batch verification:")
    batch_inclusion_leaves = [b"one", b"two", b"three", b"four"]
    batch_inclusion_root = merkle_root(batch_inclusion_leaves)
    inclusion_entries = [
        MerkleInclusionBatchEntry(b"gamma", prove_inclusion(leaves, 2), root),
        MerkleInclusionBatchEntry(
            b"four", prove_inclusion(batch_inclusion_leaves, 3), batch_inclusion_root
        ),
    ]
    print(f"  valid batch of {len(inclusion_entries)} independent entries accepted: "
          f"{verify_inclusion_batch(inclusion_entries)}")
    print(f"  tuple and duplicate entries accepted: "
          f"{verify_inclusion_batch(tuple(inclusion_entries) + tuple(inclusion_entries[:1]))}")
    print(f"  empty batch rejected: {not verify_inclusion_batch(())}")
    tampered_inclusion = [
        MerkleInclusionBatchEntry(b"other", inclusion_entries[0].proof, root),
        inclusion_entries[1],
    ]
    print(f"  tampered entry rejected: {not verify_inclusion_batch(tampered_inclusion)}")

    print()
    print("Merkle-committed complete single-leaf inclusion batch verification:")

    def bound_inclusion_leaf(entry: MerkleInclusionBatchEntry) -> bytes:
        def frame(item: bytes) -> bytes:
            return len(item).to_bytes(4, "big") + item

        def u64(value: int) -> bytes:
            return value.to_bytes(8, "big")

        proof = entry.proof
        q = bytearray()
        q += frame(entry.leaf)
        q += frame(entry.root)
        q += frame(u64(proof.index))
        q += frame(u64(len(proof.siblings)))
        for sibling in proof.siblings:
            q += frame(sibling)
        return frame(b"zkregion/inclusion-batch/v1") + frame(bytes(q))

    inclusion_bound_leaves = [
        bound_inclusion_leaf(entry) for entry in inclusion_entries
    ]
    inclusion_bound_root = merkle_root(inclusion_bound_leaves)
    inclusion_bound_proof = prove_multi_inclusion(
        inclusion_bound_leaves, tuple(range(len(inclusion_bound_leaves)))
    )
    inclusion_bound = BoundMerkleInclusionBatch(
        tuple(inclusion_entries), len(inclusion_entries), inclusion_bound_proof
    )
    print("  valid bound batch accepted: "
          f"{verify_inclusion_batch_bound(inclusion_bound, inclusion_bound_root)}")
    print("  wrong root rejected: "
          f"{not verify_inclusion_batch_bound(inclusion_bound, merkle_root(inclusion_bound_leaves[:1]))}")
    print("  empty batch rejected: "
          f"{not verify_inclusion_batch_bound(BoundMerkleInclusionBatch((), 0, MerkleMultiProof(0, (), ())), bytes(32))}")
    gap_proof = MerkleMultiProof(
        len(inclusion_entries), (1,), inclusion_bound_proof.siblings
    )
    print("  incomplete indices rejected: "
          f"{not verify_inclusion_batch_bound(BoundMerkleInclusionBatch(tuple(inclusion_entries), len(inclusion_entries), gap_proof), inclusion_bound_root)}")
    forged_inclusion_leaves = [
        bound_inclusion_leaf(entry) for entry in tampered_inclusion
    ]
    forged_inclusion_proof = prove_multi_inclusion(
        forged_inclusion_leaves, tuple(range(len(forged_inclusion_leaves)))
    )
    forged_inclusion_bound = BoundMerkleInclusionBatch(
        tuple(tampered_inclusion), len(tampered_inclusion), forged_inclusion_proof
    )
    print("  tampered entry rejected: "
          f"{not verify_inclusion_batch_bound(forged_inclusion_bound, merkle_root(forged_inclusion_leaves))}")

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
    print("per-instance replay protection for inclusion batches (bind once, check once):")
    mibr = MerkleInclusionBatchReplayGuard()
    mibr_binding = mibr.bind_once(inclusion_entries, b"inclusion-batch-session-1", expires_at=10**12)
    print(f"  digest={mibr_binding.digest.hex()[:32]}…  expires_at={mibr_binding.expires_at}")
    print(f"  valid first check accepted: {mibr.check(inclusion_entries, mibr_binding, now=100)}")
    print(f"  replay rejected: {not mibr.check(inclusion_entries, mibr_binding, now=101)}")
    other_mibr = MerkleInclusionBatchReplayGuard()
    other_mibr_binding = other_mibr.bind_once(inclusion_entries, b"inclusion-batch-session-2")
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_mibr.check(inclusion_entries[::-1], other_mibr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mibr.check(inclusion_entries, other_mibr_binding, now=1)}")
    try:
        mibr.bind_once(inclusion_entries, b"inclusion-batch-session-1")
    except ValueError:
        print("  rebind of a consumed id rejected: True")
    else:
        print("  rebind of a consumed id rejected: False")
    foreign_mibr = MerkleInclusionBatchReplayGuard()
    foreign_mibr_binding = foreign_mibr.bind_once(inclusion_entries, b"inclusion-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mibr.check(inclusion_entries, foreign_mibr_binding, now=1)}")

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
    print("per-instance replay protection for bound Merkle multi-inclusion batches (bind once, check once):")

    def bound_multi_batch_leaf(item: MerkleMultiBatchEntry) -> bytes:
        def frame(value: bytes) -> bytes:
            return len(value).to_bytes(4, "big") + value

        def u64(value: int) -> bytes:
            return value.to_bytes(8, "big")

        q = bytearray()
        q += frame(item.root)
        q += frame(u64(item.proof.leaf_count))
        q += frame(u64(len(item.proof.indices)))
        for index in item.proof.indices:
            q += frame(u64(index))
        q += frame(u64(len(item.entries)))
        for index, leaf in item.entries:
            q += frame(frame(u64(index)) + frame(leaf))
        q += frame(u64(len(item.proof.siblings)))
        for sibling in item.proof.siblings:
            q += frame(sibling)
        return frame(b"zkregion/multi-batch/v1") + frame(bytes(q))

    bmmbr_tree_leaves = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
    bmmbr_tree_root = merkle_root(bmmbr_tree_leaves)
    bmmbr_items = [
        MerkleMultiBatchEntry(
            tuple((i, bmmbr_tree_leaves[i]) for i in (0, 2, 4)),
            prove_multi_inclusion(bmmbr_tree_leaves, (0, 2, 4)),
            bmmbr_tree_root,
        ),
        MerkleMultiBatchEntry(
            ((1, bmmbr_tree_leaves[1]),),
            prove_multi_inclusion(bmmbr_tree_leaves, (1,)),
            bmmbr_tree_root,
        ),
    ]
    bmmbr_leaves = [bound_multi_batch_leaf(item) for item in bmmbr_items]
    bmmbr_root = merkle_root(bmmbr_leaves)
    bmmbr_bound = BoundMerkleMultiBatch(
        tuple(bmmbr_items),
        len(bmmbr_items),
        prove_multi_inclusion(bmmbr_leaves, tuple(range(len(bmmbr_items)))),
    )
    bmmbr = BoundMerkleMultiBatchReplayGuard()
    bmmbr_binding = bmmbr.bind_once(bmmbr_bound, bmmbr_root, b"bound-multi-batch-session-1", expires_at=10**12)
    print(f"  digest={bmmbr_binding.digest.hex()[:32]}…  expires_at={bmmbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{bmmbr.check(bmmbr_bound, bmmbr_root, bmmbr_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not bmmbr.check(bmmbr_bound, bmmbr_root, bmmbr_binding, now=101)}")
    other_bmmbr = BoundMerkleMultiBatchReplayGuard()
    other_bmmbr_binding = other_bmmbr.bind_once(bmmbr_bound, bmmbr_root, b"bound-multi-batch-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_bmmbr.check(bmmbr_bound, bytes(32), other_bmmbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_bmmbr.check(bmmbr_bound, bmmbr_root, other_bmmbr_binding, now=1)}")
    foreign_bmmbr = BoundMerkleMultiBatchReplayGuard()
    foreign_bmmbr_binding = foreign_bmmbr.bind_once(bmmbr_bound, bmmbr_root, b"bound-multi-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_bmmbr.check(bmmbr_bound, bmmbr_root, foreign_bmmbr_binding, now=1)}")

    print()
    print("per-instance replay protection for bound inclusion batches (bind once, check once):")
    bmibr = BoundMerkleInclusionBatchReplayGuard()
    bmibr_binding = bmibr.bind_once(inclusion_bound, inclusion_bound_root, b"bound-inclusion-batch-session-1", expires_at=10**12)
    print(f"  digest={bmibr_binding.digest.hex()[:32]}…  expires_at={bmibr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{bmibr.check(inclusion_bound, inclusion_bound_root, bmibr_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not bmibr.check(inclusion_bound, inclusion_bound_root, bmibr_binding, now=101)}")
    other_bmibr = BoundMerkleInclusionBatchReplayGuard()
    other_bmibr_binding = other_bmibr.bind_once(inclusion_bound, inclusion_bound_root, b"bound-inclusion-batch-session-2")
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_bmibr.check(inclusion_bound, merkle_root(inclusion_bound_leaves[:1]), other_bmibr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_bmibr.check(inclusion_bound, inclusion_bound_root, other_bmibr_binding, now=1)}")
    foreign_bmibr = BoundMerkleInclusionBatchReplayGuard()
    foreign_bmibr_binding = foreign_bmibr.bind_once(inclusion_bound, inclusion_bound_root, b"bound-inclusion-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_bmibr.check(inclusion_bound, inclusion_bound_root, foreign_bmibr_binding, now=1)}")

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

    print()
    print("per-instance replay protection for wide 2-D region entries (bind once, check once):")
    wide_region = Region(0, 255, -2048, 2047)
    wx, wx_r = pedersen_commit(40, wide_region.min_x, wide_region.max_x, blinding=1234)
    wy, wy_r = pedersen_commit(60, wide_region.min_y, wide_region.max_y, blinding=4321)
    wide_proof = prove_region_wide(
        wx, wy, 40, 60, wx_r, wy_r, wide_region, b"wide-demo",
        randbelow=counter_randbelow(),
    )
    wide_entry = RegionWideBatchEntry(wx, wy, wide_region, wide_proof, b"wide-demo")
    wx2, wx2_r = pedersen_commit(7, wide_region.min_x, wide_region.max_x, blinding=777)
    wy2, wy2_r = pedersen_commit(-5, wide_region.min_y, wide_region.max_y, blinding=888)
    wide_proof2 = prove_region_wide(
        wx2, wy2, 7, -5, wx2_r, wy2_r, wide_region, b"wide-demo",
        randbelow=counter_randbelow(),
    )
    wide_entry2 = RegionWideBatchEntry(wx2, wy2, wide_region, wide_proof2, b"wide-demo")
    wide_entries = [wide_entry, wide_entry2]
    print(f"  entry: region x=[{wide_region.min_x}, {wide_region.max_x}] "
          f"y=[{wide_region.min_y}, {wide_region.max_y}]  context={wide_entry.context!r}")
    rwr = RegionWideReplayGuard()
    rwr_binding = rwr.bind_once(wide_entry, b"region-wide-session-1", expires_at=10**12)
    print(f"  session_id={rwr_binding.session_id!r}  digest={rwr_binding.digest.hex()[:32]}…  "
          f"expires_at={rwr_binding.expires_at}")
    print(f"  valid first check accepted: {rwr.check(wide_entry, rwr_binding, now=100)}")
    print(f"  replay rejected: {not rwr.check(wide_entry, rwr_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        rwr.bind_once(wide_entry, b"region-wide-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_rwr = RegionWideReplayGuard()
    other_rwr_binding = other_rwr.bind_once(wide_entry, b"region-wide-session-2")
    swapped_entry = dataclasses.replace(wide_entry, context=b"other")
    print(f"  replaced entry rejected without consuming the id: "
          f"{not other_rwr.check(swapped_entry, other_rwr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_rwr.check(wide_entry, other_rwr_binding, now=1)}")
    foreign_rwr = RegionWideReplayGuard()
    foreign_rwr_binding = foreign_rwr.bind_once(wide_entry, b"region-wide-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_rwr.check(wide_entry, foreign_rwr_binding, now=1)}")
    fresh_rwr = RegionWideReplayGuard()
    fresh_rwr.bind_once(wide_entry, b"region-wide-pending")
    print("  rebind of a pending id: ", end="")
    try:
        fresh_rwr.bind_once(wide_entry, b"region-wide-pending")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  empty session id: ", end="")
    try:
        fresh_rwr.bind_once(wide_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_rwr.bind_once(wide_entry, b"region-wide-session-4", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_rwr.bind_once("not-an-entry", b"region-wide-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("per-instance replay protection for wide 2-D region entry batches (bind once, check once):")
    rwbr = RegionWideBatchReplayGuard()
    rwbr_binding = rwbr.bind_once(wide_entries, b"region-wide-batch-session-1", expires_at=10**12)
    print(f"  batch: {len(wide_entries)} entries  session_id={rwbr_binding.session_id!r}  "
          f"digest={rwbr_binding.digest.hex()[:32]}…  expires_at={rwbr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{rwbr.check(wide_entries, rwbr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not rwbr.check(wide_entries, rwbr_binding, now=101, randbelow=counter_randbelow())}")
    other_rwbr = RegionWideBatchReplayGuard()
    other_rwbr_binding = other_rwbr.bind_once(wide_entries, b"region-wide-batch-session-2")
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_rwbr.check(wide_entries[::-1], other_rwbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_rwbr.check(wide_entries, other_rwbr_binding, now=1, randbelow=counter_randbelow())}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        rwbr.bind_once(wide_entries, b"region-wide-batch-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    foreign_rwbr = RegionWideBatchReplayGuard()
    foreign_rwbr_binding = foreign_rwbr.bind_once(wide_entries, b"region-wide-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_rwbr.check(wide_entries, foreign_rwbr_binding, now=1)}")
    fresh_rwbr = RegionWideBatchReplayGuard()
    print("  empty batch: ", end="")
    try:
        fresh_rwbr.bind_once([], b"region-wide-batch-session-4")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  empty session id: ", end="")
    try:
        fresh_rwbr.bind_once(wide_entries, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_rwbr.bind_once(wide_entries, b"region-wide-batch-session-5", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_rwbr.bind_once("not-a-batch", b"region-wide-batch-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("per-instance replay protection for bound wide 2-D region batches (bind once, check once):")
    wide_bound, wide_bound_root = prove_region_wide_batch_bound(
        wide_entries, randbelow=counter_randbelow()
    )
    print(f"  entries={len(wide_entries)}  complete index coverage 0..{len(wide_entries) - 1}")
    brwr = BoundRegionWideReplayGuard()
    brwr_binding = brwr.bind_once(
        wide_bound, wide_bound_root, b"bound-region-wide-session-1", expires_at=10**12
    )
    print(f"  session_id={brwr_binding.session_id!r}  digest={brwr_binding.digest.hex()[:32]}…  "
          f"expires_at={brwr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{brwr.check(wide_bound, wide_bound_root, brwr_binding, now=100, randbelow=counter_randbelow())}")
    print(f"  replay rejected: "
          f"{not brwr.check(wide_bound, wide_bound_root, brwr_binding, now=101, randbelow=counter_randbelow())}")
    other_brwr = BoundRegionWideReplayGuard()
    other_brwr_binding = other_brwr.bind_once(
        wide_bound, wide_bound_root, b"bound-region-wide-session-2"
    )
    wrong_wide_root = prove_region_wide_batch_bound(
        wide_entries[:1], randbelow=counter_randbelow()
    )[1]
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_brwr.check(wide_bound, wrong_wide_root, other_brwr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_brwr.check(wide_bound, wide_bound_root, other_brwr_binding, now=1, randbelow=counter_randbelow())}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        brwr.bind_once(wide_bound, wide_bound_root, b"bound-region-wide-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    foreign_brwr = BoundRegionWideReplayGuard()
    foreign_brwr_binding = foreign_brwr.bind_once(
        wide_bound, wide_bound_root, b"bound-region-wide-session-3"
    )
    print(f"  binding from another guard instance rejected: "
          f"{not other_brwr.check(wide_bound, wide_bound_root, foreign_brwr_binding, now=1)}")
    fresh_brwr = BoundRegionWideReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_brwr.bind_once(wide_bound, wide_bound_root, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_brwr.bind_once(
            wide_bound, wide_bound_root, b"bound-region-wide-session-4", expires_at=1 << 64
        )
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_brwr.bind_once("not-a-batch", wide_bound_root, b"bound-region-wide-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one wide-region id (at most one winner):")
    race_rwr = RegionWideReplayGuard()
    race_binding = race_rwr.bind_once(wide_entry, b"region-wide-race", expires_at=10**12)
    race_results = []
    race_lock = threading.Lock()

    def race_attempt():
        outcome = race_rwr.check(wide_entry, race_binding, now=100)
        with race_lock:
            race_results.append(outcome)

    race_threads = [threading.Thread(target=race_attempt) for _ in range(8)]
    for thread in race_threads:
        thread.start()
    for thread in race_threads:
        thread.join()
    race_wins = sum(race_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_wins} succeeded, {len(race_results) - race_wins} rejected")

    print()
    print("SQLite-backed wide-region replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_a = RegionWideReplayGuard(store=store)
        persist_binding = persist_a.bind_once(
            wide_entry, b"region-wide-persist", expires_at=10**12
        )
        print(f"  valid first check accepted: "
              f"{persist_a.check(wide_entry, persist_binding, now=100)}")
        persist_b = RegionWideReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_b.check(wide_entry, persist_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_c = RegionWideReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_c.check(wide_entry, persist_binding, now=100)}")
        reopened.close()

    print()
    print("concurrent checks of one wide-region batch id (at most one winner):")
    race_rwbr = RegionWideBatchReplayGuard()
    race_rwbr_binding = race_rwbr.bind_once(
        wide_entries, b"region-wide-batch-race", expires_at=10**12
    )
    print(f"  session_id={race_rwbr_binding.session_id!r}  "
          f"digest={race_rwbr_binding.digest.hex()[:32]}…  "
          f"expires_at={race_rwbr_binding.expires_at}")
    race_rwbr_results = []
    race_rwbr_lock = threading.Lock()

    def race_rwbr_attempt():
        outcome = race_rwbr.check(
            wide_entries, race_rwbr_binding, now=100, randbelow=counter_randbelow()
        )
        with race_rwbr_lock:
            race_rwbr_results.append(outcome)

    race_rwbr_threads = [threading.Thread(target=race_rwbr_attempt) for _ in range(8)]
    for thread in race_rwbr_threads:
        thread.start()
    for thread in race_rwbr_threads:
        thread.join()
    race_rwbr_wins = sum(race_rwbr_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_rwbr_wins} succeeded, {len(race_rwbr_results) - race_rwbr_wins} rejected")

    print()
    print("concurrent checks of one bound wide-region batch id (at most one winner):")
    race_brwr = BoundRegionWideReplayGuard()
    race_brwr_binding = race_brwr.bind_once(
        wide_bound, wide_bound_root, b"bound-region-wide-batch-race", expires_at=10**12
    )
    print(f"  session_id={race_brwr_binding.session_id!r}  "
          f"digest={race_brwr_binding.digest.hex()[:32]}…  "
          f"expires_at={race_brwr_binding.expires_at}")
    race_brwr_results = []
    race_brwr_lock = threading.Lock()

    def race_brwr_attempt():
        outcome = race_brwr.check(
            wide_bound, wide_bound_root, race_brwr_binding,
            now=100, randbelow=counter_randbelow(),
        )
        with race_brwr_lock:
            race_brwr_results.append(outcome)

    race_brwr_threads = [threading.Thread(target=race_brwr_attempt) for _ in range(8)]
    for thread in race_brwr_threads:
        thread.start()
    for thread in race_brwr_threads:
        thread.join()
    race_brwr_wins = sum(race_brwr_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_brwr_wins} succeeded, {len(race_brwr_results) - race_brwr_wins} rejected")

    print()
    print("SQLite-backed wide-region batch replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_rwbr_a = RegionWideBatchReplayGuard(store=store)
        persist_rwbr_binding = persist_rwbr_a.bind_once(
            wide_entries, b"region-wide-batch-persist", expires_at=10**12
        )
        print(f"  session_id={persist_rwbr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_rwbr_a.check(wide_entries, persist_rwbr_binding, now=100, randbelow=counter_randbelow())}")
        persist_rwbr_b = RegionWideBatchReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_rwbr_b.check(wide_entries, persist_rwbr_binding, now=100, randbelow=counter_randbelow())}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_rwbr_c = RegionWideBatchReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_rwbr_c.check(wide_entries, persist_rwbr_binding, now=100, randbelow=counter_randbelow())}")
        reopened.close()

    print()
    print("SQLite-backed bound wide-region batch replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_brwr_a = BoundRegionWideReplayGuard(store=store)
        persist_brwr_binding = persist_brwr_a.bind_once(
            wide_bound, wide_bound_root, b"bound-region-wide-batch-persist", expires_at=10**12
        )
        print(f"  session_id={persist_brwr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_brwr_a.check(wide_bound, wide_bound_root, persist_brwr_binding, now=100, randbelow=counter_randbelow())}")
        persist_brwr_b = BoundRegionWideReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_brwr_b.check(wide_bound, wide_bound_root, persist_brwr_binding, now=100, randbelow=counter_randbelow())}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_brwr_c = BoundRegionWideReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_brwr_c.check(wide_bound, wide_bound_root, persist_brwr_binding, now=100, randbelow=counter_randbelow())}")
        reopened.close()

    print()
    print("wide range proofs, batch entries and a bound complete batch (public entry points):")
    wr_lower, wr_upper = 0, (1 << 24) - 1
    wr_entries = []
    for wr_value in (40, 100000):
        wr_commitment, wr_blinding = pedersen_commit(
            wr_value, wr_lower, wr_upper, blinding=31000 + wr_value
        )
        wr_proof = prove_range_wide(
            wr_commitment, wr_value, wr_blinding, b"wide-range-demo",
            randbelow=counter_randbelow(),
        )
        wr_entries.append(WideRangeBatchEntry(wr_commitment, wr_proof, b"wide-range-demo"))
    wr_entry = wr_entries[0]
    wr_bound, wr_outer_root = prove_range_wide_batch_bound(
        wr_entries, randbelow=counter_randbelow()
    )
    print(f"  declared range [{wr_lower}, {wr_upper}]  "
          f"{len(wr_entries)} non-empty batch entries")
    print(f"  single entry context={wr_entry.context!r}  "
          f"bit commitments per proof={len(wr_entry.proof.commitments)}")
    print(f"  complete batch plus outer Merkle root from the public constructor: "
          f"{wr_outer_root.hex()[:32]}…")

    print()
    print("concurrent checks of one wide range id (at most one winner):")
    race_wr = WideRangeReplayGuard()
    race_wr_binding = race_wr.bind_once(
        wr_entry, b"wide-range-race", expires_at=10**12
    )
    print(f"  session_id={race_wr_binding.session_id!r}  "
          f"digest={race_wr_binding.digest.hex()[:32]}…  "
          f"expires_at={race_wr_binding.expires_at}")
    race_wr_results = []
    race_wr_lock = threading.Lock()

    def race_wr_attempt():
        outcome = race_wr.check(wr_entry, race_wr_binding, now=100)
        with race_wr_lock:
            race_wr_results.append(outcome)

    race_wr_threads = [threading.Thread(target=race_wr_attempt) for _ in range(8)]
    for thread in race_wr_threads:
        thread.start()
    for thread in race_wr_threads:
        thread.join()
    race_wr_wins = sum(race_wr_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_wr_wins} succeeded, {len(race_wr_results) - race_wr_wins} rejected")
    print("  consumed id cannot be rebound: ", end="")
    try:
        race_wr.bind_once(wr_entry, b"wide-range-race")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    fresh_wr = WideRangeReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_wr.bind_once(wr_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_wr.bind_once(wr_entry, b"wide-range-session-1", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_wr.bind_once("not-an-entry", b"wide-range-session-2")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_wr_entry = dataclasses.replace(
        wr_entry, commitment=dataclasses.replace(wr_entry.commitment, lower=True)
    )
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_wr.bind_once(bool_wr_entry, b"wide-range-session-3")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("SQLite-backed wide range replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_wr_a = WideRangeReplayGuard(store=store)
        persist_wr_binding = persist_wr_a.bind_once(
            wr_entry, b"wide-range-persist", expires_at=10**12
        )
        print(f"  session_id={persist_wr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_wr_a.check(wr_entry, persist_wr_binding, now=100)}")
        persist_wr_b = WideRangeReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_wr_b.check(wr_entry, persist_wr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_wr_c = WideRangeReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_wr_c.check(wr_entry, persist_wr_binding, now=100)}")
        reopened.close()

    print()
    print("concurrent checks of one wide range batch id (at most one winner):")
    race_wbr = WideRangeBatchReplayGuard()
    race_wbr_binding = race_wbr.bind_once(
        wr_entries, b"wide-range-batch-race", expires_at=10**12
    )
    print(f"  session_id={race_wbr_binding.session_id!r}  "
          f"digest={race_wbr_binding.digest.hex()[:32]}…  "
          f"expires_at={race_wbr_binding.expires_at}")
    race_wbr_results = []
    race_wbr_lock = threading.Lock()

    def race_wbr_attempt():
        outcome = race_wbr.check(
            wr_entries, race_wbr_binding, now=100, randbelow=counter_randbelow()
        )
        with race_wbr_lock:
            race_wbr_results.append(outcome)

    race_wbr_threads = [threading.Thread(target=race_wbr_attempt) for _ in range(8)]
    for thread in race_wbr_threads:
        thread.start()
    for thread in race_wbr_threads:
        thread.join()
    race_wbr_wins = sum(race_wbr_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_wbr_wins} succeeded, {len(race_wbr_results) - race_wbr_wins} rejected")
    print("  consumed id cannot be rebound: ", end="")
    try:
        race_wbr.bind_once(wr_entries, b"wide-range-batch-race")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    fresh_wbr = WideRangeBatchReplayGuard()
    print("  empty batch: ", end="")
    try:
        fresh_wbr.bind_once([], b"wide-range-batch-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  empty session id: ", end="")
    try:
        fresh_wbr.bind_once(wr_entries, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_wbr.bind_once(wr_entries, b"wide-range-batch-session-2", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_wbr.bind_once("not-a-batch", b"wide-range-batch-session-3")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_wbr_entry = dataclasses.replace(
        wr_entry, proof=WideRangeProof(
            wr_entry.proof.commitments,
            ((True, False),) + wr_entry.proof.challenges[1:],
            wr_entry.proof.responses,
        )
    )
    print("  boolean posing as a nested proof integer: ", end="")
    try:
        fresh_wbr.bind_once([bool_wbr_entry], b"wide-range-batch-session-4")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one bound wide range batch id (at most one winner):")
    race_bwr = BoundWideRangeReplayGuard()
    race_bwr_binding = race_bwr.bind_once(
        wr_bound, wr_outer_root, b"bound-wide-range-race", expires_at=10**12
    )
    print(f"  session_id={race_bwr_binding.session_id!r}  "
          f"digest={race_bwr_binding.digest.hex()[:32]}…  "
          f"expires_at={race_bwr_binding.expires_at}")
    race_bwr_results = []
    race_bwr_lock = threading.Lock()

    def race_bwr_attempt():
        outcome = race_bwr.check(
            wr_bound, wr_outer_root, race_bwr_binding,
            now=100, randbelow=counter_randbelow(),
        )
        with race_bwr_lock:
            race_bwr_results.append(outcome)

    race_bwr_threads = [threading.Thread(target=race_bwr_attempt) for _ in range(8)]
    for thread in race_bwr_threads:
        thread.start()
    for thread in race_bwr_threads:
        thread.join()
    race_bwr_wins = sum(race_bwr_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_bwr_wins} succeeded, {len(race_bwr_results) - race_bwr_wins} rejected")
    print("  consumed id cannot be rebound: ", end="")
    try:
        race_bwr.bind_once(wr_bound, wr_outer_root, b"bound-wide-range-race")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    fresh_bwr = BoundWideRangeReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_bwr.bind_once(wr_bound, wr_outer_root, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_bwr.bind_once(
            wr_bound, wr_outer_root, b"bound-wide-range-session-1", expires_at=1 << 64
        )
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_bwr.bind_once("not-a-batch", wr_outer_root, b"bound-wide-range-session-2")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("SQLite-backed wide range batch replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_wbr_a = WideRangeBatchReplayGuard(store=store)
        persist_wbr_binding = persist_wbr_a.bind_once(
            wr_entries, b"wide-range-batch-persist", expires_at=10**12
        )
        print(f"  session_id={persist_wbr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_wbr_a.check(wr_entries, persist_wbr_binding, now=100, randbelow=counter_randbelow())}")
        persist_wbr_b = WideRangeBatchReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_wbr_b.check(wr_entries, persist_wbr_binding, now=100, randbelow=counter_randbelow())}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_wbr_c = WideRangeBatchReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_wbr_c.check(wr_entries, persist_wbr_binding, now=100, randbelow=counter_randbelow())}")
        reopened.close()

    print()
    print("SQLite-backed bound wide range batch replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_bwr_a = BoundWideRangeReplayGuard(store=store)
        persist_bwr_binding = persist_bwr_a.bind_once(
            wr_bound, wr_outer_root, b"bound-wide-range-persist", expires_at=10**12
        )
        print(f"  session_id={persist_bwr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_bwr_a.check(wr_bound, wr_outer_root, persist_bwr_binding, now=100, randbelow=counter_randbelow())}")
        persist_bwr_b = BoundWideRangeReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_bwr_b.check(wr_bound, wr_outer_root, persist_bwr_binding, now=100, randbelow=counter_randbelow())}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_bwr_c = BoundWideRangeReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_bwr_c.check(wr_bound, wr_outer_root, persist_bwr_binding, now=100, randbelow=counter_randbelow())}")
        reopened.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
