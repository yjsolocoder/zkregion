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
    BoundRegionContainsBatch,
    BoundRegionContainsReplayGuard,
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
    MerkleConsistencyEntryReplayGuard,
    MerkleConsistencyReplayGuard,
    MerkleInclusionBatchEntry,
    MerkleInclusionBatchReplayGuard,
    MerkleInclusionEntryReplayGuard,
    MerkleMultiBatchEntry,
    MerkleMultiBatchReplayGuard,
    MerkleMultiEntryReplayGuard,
    MerkleMultiProof,
    MerkleMultiReplayGuard,
    MultiSchnorrEntry,
    OpeningBatchEntry,
    OpeningBatchReplayGuard,
    OpeningReplayGuard,
    PedersenOpeningBatchEntry,
    PedersenOpeningBatchReplayGuard,
    PedersenOpeningReplayGuard,
    RangeBatchEntry,
    RangeBatchReplayGuard,
    RangeProof,
    RangeReplayGuard,
    Region,
    RegionBatchEntry,
    RegionBatchReplayGuard,
    RegionContainsBatchReplayGuard,
    RegionContainsEntry,
    RegionContainsReplayGuard,
    RegionProof,
    RegionReplayGuard,
    RegionWideBatchEntry,
    RegionWideBatchReplayGuard,
    RegionWideProof,
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
    SingleKeyEntryReplayGuard,
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
    prove_region_contains_bound,
    prove_region_wide,
    prove_region_wide_batch_bound,
    region_contains_committed,
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
    verify_region_contains_batch,
    verify_region_contains_bound,
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
    bool_rwr_entry = dataclasses.replace(
        wide_entry, x_commitment=dataclasses.replace(wx, h=True)
    )
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_rwr.bind_once(bool_rwr_entry, b"region-wide-session-6")
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
    bool_rwbr_entry = dataclasses.replace(
        wide_entry,
        proof=RegionWideProof(
            WideRangeProof(
                wide_entry.proof.x_proof.commitments,
                ((True, False),) + wide_entry.proof.x_proof.challenges[1:],
                wide_entry.proof.x_proof.responses,
            ),
            wide_entry.proof.y_proof,
        ),
    )
    print("  boolean posing as a nested proof integer: ", end="")
    try:
        fresh_rwbr.bind_once([bool_rwbr_entry], b"region-wide-batch-session-7")
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
    bool_brwr_batch = dataclasses.replace(wide_bound, leaf_count=True)
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_brwr.bind_once(
            bool_brwr_batch, wide_bound_root, b"bound-region-wide-session-6"
        )
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

    print()
    print("per-instance replay protection for hash-commitment openings (bind once, check once):")
    opening_commitment, opening_nonce = commit(
        b"opening-payload", nonce=b"zkregion-demo-opening-01"
    )
    opening_entry = OpeningBatchEntry(opening_commitment, b"opening-payload", opening_nonce)
    print(f"  entry: value={opening_entry.value!r}  opening verifies: "
          f"{verify_opening(opening_entry.commitment, opening_entry.value, opening_entry.nonce)}")
    ogr = OpeningReplayGuard()
    ogr_binding = ogr.bind_once(opening_entry, b"opening-session-1", expires_at=10**12)
    print(f"  session_id={ogr_binding.session_id!r}  digest={ogr_binding.digest.hex()[:32]}…  "
          f"expires_at={ogr_binding.expires_at}")
    print(f"  valid first check accepted: {ogr.check(opening_entry, ogr_binding, now=100)}")
    print(f"  replay rejected: {not ogr.check(opening_entry, ogr_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        ogr.bind_once(opening_entry, b"opening-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_opening_commitment, other_opening_nonce = commit(
        b"other-payload", nonce=b"zkregion-demo-opening-02"
    )
    other_opening_entry = OpeningBatchEntry(
        other_opening_commitment, b"other-payload", other_opening_nonce
    )
    other_ogr = OpeningReplayGuard()
    other_ogr_binding = other_ogr.bind_once(other_opening_entry, b"opening-session-2")
    print(f"  replaced entry rejected without consuming the id: "
          f"{not other_ogr.check(opening_entry, other_ogr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_ogr.check(other_opening_entry, other_ogr_binding, now=1)}")
    foreign_ogr = OpeningReplayGuard()
    foreign_ogr_binding = foreign_ogr.bind_once(opening_entry, b"opening-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_ogr.check(opening_entry, foreign_ogr_binding, now=1)}")
    fresh_ogr = OpeningReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_ogr.bind_once(opening_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_ogr.bind_once(opening_entry, b"opening-session-4", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_ogr.bind_once("not-an-entry", b"opening-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  wrong field type: ", end="")
    try:
        fresh_ogr.bind_once(
            OpeningBatchEntry(opening_commitment, b"opening-payload", 42),
            b"opening-session-6",
        )
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one hash-opening id (at most one winner):")
    race_ogr = OpeningReplayGuard()
    race_ogr_binding = race_ogr.bind_once(opening_entry, b"opening-race", expires_at=10**12)
    race_ogr_results = []
    race_ogr_lock = threading.Lock()

    def race_ogr_attempt():
        outcome = race_ogr.check(opening_entry, race_ogr_binding, now=100)
        with race_ogr_lock:
            race_ogr_results.append(outcome)

    race_ogr_threads = [threading.Thread(target=race_ogr_attempt) for _ in range(8)]
    for thread in race_ogr_threads:
        thread.start()
    for thread in race_ogr_threads:
        thread.join()
    race_ogr_wins = sum(race_ogr_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_ogr_wins} succeeded, {len(race_ogr_results) - race_ogr_wins} rejected")

    print()
    print("SQLite-backed hash-opening replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_ogr_a = OpeningReplayGuard(store=store)
        persist_ogr_binding = persist_ogr_a.bind_once(
            opening_entry, b"opening-persist", expires_at=10**12
        )
        print(f"  session_id={persist_ogr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_ogr_a.check(opening_entry, persist_ogr_binding, now=100)}")
        persist_ogr_b = OpeningReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_ogr_b.check(opening_entry, persist_ogr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_ogr_c = OpeningReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_ogr_c.check(opening_entry, persist_ogr_binding, now=100)}")
        reopened.close()

    print()
    print("per-instance replay protection for Pedersen openings (bind once, check once):")
    porg_commitment, porg_blinding = pedersen_commit(40, 0, 100, blinding=1000)
    porg_entry = PedersenOpeningBatchEntry(porg_commitment, 40, porg_blinding)
    print(f"  entry: value={porg_entry.value}  opening verifies: "
          f"{verify_pedersen_opening(porg_entry.commitment, porg_entry.value, porg_entry.blinding)}")
    porg = PedersenOpeningReplayGuard()
    porg_binding = porg.bind_once(porg_entry, b"pedersen-opening-session-1", expires_at=10**12)
    print(f"  session_id={porg_binding.session_id!r}  digest={porg_binding.digest.hex()[:32]}…  "
          f"expires_at={porg_binding.expires_at}")
    print(f"  valid first check accepted: {porg.check(porg_entry, porg_binding, now=100)}")
    print(f"  replay rejected: {not porg.check(porg_entry, porg_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        porg.bind_once(porg_entry, b"pedersen-opening-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    porg_other_commitment, porg_other_blinding = pedersen_commit(41, 0, 100, blinding=1001)
    porg_other_entry = PedersenOpeningBatchEntry(
        porg_other_commitment, 41, porg_other_blinding
    )
    other_porg = PedersenOpeningReplayGuard()
    other_porg_binding = other_porg.bind_once(porg_other_entry, b"pedersen-opening-session-2")
    print(f"  replaced entry rejected without consuming the id: "
          f"{not other_porg.check(porg_entry, other_porg_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_porg.check(porg_other_entry, other_porg_binding, now=1)}")
    foreign_porg = PedersenOpeningReplayGuard()
    foreign_porg_binding = foreign_porg.bind_once(porg_entry, b"pedersen-opening-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_porg.check(porg_entry, foreign_porg_binding, now=1)}")
    fresh_porg = PedersenOpeningReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_porg.bind_once(porg_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_porg.bind_once(porg_entry, b"pedersen-opening-session-4", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_porg.bind_once("not-an-entry", b"pedersen-opening-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_porg_entry = dataclasses.replace(porg_entry, value=True)
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_porg.bind_once(bool_porg_entry, b"pedersen-opening-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one Pedersen-opening id (at most one winner):")
    race_porg = PedersenOpeningReplayGuard()
    race_porg_binding = race_porg.bind_once(
        porg_entry, b"pedersen-opening-race", expires_at=10**12
    )
    race_porg_results = []
    race_porg_lock = threading.Lock()

    def race_porg_attempt():
        outcome = race_porg.check(porg_entry, race_porg_binding, now=100)
        with race_porg_lock:
            race_porg_results.append(outcome)

    race_porg_threads = [threading.Thread(target=race_porg_attempt) for _ in range(8)]
    for thread in race_porg_threads:
        thread.start()
    for thread in race_porg_threads:
        thread.join()
    race_porg_wins = sum(race_porg_results)
    print(f"  8 overlapping checks of the same id: "
          f"{race_porg_wins} succeeded, {len(race_porg_results) - race_porg_wins} rejected")

    print()
    print("SQLite-backed Pedersen-opening replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_porg_a = PedersenOpeningReplayGuard(store=store)
        persist_porg_binding = persist_porg_a.bind_once(
            porg_entry, b"pedersen-opening-persist", expires_at=10**12
        )
        print(f"  session_id={persist_porg_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_porg_a.check(porg_entry, persist_porg_binding, now=100)}")
        persist_porg_b = PedersenOpeningReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_porg_b.check(porg_entry, persist_porg_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_porg_c = PedersenOpeningReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_porg_c.check(porg_entry, persist_porg_binding, now=100)}")
        reopened.close()

    print()
    print("per-instance replay protection for single-leaf inclusion entries (bind once, check once):")
    se_inclusion_entry = MerkleInclusionBatchEntry(b"gamma", prove_inclusion(leaves, 2), root)
    mirr = MerkleInclusionEntryReplayGuard()
    mirr_binding = mirr.bind_once(se_inclusion_entry, b"inclusion-entry-session-1", expires_at=10**12)
    print(f"  session_id={mirr_binding.session_id!r}  digest={mirr_binding.digest.hex()[:32]}…  "
          f"expires_at={mirr_binding.expires_at}")
    print(f"  valid first check accepted: {mirr.check(se_inclusion_entry, mirr_binding, now=100)}")
    print(f"  replay rejected: {not mirr.check(se_inclusion_entry, mirr_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        mirr.bind_once(se_inclusion_entry, b"inclusion-entry-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_mirr = MerkleInclusionEntryReplayGuard()
    other_mirr_entry = MerkleInclusionBatchEntry(b"delta", prove_inclusion(leaves, 3), root)
    other_mirr_binding = other_mirr.bind_once(other_mirr_entry, b"inclusion-entry-session-2")
    print(f"  replaced entry rejected without consuming the id: "
          f"{not other_mirr.check(se_inclusion_entry, other_mirr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mirr.check(other_mirr_entry, other_mirr_binding, now=1)}")
    foreign_mirr = MerkleInclusionEntryReplayGuard()
    foreign_mirr_binding = foreign_mirr.bind_once(se_inclusion_entry, b"inclusion-entry-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mirr.check(se_inclusion_entry, foreign_mirr_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_mirr.check(se_inclusion_entry, foreign_mirr_binding, now=1)}")
    fresh_mirr = MerkleInclusionEntryReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_mirr.bind_once(se_inclusion_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_mirr.bind_once(se_inclusion_entry, b"inclusion-entry-session-4", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_mirr.bind_once("not-an-entry", b"inclusion-entry-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_mirr_entry = dataclasses.replace(
        se_inclusion_entry, proof=dataclasses.replace(se_inclusion_entry.proof, index=True)
    )
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_mirr.bind_once(bool_mirr_entry, b"inclusion-entry-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("per-instance replay protection for compact multi-inclusion entries (bind once, check once):")
    se_multi_indices = (0, 2, 4)
    se_multi_entry = MerkleMultiBatchEntry(
        tuple((index, leaves[index]) for index in se_multi_indices),
        prove_multi_inclusion(leaves, se_multi_indices),
        root,
    )
    mmer = MerkleMultiEntryReplayGuard()
    mmer_binding = mmer.bind_once(se_multi_entry, b"multi-entry-session-1", expires_at=10**12)
    print(f"  session_id={mmer_binding.session_id!r}  digest={mmer_binding.digest.hex()[:32]}…  "
          f"expires_at={mmer_binding.expires_at}")
    print(f"  valid first check accepted: {mmer.check(se_multi_entry, mmer_binding, now=100)}")
    print(f"  replay rejected: {not mmer.check(se_multi_entry, mmer_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        mmer.bind_once(se_multi_entry, b"multi-entry-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_mmer = MerkleMultiEntryReplayGuard()
    other_mmer_indices = (1, 3)
    other_mmer_entry = MerkleMultiBatchEntry(
        tuple((index, leaves[index]) for index in other_mmer_indices),
        prove_multi_inclusion(leaves, other_mmer_indices),
        root,
    )
    other_mmer_binding = other_mmer.bind_once(other_mmer_entry, b"multi-entry-session-2")
    print(f"  replaced entry rejected without consuming the id: "
          f"{not other_mmer.check(se_multi_entry, other_mmer_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mmer.check(other_mmer_entry, other_mmer_binding, now=1)}")
    foreign_mmer = MerkleMultiEntryReplayGuard()
    foreign_mmer_binding = foreign_mmer.bind_once(se_multi_entry, b"multi-entry-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mmer.check(se_multi_entry, foreign_mmer_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_mmer.check(se_multi_entry, foreign_mmer_binding, now=1)}")
    fresh_mmer = MerkleMultiEntryReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_mmer.bind_once(se_multi_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_mmer.bind_once(se_multi_entry, b"multi-entry-session-4", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_mmer.bind_once("not-an-entry", b"multi-entry-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_mmer_entry = dataclasses.replace(
        se_multi_entry, proof=dataclasses.replace(se_multi_entry.proof, leaf_count=True)
    )
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_mmer.bind_once(bool_mmer_entry, b"multi-entry-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("per-instance replay protection for single consistency entries (bind once, check once):")
    se_consistency_entry = MerkleConsistencyBatchEntry(
        merkle_root(leaves[:2]), root, prove_consistency(leaves, 2)
    )
    mcer = MerkleConsistencyEntryReplayGuard()
    mcer_binding = mcer.bind_once(se_consistency_entry, b"consistency-entry-session-1", expires_at=10**12)
    print(f"  session_id={mcer_binding.session_id!r}  digest={mcer_binding.digest.hex()[:32]}…  "
          f"expires_at={mcer_binding.expires_at}")
    print(f"  valid first check accepted: {mcer.check(se_consistency_entry, mcer_binding, now=100)}")
    print(f"  replay rejected: {not mcer.check(se_consistency_entry, mcer_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        mcer.bind_once(se_consistency_entry, b"consistency-entry-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_mcer = MerkleConsistencyEntryReplayGuard()
    other_mcer_entry = MerkleConsistencyBatchEntry(
        merkle_root(leaves[:3]), root, prove_consistency(leaves, 3)
    )
    other_mcer_binding = other_mcer.bind_once(other_mcer_entry, b"consistency-entry-session-2")
    print(f"  replaced entry rejected without consuming the id: "
          f"{not other_mcer.check(se_consistency_entry, other_mcer_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mcer.check(other_mcer_entry, other_mcer_binding, now=1)}")
    foreign_mcer = MerkleConsistencyEntryReplayGuard()
    foreign_mcer_binding = foreign_mcer.bind_once(se_consistency_entry, b"consistency-entry-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_mcer.check(se_consistency_entry, foreign_mcer_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_mcer.check(se_consistency_entry, foreign_mcer_binding, now=1)}")
    fresh_mcer = MerkleConsistencyEntryReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_mcer.bind_once(se_consistency_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_mcer.bind_once(se_consistency_entry, b"consistency-entry-session-4", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_mcer.bind_once("not-an-entry", b"consistency-entry-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_mcer_entry = dataclasses.replace(
        se_consistency_entry, proof=dataclasses.replace(se_consistency_entry.proof, old_count=True)
    )
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_mcer.bind_once(bool_mcer_entry, b"consistency-entry-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one id per single-entry guard (at most one winner each):")
    race_mirr = MerkleInclusionEntryReplayGuard()
    race_mirr_binding = race_mirr.bind_once(
        se_inclusion_entry, b"inclusion-entry-race", expires_at=10**12
    )
    race_mirr_results = []
    race_mirr_lock = threading.Lock()

    def race_mirr_attempt():
        outcome = race_mirr.check(se_inclusion_entry, race_mirr_binding, now=100)
        with race_mirr_lock:
            race_mirr_results.append(outcome)

    race_mirr_threads = [threading.Thread(target=race_mirr_attempt) for _ in range(8)]
    for thread in race_mirr_threads:
        thread.start()
    for thread in race_mirr_threads:
        thread.join()
    race_mirr_wins = sum(race_mirr_results)
    print(f"  inclusion entry, 8 overlapping checks of the same id: "
          f"{race_mirr_wins} succeeded, {len(race_mirr_results) - race_mirr_wins} rejected")
    race_mmer = MerkleMultiEntryReplayGuard()
    race_mmer_binding = race_mmer.bind_once(
        se_multi_entry, b"multi-entry-race", expires_at=10**12
    )
    race_mmer_results = []
    race_mmer_lock = threading.Lock()

    def race_mmer_attempt():
        outcome = race_mmer.check(se_multi_entry, race_mmer_binding, now=100)
        with race_mmer_lock:
            race_mmer_results.append(outcome)

    race_mmer_threads = [threading.Thread(target=race_mmer_attempt) for _ in range(8)]
    for thread in race_mmer_threads:
        thread.start()
    for thread in race_mmer_threads:
        thread.join()
    race_mmer_wins = sum(race_mmer_results)
    print(f"  multi-inclusion entry, 8 overlapping checks of the same id: "
          f"{race_mmer_wins} succeeded, {len(race_mmer_results) - race_mmer_wins} rejected")
    race_mcer = MerkleConsistencyEntryReplayGuard()
    race_mcer_binding = race_mcer.bind_once(
        se_consistency_entry, b"consistency-entry-race", expires_at=10**12
    )
    race_mcer_results = []
    race_mcer_lock = threading.Lock()

    def race_mcer_attempt():
        outcome = race_mcer.check(se_consistency_entry, race_mcer_binding, now=100)
        with race_mcer_lock:
            race_mcer_results.append(outcome)

    race_mcer_threads = [threading.Thread(target=race_mcer_attempt) for _ in range(8)]
    for thread in race_mcer_threads:
        thread.start()
    for thread in race_mcer_threads:
        thread.join()
    race_mcer_wins = sum(race_mcer_results)
    print(f"  consistency entry, 8 overlapping checks of the same id: "
          f"{race_mcer_wins} succeeded, {len(race_mcer_results) - race_mcer_wins} rejected")

    print()
    print("SQLite-backed single-entry replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_mirr_a = MerkleInclusionEntryReplayGuard(store=store)
        persist_mirr_binding = persist_mirr_a.bind_once(
            se_inclusion_entry, b"inclusion-entry-persist", expires_at=10**12
        )
        print(f"  inclusion entry session_id={persist_mirr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_mirr_a.check(se_inclusion_entry, persist_mirr_binding, now=100)}")
        persist_mirr_b = MerkleInclusionEntryReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_mirr_b.check(se_inclusion_entry, persist_mirr_binding, now=100)}")
        local_mirr = MerkleInclusionEntryReplayGuard()
        local_mirr_binding = local_mirr.bind_once(
            se_inclusion_entry, b"inclusion-entry-persist", expires_at=10**12
        )
        print(f"  in-memory instance shares nothing and accepts the same id: "
              f"{local_mirr.check(se_inclusion_entry, local_mirr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_mirr_c = MerkleInclusionEntryReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_mirr_c.check(se_inclusion_entry, persist_mirr_binding, now=100)}")
        reopened.close()
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_mmer_a = MerkleMultiEntryReplayGuard(store=store)
        persist_mmer_binding = persist_mmer_a.bind_once(
            se_multi_entry, b"multi-entry-persist", expires_at=10**12
        )
        print(f"  multi-inclusion entry session_id={persist_mmer_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_mmer_a.check(se_multi_entry, persist_mmer_binding, now=100)}")
        persist_mmer_b = MerkleMultiEntryReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_mmer_b.check(se_multi_entry, persist_mmer_binding, now=100)}")
        local_mmer = MerkleMultiEntryReplayGuard()
        local_mmer_binding = local_mmer.bind_once(
            se_multi_entry, b"multi-entry-persist", expires_at=10**12
        )
        print(f"  in-memory instance shares nothing and accepts the same id: "
              f"{local_mmer.check(se_multi_entry, local_mmer_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_mmer_c = MerkleMultiEntryReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_mmer_c.check(se_multi_entry, persist_mmer_binding, now=100)}")
        reopened.close()
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_mcer_a = MerkleConsistencyEntryReplayGuard(store=store)
        persist_mcer_binding = persist_mcer_a.bind_once(
            se_consistency_entry, b"consistency-entry-persist", expires_at=10**12
        )
        print(f"  consistency entry session_id={persist_mcer_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_mcer_a.check(se_consistency_entry, persist_mcer_binding, now=100)}")
        persist_mcer_b = MerkleConsistencyEntryReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_mcer_b.check(se_consistency_entry, persist_mcer_binding, now=100)}")
        local_mcer = MerkleConsistencyEntryReplayGuard()
        local_mcer_binding = local_mcer.bind_once(
            se_consistency_entry, b"consistency-entry-persist", expires_at=10**12
        )
        print(f"  in-memory instance shares nothing and accepts the same id: "
              f"{local_mcer.check(se_consistency_entry, local_mcer_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_mcer_c = MerkleConsistencyEntryReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_mcer_c.check(se_consistency_entry, persist_mcer_binding, now=100)}")
        reopened.close()

    print()
    print("per-instance replay protection for hash-opening batches (bind once, check once):")
    obr_items = []
    for obr_payload, obr_nonce_seed in (
        (b"opening-batch-alpha", b"zkregion-demo-opening-batch-01"),
        (b"opening-batch-beta", b"zkregion-demo-opening-batch-02"),
    ):
        obr_commitment, obr_nonce = commit(obr_payload, nonce=obr_nonce_seed)
        obr_items.append(OpeningBatchEntry(obr_commitment, obr_payload, obr_nonce))
    obr_entries = tuple(obr_items)
    print(f"  batch: {len(obr_entries)} entries  every opening verifies: "
          f"{all(verify_opening(e.commitment, e.value, e.nonce) for e in obr_entries)}")
    obr = OpeningBatchReplayGuard()
    obr_binding = obr.bind_once(obr_entries, b"opening-batch-session-1", expires_at=10**12)
    print(f"  session_id={obr_binding.session_id!r}  digest={obr_binding.digest.hex()[:32]}…  "
          f"expires_at={obr_binding.expires_at}")
    print(f"  valid first check accepted: {obr.check(obr_entries, obr_binding, now=100)}")
    print(f"  replay rejected: {not obr.check(obr_entries, obr_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        obr.bind_once(obr_entries, b"opening-batch-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_obr_items = []
    for obr_payload, obr_nonce_seed in (
        (b"opening-batch-alpha", b"zkregion-demo-opening-batch-01"),
        (b"opening-batch-other", b"zkregion-demo-opening-batch-03"),
    ):
        obr_commitment, obr_nonce = commit(obr_payload, nonce=obr_nonce_seed)
        other_obr_items.append(OpeningBatchEntry(obr_commitment, obr_payload, obr_nonce))
    other_obr_entries = tuple(other_obr_items)
    other_obr = OpeningBatchReplayGuard()
    other_obr_binding = other_obr.bind_once(other_obr_entries, b"opening-batch-session-2")
    print(f"  rebound batch rejected without consuming the id: "
          f"{not other_obr.check(obr_entries, other_obr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_obr.check(other_obr_entries, other_obr_binding, now=1)}")
    foreign_obr = OpeningBatchReplayGuard()
    foreign_obr_binding = foreign_obr.bind_once(obr_entries, b"opening-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_obr.check(obr_entries, foreign_obr_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_obr.check(obr_entries, foreign_obr_binding, now=1)}")
    fresh_obr = OpeningBatchReplayGuard()
    print("  empty batch: ", end="")
    try:
        fresh_obr.bind_once([], b"opening-batch-session-4")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  empty session id: ", end="")
    try:
        fresh_obr.bind_once(obr_entries, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_obr.bind_once(obr_entries, b"opening-batch-session-5", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_obr.bind_once("not-a-batch", b"opening-batch-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  wrong entry type: ", end="")
    try:
        fresh_obr.bind_once(["not-an-entry"], b"opening-batch-session-7")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  wrong entry-field type: ", end="")
    try:
        fresh_obr.bind_once(
            [OpeningBatchEntry(obr_entries[0].commitment, b"opening-batch-alpha", 42)],
            b"opening-batch-session-8",
        )
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  boolean posing as a bytes field: ", end="")
    try:
        fresh_obr.bind_once(
            [OpeningBatchEntry(obr_entries[0].commitment, b"opening-batch-alpha", True)],
            b"opening-batch-session-9",
        )
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one hash-opening batch id (at most one winner):")
    race_obr_items = []
    for obr_payload, obr_nonce_seed in (
        (b"opening-race-alpha", b"zkregion-demo-opening-batch-race-01"),
        (b"opening-race-beta", b"zkregion-demo-opening-batch-race-02"),
    ):
        obr_commitment, obr_nonce = commit(obr_payload, nonce=obr_nonce_seed)
        race_obr_items.append(OpeningBatchEntry(obr_commitment, obr_payload, obr_nonce))
    race_obr_entries = tuple(race_obr_items)
    race_obr = OpeningBatchReplayGuard()
    race_obr_binding = race_obr.bind_once(
        race_obr_entries, b"opening-batch-race", expires_at=10**12
    )
    race_obr_results = []
    race_obr_lock = threading.Lock()

    def race_obr_attempt():
        outcome = race_obr.check(race_obr_entries, race_obr_binding, now=100)
        with race_obr_lock:
            race_obr_results.append(outcome)

    race_obr_threads = [threading.Thread(target=race_obr_attempt) for _ in range(8)]
    for thread in race_obr_threads:
        thread.start()
    for thread in race_obr_threads:
        thread.join()
    race_obr_wins = sum(race_obr_results)
    print(f"  {race_obr_wins} succeeded, {len(race_obr_results) - race_obr_wins} rejected")

    print()
    print("SQLite-backed hash-opening batch replay state shared across instances and restarts:")
    persist_obr_items = []
    for obr_payload, obr_nonce_seed in (
        (b"opening-persist-alpha", b"zkregion-demo-opening-batch-persist-01"),
        (b"opening-persist-beta", b"zkregion-demo-opening-batch-persist-02"),
    ):
        obr_commitment, obr_nonce = commit(obr_payload, nonce=obr_nonce_seed)
        persist_obr_items.append(OpeningBatchEntry(obr_commitment, obr_payload, obr_nonce))
    persist_obr_entries = tuple(persist_obr_items)
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_obr_a = OpeningBatchReplayGuard(store=store)
        persist_obr_binding = persist_obr_a.bind_once(
            persist_obr_entries, b"opening-batch-persist", expires_at=10**12
        )
        print(f"  session_id={persist_obr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_obr_a.check(persist_obr_entries, persist_obr_binding, now=100)}")
        persist_obr_b = OpeningBatchReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_obr_b.check(persist_obr_entries, persist_obr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_obr_c = OpeningBatchReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_obr_c.check(persist_obr_entries, persist_obr_binding, now=100)}")
        reopened.close()

    print()
    print("per-instance replay protection for Pedersen opening batches (bind once, check once):")
    pobr_items = []
    for pobr_value, pobr_blinding_seed in ((40, 2000), (60, 2001)):
        pobr_commitment, pobr_blinding = pedersen_commit(
            pobr_value, 0, 100, blinding=pobr_blinding_seed
        )
        pobr_items.append(PedersenOpeningBatchEntry(pobr_commitment, pobr_value, pobr_blinding))
    pobr_entries = tuple(pobr_items)
    print(f"  batch: {len(pobr_entries)} entries  every opening verifies: "
          f"{all(verify_pedersen_opening(e.commitment, e.value, e.blinding) for e in pobr_entries)}")
    pobr = PedersenOpeningBatchReplayGuard()
    pobr_binding = pobr.bind_once(
        pobr_entries, b"pedersen-opening-batch-session-1", expires_at=10**12
    )
    print(f"  session_id={pobr_binding.session_id!r}  digest={pobr_binding.digest.hex()[:32]}…  "
          f"expires_at={pobr_binding.expires_at}")
    print(f"  valid first check accepted: {pobr.check(pobr_entries, pobr_binding, now=100)}")
    print(f"  replay rejected: {not pobr.check(pobr_entries, pobr_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        pobr.bind_once(pobr_entries, b"pedersen-opening-batch-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    pobr_other_commitment, pobr_other_blinding = pedersen_commit(61, 0, 100, blinding=2002)
    other_pobr_entries = (
        pobr_entries[0],
        PedersenOpeningBatchEntry(pobr_other_commitment, 61, pobr_other_blinding),
    )
    other_pobr = PedersenOpeningBatchReplayGuard()
    other_pobr_binding = other_pobr.bind_once(
        other_pobr_entries, b"pedersen-opening-batch-session-2"
    )
    print(f"  rebound batch rejected without consuming the id: "
          f"{not other_pobr.check(pobr_entries, other_pobr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_pobr.check(other_pobr_entries, other_pobr_binding, now=1)}")
    foreign_pobr = PedersenOpeningBatchReplayGuard()
    foreign_pobr_binding = foreign_pobr.bind_once(
        pobr_entries, b"pedersen-opening-batch-session-3"
    )
    print(f"  binding from another guard instance rejected: "
          f"{not other_pobr.check(pobr_entries, foreign_pobr_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_pobr.check(pobr_entries, foreign_pobr_binding, now=1)}")
    fresh_pobr = PedersenOpeningBatchReplayGuard()
    print("  empty batch: ", end="")
    try:
        fresh_pobr.bind_once([], b"pedersen-opening-batch-session-4")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  empty session id: ", end="")
    try:
        fresh_pobr.bind_once(pobr_entries, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_pobr.bind_once(
            pobr_entries, b"pedersen-opening-batch-session-5", expires_at=1 << 64
        )
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_pobr.bind_once("not-a-batch", b"pedersen-opening-batch-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  wrong entry type: ", end="")
    try:
        fresh_pobr.bind_once(["not-an-entry"], b"pedersen-opening-batch-session-7")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_pobr.bind_once(
            [PedersenOpeningBatchEntry(pobr_entries[0].commitment, True, 2000)],
            b"pedersen-opening-batch-session-8",
        )
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  non-boolean wrong field type: ", end="")
    try:
        fresh_pobr.bind_once(
            [PedersenOpeningBatchEntry(pobr_entries[0].commitment, 40, "not-an-integer")],
            b"pedersen-opening-batch-session-9",
        )
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one Pedersen-opening batch id (at most one winner):")
    race_pobr_items = []
    for pobr_value, pobr_blinding_seed in ((41, 2010), (59, 2011)):
        pobr_commitment, pobr_blinding = pedersen_commit(
            pobr_value, 0, 100, blinding=pobr_blinding_seed
        )
        race_pobr_items.append(PedersenOpeningBatchEntry(pobr_commitment, pobr_value, pobr_blinding))
    race_pobr_entries = tuple(race_pobr_items)
    race_pobr = PedersenOpeningBatchReplayGuard()
    race_pobr_binding = race_pobr.bind_once(
        race_pobr_entries, b"pedersen-opening-batch-race", expires_at=10**12
    )
    race_pobr_results = []
    race_pobr_lock = threading.Lock()

    def race_pobr_attempt():
        outcome = race_pobr.check(race_pobr_entries, race_pobr_binding, now=100)
        with race_pobr_lock:
            race_pobr_results.append(outcome)

    race_pobr_threads = [threading.Thread(target=race_pobr_attempt) for _ in range(8)]
    for thread in race_pobr_threads:
        thread.start()
    for thread in race_pobr_threads:
        thread.join()
    race_pobr_wins = sum(race_pobr_results)
    print(f"  {race_pobr_wins} succeeded, {len(race_pobr_results) - race_pobr_wins} rejected")

    print()
    print("SQLite-backed Pedersen-opening batch replay state shared across instances and restarts:")
    persist_pobr_items = []
    for pobr_value, pobr_blinding_seed in ((42, 2020), (58, 2021)):
        pobr_commitment, pobr_blinding = pedersen_commit(
            pobr_value, 0, 100, blinding=pobr_blinding_seed
        )
        persist_pobr_items.append(PedersenOpeningBatchEntry(pobr_commitment, pobr_value, pobr_blinding))
    persist_pobr_entries = tuple(persist_pobr_items)
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_pobr_a = PedersenOpeningBatchReplayGuard(store=store)
        persist_pobr_binding = persist_pobr_a.bind_once(
            persist_pobr_entries, b"pedersen-opening-batch-persist", expires_at=10**12
        )
        print(f"  session_id={persist_pobr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_pobr_a.check(persist_pobr_entries, persist_pobr_binding, now=100)}")
        persist_pobr_b = PedersenOpeningBatchReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_pobr_b.check(persist_pobr_entries, persist_pobr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_pobr_c = PedersenOpeningBatchReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_pobr_c.check(persist_pobr_entries, persist_pobr_binding, now=100)}")
        reopened.close()

    print()
    print("per-instance replay protection for compact multi-inclusion proofs (bind once, check once):")
    mmr_indices = (0, 2, 4)
    mmr_entries = tuple((index, leaves[index]) for index in mmr_indices)
    mmr_proof = prove_multi_inclusion(leaves, mmr_indices)
    mmr = MerkleMultiReplayGuard()
    mmr_binding = mmr.bind_once(
        mmr_entries, root, mmr_proof, b"multi-inclusion-session-1", expires_at=10**12
    )
    print(f"  session_id={mmr_binding.session_id!r}  digest={mmr_binding.digest.hex()[:32]}…  "
          f"expires_at={mmr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{mmr.check(mmr_entries, root, mmr_proof, mmr_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not mmr.check(mmr_entries, root, mmr_proof, mmr_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        mmr.bind_once(mmr_entries, root, mmr_proof, b"multi-inclusion-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_mmr_indices = (1, 3)
    other_mmr_entries = tuple((index, leaves[index]) for index in other_mmr_indices)
    other_mmr_proof = prove_multi_inclusion(leaves, other_mmr_indices)
    other_mmr = MerkleMultiReplayGuard()
    other_mmr_binding = other_mmr.bind_once(
        other_mmr_entries, root, other_mmr_proof, b"multi-inclusion-session-2"
    )
    print(f"  replaced entries rejected without consuming the id: "
          f"{not other_mmr.check(mmr_entries, root, other_mmr_proof, other_mmr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mmr.check(other_mmr_entries, root, other_mmr_proof, other_mmr_binding, now=1)}")
    foreign_mmr = MerkleMultiReplayGuard()
    foreign_mmr_binding = foreign_mmr.bind_once(
        mmr_entries, root, mmr_proof, b"multi-inclusion-session-3"
    )
    print(f"  binding from another guard instance rejected: "
          f"{not other_mmr.check(mmr_entries, root, mmr_proof, foreign_mmr_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_mmr.check(mmr_entries, root, mmr_proof, foreign_mmr_binding, now=1)}")
    fresh_mmr = MerkleMultiReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_mmr.bind_once(mmr_entries, root, mmr_proof, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_mmr.bind_once(
            mmr_entries, root, mmr_proof, b"multi-inclusion-session-4", expires_at=1 << 64
        )
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_mmr.bind_once("not-a-sequence", root, mmr_proof, b"multi-inclusion-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_mmr_entries = ((True, leaves[0]),) + mmr_entries[1:]
    print("  boolean posing as an integer index: ", end="")
    try:
        fresh_mmr.bind_once(
            bool_mmr_entries, root, mmr_proof, b"multi-inclusion-session-6"
        )
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one compact multi-inclusion id (at most one winner):")
    race_mmr = MerkleMultiReplayGuard()
    race_mmr_binding = race_mmr.bind_once(
        mmr_entries, root, mmr_proof, b"multi-inclusion-race", expires_at=10**12
    )
    race_mmr_results = []
    race_mmr_lock = threading.Lock()

    def race_mmr_attempt():
        outcome = race_mmr.check(mmr_entries, root, mmr_proof, race_mmr_binding, now=100)
        with race_mmr_lock:
            race_mmr_results.append(outcome)

    race_mmr_threads = [threading.Thread(target=race_mmr_attempt) for _ in range(8)]
    for thread in race_mmr_threads:
        thread.start()
    for thread in race_mmr_threads:
        thread.join()
    race_mmr_wins = sum(race_mmr_results)
    print(f"  {race_mmr_wins} succeeded, {len(race_mmr_results) - race_mmr_wins} rejected")

    print()
    print("SQLite-backed compact multi-inclusion replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_mmr_a = MerkleMultiReplayGuard(store=store)
        persist_mmr_binding = persist_mmr_a.bind_once(
            mmr_entries, root, mmr_proof, b"multi-inclusion-persist", expires_at=10**12
        )
        print(f"  session_id={persist_mmr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_mmr_a.check(mmr_entries, root, mmr_proof, persist_mmr_binding, now=100)}")
        persist_mmr_b = MerkleMultiReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_mmr_b.check(mmr_entries, root, mmr_proof, persist_mmr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_mmr_c = MerkleMultiReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_mmr_c.check(mmr_entries, root, mmr_proof, persist_mmr_binding, now=100)}")
        reopened.close()

    print()
    print("per-instance replay protection for independent compact multi-inclusion batches (bind once, check once):")
    mmb_tree_leaves = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
    mmb_tree_root = merkle_root(mmb_tree_leaves)
    mmb_entries = tuple([
        MerkleMultiBatchEntry(
            tuple((i, mmb_tree_leaves[i]) for i in (0, 2, 4)),
            prove_multi_inclusion(mmb_tree_leaves, (0, 2, 4)),
            mmb_tree_root,
        ),
        MerkleMultiBatchEntry(
            ((1, mmb_tree_leaves[1]),),
            prove_multi_inclusion(mmb_tree_leaves, (1,)),
            mmb_tree_root,
        ),
    ])
    mmb = MerkleMultiBatchReplayGuard()
    mmb_binding = mmb.bind_once(
        mmb_entries, b"multi-inclusion-batch-session-1", expires_at=10**12
    )
    print(f"  batch: {len(mmb_entries)} entries  session_id={mmb_binding.session_id!r}  "
          f"digest={mmb_binding.digest.hex()[:32]}…  expires_at={mmb_binding.expires_at}")
    print(f"  valid first check accepted: {mmb.check(mmb_entries, mmb_binding, now=100)}")
    print(f"  replay rejected: {not mmb.check(mmb_entries, mmb_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        mmb.bind_once(mmb_entries, b"multi-inclusion-batch-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_mmb = MerkleMultiBatchReplayGuard()
    other_mmb_binding = other_mmb.bind_once(
        mmb_entries[::-1], b"multi-inclusion-batch-session-2"
    )
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_mmb.check(mmb_entries, other_mmb_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_mmb.check(mmb_entries[::-1], other_mmb_binding, now=1)}")
    foreign_mmb = MerkleMultiBatchReplayGuard()
    foreign_mmb_binding = foreign_mmb.bind_once(
        mmb_entries, b"multi-inclusion-batch-session-3"
    )
    print(f"  binding from another guard instance rejected: "
          f"{not other_mmb.check(mmb_entries, foreign_mmb_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_mmb.check(mmb_entries, foreign_mmb_binding, now=1)}")
    fresh_mmb = MerkleMultiBatchReplayGuard()
    print("  empty batch: ", end="")
    try:
        fresh_mmb.bind_once([], b"multi-inclusion-batch-session-4")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  empty session id: ", end="")
    try:
        fresh_mmb.bind_once(mmb_entries, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_mmb.bind_once(
            mmb_entries, b"multi-inclusion-batch-session-5", expires_at=1 << 64
        )
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_mmb.bind_once("not-a-batch", b"multi-inclusion-batch-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_mmb_item = dataclasses.replace(
        mmb_entries[0],
        entries=((True, mmb_tree_leaves[0]),) + mmb_entries[0].entries[1:],
    )
    print("  boolean posing as an integer index: ", end="")
    try:
        fresh_mmb.bind_once([bool_mmb_item], b"multi-inclusion-batch-session-7")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one compact multi-inclusion batch id (at most one winner):")
    race_mmb = MerkleMultiBatchReplayGuard()
    race_mmb_binding = race_mmb.bind_once(
        mmb_entries, b"multi-inclusion-batch-race", expires_at=10**12
    )
    race_mmb_results = []
    race_mmb_lock = threading.Lock()

    def race_mmb_attempt():
        outcome = race_mmb.check(mmb_entries, race_mmb_binding, now=100)
        with race_mmb_lock:
            race_mmb_results.append(outcome)

    race_mmb_threads = [threading.Thread(target=race_mmb_attempt) for _ in range(8)]
    for thread in race_mmb_threads:
        thread.start()
    for thread in race_mmb_threads:
        thread.join()
    race_mmb_wins = sum(race_mmb_results)
    print(f"  {race_mmb_wins} succeeded, {len(race_mmb_results) - race_mmb_wins} rejected")

    print()
    print("SQLite-backed compact multi-inclusion batch replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_mmb_a = MerkleMultiBatchReplayGuard(store=store)
        persist_mmb_binding = persist_mmb_a.bind_once(
            mmb_entries, b"multi-inclusion-batch-persist", expires_at=10**12
        )
        print(f"  session_id={persist_mmb_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_mmb_a.check(mmb_entries, persist_mmb_binding, now=100)}")
        persist_mmb_b = MerkleMultiBatchReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_mmb_b.check(mmb_entries, persist_mmb_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_mmb_c = MerkleMultiBatchReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_mmb_c.check(mmb_entries, persist_mmb_binding, now=100)}")
        reopened.close()

    print()
    print("per-instance replay protection for same-key single signature entries (bind once, check once):")
    sker_entry = SchnorrBatchEntry(
        b"same-key-entry", prover.prove(b"same-key-entry", context=b"single"), context=b"single"
    )
    sker = SingleKeyEntryReplayGuard(prover.public_key)
    sker_binding = sker.bind_once(
        sker_entry, b"single-key-entry-session-1", expires_at=10**12
    )
    print(f"  session_id={sker_binding.session_id!r}  digest={sker_binding.digest.hex()[:32]}…  "
          f"expires_at={sker_binding.expires_at}")
    print(f"  valid first check accepted: {sker.check(sker_entry, sker_binding, now=100)}")
    print(f"  replay rejected: {not sker.check(sker_entry, sker_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        sker.bind_once(sker_entry, b"single-key-entry-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_sker = SingleKeyEntryReplayGuard(prover.public_key)
    other_sker_entry = SchnorrBatchEntry(
        b"same-key-other", prover.prove(b"same-key-other", context=b"single"), context=b"single"
    )
    other_sker_binding = other_sker.bind_once(
        other_sker_entry, b"single-key-entry-session-2"
    )
    print(f"  replaced entry rejected without consuming the id: "
          f"{not other_sker.check(sker_entry, other_sker_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_sker.check(other_sker_entry, other_sker_binding, now=1)}")
    foreign_sker = SingleKeyEntryReplayGuard(prover.public_key)
    foreign_sker_binding = foreign_sker.bind_once(
        sker_entry, b"single-key-entry-session-3"
    )
    print(f"  binding from another guard instance rejected: "
          f"{not other_sker.check(sker_entry, foreign_sker_binding, now=1)}")
    print(f"  that id was not consumed and still verifies on its own guard: "
          f"{foreign_sker.check(sker_entry, foreign_sker_binding, now=1)}")
    fresh_sker = SingleKeyEntryReplayGuard(prover.public_key)
    print("  empty session id: ", end="")
    try:
        fresh_sker.bind_once(sker_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_sker.bind_once(
            sker_entry, b"single-key-entry-session-4", expires_at=1 << 64
        )
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_sker.bind_once("not-an-entry", b"single-key-entry-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_sker_entry = dataclasses.replace(
        sker_entry, proof=SchnorrProof(sker_entry.proof.commitment, True)
    )
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_sker.bind_once(bool_sker_entry, b"single-key-entry-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one same-key single-entry id (at most one winner):")
    race_sker = SingleKeyEntryReplayGuard(prover.public_key)
    race_sker_binding = race_sker.bind_once(
        sker_entry, b"single-key-entry-race", expires_at=10**12
    )
    race_sker_results = []
    race_sker_lock = threading.Lock()

    def race_sker_attempt():
        outcome = race_sker.check(sker_entry, race_sker_binding, now=100)
        with race_sker_lock:
            race_sker_results.append(outcome)

    race_sker_threads = [threading.Thread(target=race_sker_attempt) for _ in range(8)]
    for thread in race_sker_threads:
        thread.start()
    for thread in race_sker_threads:
        thread.join()
    race_sker_wins = sum(race_sker_results)
    print(f"  {race_sker_wins} succeeded, {len(race_sker_results) - race_sker_wins} rejected")

    print()
    print("SQLite-backed same-key single-entry replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_sker_a = SingleKeyEntryReplayGuard(prover.public_key, store=store)
        persist_sker_binding = persist_sker_a.bind_once(
            sker_entry, b"single-key-entry-persist", expires_at=10**12
        )
        print(f"  session_id={persist_sker_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_sker_a.check(sker_entry, persist_sker_binding, now=100)}")
        persist_sker_b = SingleKeyEntryReplayGuard(prover.public_key, store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_sker_b.check(sker_entry, persist_sker_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_sker_c = SingleKeyEntryReplayGuard(prover.public_key, store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_sker_c.check(sker_entry, persist_sker_binding, now=100)}")
        reopened.close()

    print()
    print("commitment-bound rectangle membership decision:")
    rc_region = Region(0, 100, 0, 100)
    rc_xc, rc_xr = pedersen_commit(40, rc_region.min_x, rc_region.max_x, blinding=51000)
    rc_yc, rc_yr = pedersen_commit(60, rc_region.min_y, rc_region.max_y, blinding=52000)
    rc_entry = RegionContainsEntry(rc_region, rc_xc, rc_yc, 40, 60, rc_xr, rc_yr)
    rc_xc2, rc_xr2 = pedersen_commit(10, rc_region.min_x, rc_region.max_x, blinding=53000)
    rc_yc2, rc_yr2 = pedersen_commit(90, rc_region.min_y, rc_region.max_y, blinding=54000)
    rc_entry2 = RegionContainsEntry(rc_region, rc_xc2, rc_yc2, 10, 90, rc_xr2, rc_yr2)
    rc_entries = [rc_entry, rc_entry2]
    print(f"  region x=[{rc_region.min_x}, {rc_region.max_x}] "
          f"y=[{rc_region.min_y}, {rc_region.max_y}]  point (40, 60)")
    rc_honest = region_contains_committed(rc_region, rc_xc, rc_yc, 40, 60, rc_xr, rc_yr)
    print(f"  honest coordinates accepted: {rc_honest}")
    rc_rebound_x, _ = pedersen_commit(41, rc_region.min_x, rc_region.max_x, blinding=51001)
    print(f"  re-bound x commitment rejected: "
          f"{not region_contains_committed(rc_region, rc_rebound_x, rc_yc, 40, 60, rc_xr, rc_yr)}")
    rc_rebound_y, _ = pedersen_commit(61, rc_region.min_y, rc_region.max_y, blinding=52001)
    print(f"  re-bound y commitment rejected: "
          f"{not region_contains_committed(rc_region, rc_xc, rc_rebound_y, 40, 60, rc_xr, rc_yr)}")
    print(f"  changed x blinding rejected: "
          f"{not region_contains_committed(rc_region, rc_xc, rc_yc, 40, 60, rc_xr + 1, rc_yr)}")
    print(f"  swapped x/y blindings rejected: "
          f"{not region_contains_committed(rc_region, rc_xc, rc_yc, 40, 60, rc_yr, rc_xr)}")
    print(f"  x coordinate outside the rectangle rejected: "
          f"{not region_contains_committed(rc_region, rc_xc, rc_yc, 101, 60, rc_xr, rc_yr)}")
    print(f"  y coordinate outside the rectangle rejected: "
          f"{not region_contains_committed(rc_region, rc_xc, rc_yc, 40, -1, rc_xr, rc_yr)}")

    print()
    print("independent commitment-bound rectangle batch verification:")
    print(f"  valid batch of {len(rc_entries)} accepted: "
          f"{verify_region_contains_batch(rc_entries)}")
    print(f"  tuple, reordered and duplicate entries accepted: "
          f"{verify_region_contains_batch(tuple(reversed(rc_entries)) + (rc_entries[0],))}")
    print(f"  empty batch rejected: {not verify_region_contains_batch(())}")
    rc_forged_entry = dataclasses.replace(rc_entry, x_blinding=rc_xr + 1)
    print(f"  entry with a changed blinding rejected: "
          f"{not verify_region_contains_batch([rc_forged_entry, rc_entry2])}")

    print()
    print("Merkle-committed complete region-contains batch (root check, then per-entry decisions):")
    rc_bound, rc_bound_root = prove_region_contains_bound(rc_entries)
    print(f"  entries={len(rc_entries)}  complete index coverage 0..{len(rc_entries) - 1}")
    print(f"  complete batch plus outer Merkle root from the public constructor: "
          f"{rc_bound_root.hex()[:32]}…")
    print(f"  valid bound batch accepted: {verify_region_contains_bound(rc_bound, rc_bound_root)}")
    print(f"  wrong root rejected: {not verify_region_contains_bound(rc_bound, bytes(32))}")
    rc_tampered_bound = dataclasses.replace(rc_bound, entries=(rc_forged_entry, rc_entry2))
    print(f"  substituted entry rejected: "
          f"{not verify_region_contains_bound(rc_tampered_bound, rc_bound_root)}")

    print()
    print("per-instance replay protection for region-contains entries (bind once, check once):")
    rcr = RegionContainsReplayGuard()
    rcr_binding = rcr.bind_once(rc_entry, b"region-contains-session-1", expires_at=10**12)
    print(f"  session_id={rcr_binding.session_id!r}  digest={rcr_binding.digest.hex()[:32]}…  "
          f"expires_at={rcr_binding.expires_at}")
    print(f"  valid first check accepted: {rcr.check(rc_entry, rcr_binding, now=100)}")
    print(f"  replay rejected: {not rcr.check(rc_entry, rcr_binding, now=101)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        rcr.bind_once(rc_entry, b"region-contains-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    other_rcr = RegionContainsReplayGuard()
    other_rcr_binding = other_rcr.bind_once(rc_entry, b"region-contains-session-2")
    other_rcr_forged = dataclasses.replace(rc_entry, x_blinding=rc_xr + 1)
    print(f"  changed binding rejected without consuming the id: "
          f"{not other_rcr.check(other_rcr_forged, other_rcr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_rcr.check(rc_entry, other_rcr_binding, now=1)}")
    foreign_rcr = RegionContainsReplayGuard()
    foreign_rcr_binding = foreign_rcr.bind_once(rc_entry, b"region-contains-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_rcr.check(rc_entry, foreign_rcr_binding, now=1)}")
    fresh_rcr = RegionContainsReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_rcr.bind_once(rc_entry, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_rcr.bind_once(rc_entry, b"region-contains-session-4", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong entry type: ", end="")
    try:
        fresh_rcr.bind_once("not-an-entry", b"region-contains-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_rcr_entry = dataclasses.replace(rc_entry, x=True)
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_rcr.bind_once(bool_rcr_entry, b"region-contains-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("per-instance replay protection for region-contains batches (bind once, check once):")
    rcbr = RegionContainsBatchReplayGuard()
    rcbr_binding = rcbr.bind_once(rc_entries, b"region-contains-batch-session-1", expires_at=10**12)
    print(f"  batch: {len(rc_entries)} entries  session_id={rcbr_binding.session_id!r}  "
          f"digest={rcbr_binding.digest.hex()[:32]}…  expires_at={rcbr_binding.expires_at}")
    print(f"  valid first check accepted: {rcbr.check(rc_entries, rcbr_binding, now=100)}")
    print(f"  replay rejected: {not rcbr.check(rc_entries, rcbr_binding, now=101)}")
    other_rcbr = RegionContainsBatchReplayGuard()
    other_rcbr_binding = other_rcbr.bind_once(rc_entries, b"region-contains-batch-session-2")
    print(f"  reordered batch rejected without consuming the id: "
          f"{not other_rcbr.check(rc_entries[::-1], other_rcbr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_rcbr.check(rc_entries, other_rcbr_binding, now=1)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        rcbr.bind_once(rc_entries, b"region-contains-batch-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    foreign_rcbr = RegionContainsBatchReplayGuard()
    foreign_rcbr_binding = foreign_rcbr.bind_once(rc_entries, b"region-contains-batch-session-3")
    print(f"  binding from another guard instance rejected: "
          f"{not other_rcbr.check(rc_entries, foreign_rcbr_binding, now=1)}")
    fresh_rcbr = RegionContainsBatchReplayGuard()
    print("  empty batch: ", end="")
    try:
        fresh_rcbr.bind_once([], b"region-contains-batch-session-4")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  empty session id: ", end="")
    try:
        fresh_rcbr.bind_once(rc_entries, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_rcbr.bind_once(rc_entries, b"region-contains-batch-session-5", expires_at=1 << 64)
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_rcbr.bind_once("not-a-batch", b"region-contains-batch-session-6")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    print("  wrong entry type: ", end="")
    try:
        fresh_rcbr.bind_once(["not-an-entry"], b"region-contains-batch-session-7")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_rcbr_entry = dataclasses.replace(rc_entry, y=True)
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_rcbr.bind_once([bool_rcbr_entry], b"region-contains-batch-session-8")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("per-instance replay protection for bound region-contains batches (bind once, check once):")
    brcr = BoundRegionContainsReplayGuard()
    brcr_binding = brcr.bind_once(
        rc_bound, rc_bound_root, b"bound-region-contains-session-1", expires_at=10**12
    )
    print(f"  session_id={brcr_binding.session_id!r}  digest={brcr_binding.digest.hex()[:32]}…  "
          f"expires_at={brcr_binding.expires_at}")
    print(f"  valid first check accepted: "
          f"{brcr.check(rc_bound, rc_bound_root, brcr_binding, now=100)}")
    print(f"  replay rejected: "
          f"{not brcr.check(rc_bound, rc_bound_root, brcr_binding, now=101)}")
    other_brcr = BoundRegionContainsReplayGuard()
    other_brcr_binding = other_brcr.bind_once(
        rc_bound, rc_bound_root, b"bound-region-contains-session-2"
    )
    print(f"  wrong root rejected without consuming the id: "
          f"{not other_brcr.check(rc_bound, bytes(32), other_brcr_binding, now=1)}")
    print(f"  rejected id stays pending and later verifies: "
          f"{other_brcr.check(rc_bound, rc_bound_root, other_brcr_binding, now=1)}")
    print("  consumed id cannot be rebound: ", end="")
    try:
        brcr.bind_once(rc_bound, rc_bound_root, b"bound-region-contains-session-1")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    foreign_brcr = BoundRegionContainsReplayGuard()
    foreign_brcr_binding = foreign_brcr.bind_once(
        rc_bound, rc_bound_root, b"bound-region-contains-session-3"
    )
    print(f"  binding from another guard instance rejected: "
          f"{not other_brcr.check(rc_bound, rc_bound_root, foreign_brcr_binding, now=1)}")
    fresh_brcr = BoundRegionContainsReplayGuard()
    print("  empty session id: ", end="")
    try:
        fresh_brcr.bind_once(rc_bound, rc_bound_root, b"")
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  expiry beyond uint64: ", end="")
    try:
        fresh_brcr.bind_once(
            rc_bound, rc_bound_root, b"bound-region-contains-session-4", expires_at=1 << 64
        )
        print("no error (unexpected)")
    except ValueError:
        print("ValueError")
    print("  wrong batch type: ", end="")
    try:
        fresh_brcr.bind_once("not-a-batch", rc_bound_root, b"bound-region-contains-session-5")
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")
    bool_brcr_batch = dataclasses.replace(rc_bound, leaf_count=True)
    print("  boolean posing as an integer field: ", end="")
    try:
        fresh_brcr.bind_once(
            bool_brcr_batch, rc_bound_root, b"bound-region-contains-session-6"
        )
        print("no error (unexpected)")
    except TypeError:
        print("TypeError")

    print()
    print("concurrent checks of one id per region-contains guard (at most one winner each):")
    race_rcr = RegionContainsReplayGuard()
    race_rcr_binding = race_rcr.bind_once(
        rc_entry, b"region-contains-race", expires_at=10**12
    )
    race_rcr_results = []
    race_rcr_lock = threading.Lock()

    def race_rcr_attempt():
        outcome = race_rcr.check(rc_entry, race_rcr_binding, now=100)
        with race_rcr_lock:
            race_rcr_results.append(outcome)

    race_rcr_threads = [threading.Thread(target=race_rcr_attempt) for _ in range(8)]
    for thread in race_rcr_threads:
        thread.start()
    for thread in race_rcr_threads:
        thread.join()
    race_rcr_wins = sum(race_rcr_results)
    print(f"  region-contains entry, overlapping checks of the same id: "
          f"{race_rcr_wins} succeeded, {len(race_rcr_results) - race_rcr_wins} rejected")
    print(f"  rejected calls return False and leave the presented entry intact: "
          f"{region_contains_committed(rc_region, rc_xc, rc_yc, 40, 60, rc_xr, rc_yr)}")
    race_rcbr = RegionContainsBatchReplayGuard()
    race_rcbr_binding = race_rcbr.bind_once(
        rc_entries, b"region-contains-batch-race", expires_at=10**12
    )
    race_rcbr_payload = list(rc_entries)
    race_rcbr_results = []
    race_rcbr_lock = threading.Lock()

    def race_rcbr_attempt():
        outcome = race_rcbr.check(race_rcbr_payload, race_rcbr_binding, now=100)
        with race_rcbr_lock:
            race_rcbr_results.append(outcome)

    race_rcbr_threads = [threading.Thread(target=race_rcbr_attempt) for _ in range(8)]
    for thread in race_rcbr_threads:
        thread.start()
    for thread in race_rcbr_threads:
        thread.join()
    race_rcbr_wins = sum(race_rcbr_results)
    print(f"  region-contains batch, overlapping checks of the same id: "
          f"{race_rcbr_wins} succeeded, {len(race_rcbr_results) - race_rcbr_wins} rejected")
    print(f"  rejected calls return False and leave the presented entries intact: "
          f"{verify_region_contains_batch(race_rcbr_payload)}")
    race_brcr = BoundRegionContainsReplayGuard()
    race_brcr_binding = race_brcr.bind_once(
        rc_bound, rc_bound_root, b"bound-region-contains-race", expires_at=10**12
    )
    race_brcr_results = []
    race_brcr_lock = threading.Lock()

    def race_brcr_attempt():
        outcome = race_brcr.check(rc_bound, rc_bound_root, race_brcr_binding, now=100)
        with race_brcr_lock:
            race_brcr_results.append(outcome)

    race_brcr_threads = [threading.Thread(target=race_brcr_attempt) for _ in range(8)]
    for thread in race_brcr_threads:
        thread.start()
    for thread in race_brcr_threads:
        thread.join()
    race_brcr_wins = sum(race_brcr_results)
    print(f"  bound region-contains batch, overlapping checks of the same id: "
          f"{race_brcr_wins} succeeded, {len(race_brcr_results) - race_brcr_wins} rejected")
    print(f"  rejected calls return False and leave the presented entries and root intact: "
          f"{verify_region_contains_bound(rc_bound, rc_bound_root)}")

    print()
    print("SQLite-backed region-contains replay state shared across instances and restarts:")
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_rcr_a = RegionContainsReplayGuard(store=store)
        persist_rcr_binding = persist_rcr_a.bind_once(
            rc_entry, b"region-contains-persist", expires_at=10**12
        )
        print(f"  region-contains entry session_id={persist_rcr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_rcr_a.check(rc_entry, persist_rcr_binding, now=100)}")
        persist_rcr_b = RegionContainsReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_rcr_b.check(rc_entry, persist_rcr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_rcr_c = RegionContainsReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_rcr_c.check(rc_entry, persist_rcr_binding, now=100)}")
        reopened.close()
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_rcbr_a = RegionContainsBatchReplayGuard(store=store)
        persist_rcbr_binding = persist_rcbr_a.bind_once(
            rc_entries, b"region-contains-batch-persist", expires_at=10**12
        )
        print(f"  region-contains batch session_id={persist_rcbr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_rcbr_a.check(rc_entries, persist_rcbr_binding, now=100)}")
        persist_rcbr_b = RegionContainsBatchReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_rcbr_b.check(rc_entries, persist_rcbr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_rcbr_c = RegionContainsBatchReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_rcbr_c.check(rc_entries, persist_rcbr_binding, now=100)}")
        reopened.close()
    with tempfile.TemporaryDirectory() as tmp_dir:
        store_path = os.path.join(tmp_dir, "replay.db")
        store = SQLiteReplayStore(store_path)
        persist_brcr_a = BoundRegionContainsReplayGuard(store=store)
        persist_brcr_binding = persist_brcr_a.bind_once(
            rc_bound, rc_bound_root, b"bound-region-contains-persist", expires_at=10**12
        )
        print(f"  bound region-contains batch session_id={persist_brcr_binding.session_id!r}")
        print(f"  valid first check accepted: "
              f"{persist_brcr_a.check(rc_bound, rc_bound_root, persist_brcr_binding, now=100)}")
        persist_brcr_b = BoundRegionContainsReplayGuard(store=store)
        print(f"  second instance rejects the consumed id: "
              f"{not persist_brcr_b.check(rc_bound, rc_bound_root, persist_brcr_binding, now=100)}")
        store.close()
        reopened = SQLiteReplayStore(store_path)
        persist_brcr_c = BoundRegionContainsReplayGuard(store=reopened)
        print(f"  after restart the consumed id is still rejected: "
              f"{not persist_brcr_c.check(rc_bound, rc_bound_root, persist_brcr_binding, now=100)}")
        reopened.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
