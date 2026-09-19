"""Self-contained demo: python3 -m zkregion"""

from __future__ import annotations

from . import (
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
    print("batched Schnorr (Fiat-Shamir, random linear combination):")
    batch_messages = [b"alpha", b"beta", b"gamma"]
    entries = [
        SchnorrBatchEntry(message, prover.prove(message, context=b"batch"), context=b"batch")
        for message in batch_messages
    ]
    print(f"  batch of {len(entries)} accepted: {verifier.verify_batch(entries, randbelow=counter_randbelow())}")
    last = entries[-1]
    tampered = entries[:-1] + [
        SchnorrBatchEntry(last.message, SchnorrProof(last.proof.commitment, last.proof.response + 1), context=b"batch")
    ]
    print(f"  tampered entry rejected: {not verifier.verify_batch(tampered, randbelow=counter_randbelow())}")
    wrong_context = entries[:-1] + [SchnorrBatchEntry(last.message, last.proof)]
    print(f"  wrong context rejected: {not verifier.verify_batch(wrong_context, randbelow=counter_randbelow())}")
    print(f"  empty batch rejected: {not verifier.verify_batch([])}")

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
    print("region membership:")
    region = Region(0, 100, 0, 100)
    print(f"  region size {region.width()}x{region.height()}")
    for x, y in ((50, 50), (0, 0), (100, 100), (101, 50), (-1, 50)):
        print(f"  contains({x:>4}, {y:>4}) = {region.contains(x, y)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
