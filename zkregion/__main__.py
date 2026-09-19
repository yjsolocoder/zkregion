"""Self-contained demo: python3 -m zkregion"""

from __future__ import annotations

from . import (
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
    print("Pedersen range proof (non-interactive Schnorr OR):")
    range_proof = prove_range(commitment, 40, blinding, context=b"demo")
    print(f"  branches={len(range_proof.t)}  (one per integer in [{lower}, {upper}])")
    print(f"  valid proof accepted: {verify_range(commitment, range_proof, context=b'demo')}")
    print(f"  wrong context rejected: {not verify_range(commitment, range_proof)}")
    forged = RangeProof(range_proof.t, range_proof.e, (range_proof.s[0] + 1,) + range_proof.s[1:])
    print(f"  tampered response rejected: {not verify_range(commitment, forged, context=b'demo')}")
    other, _ = pedersen_commit(41, lower, upper, blinding=1001)
    print(f"  foreign commitment rejected: {not verify_range(other, range_proof, context=b'demo')}")
    print("  (demonstration group and transcript only; not production-grade)")

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
