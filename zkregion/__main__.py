"""Self-contained demo: python3 -m zkregion"""

from __future__ import annotations

from . import (
    Region,
    SchnorrProver,
    SchnorrVerifier,
    commit,
    commit_coordinate,
    merkle_root,
    prove_inclusion,
    verify_inclusion,
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
    print("region membership:")
    region = Region(0, 100, 0, 100)
    print(f"  region size {region.width()}x{region.height()}")
    for x, y in ((50, 50), (0, 0), (100, 100), (101, 50), (-1, 50)):
        print(f"  contains({x:>4}, {y:>4}) = {region.contains(x, y)}")

    print()
    print("Merkle inclusion proofs:")
    leaves = [f"leaf-{i}".encode() for i in range(5)]
    root = merkle_root(leaves)
    print(f"  root={root.hex()[:32]}…")
    for index in (0, 2, 4):
        proof = prove_inclusion(leaves, index)
        accepted = verify_inclusion(leaves[index], proof, root)
        print(f"  leaf {index} proof has {len(proof.siblings)} siblings, accepted: {accepted}")
    single = [b"only"]
    single_root = merkle_root(single)
    single_proof = prove_inclusion(single, 0)
    print(
        "  single-leaf root is the leaf digest, empty path: "
        f"{single_proof.siblings == () and verify_inclusion(b'only', single_proof, single_root)}"
    )
    duplicate = [b"same", b"same", b"same"]
    duplicate_root = merkle_root(duplicate)
    middle = prove_inclusion(duplicate, 1)
    print(f"  duplicate leaves located by index: {verify_inclusion(b'same', middle, duplicate_root)}")
    tampered = prove_inclusion(leaves, 2)
    print(f"  tampered leaf rejected: {not verify_inclusion(b'forged', tampered, root)}")
    print(f"  tampered root rejected: {not verify_inclusion(leaves[2], tampered, b'\\x00' * 32)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
