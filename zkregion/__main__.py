"""Self-contained demo: python3 -m zkregion"""

from __future__ import annotations

from . import Region, SchnorrProver, SchnorrVerifier, commit, commit_coordinate, verify_opening


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
    print("region membership:")
    region = Region(0, 100, 0, 100)
    print(f"  region size {region.width()}x{region.height()}")
    for x, y in ((50, 50), (0, 0), (100, 100), (101, 50), (-1, 50)):
        print(f"  contains({x:>4}, {y:>4}) = {region.contains(x, y)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
