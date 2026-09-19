"""zkregion - commitments and interactive proofs for region membership.

Public API: commit / verify_opening / commit_coordinate / SchnorrProof /
SchnorrProver / SchnorrVerifier / Region / MerkleProof / merkle_root /
prove_inclusion / verify_inclusion.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Callable

__all__ = [
    "DEFAULT_GENERATOR",
    "DEFAULT_PRIME",
    "MerkleProof",
    "Region",
    "SchnorrProof",
    "SchnorrProver",
    "SchnorrVerifier",
    "commit",
    "commit_coordinate",
    "merkle_root",
    "prove_inclusion",
    "verify_inclusion",
    "verify_opening",
]

# Mersenne prime 2**127 - 1 and a small generator. This is a demonstration
# group: its order is composite and not factored here, so the baseline treats
# exponents as plain integers. See README "限制".
DEFAULT_PRIME = (1 << 127) - 1
DEFAULT_GENERATOR = 3

NONCE_BYTES = 16
_DOMAIN = b"zkregion/commit/v1"
_FS_DOMAIN = b"zkregion/schnorr-fs/v1"


@dataclass(frozen=True)
class SchnorrProof:
    """A Fiat-Shamir Schnorr proof: commitment ``t`` and response ``s``."""

    commitment: int
    response: int


def _encode_int(value: int) -> bytes:
    """Shortest unsigned big-endian encoding of a non-negative integer."""
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _fs_challenge(
    prime: int,
    generator: int,
    public_key: int,
    commitment: int,
    context: bytes,
    message: bytes,
) -> int:
    """SHA-256 transcript challenge as a big-endian integer mod ``prime``."""
    transcript = hashlib.sha256()
    for item in (
        _FS_DOMAIN,
        _encode_int(prime),
        _encode_int(generator),
        _encode_int(public_key),
        _encode_int(commitment),
        context,
        message,
    ):
        transcript.update(len(item).to_bytes(4, "big"))
        transcript.update(item)
    return int.from_bytes(transcript.digest(), "big") % prime


def _check_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def commit(value: bytes, *, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(commitment, nonce)`` for ``value``."""
    material = bytes(value)
    chosen = secrets.token_bytes(NONCE_BYTES) if nonce is None else bytes(nonce)
    if not chosen:
        raise ValueError("nonce must not be empty")
    digest = hashlib.sha256(_DOMAIN + chosen + material).digest()
    return digest, chosen


def verify_opening(commitment: bytes, value: bytes, nonce: bytes) -> bool:
    """Constant-time check that ``commitment`` opens to ``value`` under ``nonce``."""
    expected, _ = commit(value, nonce=nonce)
    return hmac.compare_digest(bytes(commitment), expected)


def commit_coordinate(x: int, y: int, *, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """Commit to a quantized integer coordinate pair."""
    if not isinstance(x, int) or not isinstance(y, int):
        raise TypeError("coordinates must be integers")
    return commit(f"{x}:{y}".encode("utf-8"), nonce=nonce)


class SchnorrProver:
    """Interactive Schnorr prover over a multiplicative group."""

    def __init__(
        self,
        secret: int,
        *,
        prime: int = DEFAULT_PRIME,
        generator: int = DEFAULT_GENERATOR,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> None:
        if not isinstance(secret, int):
            raise TypeError("secret must be an integer")
        if not 0 < secret < prime:
            raise ValueError("secret must satisfy 0 < secret < prime")
        if not 1 < generator < prime:
            raise ValueError("generator must satisfy 1 < generator < prime")
        self._secret = secret
        self._prime = prime
        self._generator = generator
        self._randbelow = randbelow
        self._nonce: int | None = None

    @property
    def prime(self) -> int:
        return self._prime

    @property
    def generator(self) -> int:
        return self._generator

    @property
    def public_key(self) -> int:
        return pow(self._generator, self._secret, self._prime)

    def new_commitment(self) -> int:
        """Draw a fresh nonce and publish ``g**k mod prime``."""
        self._nonce = self._randbelow(self._prime - 1) + 1
        return pow(self._generator, self._nonce, self._prime)

    def respond(self, challenge: int) -> int:
        """Answer the verifier's challenge for the most recent commitment."""
        if self._nonce is None:
            raise RuntimeError("call new_commitment() before respond()")
        if not isinstance(challenge, int):
            raise TypeError("challenge must be an integer")
        bounded = challenge % self._prime
        return self._nonce + bounded * self._secret

    def prove(self, message: bytes, *, context: bytes = b"") -> SchnorrProof:
        """Non-interactive Fiat-Shamir proof of knowledge of the secret.

        Draws a fresh ephemeral ``k`` independently of the interactive nonce
        and returns ``SchnorrProof(t, s)`` with ``s = k + c * secret`` (not
        reduced modulo the group order).
        """
        _check_bytes(message, "message")
        _check_bytes(context, "context")
        k = self._randbelow(self._prime - 1) + 1
        commitment = pow(self._generator, k, self._prime)
        challenge = _fs_challenge(
            self._prime, self._generator, self.public_key, commitment, context, message
        )
        return SchnorrProof(commitment=commitment, response=k + challenge * self._secret)


class SchnorrVerifier:
    """Checks the Schnorr response against a published commitment."""

    def __init__(self, public_key: int, *, prime: int = DEFAULT_PRIME, generator: int = DEFAULT_GENERATOR) -> None:
        if not isinstance(public_key, int):
            raise TypeError("public_key must be an integer")
        if not 0 < public_key < prime:
            raise ValueError("public_key must satisfy 0 < public_key < prime")
        if not 1 < generator < prime:
            raise ValueError("generator must satisfy 1 < generator < prime")
        self._public_key = public_key
        self._prime = prime
        self._generator = generator

    @property
    def public_key(self) -> int:
        return self._public_key

    def verify(self, commitment: int, challenge: int, response: int) -> bool:
        for value in (commitment, challenge, response):
            if not isinstance(value, int):
                raise TypeError("commitment, challenge and response must be integers")
        bounded = challenge % self._prime
        left = pow(self._generator, response, self._prime)
        right = commitment * pow(self._public_key, bounded, self._prime) % self._prime
        return left == right

    def verify_proof(self, message: bytes, proof: SchnorrProof, *, context: bytes = b"") -> bool:
        """Check a Fiat-Shamir proof produced by :meth:`SchnorrProver.prove`."""
        _check_bytes(message, "message")
        _check_bytes(context, "context")
        if not isinstance(proof, SchnorrProof):
            raise TypeError("proof must be a SchnorrProof")
        if not isinstance(proof.commitment, int) or not isinstance(proof.response, int):
            raise TypeError("proof commitment and response must be integers")
        if not 1 <= proof.commitment < self._prime or proof.response < 0:
            return False
        challenge = _fs_challenge(
            self._prime, self._generator, self._public_key, proof.commitment, context, message
        )
        left = pow(self._generator, proof.response, self._prime)
        right = proof.commitment * pow(self._public_key, challenge, self._prime) % self._prime
        return left == right


@dataclass(frozen=True)
class Region:
    """An axis-aligned rectangle over quantized integer coordinates (inclusive)."""

    min_x: int
    max_x: int
    min_y: int
    max_y: int

    def __post_init__(self) -> None:
        for name in ("min_x", "max_x", "min_y", "max_y"):
            if not isinstance(getattr(self, name), int):
                raise TypeError(f"{name} must be an integer")
        if self.min_x > self.max_x:
            raise ValueError("min_x must not exceed max_x")
        if self.min_y > self.max_y:
            raise ValueError("min_y must not exceed max_y")

    def contains(self, x: int, y: int) -> bool:
        if not isinstance(x, int) or not isinstance(y, int):
            raise TypeError("coordinates must be integers")
        return self.min_x <= x <= self.max_x and self.min_y <= y <= self.max_y

    def width(self) -> int:
        return self.max_x - self.min_x + 1

    def height(self) -> int:
        return self.max_y - self.min_y + 1


@dataclass(frozen=True)
class MerkleProof:
    """An inclusion proof for one leaf.

    ``index`` is the zero-based leaf position and ``siblings`` are the
    co-nodes ordered from leaf level up to the root.
    """

    index: int
    siblings: tuple[bytes, ...]


def _leaf_digest(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + len(leaf).to_bytes(4, "big") + leaf).digest()


def _node_digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _validate_leaves(leaves: object) -> int:
    try:
        length = len(leaves)
    except TypeError:
        raise TypeError("leaves must be a non-empty sequence of bytes")
    if length == 0:
        raise ValueError("leaves must be non-empty")
    for leaf in leaves:
        if not isinstance(leaf, bytes):
            raise TypeError("all leaves must be bytes")
    return length


def _merkle_levels(leaves: object) -> list[list[bytes]]:
    """Return the tree levels bottom-up; inputs are never mutated."""
    _validate_leaves(leaves)
    level = [_leaf_digest(leaf) for leaf in leaves]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [_node_digest(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_root(leaves: object) -> bytes:
    """Return the deterministic SHA-256 Merkle root of ``leaves``."""
    return _merkle_levels(leaves)[-1][0]


def prove_inclusion(leaves: object, index: int) -> MerkleProof:
    """Build a :class:`MerkleProof` for ``leaves[index]``.

    The index is positional: duplicate leaves are distinguished by the
    caller-supplied zero-based index, never searched by content.
    """
    if not isinstance(index, int):
        raise TypeError("index must be an integer")
    levels = _merkle_levels(leaves)
    if not 0 <= index < len(levels[0]):
        raise IndexError("leaf index out of range")
    siblings = []
    position = index
    for level in levels[:-1]:
        if position % 2:
            siblings.append(level[position - 1])
        else:
            paired = level[position + 1] if position + 1 < len(level) else level[position]
            siblings.append(paired)
        position //= 2
    return MerkleProof(index=index, siblings=tuple(siblings))


def verify_inclusion(leaf: object, proof: object, root: object) -> bool:
    """Check a :class:`MerkleProof` against ``root``; never raises on bad data."""
    if not isinstance(leaf, bytes):
        raise TypeError("leaf must be bytes")
    if not isinstance(root, bytes):
        raise TypeError("root must be bytes")
    if len(root) != 32:
        return False
    if not isinstance(proof, MerkleProof):
        raise TypeError("proof must be a MerkleProof")
    if not isinstance(proof.index, int) or proof.index < 0:
        return False
    if not isinstance(proof.siblings, tuple):
        return False
    node = _leaf_digest(leaf)
    position = proof.index
    for sibling in proof.siblings:
        if not isinstance(sibling, bytes) or len(sibling) != 32:
            return False
        node = (
            _node_digest(sibling, node) if position % 2 else _node_digest(node, sibling)
        )
        position //= 2
    return position == 0 and hmac.compare_digest(node, root)
