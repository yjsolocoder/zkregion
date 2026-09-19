"""zkregion - commitments and interactive proofs for region membership.

Public API: commit / verify_opening / commit_coordinate / SchnorrProof /
SchnorrBatchEntry / SchnorrProver / SchnorrVerifier / Region / MerkleProof /
merkle_root / prove_inclusion / verify_inclusion / MerkleMultiProof /
prove_multi_inclusion / verify_multi_inclusion.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Callable

__all__ = [
    "DEFAULT_GENERATOR",
    "DEFAULT_PRIME",
    "MerkleMultiProof",
    "MerkleProof",
    "Region",
    "SchnorrBatchEntry",
    "SchnorrProof",
    "SchnorrProver",
    "SchnorrVerifier",
    "commit",
    "commit_coordinate",
    "merkle_root",
    "prove_inclusion",
    "prove_multi_inclusion",
    "verify_inclusion",
    "verify_multi_inclusion",
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


@dataclass(frozen=True)
class SchnorrBatchEntry:
    """One item of a batch verification: ``message``, ``proof`` and ``context``."""

    message: bytes
    proof: SchnorrProof
    context: bytes = b""


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

    def verify_batch(
        self,
        entries: Sequence[SchnorrBatchEntry],
        *,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify a batch of Fiat-Shamir proofs made for this public key.

        Every structurally valid entry recomputes its transcript challenge
        ``c`` and draws exactly one coefficient ``a = r + 1`` from
        ``r = randbelow(prime - 1)``; the batch is accepted iff the random
        linear combination ``g**Σ(a*s) == Π(t**a * public_key**(a*c))``
        holds modulo ``prime`` — never a per-entry boolean summary. An
        empty batch returns False; out-of-range commitments, negative
        responses, mismatched messages or contexts and any tampering
        return False, and an invalid proof may short-circuit the batch.
        Duplicate entries are legal and each draws its own coefficient.
        A fixed ``randbelow`` makes the result reproducible; the default
        is :func:`secrets.randbelow`.
        """
        if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
            raise TypeError("entries must be a sequence of SchnorrBatchEntry")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        items = list(entries)  # copy: inputs are never mutated
        if not items:
            return False
        exponent_sum = 0
        product = 1
        for position, entry in enumerate(items):
            if not isinstance(entry, SchnorrBatchEntry):
                raise TypeError(f"entries[{position}] must be a SchnorrBatchEntry")
            _check_bytes(entry.message, f"entries[{position}] message")
            _check_bytes(entry.context, f"entries[{position}] context")
            proof = entry.proof
            if not isinstance(proof, SchnorrProof):
                raise TypeError(f"entries[{position}] proof must be a SchnorrProof")
            if (
                not isinstance(proof.commitment, int)
                or isinstance(proof.commitment, bool)
                or not isinstance(proof.response, int)
                or isinstance(proof.response, bool)
            ):
                raise TypeError(
                    f"entries[{position}] proof commitment and response must be integers"
                )
            if not 1 <= proof.commitment < self._prime or proof.response < 0:
                return False  # structurally invalid proof: short-circuit
            challenge = _fs_challenge(
                self._prime,
                self._generator,
                self._public_key,
                proof.commitment,
                entry.context,
                entry.message,
            )
            r = randbelow(self._prime - 1)
            if not isinstance(r, int) or isinstance(r, bool):
                raise TypeError("coefficient source randbelow must return an integer")
            if not 0 <= r < self._prime - 1:
                raise ValueError("coefficient source must satisfy 0 <= r < prime - 1")
            coefficient = r + 1
            exponent_sum += coefficient * proof.response
            product = product * pow(proof.commitment, coefficient, self._prime) % self._prime
            product = (
                product
                * pow(self._public_key, coefficient * challenge, self._prime)
                % self._prime
            )
        return pow(self._generator, exponent_sum, self._prime) == product


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


# ---------------------------------------------------------------------------
# Deterministic SHA-256 Merkle inclusion proofs
#
# Leaf digest:     SHA-256(b"\x00" + len4 + leaf)   (len4 = 4-byte BE length)
# Internal digest: SHA-256(b"\x01" + left + right)
# Layers pair nodes in input order; an odd node is duplicated before merging.
# A single-leaf tree's root is the leaf digest and its proof path is empty.

_MERKLE_LEAF_PREFIX = b"\x00"
_MERKLE_NODE_PREFIX = b"\x01"
_MERKLE_DIGEST_SIZE = 32


@dataclass(frozen=True)
class MerkleProof:
    """Inclusion proof: zero-based leaf ``index`` and ``siblings`` from leaf to root."""

    index: int
    siblings: tuple[bytes, ...]


def _leaf_digest(leaf: bytes) -> bytes:
    return hashlib.sha256(
        _MERKLE_LEAF_PREFIX + len(leaf).to_bytes(4, "big") + leaf
    ).digest()


def _node_digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_MERKLE_NODE_PREFIX + left + right).digest()


def _checked_leaves(leaves: Sequence[bytes]) -> list[bytes]:
    if isinstance(leaves, (bytes, bytearray, str)) or not isinstance(leaves, Sequence):
        raise TypeError("leaves must be a sequence of bytes")
    items = list(leaves)  # copy: inputs are never mutated
    if not items:
        raise ValueError("leaves must not be empty")
    for position, leaf in enumerate(items):
        if not isinstance(leaf, bytes):
            raise TypeError(f"leaves[{position}] must be bytes")
    return items


def _check_merkle_index(index: int, size: int) -> None:
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("index must be an integer")
    if not 0 <= index < size:
        raise IndexError(f"index {index} out of range for {size} leaves")


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Return the Merkle root digest of a non-empty sequence of byte leaves."""
    level = [_leaf_digest(leaf) for leaf in _checked_leaves(leaves)]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        level = [
            _node_digest(level[offset], level[offset + 1])
            for offset in range(0, len(level), 2)
        ]
    return level[0]


def prove_inclusion(leaves: Sequence[bytes], index: int) -> MerkleProof:
    """Build a :class:`MerkleProof` for the leaf at zero-based ``index``.

    Duplicate leaves are located purely by position; content is never searched.
    """
    items = _checked_leaves(leaves)
    _check_merkle_index(index, len(items))
    level = [_leaf_digest(leaf) for leaf in items]
    siblings: list[bytes] = []
    position = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        siblings.append(level[position ^ 1])
        level = [
            _node_digest(level[offset], level[offset + 1])
            for offset in range(0, len(level), 2)
        ]
        position //= 2
    return MerkleProof(index=index, siblings=tuple(siblings))


def verify_inclusion(leaf: bytes, proof: MerkleProof, root: bytes) -> bool:
    """Check that ``leaf`` sits at ``proof.index`` under Merkle ``root``.

    Type errors raise :class:`TypeError`; malformed digest lengths or an
    index/path structure that cannot correspond to a real tree return False.
    """
    _check_bytes(leaf, "leaf")
    _check_bytes(root, "root")
    if not isinstance(proof, MerkleProof):
        raise TypeError("proof must be a MerkleProof")
    if not isinstance(proof.index, int) or isinstance(proof.index, bool):
        raise TypeError("proof index must be an integer")
    if not isinstance(proof.siblings, tuple):
        raise TypeError("proof siblings must be a tuple of bytes")
    for sibling in proof.siblings:
        _check_bytes(sibling, "proof sibling")
    if len(root) != _MERKLE_DIGEST_SIZE:
        return False
    if proof.index < 0:
        return False
    if any(len(sibling) != _MERKLE_DIGEST_SIZE for sibling in proof.siblings):
        return False
    digest = _leaf_digest(leaf)
    position = proof.index
    for sibling in proof.siblings:
        if position % 2 == 0:
            digest = _node_digest(digest, sibling)
        else:
            digest = _node_digest(sibling, digest)
        position //= 2
    if position != 0:
        return False  # index deeper than the path allows
    return hmac.compare_digest(digest, root)


# ---------------------------------------------------------------------------
# Compact Merkle multi-inclusion proofs
#
# Same digests and odd-node duplication as the single-leaf proofs above, but
# one proof covers several leaves at once: siblings shared by two proven
# nodes are collected only once, and a sibling that is itself proven (or an
# odd last node that duplicates itself) is never collected at all.


@dataclass(frozen=True)
class MerkleMultiProof:
    """Multi-inclusion proof for ``indices`` within ``leaf_count`` leaves.

    ``siblings`` lists the digests the verifier cannot recompute, ordered
    level by level from leaf to root and left to right within each level.
    """

    leaf_count: int
    indices: tuple[int, ...]
    siblings: tuple[bytes, ...]


def _checked_multi_indices(indices: Sequence[int], size: int) -> list[int]:
    if isinstance(indices, (bytes, bytearray, str)) or not isinstance(indices, Sequence):
        raise TypeError("indices must be a sequence of integers")
    items = list(indices)  # copy: inputs are never mutated
    if not items:
        raise ValueError("indices must not be empty")
    previous: int | None = None
    for position, index in enumerate(items):
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError(f"indices[{position}] must be an integer")
        if previous is not None and index <= previous:
            raise ValueError("indices must be strictly increasing without duplicates")
        previous = index
    for index in items:
        if not 0 <= index < size:
            raise IndexError(f"index {index} out of range for {size} leaves")
    return items


def prove_multi_inclusion(leaves: Sequence[bytes], indices: Sequence[int]) -> MerkleMultiProof:
    """Build a compact :class:`MerkleMultiProof` for the leaves at ``indices``.

    ``indices`` must be non-empty, strictly increasing and duplicate-free.
    The proof is deterministic and minimal: when every leaf is proven,
    ``siblings`` is empty.
    """
    items = _checked_leaves(leaves)
    positions = _checked_multi_indices(indices, len(items))
    level = [_leaf_digest(leaf) for leaf in items]
    siblings: list[bytes] = []
    known = positions
    while len(level) > 1:
        size = len(level)
        known_set = set(known)
        for position in known:  # ascending: siblings collected left to right
            sibling = position ^ 1
            if sibling in known_set:
                continue  # sibling is proven too, nothing to collect
            if position == size - 1 and size % 2 == 1:
                continue  # odd last node duplicates itself
            siblings.append(level[sibling])
        if size % 2 == 1:
            level = level + [level[-1]]
        level = [
            _node_digest(level[offset], level[offset + 1])
            for offset in range(0, len(level), 2)
        ]
        known = sorted({position // 2 for position in known})
    return MerkleMultiProof(
        leaf_count=len(items),
        indices=tuple(positions),
        siblings=tuple(siblings),
    )


def verify_multi_inclusion(
    entries: Sequence[tuple[int, bytes]],
    proof: MerkleMultiProof,
    root: bytes,
) -> bool:
    """Check ``entries`` against ``proof`` and Merkle ``root`` without the full leaf set.

    ``entries`` holds one ``(index, leaf)`` pair per entry, in the exact order
    of ``proof.indices``. Type errors raise :class:`TypeError`; empty,
    misordered, out-of-range, miscounted or tampered inputs return False.
    """
    _check_bytes(root, "root")
    if not isinstance(proof, MerkleMultiProof):
        raise TypeError("proof must be a MerkleMultiProof")
    if not isinstance(proof.leaf_count, int) or isinstance(proof.leaf_count, bool):
        raise TypeError("proof leaf_count must be an integer")
    if not isinstance(proof.indices, tuple):
        raise TypeError("proof indices must be a tuple of integers")
    for index in proof.indices:
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("proof indices must be a tuple of integers")
    if not isinstance(proof.siblings, tuple):
        raise TypeError("proof siblings must be a tuple of bytes")
    for sibling in proof.siblings:
        _check_bytes(sibling, "proof sibling")
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of (index, leaf) pairs")
    pairs: list[tuple[int, bytes]] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise TypeError(f"entries[{position}] must be an (index, leaf) pair")
        index, leaf = entry
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError(f"entries[{position}] index must be an integer")
        if not isinstance(leaf, bytes):
            raise TypeError(f"entries[{position}] leaf must be bytes")
        pairs.append((index, leaf))
    if proof.leaf_count < 1:
        return False
    if not proof.indices:
        return False
    if any(
        later <= earlier for earlier, later in zip(proof.indices, proof.indices[1:])
    ):
        return False  # duplicates or out-of-order indices
    if proof.indices[0] < 0 or proof.indices[-1] >= proof.leaf_count:
        return False
    if not pairs:
        return False
    if tuple(index for index, _ in pairs) != proof.indices:
        return False
    if len(root) != _MERKLE_DIGEST_SIZE:
        return False
    if any(len(sibling) != _MERKLE_DIGEST_SIZE for sibling in proof.siblings):
        return False
    known = {index: _leaf_digest(leaf) for index, leaf in pairs}
    size = proof.leaf_count
    siblings = proof.siblings
    cursor = 0
    while size > 1:
        next_known: dict[int, bytes] = {}
        for position in sorted(known):
            sibling = position ^ 1
            if sibling in known:
                sibling_digest = known[sibling]
            elif position == size - 1 and size % 2 == 1:
                sibling_digest = known[position]  # odd last node duplicates itself
            else:
                if cursor >= len(siblings):
                    return False  # proof ran out of siblings
                sibling_digest = siblings[cursor]
                cursor += 1
            if position % 2 == 0:
                digest = _node_digest(known[position], sibling_digest)
            else:
                digest = _node_digest(sibling_digest, known[position])
            next_known[position // 2] = digest
        known = next_known
        size = (size + 1) // 2
    if cursor != len(siblings):
        return False  # every sibling must be consumed
    return hmac.compare_digest(known[0], root)
