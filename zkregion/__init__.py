"""zkregion - commitments and proofs for region membership.

Public API: commit / verify_opening / commit_coordinate / SchnorrProver /
SchnorrVerifier / SchnorrProof / Region.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from typing import Callable

__all__ = [
    "DEFAULT_GENERATOR",
    "DEFAULT_PRIME",
    "Region",
    "SchnorrProof",
    "SchnorrProver",
    "SchnorrVerifier",
    "commit",
    "commit_coordinate",
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


def _minimal_uint(value: int) -> bytes:
    """Shortest unsigned big-endian encoding of a non-negative integer."""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _transcript_item(data: bytes) -> bytes:
    """Prefix a transcript item with its four-byte unsigned big-endian length."""
    return struct.pack(">I", len(data)) + data


def _fs_challenge(
    prime: int,
    generator: int,
    public_key: int,
    commitment: int,
    context: bytes,
    message: bytes,
) -> int:
    """Fiat-Shamir challenge: SHA-256 over the length-prefixed transcript."""
    transcript = hashlib.sha256()
    transcript.update(_transcript_item(_FS_DOMAIN))
    for value in (prime, generator, public_key, commitment):
        transcript.update(_transcript_item(_minimal_uint(value)))
    transcript.update(_transcript_item(context))
    transcript.update(_transcript_item(message))
    return int.from_bytes(transcript.digest(), "big") % prime


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


@dataclass(frozen=True)
class SchnorrProof:
    """A non-interactive Schnorr proof: the ``(commitment, response)`` pair."""

    commitment: int
    response: int


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
        """Non-interactive Fiat-Shamir proof over ``message`` and ``context``.

        Draws a one-off nonce independently of :meth:`new_commitment`; the
        interactive nonce state is neither read nor modified.
        """
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        if not isinstance(context, bytes):
            raise TypeError("context must be bytes")
        k = self._randbelow(self._prime - 1) + 1
        commitment = pow(self._generator, k, self._prime)
        challenge = _fs_challenge(
            self._prime, self._generator, self.public_key, commitment, context, message
        )
        response = k + challenge * self._secret
        return SchnorrProof(commitment, response)


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
        """Verify a non-interactive Fiat-Shamir :class:`SchnorrProof`."""
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        if not isinstance(context, bytes):
            raise TypeError("context must be bytes")
        if not isinstance(proof, SchnorrProof):
            raise TypeError("proof must be a SchnorrProof")
        commitment = proof.commitment
        response = proof.response
        if not isinstance(commitment, int) or not isinstance(response, int):
            raise TypeError("proof fields must be integers")
        if not 1 <= commitment < self._prime or response < 0:
            return False
        challenge = _fs_challenge(
            self._prime, self._generator, self._public_key, commitment, context, message
        )
        left = pow(self._generator, response, self._prime)
        right = commitment * pow(self._public_key, challenge, self._prime) % self._prime
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
