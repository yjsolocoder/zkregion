"""zkregion - commitments and interactive proofs for region membership.

Public API: commit / verify_opening / commit_coordinate / PedersenCommitment /
pedersen_commit / verify_pedersen_opening / RangeProof / prove_range /
verify_range / SchnorrProof / SchnorrBatchEntry / SchnorrProver /
SchnorrVerifier / Region / MerkleProof / merkle_root / prove_inclusion /
verify_inclusion / MerkleMultiProof / prove_multi_inclusion /
verify_multi_inclusion.
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
    "PedersenCommitment",
    "RangeProof",
    "Region",
    "SchnorrBatchEntry",
    "SchnorrProof",
    "SchnorrProver",
    "SchnorrVerifier",
    "commit",
    "commit_coordinate",
    "merkle_root",
    "pedersen_commit",
    "prove_inclusion",
    "prove_multi_inclusion",
    "prove_range",
    "verify_inclusion",
    "verify_multi_inclusion",
    "verify_opening",
    "verify_pedersen_opening",
    "verify_range",
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


@dataclass(frozen=True)
class PedersenCommitment:
    """A Pedersen commitment over a multiplicative group modulo ``prime``.

    Fields:

    - ``element`` — the commitment ``C = g**m * h**r mod prime``, where the
      message is the offset ``m = value - lower``;
    - ``lower`` / ``upper`` — inclusive quantized range declared at commit;
    - ``prime`` / ``generator`` — modulus and base ``g``;
    - ``h`` — the blinding base.

    .. warning::
       With the default ``h = g**2 mod prime`` the discrete logarithm
       ``log_g(h) = 2`` is publicly known, so the commitment is **not
       binding**: anyone can open one commitment to several values. It is a
       demonstration trapdoor commitment, not a range proof.
    """

    element: int
    lower: int
    upper: int
    prime: int
    generator: int
    h: int


def _check_int(value: object, name: str) -> None:
    """Numbers are non-bool integers; bool is rejected everywhere."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")


def pedersen_commit(
    value: int,
    lower: int,
    upper: int,
    *,
    prime: int = DEFAULT_PRIME,
    generator: int = DEFAULT_GENERATOR,
    h: int | None = None,
    blinding: int | None = None,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[PedersenCommitment, int]:
    """Commit to ``value`` inside the inclusive range ``[lower, upper]``.

    Returns ``(commitment, blinding)``. The encoded message is the offset
    ``m = value - lower`` and the commitment is ``g**m * h**r mod prime``.
    ``lower <= value <= upper`` must hold and the range width
    ``upper - lower`` must be strictly smaller than ``prime - 1``.

    ``prime`` and ``generator`` (``g``) default to :data:`DEFAULT_PRIME` and
    :data:`DEFAULT_GENERATOR`; ``h`` defaults to ``g**2 mod prime``, whose
    discrete log is publicly known (see the trapdoor warning on
    :class:`PedersenCommitment`). The default ``h`` is validated like an
    explicit one: if ``g**2 mod prime`` falls outside ``(1, prime)`` a
    :class:`ValueError` is raised. The blinding ``r`` defaults to
    ``randbelow(prime - 2) + 1`` and must lie in ``[1, prime - 1)``; the
    default source is :func:`secrets.randbelow`.

    Type errors (including non-callable ``randbelow`` or a non-integer value
    drawn from it) raise :class:`TypeError`; an invalid range, an out-of-range
    value, bad group parameters or a bad blinding raise :class:`ValueError`.
    """
    _check_int(value, "value")
    _check_int(lower, "lower")
    _check_int(upper, "upper")
    _check_int(prime, "prime")
    _check_int(generator, "generator")
    if prime <= 3:
        raise ValueError("prime must be greater than 3")
    if not 1 < generator < prime:
        raise ValueError("generator must satisfy 1 < generator < prime")
    if h is None:
        h = pow(generator, 2, prime)
    else:
        _check_int(h, "h")
    if not 1 < h < prime:
        raise ValueError("h must satisfy 1 < h < prime")
    if lower > upper:
        raise ValueError("lower must not exceed upper")
    if not lower <= value <= upper:
        raise ValueError("value must satisfy lower <= value <= upper")
    if upper - lower >= prime - 1:
        raise ValueError("range width (upper - lower) must be smaller than prime - 1")
    if blinding is None:
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        drawn = randbelow(prime - 2)
        _check_int(drawn, "randbelow return value")
        if not 0 <= drawn < prime - 2:
            raise ValueError("randbelow must return a value in [0, prime - 2)")
        blinding = drawn + 1
    else:
        _check_int(blinding, "blinding")
        if not 1 <= blinding < prime - 1:
            raise ValueError("blinding must satisfy 1 <= blinding < prime - 1")
    message = value - lower
    element = (pow(generator, message, prime) * pow(h, blinding, prime)) % prime
    return (
        PedersenCommitment(
            element=element,
            lower=lower,
            upper=upper,
            prime=prime,
            generator=generator,
            h=h,
        ),
        blinding,
    )


def verify_pedersen_opening(
    commitment: PedersenCommitment,
    value: int,
    blinding: int,
) -> bool:
    """Verify that ``commitment`` opens at ``value`` with ``blinding``.

    The group parameters and declared range come from ``commitment`` itself.
    A wrong object or field type raises :class:`TypeError`; an out-of-range
    element or value, or an incorrect opening, returns ``False``. Inputs are
    never mutated.
    """
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment")
    for name in ("element", "lower", "upper", "prime", "generator", "h"):
        _check_int(getattr(commitment, name), f"commitment {name}")
    _check_int(value, "value")
    _check_int(blinding, "blinding")
    prime = commitment.prime
    if prime <= 3:
        return False
    if not 1 < commitment.generator < prime or not 1 < commitment.h < prime:
        return False
    if not 0 < commitment.element < prime:
        return False
    if commitment.lower > commitment.upper:
        return False
    if commitment.upper - commitment.lower >= prime - 1:
        return False
    if not commitment.lower <= value <= commitment.upper:
        return False
    if not 1 <= blinding < prime - 1:
        return False
    message = value - commitment.lower
    expected = (
        pow(commitment.generator, message, prime)
        * pow(commitment.h, blinding, prime)
        % prime
    )
    return expected == commitment.element


# ---------------------------------------------------------------------------
# Non-interactive Pedersen range proofs (Schnorr OR over quantized integers)
#
# For C = g**m * h**r with m = value - lower, each offset i in [0, n) defines
# D_i = C * g**(-i) mod prime, so D_m = h**r: knowing the opening is knowing
# the base-h discrete log of D_m. The proof is a Cramer-Damgard-Schoenmakers
# OR over all n branches: every branch satisfies the Schnorr equation
# h**s_i == t_i * D_i**e_i (mod prime) and the shares sum to the Fiat-Shamir
# challenge, sum(e) % prime == c. Only the real branch is answered honestly;
# the others are simulated, so the verifier learns nothing about m.

_RANGE_DOMAIN = b"zkregion/pedersen-range/v1"
_MAX_RANGE_SIZE = 256


@dataclass(frozen=True)
class RangeProof:
    """A non-interactive Pedersen range proof.

    ``t``, ``e`` and ``s`` are integer tuples of length
    ``n = upper - lower + 1``: the per-branch commitments, challenge shares
    and responses of the Schnorr OR proof.
    """

    t: tuple[int, ...]
    e: tuple[int, ...]
    s: tuple[int, ...]


def _encode_ascii_int(value: int) -> bytes:
    """Decimal ASCII encoding of an integer (``-`` sign for negatives)."""
    return str(value).encode("ascii")


def _range_challenge(
    commitment: PedersenCommitment,
    context: bytes,
    size: int,
    t: tuple[int, ...],
) -> int:
    """SHA-256 transcript challenge as a big-endian integer mod ``prime``.

    The transcript is the domain, the six commitment fields, ``context``,
    the branch count ``n`` and every ``t``; each item is length-prefixed
    with four big-endian bytes and integers are decimal ASCII.
    """
    transcript = hashlib.sha256()
    items = [_RANGE_DOMAIN]
    items.extend(
        _encode_ascii_int(field)
        for field in (
            commitment.element,
            commitment.lower,
            commitment.upper,
            commitment.prime,
            commitment.generator,
            commitment.h,
        )
    )
    items.append(context)
    items.append(_encode_ascii_int(size))
    items.extend(_encode_ascii_int(item) for item in t)
    for item in items:
        transcript.update(len(item).to_bytes(4, "big"))
        transcript.update(item)
    return int.from_bytes(transcript.digest(), "big") % commitment.prime


def _draw_below(randbelow: Callable[[int], int], upper: int) -> int:
    drawn = randbelow(upper)
    _check_int(drawn, "randbelow return value")
    if not 0 <= drawn < upper:
        raise ValueError(f"randbelow must return a value in [0, {upper})")
    return drawn


def prove_range(
    commitment: PedersenCommitment,
    value: int,
    blinding: int,
    context: bytes = b"",
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> RangeProof:
    """Prove in zero knowledge that ``commitment`` opens inside its range.

    ``commitment`` must actually open at ``value`` with ``blinding`` — the
    opening is verified before anything is drawn — and the declared range
    must contain at most 256 integers. Returns a :class:`RangeProof` whose
    per-branch challenge shares lie in ``[0, prime)`` and whose responses
    are non-negative plain integers (not reduced modulo any group order).
    ``context`` is bound into the Fiat-Shamir transcript.

    Type errors (including a non-callable ``randbelow`` or a non-integer
    drawn from it) raise :class:`TypeError`; a failed opening, an oversized
    range or unusable group parameters raise :class:`ValueError`. Inputs
    are never mutated.
    """
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment")
    _check_bytes(context, "context")
    if not verify_pedersen_opening(commitment, value, blinding):
        raise ValueError("commitment does not open at value with blinding")
    size = commitment.upper - commitment.lower + 1
    if size > _MAX_RANGE_SIZE:
        raise ValueError("range must contain at most 256 integers")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    prime = commitment.prime
    h = commitment.h
    try:
        generator_inverse = pow(commitment.generator, -1, prime)
    except ValueError:
        raise ValueError("generator must be invertible modulo prime") from None
    bases = [
        commitment.element * pow(generator_inverse, offset, prime) % prime
        for offset in range(size)
    ]
    target = value - commitment.lower
    t: list[int] = [0] * size
    e: list[int] = [0] * size
    s: list[int] = [0] * size
    nonce = 0
    for offset in range(size):
        if offset == target:
            nonce = _draw_below(randbelow, prime - 1) + 1
            t[offset] = pow(h, nonce, prime)
        else:
            share = _draw_below(randbelow, prime)
            response = _draw_below(randbelow, prime)
            e[offset] = share
            s[offset] = response
            t[offset] = (
                pow(h, response, prime) * pow(bases[offset], -share, prime)
            ) % prime
    challenge = _range_challenge(commitment, context, size, tuple(t))
    e[target] = (challenge - sum(e)) % prime
    s[target] = nonce + e[target] * blinding
    return RangeProof(t=tuple(t), e=tuple(e), s=tuple(s))


def verify_range(
    commitment: PedersenCommitment,
    proof: RangeProof,
    context: bytes = b"",
) -> bool:
    """Verify a :class:`RangeProof` against ``commitment`` and ``context``.

    The group parameters and declared range come from ``commitment`` itself.
    A wrong object or field type raises :class:`TypeError`; out-of-range
    fields, an oversized range, malformed branch counts, tampering or a
    context/binding mismatch return ``False``. Inputs are never mutated.
    """
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment")
    if not isinstance(proof, RangeProof):
        raise TypeError("proof must be a RangeProof")
    _check_bytes(context, "context")
    for name in ("element", "lower", "upper", "prime", "generator", "h"):
        _check_int(getattr(commitment, name), f"commitment {name}")
    for name in ("t", "e", "s"):
        items = getattr(proof, name)
        if not isinstance(items, tuple):
            raise TypeError(f"proof {name} must be a tuple of integers")
        for item in items:
            _check_int(item, f"proof {name} item")
    prime = commitment.prime
    if prime <= 3:
        return False
    if not 1 < commitment.generator < prime or not 1 < commitment.h < prime:
        return False
    if not 0 < commitment.element < prime:
        return False
    if commitment.lower > commitment.upper:
        return False
    if commitment.upper - commitment.lower >= prime - 1:
        return False
    size = commitment.upper - commitment.lower + 1
    if size > _MAX_RANGE_SIZE:
        return False
    if not (len(proof.t) == len(proof.e) == len(proof.s) == size):
        return False
    if any(not 1 <= item < prime for item in proof.t):
        return False
    if any(not 0 <= item < prime for item in proof.e):
        return False
    if any(item < 0 for item in proof.s):
        return False
    challenge = _range_challenge(commitment, context, size, proof.t)
    if sum(proof.e) % prime != challenge:
        return False
    try:
        generator_inverse = pow(commitment.generator, -1, prime)
    except ValueError:
        return False
    for offset in range(size):
        base = commitment.element * pow(generator_inverse, offset, prime) % prime
        left = pow(commitment.h, proof.s[offset], prime)
        right = proof.t[offset] * pow(base, proof.e[offset], prime) % prime
        if left != right:
            return False
    return True


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
