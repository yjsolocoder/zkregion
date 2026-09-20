"""zkregion - commitments and interactive proofs for region membership.

Public API: commit / verify_opening / commit_coordinate / PedersenCommitment /
pedersen_commit / verify_pedersen_opening / RangeProof / prove_range /
verify_range / RangeBatchEntry / verify_range_batch / RegionProof /
prove_region / verify_region / RegionBatchEntry / verify_region_batch /
SchnorrProof / SchnorrBatchEntry / SchnorrProver /
SchnorrVerifier / MultiSchnorrEntry / verify_schnorr_batch /
BoundSchnorrBatch / verify_bound /
BoundRegionBatch / verify_region_bound /
BoundRangeBatch / verify_range_bound /
Region / MerkleProof / merkle_root / prove_inclusion /
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
    "BoundRangeBatch",
    "BoundRegionBatch",
    "BoundSchnorrBatch",
    "MerkleMultiProof",
    "MerkleProof",
    "MultiSchnorrEntry",
    "PedersenCommitment",
    "RangeBatchEntry",
    "RangeProof",
    "Region",
    "RegionBatchEntry",
    "RegionProof",
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
    "prove_region",
    "verify_bound",
    "verify_inclusion",
    "verify_multi_inclusion",
    "verify_opening",
    "verify_pedersen_opening",
    "verify_range",
    "verify_range_batch",
    "verify_range_bound",
    "verify_region",
    "verify_region_batch",
    "verify_region_bound",
    "verify_schnorr_batch",
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


@dataclass(frozen=True)
class MultiSchnorrEntry:
    """One item of a multi-key batch verification.

    Fields, in order: the signer's ``public_key``, the signed ``message``,
    the :class:`SchnorrProof`, then the ``context`` (empty by default) and
    the group parameters ``prime`` / ``generator`` (defaulting to
    :data:`DEFAULT_PRIME` / :data:`DEFAULT_GENERATOR`). All six are
    positional construction arguments.
    """

    public_key: int
    message: bytes
    proof: SchnorrProof
    context: bytes = b""
    prime: int = DEFAULT_PRIME
    generator: int = DEFAULT_GENERATOR


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
       demonstration trapdoor commitment; the accompanying
       :func:`prove_range` / :func:`verify_range` range proof inherits the
       same demonstration-only security level.
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
    :class:`PedersenCommitment`). Whether given explicitly or computed from
    the default, ``h`` must satisfy ``1 < h < prime``. The blinding ``r``
    defaults to ``randbelow(prime - 2) + 1`` and must lie in
    ``[1, prime - 1)``; the default source is :func:`secrets.randbelow`.

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
# Non-interactive Pedersen range proofs (Schnorr OR over the offsets)
#
# For each offset i in [0, n) define D_i = element * generator**(-i) mod prime.
# The commitment opens at value = lower + j with blinding r exactly when
# D_j = h**r, so a range proof is an OR proof: "I know the base-h discrete
# logarithm of at least one D_i". The real branch runs an honest Schnorr
# round; every other branch is simulated, and the Fiat-Shamir challenge
# shares are chosen so they sum to the transcript challenge modulo prime.

_RANGE_DOMAIN = b"zkregion/pedersen-range/v1"
_MAX_RANGE_VALUES = 256


@dataclass(frozen=True)
class RangeProof:
    """A non-interactive range proof over a :class:`PedersenCommitment`.

    ``t`` holds the per-branch announcements, ``e`` the challenge shares and
    ``s`` the responses; all three are tuples of ``upper - lower + 1``
    integers, one per integer in the declared range.
    """

    t: tuple[int, ...]
    e: tuple[int, ...]
    s: tuple[int, ...]


def _range_challenge(
    commitment: PedersenCommitment,
    context: bytes,
    size: int,
    announcements: tuple[int, ...],
) -> int:
    """SHA-256 transcript challenge as a big-endian integer mod ``prime``.

    The transcript is the domain separator, the six commitment fields, the
    context, the range size ``n`` and every announcement ``t_i``; each item
    is prefixed with its four-byte big-endian length and integers are
    encoded as decimal ASCII.
    """
    fields = (
        commitment.element,
        commitment.lower,
        commitment.upper,
        commitment.prime,
        commitment.generator,
        commitment.h,
    )
    items = [_RANGE_DOMAIN]
    items.extend(str(field).encode("ascii") for field in fields)
    items.append(context)
    items.append(str(size).encode("ascii"))
    items.extend(str(t).encode("ascii") for t in announcements)
    transcript = hashlib.sha256()
    for item in items:
        transcript.update(len(item).to_bytes(4, "big"))
        transcript.update(item)
    return int.from_bytes(transcript.digest(), "big") % commitment.prime


def _check_commitment_fields(commitment: PedersenCommitment) -> None:
    for name in ("element", "lower", "upper", "prime", "generator", "h"):
        _check_int(getattr(commitment, name), f"commitment {name}")


def prove_range(
    commitment: PedersenCommitment,
    value: int,
    blinding: int,
    context: bytes = b"",
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> RangeProof:
    """Prove that ``commitment`` opens at some value inside its declared range.

    ``value`` and ``blinding`` must be a valid opening of ``commitment``;
    the opening is verified before any proving work happens and a mismatch
    raises :class:`ValueError`. The declared range may contain at most 256
    integers; wider ranges raise :class:`ValueError`. Randomness is drawn
    from ``randbelow`` (default :func:`secrets.randbelow`); a draw that is
    not a non-bool integer raises :class:`TypeError`, an out-of-range draw
    raises :class:`ValueError`.
    """
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment")
    _check_commitment_fields(commitment)
    _check_int(value, "value")
    _check_int(blinding, "blinding")
    _check_bytes(context, "context")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    size = commitment.upper - commitment.lower + 1
    if size > _MAX_RANGE_VALUES:
        raise ValueError(
            f"range must contain at most {_MAX_RANGE_VALUES} integers"
        )
    if not verify_pedersen_opening(commitment, value, blinding):
        raise ValueError("commitment does not open at (value, blinding)")
    prime = commitment.prime
    generator = commitment.generator
    h = commitment.h

    def draw(upper: int) -> int:
        drawn = randbelow(upper)
        _check_int(drawn, "randbelow return value")
        if not 0 <= drawn < upper:
            raise ValueError(f"randbelow must return a value in [0, {upper})")
        return drawn

    index = value - commitment.lower
    offsets = [commitment.element * pow(generator, -i, prime) % prime for i in range(size)]
    t: list[int] = [0] * size
    e: list[int] = [0] * size
    s: list[int] = [0] * size
    for i in range(size):
        if i == index:
            continue
        e[i] = draw(prime)  # challenge share in [0, prime)
        s[i] = draw(prime - 1) + 1  # non-negative response
        t[i] = pow(h, s[i], prime) * pow(offsets[i], -e[i], prime) % prime
    k = draw(prime - 1) + 1
    t[index] = pow(h, k, prime)
    challenge = _range_challenge(commitment, context, size, tuple(t))
    e[index] = (challenge - sum(e)) % prime
    s[index] = k + e[index] * blinding
    return RangeProof(t=tuple(t), e=tuple(e), s=tuple(s))


def verify_range(
    commitment: PedersenCommitment,
    proof: RangeProof,
    context: bytes = b"",
) -> bool:
    """Verify a :class:`RangeProof` against ``commitment`` and ``context``.

    Every branch must satisfy the Schnorr equation
    ``h**s_i == t_i * D_i**e_i (mod prime)`` with
    ``D_i = element * generator**(-i) mod prime``, the challenge shares must
    lie in ``[0, prime)`` and sum to the transcript challenge modulo
    ``prime``, and the responses must be non-negative. Type errors (wrong
    object, non-tuple or non-integer proof fields, non-bytes context) raise
    :class:`TypeError`; any other invalid structure, tampering or binding
    mismatch — including ranges wider than 256 integers — returns ``False``.
    Inputs are never mutated.
    """
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError("commitment must be a PedersenCommitment")
    _check_commitment_fields(commitment)
    if not isinstance(proof, RangeProof):
        raise TypeError("proof must be a RangeProof")
    for field_name in ("t", "e", "s"):
        field = getattr(proof, field_name)
        if not isinstance(field, tuple):
            raise TypeError(f"proof {field_name} must be a tuple of integers")
        for item in field:
            _check_int(item, f"proof {field_name} entry")
    _check_bytes(context, "context")
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
    if size > _MAX_RANGE_VALUES:
        return False
    if not (len(proof.t) == len(proof.e) == len(proof.s) == size):
        return False
    if any(not 1 <= t_i < prime for t_i in proof.t):
        return False
    if any(not 0 <= e_i < prime for e_i in proof.e):
        return False
    if any(s_i < 0 for s_i in proof.s):
        return False
    challenge = _range_challenge(commitment, context, size, proof.t)
    if sum(proof.e) % prime != challenge:
        return False
    generator = commitment.generator
    h = commitment.h
    try:
        inverses = [pow(generator, -i, prime) for i in range(size)]
    except ValueError:
        return False  # generator not invertible modulo prime
    for i in range(size):
        offset = commitment.element * inverses[i] % prime
        left = pow(h, proof.s[i], prime)
        right = proof.t[i] * pow(offset, proof.e[i], prime) % prime
        if left != right:
            return False
    return True


@dataclass(frozen=True)
class RangeBatchEntry:
    """One item of a range batch verification.

    Fields are the :class:`PedersenCommitment`, the :class:`RangeProof` and
    the ``context`` (empty by default) — exactly the arguments of
    :func:`verify_range`, in the same order.
    """

    commitment: PedersenCommitment
    proof: RangeProof
    context: bytes = b""


def verify_range_batch(
    entries: Sequence[RangeBatchEntry],
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> bool:
    """Verify a batch of :class:`RangeProof` objects with random linear checks.

    ``entries`` must be a non-empty, non-string sequence of
    :class:`RangeBatchEntry`; an empty batch returns ``False`` and
    duplicate entries are legal (each draws its own coefficients). Every
    entry reuses the established :class:`RangeProof` transcript byte for
    byte, binding the six commitment fields, the declared range and the
    ``context``: the proof structure and tuple sizes must match, the
    ``t`` / ``e`` / ``s`` values must be in range, and the challenge
    shares must sum to the transcript challenge.

    Each range-proof branch then draws exactly one random coefficient
    ``a = r + 1`` with ``r = randbelow(prime - 1)``. Branches sharing the
    same ``(prime, generator, h)`` group are checked together with a
    single aggregate equation

    ``h**Σ(a*s) == Π(t**a * D_i**(a*e)) (mod prime)``

    where ``D_i = element * generator**(-i) mod prime`` is unchanged from
    :func:`verify_range`; per-branch results are never AND-ed together.
    Type errors — including ``bool`` integers and a non-callable
    ``randbelow`` or one that returns a non-integer — raise
    :class:`TypeError`; a coefficient outside ``[0, prime - 1)`` raises
    :class:`ValueError`. Every other invalid structure, tampering,
    commitment or context binding mismatch returns ``False``;
    short-circuiting is allowed. Missing entries cannot be detected: the
    caller guarantees the batch is complete. Inputs are never mutated.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of RangeBatchEntry")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    items = list(entries)  # copy: inputs are never mutated
    if not items:
        return False

    # group -> {"sum": Σ(a*s), "product": Π(t**a * D_i**(a*e))}
    groups: dict[tuple[int, int, int], dict[str, int]] = {}

    def add_branch(
        group_key: tuple[int, int, int],
        t_i: int,
        e_i: int,
        s_i: int,
        offset_i: int,
    ) -> None:
        prime, _generator, _h = group_key
        r = randbelow(prime - 1)
        if not isinstance(r, int) or isinstance(r, bool):
            raise TypeError("coefficient source randbelow must return an integer")
        if not 0 <= r < prime - 1:
            raise ValueError("coefficient source must satisfy 0 <= r < prime - 1")
        coefficient = r + 1
        state = groups.setdefault(group_key, {"sum": 0, "product": 1})
        state["sum"] += coefficient * s_i
        state["product"] = (
            state["product"]
            * pow(t_i, coefficient, prime)
            % prime
            * pow(offset_i, coefficient * e_i, prime)
            % prime
        )

    for position, entry in enumerate(items):
        if not isinstance(entry, RangeBatchEntry):
            raise TypeError(f"entries[{position}] must be a RangeBatchEntry")
        commitment = entry.commitment
        proof = entry.proof
        if not isinstance(commitment, PedersenCommitment):
            raise TypeError(f"entries[{position}] commitment must be a PedersenCommitment")
        _check_commitment_fields(commitment)
        if not isinstance(proof, RangeProof):
            raise TypeError(f"entries[{position}] proof must be a RangeProof")
        for field_name in ("t", "e", "s"):
            field = getattr(proof, field_name)
            if not isinstance(field, tuple):
                raise TypeError(
                    f"entries[{position}] proof {field_name} must be a tuple of integers"
                )
            for item in field:
                _check_int(item, f"entries[{position}] proof {field_name} entry")
        _check_bytes(entry.context, f"entries[{position}] context")
        try:
            prime, generator, h, size, announcements, shares, responses = (
                _range_proof_check_material(commitment, proof, entry.context)
            )
            inverses = [pow(generator, -i, prime) for i in range(size)]
        except (TypeError, ValueError):
            return False  # structural/transcript mismatch: short-circuit
        group_key = (prime, generator, h)
        for i in range(size):
            offset_i = commitment.element * inverses[i] % prime
            add_branch(
                group_key,
                announcements[i],
                shares[i],
                responses[i],
                offset_i,
            )

    for (prime, _generator, _h), state in groups.items():
        if pow(_h, state["sum"], prime) != state["product"]:
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


def verify_schnorr_batch(
    entries: Sequence[MultiSchnorrEntry],
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> bool:
    """Verify a batch of Fiat-Shamir proofs, potentially under several keys.

    Unlike :meth:`SchnorrVerifier.verify_batch`, every
    :class:`MultiSchnorrEntry` carries its own ``public_key`` and group
    parameters, so a single batch may span several signers. ``entries``
    must be a non-empty, non-string sequence of :class:`MultiSchnorrEntry`;
    an empty batch returns ``False`` and duplicate entries are legal (each
    draws its own coefficient). Every entry reuses the established
    :class:`SchnorrProof` Fiat-Shamir transcript byte for byte, recomputing
    its challenge and thereby binding all six entry fields: ``public_key``,
    ``message``, ``proof``, ``context``, ``prime`` and ``generator``.

    Each structurally valid entry draws exactly one random coefficient
    ``a = r + 1`` with ``r = randbelow(prime - 1)``. Entries sharing the
    same ``(prime, generator)`` group are checked together with a single
    aggregate equation

    ``g**Σ(a*s) == Π(t**a * public_key**(a*c)) (mod prime)``

    with each entry contributing under its own ``public_key``; per-entry
    results are never AND-ed together, and errors cannot cancel across
    different groups. Type errors — including ``bool`` integers and a
    non-callable ``randbelow`` or one that returns a non-integer — raise
    :class:`TypeError`; a coefficient outside ``[0, prime - 1)`` raises
    :class:`ValueError`. Every other invalid structure, tampering or
    binding mismatch returns ``False``; short-circuiting is allowed.
    Missing entries cannot be detected: the caller guarantees the batch
    is complete. Inputs are never mutated.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of MultiSchnorrEntry")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    items = list(entries)  # copy: inputs are never mutated
    if not items:
        return False

    # (prime, generator) -> {"sum": Σ(a*s), "product": Π(t**a * y**(a*c))}
    groups: dict[tuple[int, int], dict[str, int]] = {}

    for position, entry in enumerate(items):
        if not isinstance(entry, MultiSchnorrEntry):
            raise TypeError(f"entries[{position}] must be a MultiSchnorrEntry")
        _check_int(entry.public_key, f"entries[{position}] public_key")
        _check_bytes(entry.message, f"entries[{position}] message")
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
        _check_bytes(entry.context, f"entries[{position}] context")
        _check_int(entry.prime, f"entries[{position}] prime")
        _check_int(entry.generator, f"entries[{position}] generator")
        prime = entry.prime
        generator = entry.generator
        if prime <= 3 or not 1 < generator < prime:
            return False
        if not 0 < entry.public_key < prime:
            return False
        if not 1 <= proof.commitment < prime or proof.response < 0:
            return False  # structurally invalid proof: short-circuit
        challenge = _fs_challenge(
            prime,
            generator,
            entry.public_key,
            proof.commitment,
            entry.context,
            entry.message,
        )
        r = randbelow(prime - 1)
        if not isinstance(r, int) or isinstance(r, bool):
            raise TypeError("coefficient source randbelow must return an integer")
        if not 0 <= r < prime - 1:
            raise ValueError("coefficient source must satisfy 0 <= r < prime - 1")
        coefficient = r + 1
        state = groups.setdefault((prime, generator), {"sum": 0, "product": 1})
        state["sum"] += coefficient * proof.response
        state["product"] = (
            state["product"]
            * pow(proof.commitment, coefficient, prime)
            % prime
            * pow(entry.public_key, coefficient * challenge, prime)
            % prime
        )

    for (prime, generator), state in groups.items():
        if pow(generator, state["sum"], prime) != state["product"]:
            return False
    return True


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
# Non-interactive 2-D region membership proofs
#
# A region proof is a pair of Pedersen range proofs, one per axis: the x
# commitment must be declared over exactly [region.min_x, region.max_x] and
# the y commitment over exactly [region.min_y, region.max_y]. Each sub-proof
# is produced by prove_range under a derived context that binds the region
# domain separator, the axis label, the external context, the four region
# bounds and both commitments, so a proof cannot be replayed against another
# region, context, commitment pair or axis assignment.

_REGION_DOMAIN = b"zkregion/region/v1"


@dataclass(frozen=True)
class RegionProof:
    """A non-interactive 2-D region membership proof.

    ``x_proof`` and ``y_proof`` are :class:`RangeProof` objects over the x
    and y :class:`PedersenCommitment` respectively; the verifier learns
    nothing about the coordinates or blinding factors.
    """

    x_proof: RangeProof
    y_proof: RangeProof


def _check_region_fields(region: Region) -> None:
    for name in ("min_x", "max_x", "min_y", "max_y"):
        _check_int(getattr(region, name), f"region {name}")


def _region_sub_context(
    axis: bytes,
    context: bytes,
    region: Region,
    x_commitment: PedersenCommitment,
    y_commitment: PedersenCommitment,
) -> bytes:
    """Length-prefixed transcript context for one axis sub-proof.

    Items, in order: the region domain separator, the axis label, the
    external context, the four region bounds and the six fields of the x
    then the y commitment (dataclass field order). Every item is prefixed
    with its four-byte unsigned big-endian length; integers are encoded as
    decimal ASCII.
    """
    items = [_REGION_DOMAIN, axis, context]
    items.extend(
        str(bound).encode("ascii")
        for bound in (region.min_x, region.max_x, region.min_y, region.max_y)
    )
    for commitment in (x_commitment, y_commitment):
        items.extend(
            str(getattr(commitment, name)).encode("ascii")
            for name in ("element", "lower", "upper", "prime", "generator", "h")
        )
    transcript = bytearray()
    for item in items:
        transcript += len(item).to_bytes(4, "big")
        transcript += item
    return bytes(transcript)


def prove_region(
    x_commitment: PedersenCommitment,
    y_commitment: PedersenCommitment,
    x: int,
    y: int,
    x_blinding: int,
    y_blinding: int,
    region: Region,
    context: bytes = b"",
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> RegionProof:
    """Prove that the committed ``(x, y)`` lies inside ``region``.

    ``x_commitment`` must be declared over exactly
    ``[region.min_x, region.max_x]`` and ``y_commitment`` over exactly
    ``[region.min_y, region.max_y]``; a mismatch raises :class:`ValueError`.
    Each opening is verified (via :func:`prove_range`) before its sub-proof
    is produced, and each axis range may contain at most 256 integers —
    violations raise :class:`ValueError`. Type errors (wrong objects,
    non-integer or ``bool`` numbers, non-``bytes`` context, non-callable
    ``randbelow``) raise :class:`TypeError`. Inputs are never mutated.
    """
    if not isinstance(x_commitment, PedersenCommitment):
        raise TypeError("x_commitment must be a PedersenCommitment")
    if not isinstance(y_commitment, PedersenCommitment):
        raise TypeError("y_commitment must be a PedersenCommitment")
    _check_commitment_fields(x_commitment)
    _check_commitment_fields(y_commitment)
    _check_int(x, "x")
    _check_int(y, "y")
    _check_int(x_blinding, "x_blinding")
    _check_int(y_blinding, "y_blinding")
    if not isinstance(region, Region):
        raise TypeError("region must be a Region")
    _check_region_fields(region)
    _check_bytes(context, "context")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    if (x_commitment.lower, x_commitment.upper) != (region.min_x, region.max_x):
        raise ValueError("x commitment range must equal (region.min_x, region.max_x)")
    if (y_commitment.lower, y_commitment.upper) != (region.min_y, region.max_y):
        raise ValueError("y commitment range must equal (region.min_y, region.max_y)")
    x_proof = prove_range(
        x_commitment,
        x,
        x_blinding,
        _region_sub_context(b"x", context, region, x_commitment, y_commitment),
        randbelow=randbelow,
    )
    y_proof = prove_range(
        y_commitment,
        y,
        y_blinding,
        _region_sub_context(b"y", context, region, x_commitment, y_commitment),
        randbelow=randbelow,
    )
    return RegionProof(x_proof=x_proof, y_proof=y_proof)


def verify_region(
    x_commitment: PedersenCommitment,
    y_commitment: PedersenCommitment,
    region: Region,
    proof: RegionProof,
    context: bytes = b"",
) -> bool:
    """Verify a :class:`RegionProof` against both commitments and ``region``.

    The verifier needs only the two commitments, the region and the proof —
    never the coordinates or blinding factors. Type errors (wrong objects,
    non-integer or ``bool`` fields, non-``bytes`` context) raise
    :class:`TypeError`; a commitment range that does not equal the region
    bounds, any invalid structure, tampering, a swapped region, context or
    commitment, or swapped axes returns ``False``. Inputs are never mutated.
    """
    if not isinstance(x_commitment, PedersenCommitment):
        raise TypeError("x_commitment must be a PedersenCommitment")
    if not isinstance(y_commitment, PedersenCommitment):
        raise TypeError("y_commitment must be a PedersenCommitment")
    _check_commitment_fields(x_commitment)
    _check_commitment_fields(y_commitment)
    if not isinstance(region, Region):
        raise TypeError("region must be a Region")
    _check_region_fields(region)
    if not isinstance(proof, RegionProof):
        raise TypeError("proof must be a RegionProof")
    if not isinstance(proof.x_proof, RangeProof):
        raise TypeError("proof x_proof must be a RangeProof")
    if not isinstance(proof.y_proof, RangeProof):
        raise TypeError("proof y_proof must be a RangeProof")
    _check_bytes(context, "context")
    if (x_commitment.lower, x_commitment.upper) != (region.min_x, region.max_x):
        return False
    if (y_commitment.lower, y_commitment.upper) != (region.min_y, region.max_y):
        return False
    return verify_range(
        x_commitment,
        proof.x_proof,
        _region_sub_context(b"x", context, region, x_commitment, y_commitment),
    ) and verify_range(
        y_commitment,
        proof.y_proof,
        _region_sub_context(b"y", context, region, x_commitment, y_commitment),
    )


@dataclass(frozen=True)
class RegionBatchEntry:
    """One item of a region batch verification.

    Fields are the two :class:`PedersenCommitment` objects, the claimed
    :class:`Region`, the :class:`RegionProof` and the external ``context``
    (empty by default) — exactly the arguments of :func:`verify_region`, in
    the same order.
    """

    x_commitment: PedersenCommitment
    y_commitment: PedersenCommitment
    region: Region
    proof: RegionProof
    context: bytes = b""


def _range_proof_check_material(
    commitment: PedersenCommitment,
    proof: RangeProof,
    context: bytes,
) -> tuple[int, int, int, int, tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    """Validate one range proof structurally and return its batch material.

    This mirrors :func:`verify_range` up to (but excluding) the per-branch
    Schnorr equations: group parameters, ranges, tuple lengths, the
    ``t`` / ``e`` / ``s`` bounds and the challenge sum are all checked
    against the byte-for-byte transcript. The returned tuple is
    ``(prime, generator, h, size, t, e, s)``; ``D_i`` is recomputed by the
    caller as ``element * generator**(-i) mod prime``.
    """
    prime = commitment.prime
    generator = commitment.generator
    h = commitment.h
    if prime <= 3 or not 1 < generator < prime or not 1 < h < prime:
        raise ValueError("invalid commitment group parameters")
    if not 0 < commitment.element < prime:
        raise ValueError("commitment element out of range")
    if commitment.lower > commitment.upper:
        raise ValueError("commitment lower must not exceed upper")
    if commitment.upper - commitment.lower >= prime - 1:
        raise ValueError("commitment range width must be smaller than prime - 1")
    size = commitment.upper - commitment.lower + 1
    if size > _MAX_RANGE_VALUES:
        raise ValueError(f"range must contain at most {_MAX_RANGE_VALUES} integers")
    if not (len(proof.t) == len(proof.e) == len(proof.s) == size):
        raise ValueError("proof fields must have one entry per integer in the range")
    if any(not 1 <= t_i < prime for t_i in proof.t):
        raise ValueError("proof announcement out of range")
    if any(not 0 <= e_i < prime for e_i in proof.e):
        raise ValueError("proof challenge share out of range")
    if any(s_i < 0 for s_i in proof.s):
        raise ValueError("proof response must be non-negative")
    challenge = _range_challenge(commitment, context, size, proof.t)
    if sum(proof.e) % prime != challenge:
        raise ValueError("proof challenge shares do not sum to the transcript challenge")
    return prime, generator, h, size, proof.t, proof.e, proof.s


def verify_region_batch(
    entries: Sequence[RegionBatchEntry],
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> bool:
    """Verify a batch of :class:`RegionProof` objects with random linear checks.

    ``entries`` must be a non-empty, non-string sequence of
    :class:`RegionBatchEntry`; an empty batch returns ``False`` and
    duplicate entries are legal (each draws its own coefficients). Every
    entry is validated exactly as :func:`verify_region` would, reusing the
    established :class:`Region` and :class:`RangeProof` transcripts
    byte for byte: the commitment ranges must equal the region bounds, the
    sub-proof structure and tuple sizes must match, the ``t`` / ``e`` /
    ``s`` values must be in range, and the challenge shares must sum to
    the transcript challenge.

    Each range-proof branch then draws exactly one random coefficient
    ``a = r + 1`` with ``r = randbelow(prime - 1)``. Branches sharing the
    same ``(prime, generator, h)`` group are checked together with a
    single aggregate equation

    ``h**Σ(a*s) == Π(t**a * D_i**(a*e)) (mod prime)``

    where ``D_i = element * generator**(-i) mod prime`` is unchanged from
    :func:`verify_range`; per-branch results are never AND-ed together.
    Type errors — including ``bool`` integers and a non-callable
    ``randbelow`` or one that returns a non-integer — raise
    :class:`TypeError`; a coefficient outside ``[0, prime - 1)`` raises
    :class:`ValueError`. Every other invalid structure, tampering, region,
    commitment or context binding mismatch, cross-item recombination or
    sub-proof count error returns ``False``; short-circuiting is allowed.
    Missing entries cannot be detected: the caller guarantees the batch
    is complete. Inputs are never mutated.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of RegionBatchEntry")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    items = list(entries)  # copy: inputs are never mutated
    if not items:
        return False

    # group -> {"sum": Σ(a*s), "product": Π(t**a * D_i**(a*e))}
    groups: dict[tuple[int, int, int], dict[str, int]] = {}

    def add_branch(
        group_key: tuple[int, int, int],
        t_i: int,
        e_i: int,
        s_i: int,
        offset_i: int,
    ) -> None:
        prime, _generator, _h = group_key
        r = randbelow(prime - 1)
        if not isinstance(r, int) or isinstance(r, bool):
            raise TypeError("coefficient source randbelow must return an integer")
        if not 0 <= r < prime - 1:
            raise ValueError("coefficient source must satisfy 0 <= r < prime - 1")
        coefficient = r + 1
        state = groups.setdefault(group_key, {"sum": 0, "product": 1})
        state["sum"] += coefficient * s_i
        state["product"] = (
            state["product"]
            * pow(t_i, coefficient, prime)
            % prime
            * pow(offset_i, coefficient * e_i, prime)
            % prime
        )

    for position, entry in enumerate(items):
        if not isinstance(entry, RegionBatchEntry):
            raise TypeError(f"entries[{position}] must be a RegionBatchEntry")
        x_commitment = entry.x_commitment
        y_commitment = entry.y_commitment
        region = entry.region
        proof = entry.proof
        if not isinstance(x_commitment, PedersenCommitment):
            raise TypeError(f"entries[{position}] x_commitment must be a PedersenCommitment")
        if not isinstance(y_commitment, PedersenCommitment):
            raise TypeError(f"entries[{position}] y_commitment must be a PedersenCommitment")
        _check_commitment_fields(x_commitment)
        _check_commitment_fields(y_commitment)
        if not isinstance(region, Region):
            raise TypeError(f"entries[{position}] region must be a Region")
        _check_region_fields(region)
        if not isinstance(proof, RegionProof):
            raise TypeError(f"entries[{position}] proof must be a RegionProof")
        if not isinstance(proof.x_proof, RangeProof):
            raise TypeError(f"entries[{position}] proof x_proof must be a RangeProof")
        if not isinstance(proof.y_proof, RangeProof):
            raise TypeError(f"entries[{position}] proof y_proof must be a RangeProof")
        for axis_name, sub_proof in (("x", proof.x_proof), ("y", proof.y_proof)):
            for field_name in ("t", "e", "s"):
                field = getattr(sub_proof, field_name)
                if not isinstance(field, tuple):
                    raise TypeError(
                        f"entries[{position}] {axis_name}_proof {field_name} "
                        "must be a tuple of integers"
                    )
                for item in field:
                    _check_int(
                        item,
                        f"entries[{position}] {axis_name}_proof {field_name} entry",
                    )
        _check_bytes(entry.context, f"entries[{position}] context")
        if (x_commitment.lower, x_commitment.upper) != (region.min_x, region.max_x):
            return False
        if (y_commitment.lower, y_commitment.upper) != (region.min_y, region.max_y):
            return False
        axes = (
            (
                b"x",
                x_commitment,
                proof.x_proof,
                _region_sub_context(b"x", entry.context, region, x_commitment, y_commitment),
            ),
            (
                b"y",
                y_commitment,
                proof.y_proof,
                _region_sub_context(b"y", entry.context, region, x_commitment, y_commitment),
            ),
        )
        for _axis, commitment, sub_proof, sub_context in axes:
            try:
                prime, generator, h, size, announcements, shares, responses = (
                    _range_proof_check_material(commitment, sub_proof, sub_context)
                )
                inverses = [pow(generator, -i, prime) for i in range(size)]
            except (TypeError, ValueError):
                return False  # structural/transcript mismatch: short-circuit
            group_key = (prime, generator, h)
            for i in range(size):
                offset_i = commitment.element * inverses[i] % prime
                add_branch(
                    group_key,
                    announcements[i],
                    shares[i],
                    responses[i],
                    offset_i,
                )

    for (prime, generator, h), state in groups.items():
        if pow(h, state["sum"], prime) != state["product"]:
            return False
    return True


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


# ---------------------------------------------------------------------------
# Merkle-committed Schnorr batches
#
# A complete multi-key Schnorr batch frozen together with the Merkle proof
# that commits to every entry. Each Merkle leaf is the established Schnorr
# Fiat-Shamir transcript (seven length-framed items) with one extra framed
# item appended: the shortest unsigned big-endian encoding of the proof
# response. Verification first checks every leaf against the Merkle root,
# then runs the unchanged multi-key batch signature verification.


@dataclass(frozen=True)
class BoundSchnorrBatch:
    """A complete Schnorr batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a tuple of :class:`MultiSchnorrEntry`;
    ``leaf_count`` — a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``; ``proof`` — the
    :class:`MerkleMultiProof` whose indices cover ``0 .. leaf_count - 1``
    without gaps or duplicates. All three are positional construction
    arguments; batches compare by value and are immutable.
    """

    entries: tuple[MultiSchnorrEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_schnorr_leaf(entry: MultiSchnorrEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`MultiSchnorrEntry`.

    The leaf is the seven Fiat-Shamir transcript items — domain separator,
    ``prime``, ``generator``, ``public_key``, commitment, ``context`` and
    ``message`` — each prefixed with its four-byte unsigned big-endian
    length (integers in shortest unsigned big-endian encoding), followed by
    the response framed the same way.
    """
    items = (
        _FS_DOMAIN,
        _encode_int(entry.prime),
        _encode_int(entry.generator),
        _encode_int(entry.public_key),
        _encode_int(entry.proof.commitment),
        entry.context,
        entry.message,
        _encode_int(entry.proof.response),
    )
    leaf = bytearray()
    for item in items:
        leaf += len(item).to_bytes(4, "big")
        leaf += item
    return bytes(leaf)


def verify_bound(
    batch: BoundSchnorrBatch,
    root: bytes,
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundSchnorrBatch`.

    The Merkle binding is checked first: every entry is encoded to its leaf
    exactly as specified by :func:`_bound_schnorr_leaf` and the whole batch
    is checked against ``root`` with :func:`verify_multi_inclusion`.
    ``leaf_count`` must be a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``, and ``proof.indices`` must
    cover ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering;
    an empty batch, a missing entry or any index mismatch returns ``False``.
    Only after the root checks does the batch go through
    :func:`verify_schnorr_batch` with the same ``randbelow``, under its
    unchanged randomness contract: it is called once per structurally
    valid entry as ``randbelow(prime - 1)``.

    Type errors — a batch that is not a :class:`BoundSchnorrBatch`,
    non-tuple entries, non-:class:`MultiSchnorrEntry` items, a non-integer
    or ``bool`` ``leaf_count``, a wrong proof/root object, malformed nested
    field types, or a non-callable ``randbelow`` — raise
    :class:`TypeError`; every other invalidity (including bad randomness
    outcomes surfaced by :func:`verify_schnorr_batch` per its own contract)
    behaves exactly as the delegated calls do. Inputs are never mutated.
    """
    if not isinstance(batch, BoundSchnorrBatch):
        raise TypeError("batch must be a BoundSchnorrBatch")
    _check_bytes(root, "root")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError("batch entries must be a tuple of MultiSchnorrEntry")
    leaf_count = batch.leaf_count
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool):
        raise TypeError("batch leaf_count must be an integer")
    proof = batch.proof
    if not isinstance(proof, MerkleMultiProof):
        raise TypeError("batch proof must be a MerkleMultiProof")
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
    for position, entry in enumerate(entries):
        if not isinstance(entry, MultiSchnorrEntry):
            raise TypeError(f"entries[{position}] must be a MultiSchnorrEntry")
        _check_int(entry.public_key, f"entries[{position}] public_key")
        _check_bytes(entry.message, f"entries[{position}] message")
        entry_proof = entry.proof
        if not isinstance(entry_proof, SchnorrProof):
            raise TypeError(f"entries[{position}] proof must be a SchnorrProof")
        if (
            not isinstance(entry_proof.commitment, int)
            or isinstance(entry_proof.commitment, bool)
            or not isinstance(entry_proof.response, int)
            or isinstance(entry_proof.response, bool)
        ):
            raise TypeError(
                f"entries[{position}] proof commitment and response must be integers"
            )
        _check_bytes(entry.context, f"entries[{position}] context")
        _check_int(entry.prime, f"entries[{position}] prime")
        _check_int(entry.generator, f"entries[{position}] generator")

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    # The leaf encoding is unsigned, so a negative integer cannot be framed;
    # every other structural check (group parameters, ranges) is left to
    # verify_schnorr_batch so the Merkle root is always examined first.
    for entry in entries:
        if min(
            entry.prime,
            entry.generator,
            entry.public_key,
            entry.proof.commitment,
            entry.proof.response,
        ) < 0:
            return False

    leaves = [_bound_schnorr_leaf(entry) for entry in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged multi-key batch verification checks the signatures
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_schnorr_batch(entries, randbelow=randbelow)


# ---------------------------------------------------------------------------
# Merkle-committed region batches
#
# A complete region batch frozen together with the Merkle proof that commits
# to every entry. Each Merkle leaf starts from the domain separator
# b"zkregion/region-bound/v1" and frames, in order, the six fields of the x
# then the y commitment, the four region bounds and the context, then the
# t / e / s sequences of the x and the y sub-proof (each sequence framed as
# its decimal element count followed by every value). Verification first
# checks every leaf against the Merkle root, then runs the unchanged region
# batch verification.

_REGION_BOUND_DOMAIN = b"zkregion/region-bound/v1"


@dataclass(frozen=True)
class BoundRegionBatch:
    """A complete region batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a tuple of :class:`RegionBatchEntry`;
    ``leaf_count`` — a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``; ``proof`` — the
    :class:`MerkleMultiProof` whose indices cover ``0 .. leaf_count - 1``
    without gaps or duplicates. All three are positional construction
    arguments; batches compare by value and are immutable.
    """

    entries: tuple[RegionBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_region_leaf(entry: RegionBatchEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`RegionBatchEntry`.

    Items, in order: the domain separator, the six fields of the x then the
    y commitment (dataclass field order), the four region bounds, the
    context, then for the x and the y sub-proof each of the ``t`` / ``e`` /
    ``s`` sequences framed as its decimal element count followed by every
    value. Every item is prefixed with its four-byte unsigned big-endian
    length; integers are encoded as decimal ASCII (negative sign kept).
    """
    items = [_REGION_BOUND_DOMAIN]
    for commitment in (entry.x_commitment, entry.y_commitment):
        items.extend(
            str(getattr(commitment, name)).encode("ascii")
            for name in ("element", "lower", "upper", "prime", "generator", "h")
        )
    items.extend(
        str(bound).encode("ascii")
        for bound in (
            entry.region.min_x,
            entry.region.max_x,
            entry.region.min_y,
            entry.region.max_y,
        )
    )
    items.append(entry.context)
    for sub_proof in (entry.proof.x_proof, entry.proof.y_proof):
        for field_name in ("t", "e", "s"):
            sequence = getattr(sub_proof, field_name)
            items.append(str(len(sequence)).encode("ascii"))
            items.extend(str(value).encode("ascii") for value in sequence)
    leaf = bytearray()
    for item in items:
        leaf += len(item).to_bytes(4, "big")
        leaf += item
    return bytes(leaf)


def verify_region_bound(
    batch: BoundRegionBatch,
    root: bytes,
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundRegionBatch`.

    The Merkle binding is checked first: every entry is encoded to its leaf
    exactly as specified by :func:`_bound_region_leaf` and the whole batch
    is checked against ``root`` with :func:`verify_multi_inclusion`.
    ``leaf_count`` must be a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``, and ``proof.indices`` must
    cover ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering;
    an empty batch, a missing entry or any index mismatch returns ``False``.
    Only after the root checks does the batch go through
    :func:`verify_region_batch` with the same ``randbelow``, under its
    unchanged randomness contract: it is called once per structurally
    valid range-proof branch as ``randbelow(prime - 1)``.

    Type errors — a batch that is not a :class:`BoundRegionBatch`,
    non-tuple entries, non-:class:`RegionBatchEntry` items, a non-integer
    or ``bool`` ``leaf_count``, a wrong proof/root object, malformed nested
    field types, or a non-callable ``randbelow`` — raise
    :class:`TypeError`; every other invalidity (including bad randomness
    outcomes surfaced by :func:`verify_region_batch` per its own contract)
    behaves exactly as the delegated calls do. Inputs are never mutated.
    """
    if not isinstance(batch, BoundRegionBatch):
        raise TypeError("batch must be a BoundRegionBatch")
    _check_bytes(root, "root")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError("batch entries must be a tuple of RegionBatchEntry")
    leaf_count = batch.leaf_count
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool):
        raise TypeError("batch leaf_count must be an integer")
    proof = batch.proof
    if not isinstance(proof, MerkleMultiProof):
        raise TypeError("batch proof must be a MerkleMultiProof")
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
    for position, entry in enumerate(entries):
        if not isinstance(entry, RegionBatchEntry):
            raise TypeError(f"entries[{position}] must be a RegionBatchEntry")
        x_commitment = entry.x_commitment
        y_commitment = entry.y_commitment
        region = entry.region
        entry_proof = entry.proof
        if not isinstance(x_commitment, PedersenCommitment):
            raise TypeError(f"entries[{position}] x_commitment must be a PedersenCommitment")
        if not isinstance(y_commitment, PedersenCommitment):
            raise TypeError(f"entries[{position}] y_commitment must be a PedersenCommitment")
        _check_commitment_fields(x_commitment)
        _check_commitment_fields(y_commitment)
        if not isinstance(region, Region):
            raise TypeError(f"entries[{position}] region must be a Region")
        _check_region_fields(region)
        if not isinstance(entry_proof, RegionProof):
            raise TypeError(f"entries[{position}] proof must be a RegionProof")
        if not isinstance(entry_proof.x_proof, RangeProof):
            raise TypeError(f"entries[{position}] proof x_proof must be a RangeProof")
        if not isinstance(entry_proof.y_proof, RangeProof):
            raise TypeError(f"entries[{position}] proof y_proof must be a RangeProof")
        for axis_name, sub_proof in (("x", entry_proof.x_proof), ("y", entry_proof.y_proof)):
            for field_name in ("t", "e", "s"):
                field = getattr(sub_proof, field_name)
                if not isinstance(field, tuple):
                    raise TypeError(
                        f"entries[{position}] {axis_name}_proof {field_name} "
                        "must be a tuple of integers"
                    )
                for item in field:
                    _check_int(
                        item,
                        f"entries[{position}] {axis_name}_proof {field_name} entry",
                    )
        _check_bytes(entry.context, f"entries[{position}] context")

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    leaves = [_bound_region_leaf(entry) for entry in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged region batch verification checks the sub-proofs
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_region_batch(entries, randbelow=randbelow)


# ---------------------------------------------------------------------------
# Merkle-committed range batches
#
# A complete range batch frozen together with the Merkle proof that commits
# to every entry. Each Merkle leaf starts from the domain separator
# b"zkregion/range-bound/v1" and frames, in order, the six commitment fields
# and the context, then the t / e / s sequences of the range proof (each
# sequence framed as its decimal element count followed by every value) —
# the same framing rules as the Merkle-committed region batch. Verification
# first checks every leaf against the Merkle root, then runs the unchanged
# range batch verification.

_RANGE_BOUND_DOMAIN = b"zkregion/range-bound/v1"


@dataclass(frozen=True)
class BoundRangeBatch:
    """A complete range batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a tuple of :class:`RangeBatchEntry`;
    ``leaf_count`` — a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``; ``proof`` — the
    :class:`MerkleMultiProof` whose indices cover ``0 .. leaf_count - 1``
    without gaps or duplicates. All three are positional construction
    arguments; batches compare by value and are immutable.
    """

    entries: tuple[RangeBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_range_leaf(entry: RangeBatchEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`RangeBatchEntry`.

    Items, in order: the domain separator, the six commitment fields
    (dataclass field order), the context, then each of the proof's ``t`` /
    ``e`` / ``s`` sequences framed as its decimal element count followed by
    every value. Every item is prefixed with its four-byte unsigned
    big-endian length; integers are encoded as decimal ASCII (negative sign
    kept) — the framing rules of :func:`_bound_region_leaf`.
    """
    items = [_RANGE_BOUND_DOMAIN]
    items.extend(
        str(getattr(entry.commitment, name)).encode("ascii")
        for name in ("element", "lower", "upper", "prime", "generator", "h")
    )
    items.append(entry.context)
    for field_name in ("t", "e", "s"):
        sequence = getattr(entry.proof, field_name)
        items.append(str(len(sequence)).encode("ascii"))
        items.extend(str(value).encode("ascii") for value in sequence)
    leaf = bytearray()
    for item in items:
        leaf += len(item).to_bytes(4, "big")
        leaf += item
    return bytes(leaf)


def verify_range_bound(
    batch: BoundRangeBatch,
    root: bytes,
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundRangeBatch`.

    The Merkle binding is checked first: every entry is encoded to its leaf
    exactly as specified by :func:`_bound_range_leaf` and the whole batch
    is checked against ``root`` with :func:`verify_multi_inclusion`.
    ``leaf_count`` must be a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``, and ``proof.indices`` must
    cover ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering;
    an empty batch, a missing entry or any index mismatch returns ``False``.
    Only after the root checks does the batch go through
    :func:`verify_range_batch` with the same ``randbelow``, under its
    unchanged randomness contract: it is called once per structurally
    valid range-proof branch as ``randbelow(prime - 1)``.

    Type errors — a batch that is not a :class:`BoundRangeBatch`,
    non-tuple entries, non-:class:`RangeBatchEntry` items, a non-integer
    or ``bool`` ``leaf_count``, a wrong proof/root object, malformed nested
    field types, or a non-callable ``randbelow`` — raise
    :class:`TypeError`; every other invalidity (including bad randomness
    outcomes surfaced by :func:`verify_range_batch` per its own contract)
    behaves exactly as the delegated calls do. Inputs are never mutated.
    """
    if not isinstance(batch, BoundRangeBatch):
        raise TypeError("batch must be a BoundRangeBatch")
    _check_bytes(root, "root")
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError("batch entries must be a tuple of RangeBatchEntry")
    leaf_count = batch.leaf_count
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool):
        raise TypeError("batch leaf_count must be an integer")
    proof = batch.proof
    if not isinstance(proof, MerkleMultiProof):
        raise TypeError("batch proof must be a MerkleMultiProof")
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
    for position, entry in enumerate(entries):
        if not isinstance(entry, RangeBatchEntry):
            raise TypeError(f"entries[{position}] must be a RangeBatchEntry")
        commitment = entry.commitment
        entry_proof = entry.proof
        if not isinstance(commitment, PedersenCommitment):
            raise TypeError(f"entries[{position}] commitment must be a PedersenCommitment")
        _check_commitment_fields(commitment)
        if not isinstance(entry_proof, RangeProof):
            raise TypeError(f"entries[{position}] proof must be a RangeProof")
        for field_name in ("t", "e", "s"):
            field = getattr(entry_proof, field_name)
            if not isinstance(field, tuple):
                raise TypeError(
                    f"entries[{position}] proof {field_name} must be a tuple of integers"
                )
            for item in field:
                _check_int(item, f"entries[{position}] proof {field_name} entry")
        _check_bytes(entry.context, f"entries[{position}] context")

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    leaves = [_bound_range_leaf(entry) for entry in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged range batch verification checks the proofs
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_range_batch(entries, randbelow=randbelow)
