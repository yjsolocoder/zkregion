"""zkregion - commitments and interactive proofs for region membership.

Public API: commit / verify_opening / OpeningBatchEntry /
verify_opening_batch / BoundOpeningBatch /
prove_opening_batch_bound / verify_opening_batch_bound /
OpeningBatchReplayGuard /
BoundOpeningReplayGuard /
commit_coordinate / PedersenCommitment /
pedersen_commit / verify_pedersen_opening / PedersenOpeningBatchEntry /
verify_pedersen_opening_batch / BoundPedersenOpeningBatch /
prove_pedersen_opening_batch_bound /
verify_pedersen_opening_batch_bound /
PedersenOpeningBatchReplayGuard /
BoundPedersenOpeningReplayGuard /
RangeProof / prove_range /
verify_range / RangeBatchEntry / verify_range_batch / RegionProof /
prove_region / verify_region / region_contains_committed /
RegionContainsEntry / verify_region_contains_batch /
BoundRegionContainsBatch / prove_region_contains_bound /
verify_region_contains_bound /
RegionBatchEntry / verify_region_batch /
RegionBatchReplayGuard /
SchnorrProof / SchnorrBatchEntry / SchnorrProver /
SchnorrVerifier / MultiSchnorrEntry / verify_schnorr_batch /
SchnorrBatchReplayGuard /
RangeBatchReplayGuard /
BoundSchnorrBatch / verify_bound /
SingleKeyBoundBatch / SchnorrVerifier.verify_bound_batch /
BoundRegionBatch / verify_region_bound /
BoundRangeBatch / verify_range_bound /
BoundSchnorrReplayGuard /
MerkleConsistencyChainReplayGuard /
MerkleConsistencyChainBatchReplayGuard /
MerkleConsistencyReplayGuard /
MerkleConsistencyBatchReplayGuard /
MerkleInclusionReplayGuard /
MerkleMultiReplayGuard /
MerkleMultiBatchReplayGuard /
BoundRegionReplayGuard /
BoundRangeReplayGuard /
BoundConsistencyReplayGuard /
BoundConsistencyChainReplayGuard /
ReplayBinding / ReplayGuard / SQLiteReplayStore /
RangeReplayGuard / RegionReplayGuard /
Region / MerkleProof / merkle_root / prove_inclusion /
verify_inclusion / MerkleInclusionBatchEntry / verify_inclusion_batch /
BoundMerkleInclusionBatch / prove_inclusion_batch_bound /
verify_inclusion_batch_bound /
BoundMerkleInclusionBatchReplayGuard /
MerkleMultiProof / prove_multi_inclusion /
verify_multi_inclusion / MerkleMultiBatchEntry /
verify_multi_inclusion_batch / BoundMerkleMultiBatch /
prove_multi_inclusion_batch_bound /
verify_multi_inclusion_batch_bound /
MerkleConsistencyProof / prove_consistency /
verify_consistency / MerkleConsistencyBatchEntry /
verify_consistency_batch / BoundConsistencyBatch /
prove_consistency_batch_bound /
verify_consistency_batch_bound / MerkleConsistencyChain /
prove_consistency_chain / verify_consistency_chain /
verify_consistency_chain_batch /
BoundConsistencyChainBatch /
prove_consistency_chain_batch_bound /
verify_consistency_chain_batch_bound /
BoundConsistencyChainReplayGuard.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable

__all__ = [
    "DEFAULT_GENERATOR",
    "DEFAULT_PRIME",
    "BoundConsistencyBatch",
    "BoundConsistencyChainBatch",
    "BoundConsistencyChainReplayGuard",
    "BoundConsistencyReplayGuard",
    "BoundMerkleInclusionBatch",
    "BoundMerkleInclusionBatchReplayGuard",
    "BoundMerkleMultiBatch",
    "BoundMerkleMultiBatchReplayGuard",
    "BoundOpeningBatch",
    "BoundOpeningReplayGuard",
    "BoundPedersenOpeningBatch",
    "BoundPedersenOpeningReplayGuard",
    "BoundRangeBatch",
    "BoundRegionBatch",
    "BoundRegionContainsBatch",
    "BoundRegionReplayGuard",
    "BoundRangeReplayGuard",
    "BoundSchnorrBatch",
    "BoundSchnorrReplayGuard",
    "MerkleConsistencyBatchEntry",
    "MerkleConsistencyBatchReplayGuard",
    "MerkleConsistencyChain",
    "MerkleConsistencyChainBatchReplayGuard",
    "MerkleConsistencyChainReplayGuard",
    "MerkleConsistencyProof",
    "MerkleConsistencyReplayGuard",
    "MerkleInclusionBatchEntry",
    "MerkleInclusionBatchReplayGuard",
    "MerkleInclusionReplayGuard",
    "MerkleMultiBatchEntry",
    "MerkleMultiBatchReplayGuard",
    "MerkleMultiProof",
    "MerkleMultiReplayGuard",
    "MerkleProof",
    "MultiSchnorrEntry",
    "OpeningBatchEntry",
    "OpeningBatchReplayGuard",
    "PedersenCommitment",
    "PedersenOpeningBatchEntry",
    "PedersenOpeningBatchReplayGuard",
    "RangeBatchEntry",
    "RangeBatchReplayGuard",
    "RangeProof",
    "RangeReplayGuard",
    "Region",
    "RegionBatchEntry",
    "RegionBatchReplayGuard",
    "RegionContainsEntry",
    "RegionProof",
    "RegionReplayGuard",
    "ReplayBinding",
    "ReplayGuard",
    "SchnorrBatchEntry",
    "SchnorrBatchReplayGuard",
    "SchnorrProof",
    "SchnorrProver",
    "SchnorrVerifier",
    "SQLiteReplayStore",
    "SingleKeyBatchGuard",
    "SingleKeyBoundBatch",
    "SingleKeyBoundReplayGuard",
    "commit",
    "commit_coordinate",
    "merkle_root",
    "pedersen_commit",
    "prove_consistency",
    "prove_consistency_batch_bound",
    "prove_consistency_chain",
    "prove_consistency_chain_batch_bound",
    "prove_inclusion",
    "prove_inclusion_batch_bound",
    "prove_multi_inclusion",
    "prove_multi_inclusion_batch_bound",
    "prove_opening_batch_bound",
    "prove_pedersen_opening_batch_bound",
    "prove_range",
    "prove_range_batch_bound",
    "prove_region",
    "prove_region_batch_bound",
    "prove_region_contains_bound",
    "prove_schnorr_batch_bound",
    "region_contains_committed",
    "verify_bound",
    "verify_consistency",
    "verify_consistency_batch",
    "verify_consistency_batch_bound",
    "verify_consistency_chain",
    "verify_consistency_chain_batch",
    "verify_consistency_chain_batch_bound",
    "verify_inclusion",
    "verify_inclusion_batch",
    "verify_inclusion_batch_bound",
    "verify_multi_inclusion",
    "verify_multi_inclusion_batch",
    "verify_multi_inclusion_batch_bound",
    "verify_opening",
    "verify_opening_batch",
    "verify_opening_batch_bound",
    "verify_pedersen_opening",
    "verify_pedersen_opening_batch",
    "verify_pedersen_opening_batch_bound",
    "verify_range",
    "verify_range_batch",
    "verify_range_bound",
    "verify_region",
    "verify_region_batch",
    "verify_region_bound",
    "verify_region_contains_batch",
    "verify_region_contains_bound",
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
class OpeningBatchEntry:
    """One item of a hash-commitment opening batch verification.

    Fields, in order: ``commitment``, ``value`` and ``nonce`` (all
    ``bytes``) — exactly the arguments of :func:`verify_opening`, in the
    same order. All three are positional construction arguments; entries
    compare by value and are immutable.
    """

    commitment: bytes
    value: bytes
    nonce: bytes


def _check_opening_batch_entries_types(
    entries: object,
) -> list[OpeningBatchEntry]:
    """Validate the opening-batch ``entries`` argument types.

    Mirrors the type expectations of :func:`verify_opening` for *every*
    entry before any verification runs: ``entries`` must be a
    non-``bytes`` / ``bytearray`` / ``str`` sequence of
    :class:`OpeningBatchEntry` objects whose ``commitment`` / ``value``
    / ``nonce`` are all ``bytes``. The whole batch is walked (a bad type
    in a later entry still raises), and the entries are copied into a
    fresh list so the inputs are never mutated. An empty batch is left
    to :func:`verify_opening_batch` to reject with ``False``; value
    problems (a mismatching commitment or nonce) are left to
    :func:`verify_opening` during verification.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of OpeningBatchEntry")
    items: list[OpeningBatchEntry] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, OpeningBatchEntry):
            raise TypeError(f"entries[{position}] must be an OpeningBatchEntry")
        _check_bytes(entry.commitment, f"entries[{position}] commitment")
        _check_bytes(entry.value, f"entries[{position}] value")
        _check_bytes(entry.nonce, f"entries[{position}] nonce")
        items.append(entry)
    return items


def verify_opening_batch(entries: Sequence[OpeningBatchEntry]) -> bool:
    """Check several independent hash-commitment openings.

    ``entries`` must be a non-``bytes`` / ``bytearray`` / ``str``
    sequence of :class:`OpeningBatchEntry`; an empty batch returns
    ``False`` and lists, tuples and duplicate entries are legal. The
    nested types of the *whole* batch are preflighted first, so a wrong
    type in any entry — including a later one — raises
    :class:`TypeError` rather than being converted into a batch
    rejection (returning ``False``). Each entry is then checked, in
    order, with :func:`verify_opening` against its ``commitment``,
    ``value`` and ``nonce`` fields; the first entry that returns
    ``False`` short-circuits the batch. Entries are independent of one
    another, and no hash encoding or cryptographic aggregation is added.
    Inputs are never mutated.
    """
    items = _check_opening_batch_entries_types(entries)
    if not items:
        return False
    for entry in items:
        if not verify_opening(entry.commitment, entry.value, entry.nonce):
            return False
    return True


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


@dataclass(frozen=True)
class PedersenOpeningBatchEntry:
    """One item of a Pedersen opening batch verification.

    Fields, in order: ``commitment`` (:class:`PedersenCommitment`),
    ``value`` and ``blinding`` (both non-``bool`` integers) — exactly
    the arguments of :func:`verify_pedersen_opening`, in the same order.
    All three are positional construction arguments; entries compare by
    value and are immutable.
    """

    commitment: PedersenCommitment
    value: int
    blinding: int


def _check_pedersen_opening_batch_entries_types(
    entries: object,
) -> list[PedersenOpeningBatchEntry]:
    """Validate the Pedersen-opening-batch ``entries`` argument types.

    Mirrors the type checks of :func:`verify_pedersen_opening` for
    *every* entry before any verification runs: ``entries`` must be a
    non-``bytes`` / ``bytearray`` / ``str`` sequence of
    :class:`PedersenOpeningBatchEntry` objects whose ``commitment`` is a
    :class:`PedersenCommitment` with non-``bool`` integer
    ``element`` / ``lower`` / ``upper`` / ``prime`` / ``generator`` /
    ``h`` fields and whose ``value`` / ``blinding`` are non-``bool``
    integers. The whole batch is walked (a bad type in a later entry
    still raises), and the entries are copied into a fresh list so the
    inputs are never mutated. An empty batch is left to
    :func:`verify_pedersen_opening_batch` to reject with ``False``;
    value problems (out-of-range parameters, a value outside the
    declared range or an incorrect opening) are left to
    :func:`verify_pedersen_opening` during verification.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of PedersenOpeningBatchEntry")
    items: list[PedersenOpeningBatchEntry] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, PedersenOpeningBatchEntry):
            raise TypeError(
                f"entries[{position}] must be a PedersenOpeningBatchEntry"
            )
        commitment = entry.commitment
        if not isinstance(commitment, PedersenCommitment):
            raise TypeError(
                f"entries[{position}] commitment must be a PedersenCommitment"
            )
        for name in ("element", "lower", "upper", "prime", "generator", "h"):
            _check_int(
                getattr(commitment, name),
                f"entries[{position}] commitment {name}",
            )
        _check_int(entry.value, f"entries[{position}] value")
        _check_int(entry.blinding, f"entries[{position}] blinding")
        items.append(entry)
    return items


def verify_pedersen_opening_batch(
    entries: Sequence[PedersenOpeningBatchEntry],
) -> bool:
    """Check several independent Pedersen commitment openings.

    ``entries`` must be a non-``bytes`` / ``bytearray`` / ``str``
    sequence of :class:`PedersenOpeningBatchEntry`; an empty batch
    returns ``False`` and lists, tuples and duplicate entries are legal.
    The nested types of the *whole* batch are preflighted first, so a
    wrong type in any entry — including a later one, and including a
    ``bool`` passed as an integer — raises :class:`TypeError` rather
    than being converted into a batch rejection (returning ``False``).
    Each entry is then checked, in order, with
    :func:`verify_pedersen_opening` against its ``commitment``,
    ``value`` and ``blinding`` fields, reusing its group-parameter,
    declared-range and opening rules; the first entry that returns
    ``False`` short-circuits the batch. Entries are independent of one
    another: their commitments and ranges need not relate, and no
    encoding or cryptographic aggregation is added. Inputs are never
    mutated.
    """
    items = _check_pedersen_opening_batch_entries_types(entries)
    if not items:
        return False
    for entry in items:
        if not verify_pedersen_opening(entry.commitment, entry.value, entry.blinding):
            return False
    return True


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

    def verify_bound_batch(
        self,
        batch: "SingleKeyBoundBatch",
        root: bytes,
        *,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify a Merkle-committed complete :class:`SingleKeyBoundBatch`.

        Every entry is checked against this verifier's fixed public key and
        group: each entry's ``message``, ``proof`` and ``context`` are lifted
        into a :class:`MultiSchnorrEntry` carrying ``public_key`` /
        ``prime`` / ``generator`` of this verifier, and the committed leaf
        reuses the established BoundSchnorr encoding byte for byte (see
        :func:`_bound_schnorr_leaf`). The whole batch is then checked
        against ``root`` with :func:`verify_multi_inclusion`; ``leaf_count``
        must be a positive, non-``bool`` integer equal to both
        ``len(entries)`` and ``proof.leaf_count``, and ``proof.indices``
        must equal ``tuple(range(leaf_count))`` — an empty batch, a missing
        entry, a gap, duplicate or reordering returns ``False``. Only after
        the root checks does :meth:`verify_batch` run with ``randbelow``
        passed through unchanged, so no randomness is drawn when the Merkle
        binding fails.

        Type errors — a batch that is not a :class:`SingleKeyBoundBatch`,
        non-tuple entries, non-:class:`SchnorrBatchEntry` items, a
        non-integer or ``bool`` ``leaf_count``, a wrong proof/root object,
        malformed nested field types, or a non-callable ``randbelow`` —
        raise :class:`TypeError`; out-of-range randomness surfaces as
        :class:`ValueError` from :meth:`verify_batch`; every other
        invalidity returns ``False``. Inputs are never mutated.
        """
        if not isinstance(batch, SingleKeyBoundBatch):
            raise TypeError("batch must be a SingleKeyBoundBatch")
        _check_bytes(root, "root")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        entries = batch.entries
        if not isinstance(entries, tuple):
            raise TypeError("batch entries must be a tuple of SchnorrBatchEntry")
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
            if not isinstance(entry, SchnorrBatchEntry):
                raise TypeError(f"entries[{position}] must be a SchnorrBatchEntry")
            _check_bytes(entry.message, f"entries[{position}] message")
            _check_bytes(entry.context, f"entries[{position}] context")
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

        if leaf_count < 1:
            return False
        if leaf_count != len(entries) or leaf_count != proof.leaf_count:
            return False
        if proof.indices != tuple(range(leaf_count)):
            return False  # empty coverage, gaps, duplicates or reordering

        # The leaf encoding is unsigned, so a negative proof integer cannot
        # be framed; every other structural check (commitment range) is left
        # to verify_batch so the Merkle root is always examined first.
        for entry in entries:
            if min(entry.proof.commitment, entry.proof.response) < 0:
                return False

        # Lift every same-key entry into a MultiSchnorrEntry carrying this
        # verifier's fixed key/group, reusing the BoundSchnorr leaf bytes.
        lifted = [
            MultiSchnorrEntry(
                self._public_key,
                entry.message,
                entry.proof,
                entry.context,
                self._prime,
                self._generator,
            )
            for entry in entries
        ]
        leaves = [_bound_schnorr_leaf(entry) for entry in lifted]

        # 1) the Merkle root commits to every entry leaf, then
        # 2) the unchanged same-key batch verification checks the proofs
        if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
            return False
        return self.verify_batch(entries, randbelow=randbelow)

    def prove_bound_batch(
        self,
        entries: Sequence[SchnorrBatchEntry],
        *,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> tuple["SingleKeyBoundBatch", bytes]:
        """Build a complete, Merkle-committed :class:`SingleKeyBoundBatch`.

        ``entries`` follows the same non-``bytes`` / ``bytearray`` /
        ``str`` sequence-of-:class:`SchnorrBatchEntry` rules as
        :meth:`verify_batch` and must be non-empty; every entry is copied
        into a tuple in its original order with duplicates preserved, and
        the inputs are never mutated. The batch's public key and group
        parameters are this verifier's fixed values; each entry is lifted
        into a :class:`MultiSchnorrEntry` carrying them and encoded to its
        outer leaf byte for byte with :func:`_bound_schnorr_leaf`, the
        same leaf bytes :meth:`verify_bound_batch` recomputes — the
        domain separator, length framing and field order stay unchanged,
        and the leaf digests and internal nodes follow the existing
        SHA-256 Merkle rules. With ``n = len(entries)``, the complete
        multi-inclusion proof is built with
        :func:`prove_multi_inclusion` over the encoded leaves and the
        full indices ``tuple(range(n))`` — so its ``indices`` cover
        every leaf from zero and its ``siblings`` are empty — and the
        returned batch carries ``leaf_count = n`` alongside that proof.
        The second return value is the outer tree's
        :func:`merkle_root` of the encoded leaves, which is exactly the
        root the batch verifies under:
        ``verify_bound_batch(batch, root)`` returns ``True``.
        Single-item, odd- and even-sized batches and duplicate entries
        are all deterministic and byte for byte compatible with the
        previous manual construction.

        A type preflight over the whole batch — every entry and every
        nested field, including ``bool`` integers and later entries —
        raises :class:`TypeError` before anything is built, as does a
        non-callable ``randbelow``; an empty batch, a ``U``-framed batch
        count outside uint64, a negative proof integer, or
        :meth:`verify_batch` returning ``False`` (an invalid inner
        signature) raises :class:`ValueError`. The ``randbelow``
        argument is passed through to :meth:`verify_batch` unchanged
        under its randomness contract, so the random source's own
        exceptions surface unchanged.
        """
        items = _check_schnorr_batch_entries_types(entries)
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if not items:
            raise ValueError("entries must not be empty")
        if not _single_key_batch_replay_encodable(items):
            raise ValueError("entries contain an integer that cannot be U-framed")
        if not self.verify_batch(items, randbelow=randbelow):
            raise ValueError("entries must pass verify_batch")
        ordered = tuple(items)
        leaves = [
            _single_key_batch_leaf(entry, self._public_key, self._prime, self._generator)
            for entry in ordered
        ]
        root = merkle_root(leaves)
        proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
        batch = SingleKeyBoundBatch(
            entries=ordered,
            leaf_count=len(ordered),
            proof=proof,
        )
        return batch, root


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


def region_contains_committed(
    region: Region,
    x_commitment: PedersenCommitment,
    y_commitment: PedersenCommitment,
    x: int,
    y: int,
    x_blinding: int,
    y_blinding: int,
) -> bool:
    """Decide rectangle membership of a point bound to two Pedersen commitments.

    Unlike :meth:`Region.contains`, this binds the plain coordinate test to
    commitment openings. Each axis is checked first, in fixed order x then y:

    1. the commitment's declared range must equal the region's two bounds on
       that axis — ``(x_commitment.lower, x_commitment.upper)`` must equal
       ``(region.min_x, region.max_x)`` and likewise for y / ``min_y``,
       ``max_y``;
    2. ``value`` and ``blinding`` must open the commitment, recomputed and
       compared with :func:`verify_pedersen_opening` (group parameters, the
       element, the declared range, the value and the blinding all come from
       / are checked against the commitment object itself, so non-default
       group parameters and an explicit ``h`` are honoured).

    Only after both axes pass is ``(x, y)`` tested against the closed
    rectangle, so the four edges count as inside.

    A wrong object (not a :class:`Region` / :class:`PedersenCommitment`) or a
    wrong field type anywhere — including a ``bool`` masquerading as an
    integer — raises :class:`TypeError`. Every other rejection (an opening
    mismatch, an out-of-range blinding or embedded parameter, a declared
    range that does not match the region bounds, an illegal declaration with
    ``lower > upper`` or a value outside the declared range, or a point
    outside the rectangle) returns ``False``. Swapping either commitment or
    blinding therefore returns ``False``. The function is pure: it is
    deterministic, performs no I/O and never mutates its inputs.
    """
    if not isinstance(region, Region):
        raise TypeError("region must be a Region")
    if not isinstance(x_commitment, PedersenCommitment):
        raise TypeError("x_commitment must be a PedersenCommitment")
    if not isinstance(y_commitment, PedersenCommitment):
        raise TypeError("y_commitment must be a PedersenCommitment")
    _check_region_fields(region)
    _check_commitment_fields(x_commitment)
    _check_commitment_fields(y_commitment)
    _check_int(x, "x")
    _check_int(y, "y")
    _check_int(x_blinding, "x_blinding")
    _check_int(y_blinding, "y_blinding")
    if (x_commitment.lower, x_commitment.upper) != (region.min_x, region.max_x):
        return False
    if (y_commitment.lower, y_commitment.upper) != (region.min_y, region.max_y):
        return False
    if not verify_pedersen_opening(x_commitment, x, x_blinding):
        return False
    if not verify_pedersen_opening(y_commitment, y, y_blinding):
        return False
    return region.min_x <= x <= region.max_x and region.min_y <= y <= region.max_y


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
# Commitment-bound region-contains batch verification
#
# A RegionContainsEntry freezes the seven arguments of
# region_contains_committed (region, both commitments, both coordinates and
# both blinding factors, x axis before y axis); verify_region_contains_batch
# preflights the nested types of the whole batch and then delegates each
# entry to region_contains_committed unchanged.


@dataclass(frozen=True)
class RegionContainsEntry:
    """One item of a committed region-contains batch verification.

    Fields, in order: ``region`` (:class:`Region`), ``x_commitment`` and
    ``y_commitment`` (:class:`PedersenCommitment`), the coordinates ``x``
    and ``y`` and the blinding factors ``x_blinding`` / ``y_blinding``
    (all non-``bool`` integers) — exactly the arguments of
    :func:`region_contains_committed`, in the same order (x axis before
    y axis). All seven are positional construction arguments; entries
    compare by value and are immutable.
    """

    region: Region
    x_commitment: PedersenCommitment
    y_commitment: PedersenCommitment
    x: int
    y: int
    x_blinding: int
    y_blinding: int


def _check_region_contains_entries_types(
    entries: object,
) -> list[RegionContainsEntry]:
    """Validate the region-contains-batch ``entries`` argument types.

    Mirrors the type checks of :func:`region_contains_committed` for
    *every* entry before any verification runs: ``entries`` must be a
    non-``bytes`` / ``bytearray`` / ``str`` sequence of
    :class:`RegionContainsEntry` objects whose ``region`` is a
    :class:`Region` with non-``bool`` integer bounds, whose
    ``x_commitment`` / ``y_commitment`` are :class:`PedersenCommitment`
    objects with non-``bool`` integer ``element`` / ``lower`` /
    ``upper`` / ``prime`` / ``generator`` / ``h`` fields and whose
    ``x`` / ``y`` / ``x_blinding`` / ``y_blinding`` are non-``bool``
    integers. The whole batch is walked (a bad type in a later entry
    still raises), and the entries are copied into a fresh list so the
    inputs are never mutated. An empty batch is left to
    :func:`verify_region_contains_batch` to reject with ``False``;
    value problems (an opening mismatch, an out-of-range blinding or
    embedded parameter, a declared range that does not match the region
    bounds or a point outside the rectangle) are left to
    :func:`region_contains_committed` during verification.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of RegionContainsEntry")
    items: list[RegionContainsEntry] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, RegionContainsEntry):
            raise TypeError(
                f"entries[{position}] must be a RegionContainsEntry"
            )
        region = entry.region
        if not isinstance(region, Region):
            raise TypeError(f"entries[{position}] region must be a Region")
        for name in ("min_x", "max_x", "min_y", "max_y"):
            _check_int(getattr(region, name), f"entries[{position}] region {name}")
        for axis in ("x_commitment", "y_commitment"):
            commitment = getattr(entry, axis)
            if not isinstance(commitment, PedersenCommitment):
                raise TypeError(
                    f"entries[{position}] {axis} must be a PedersenCommitment"
                )
            for name in ("element", "lower", "upper", "prime", "generator", "h"):
                _check_int(
                    getattr(commitment, name),
                    f"entries[{position}] {axis} {name}",
                )
        _check_int(entry.x, f"entries[{position}] x")
        _check_int(entry.y, f"entries[{position}] y")
        _check_int(entry.x_blinding, f"entries[{position}] x_blinding")
        _check_int(entry.y_blinding, f"entries[{position}] y_blinding")
        items.append(entry)
    return items


def verify_region_contains_batch(
    entries: Sequence[RegionContainsEntry],
) -> bool:
    """Check several independent commitment-bound rectangle decisions.

    ``entries`` must be a non-``bytes`` / ``bytearray`` / ``str``
    sequence of :class:`RegionContainsEntry`; an empty batch returns
    ``False`` and lists, tuples, reordered and duplicate entries are
    legal. The nested types of the *whole* batch are preflighted first,
    so a wrong type in any entry — including a later one, and including
    a ``bool`` passed as an integer — raises :class:`TypeError` rather
    than being converted into a batch rejection (returning ``False``).
    Each entry is then checked, in order, with
    :func:`region_contains_committed` against its own fields, reusing
    its per-axis declared-range, opening and closed-rectangle rules; the
    first entry that returns ``False`` short-circuits the batch. Entries
    are independent of one another: their regions, commitments and
    ranges need not relate, and no encoding or cryptographic aggregation
    is added. Inputs are never mutated.
    """
    items = _check_region_contains_entries_types(entries)
    if not items:
        return False
    for entry in items:
        if not region_contains_committed(
            entry.region,
            entry.x_commitment,
            entry.y_commitment,
            entry.x,
            entry.y,
            entry.x_blinding,
            entry.y_blinding,
        ):
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


@dataclass(frozen=True)
class MerkleInclusionBatchEntry:
    """One independent item of a single-leaf inclusion batch verification.

    Fields, in order: ``leaf`` (``bytes``), ``proof``
    (:class:`MerkleProof`) and ``root`` (``bytes``) — exactly the
    arguments of :func:`verify_inclusion`, in the same order. All three
    are positional construction arguments; entries compare by value and
    are immutable.
    """

    leaf: bytes
    proof: MerkleProof
    root: bytes


def _check_inclusion_batch_entries_types(
    entries: object,
) -> list[MerkleInclusionBatchEntry]:
    """Validate the inclusion-batch ``entries`` argument types.

    Mirrors the type checks of :func:`verify_inclusion` for *every* entry
    before any verification runs: ``entries`` must be a non-``bytes`` /
    ``bytearray`` / ``str`` sequence of
    :class:`MerkleInclusionBatchEntry` objects whose ``leaf`` / ``root``
    are ``bytes`` and whose ``proof`` is a :class:`MerkleProof` with a
    non-``bool`` integer ``index`` and a tuple-of-bytes ``siblings``.
    The whole batch is walked (a bad type in a later entry still raises),
    and the entries are copied into a fresh list so the inputs are never
    mutated. An empty batch is left to :func:`verify_inclusion_batch` to
    reject with ``False``; structural/value problems (digest lengths, a
    negative index or an index/path structure that cannot match a real
    tree) are left to :func:`verify_inclusion` during verification.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of MerkleInclusionBatchEntry")
    items: list[MerkleInclusionBatchEntry] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, MerkleInclusionBatchEntry):
            raise TypeError(
                f"entries[{position}] must be a MerkleInclusionBatchEntry"
            )
        _check_bytes(entry.leaf, f"entries[{position}] leaf")
        _check_bytes(entry.root, f"entries[{position}] root")
        proof = entry.proof
        if not isinstance(proof, MerkleProof):
            raise TypeError(f"entries[{position}] proof must be a MerkleProof")
        if not isinstance(proof.index, int) or isinstance(proof.index, bool):
            raise TypeError(f"entries[{position}] proof index must be an integer")
        if not isinstance(proof.siblings, tuple):
            raise TypeError(
                f"entries[{position}] proof siblings must be a tuple of bytes"
            )
        for sibling in proof.siblings:
            _check_bytes(sibling, f"entries[{position}] proof sibling")
        items.append(entry)
    return items


def verify_inclusion_batch(entries: Sequence[MerkleInclusionBatchEntry]) -> bool:
    """Check several independent single-leaf Merkle inclusion proofs.

    ``entries`` must be a non-``bytes`` / ``bytearray`` / ``str``
    sequence of :class:`MerkleInclusionBatchEntry`; an empty batch
    returns ``False`` and lists, tuples and duplicate entries are legal.
    The nested types of the *whole* batch are preflighted first, so a
    wrong type in any entry — including a later one — raises
    :class:`TypeError` rather than being converted into a batch
    rejection (returning ``False``). Each entry is then checked, in
    order, with :func:`verify_inclusion` against its ``leaf``,
    :attr:`MerkleInclusionBatchEntry.proof` and ``root`` fields, reusing
    its root length, index, sibling length and path-walk rules; the
    first entry that returns ``False`` short-circuits the batch.
    Entries are independent of one another: their roots and trees need
    not relate, and no hash encoding or cryptographic aggregation is
    added. Inputs are never mutated.
    """
    items = _check_inclusion_batch_entries_types(entries)
    if not items:
        return False
    for entry in items:
        if not verify_inclusion(entry.leaf, entry.proof, entry.root):
            return False
    return True


# ---------------------------------------------------------------------------
# Merkle-committed single-leaf inclusion batches
#
# A BoundMerkleInclusionBatch commits a whole inclusion batch — the same
# sequence of MerkleInclusionBatchEntry items accepted by
# verify_inclusion_batch, kept in batch order with duplicates preserved —
# under one outer Merkle root. Each item is encoded to a leaf as
#
#   leaf(item) = F(D) || F(Q(item))
#   D = b"zkregion/inclusion-batch/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   Q(item) = the continuous run of the MerkleInclusionReplayGuard transcript
#             from F(leaf) through S(proof.siblings, id) — exactly the bytes
#             of _merkle_inclusion_proof_framing(item.leaf, item.root,
#             item.proof)
#
# and the leaves become the outer tree's leaves 0 .. leaf_count - 1 in
# batch order, their digests following the standard Merkle leaf rule.
# verify_inclusion_batch_bound checks the outer proof against the root with
# verify_multi_inclusion first; only when the root checks does the unchanged
# batch go through verify_inclusion_batch.


_INCLUSION_BATCH_BOUND_DOMAIN = b"zkregion/inclusion-batch/v1"


@dataclass(frozen=True)
class BoundMerkleInclusionBatch:
    """A complete single-leaf inclusion batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a non-empty tuple of
    :class:`MerkleInclusionBatchEntry`; ``leaf_count`` — a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``; ``proof`` — the :class:`MerkleMultiProof` whose
    indices cover ``0 .. leaf_count - 1`` without gaps or duplicates. All
    three are positional construction arguments; batches compare by value
    and are immutable.
    """

    entries: tuple[MerkleInclusionBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_merkle_inclusion_leaf(item: MerkleInclusionBatchEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`MerkleInclusionBatchEntry`.

    The leaf bytes are ``F(D) || F(Q(item))`` with the domain separator
    ``D = b"zkregion/inclusion-batch/v1"`` and ``F(x)`` the four-byte
    unsigned big-endian length prefix of ``x`` followed by ``x``.
    ``Q(item)`` is the continuous run of the
    :class:`MerkleInclusionReplayGuard` transcript from ``F(leaf)``
    through ``S(proof.siblings, id)`` — exactly
    :func:`_merkle_inclusion_proof_framing` applied to the item's
    ``leaf``, ``root`` and ``proof``. The leaf digest then follows the
    standard Merkle leaf rule.
    """
    q = _merkle_inclusion_proof_framing(item.leaf, item.root, item.proof)
    return (
        _frame_length_prefixed(_INCLUSION_BATCH_BOUND_DOMAIN)
        + _frame_length_prefixed(q)
    )


def verify_inclusion_batch_bound(
    batch: BoundMerkleInclusionBatch,
    root: bytes,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundMerkleInclusionBatch`.

    The Merkle binding is checked first: every entry is encoded to its leaf
    exactly as specified by :func:`_bound_merkle_inclusion_leaf` and the
    whole batch is checked against ``root`` with
    :func:`verify_multi_inclusion`. ``leaf_count`` must be a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``, and ``proof.indices`` must cover
    ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering; an
    empty batch, a missing entry, a count mismatch or any index mismatch
    returns ``False``. Only after the root checks does the batch go through
    :func:`verify_inclusion_batch` unchanged, which reuses its root length,
    index, sibling length and path-walk rules for every entry in order.

    Type errors — a batch that is not a :class:`BoundMerkleInclusionBatch`,
    non-tuple entries, non-:class:`MerkleInclusionBatchEntry` items, a
    non-integer or ``bool`` ``leaf_count``, a wrong proof/root object, or
    malformed nested field types (including ``bool`` indices, a non-tuple
    ``indices`` / ``siblings`` or a non-``bytes`` root, leaf or sibling) —
    raise :class:`TypeError`; every other invalidity (empty batch,
    miscount, incomplete indices, an unencodable U-framed integer, wrong
    root, tampered leaf bytes or any :func:`verify_inclusion_batch`
    rejection) returns ``False``. Inputs are never mutated.
    """
    if not isinstance(batch, BoundMerkleInclusionBatch):
        raise TypeError("batch must be a BoundMerkleInclusionBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of MerkleInclusionBatchEntry"
        )
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
    _check_inclusion_batch_entries_types(entries)

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering
    if not _merkle_inclusion_batch_replay_encodable(entries):
        return False  # negative or oversized U-framed integers

    leaves = [_bound_merkle_inclusion_leaf(item) for item in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged inclusion batch verification checks each entry
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_inclusion_batch(entries)


def prove_inclusion_batch_bound(
    entries: Sequence[MerkleInclusionBatchEntry],
) -> tuple[BoundMerkleInclusionBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundMerkleInclusionBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`MerkleInclusionBatchEntry` rules as
    :func:`verify_inclusion_batch` and must be non-empty; every item is
    copied into a tuple in its original order with duplicates preserved,
    and the inputs are never mutated. Each item is encoded to its outer
    leaf byte for byte with :func:`_bound_merkle_inclusion_leaf`; the leaf
    digests and internal nodes follow the existing SHA-256 Merkle rules.
    With ``n = len(entries)``, the complete multi-inclusion proof is built
    with :func:`prove_multi_inclusion` over
    ``tuple(range(n))`` — so its ``indices`` cover every leaf and its
    ``siblings`` are empty — and the returned batch carries
    ``leaf_count = n`` alongside that proof. The second return value is
    the outer tree's :func:`merkle_root` of the encoded leaves, which is
    exactly the root the batch verifies under:
    ``verify_inclusion_batch_bound(batch, root)`` returns ``True``.

    A type preflight over the whole batch raises :class:`TypeError` before
    anything is built; an empty batch, any ``U``-framed integer outside
    uint64 (a proof ``index`` or ``siblings`` length), or
    :func:`verify_inclusion_batch` returning ``False`` raises
    :class:`ValueError`.
    """
    items = _check_inclusion_batch_entries_types(entries)
    if not items:
        raise ValueError("entries must not be empty")
    if not _merkle_inclusion_batch_replay_encodable(items):
        raise ValueError("entries contain an integer that cannot be U-framed")
    if not verify_inclusion_batch(items):
        raise ValueError("entries must pass verify_inclusion_batch")
    ordered = tuple(items)
    leaves = [_bound_merkle_inclusion_leaf(item) for item in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundMerkleInclusionBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


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


@dataclass(frozen=True)
class MerkleMultiBatchEntry:
    """One independent item of a multi-inclusion batch verification.

    Fields, in order: ``entries`` (``tuple[tuple[int, bytes], ...]`` of
    ``(index, leaf)`` pairs in the exact order of ``proof.indices``),
    ``proof`` (:class:`MerkleMultiProof`) and ``root`` (``bytes``) —
    exactly the arguments of :func:`verify_multi_inclusion`, in the same
    order. All three are positional construction arguments; entries
    compare by value and are immutable.
    """

    entries: tuple[tuple[int, bytes], ...]
    proof: MerkleMultiProof
    root: bytes


def _check_multi_inclusion_batch_entries_types(
    batch: object,
) -> list[MerkleMultiBatchEntry]:
    """Validate the multi-inclusion-batch ``batch`` argument types.

    Mirrors the type checks of :func:`verify_multi_inclusion` for *every*
    item before any verification runs: ``batch`` must be a non-``bytes`` /
    ``bytearray`` / ``str`` sequence of :class:`MerkleMultiBatchEntry`
    objects whose ``entries`` is a tuple of two-item ``(index, leaf)``
    pairs with a non-``bool`` integer index and ``bytes`` leaf, whose
    ``root`` is ``bytes`` and whose ``proof`` is a
    :class:`MerkleMultiProof` with a non-``bool`` integer
    ``leaf_count``, a tuple of non-``bool`` integer ``indices`` and a
    tuple-of-bytes ``siblings``. The whole batch is walked (a bad type
    in a later item still raises), and the items are copied into a fresh
    list so the inputs are never mutated. An empty batch is left to
    :func:`verify_multi_inclusion_batch` to reject with ``False``;
    structural/value problems (a non-positive ``leaf_count``, empty or
    out-of-order indices, malformed digest lengths, an index out of
    range, mismatched pair/indices counts) are left to
    :func:`verify_multi_inclusion` during verification.
    """
    if isinstance(batch, (bytes, bytearray, str)) or not isinstance(batch, Sequence):
        raise TypeError("batch must be a sequence of MerkleMultiBatchEntry")
    items: list[MerkleMultiBatchEntry] = []
    for position, item in enumerate(batch):
        if not isinstance(item, MerkleMultiBatchEntry):
            raise TypeError(
                f"batch[{position}] must be a MerkleMultiBatchEntry"
            )
        if not isinstance(item.entries, tuple):
            raise TypeError(
                f"batch[{position}] entries must be a tuple of (index, leaf) pairs"
            )
        for pair_position, pair in enumerate(item.entries):
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise TypeError(
                    f"batch[{position}] entries[{pair_position}] must be an "
                    "(index, leaf) pair"
                )
            index, leaf = pair
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError(
                    f"batch[{position}] entries[{pair_position}] index must be "
                    "an integer"
                )
            if not isinstance(leaf, bytes):
                raise TypeError(
                    f"batch[{position}] entries[{pair_position}] leaf must be bytes"
                )
        _check_bytes(item.root, f"batch[{position}] root")
        proof = item.proof
        if not isinstance(proof, MerkleMultiProof):
            raise TypeError(
                f"batch[{position}] proof must be a MerkleMultiProof"
            )
        if not isinstance(proof.leaf_count, int) or isinstance(proof.leaf_count, bool):
            raise TypeError(
                f"batch[{position}] proof leaf_count must be an integer"
            )
        if not isinstance(proof.indices, tuple):
            raise TypeError(
                f"batch[{position}] proof indices must be a tuple of integers"
            )
        for index_position, index in enumerate(proof.indices):
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError(
                    f"batch[{position}] proof indices[{index_position}] must be "
                    "an integer"
                )
        if not isinstance(proof.siblings, tuple):
            raise TypeError(
                f"batch[{position}] proof siblings must be a tuple of bytes"
            )
        for sibling_position, sibling in enumerate(proof.siblings):
            _check_bytes(
                sibling, f"batch[{position}] proof siblings[{sibling_position}]"
            )
        items.append(item)
    return items


def verify_multi_inclusion_batch(batch: Sequence[MerkleMultiBatchEntry]) -> bool:
    """Check several independent compact Merkle multi-inclusion proofs.

    ``batch`` must be a non-``bytes`` / ``bytearray`` / ``str`` sequence
    of :class:`MerkleMultiBatchEntry`; an empty batch returns ``False``
    and lists, tuples and duplicate items are legal. The nested types of
    the *whole* batch are preflighted first, so a wrong type in any item
    — including a later one — raises :class:`TypeError` rather than being
    converted into a batch rejection (returning ``False``). Each item is
    then checked, in order, with :func:`verify_multi_inclusion` against
    its ``entries``, :attr:`MerkleMultiBatchEntry.proof` and ``root``
    fields, reusing its root length, index/entries ordering, sibling
    length and path-walk rules; the first item that returns ``False``
    short-circuits the batch. Items are independent of one another:
    their roots and trees need not relate, and no hash encoding or
    cryptographic aggregation is added. Inputs are never mutated.
    """
    items = _check_multi_inclusion_batch_entries_types(batch)
    if not items:
        return False
    for item in items:
        if not verify_multi_inclusion(item.entries, item.proof, item.root):
            return False
    return True


# ---------------------------------------------------------------------------
# Merkle-committed multi-inclusion batches
#
# A BoundMerkleMultiBatch commits a whole multi-inclusion batch — the same
# sequence of MerkleMultiBatchEntry items accepted by
# verify_multi_inclusion_batch, kept in batch order with duplicates
# preserved — under one outer Merkle root. Each item is encoded to a leaf
# as
#
#   leaf(item) = F(D) || F(Q(item))
#   D = b"zkregion/multi-batch/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   Q(item) = the continuous run of the MerkleMultiReplayGuard transcript
#             from F(root) through S(proof.siblings, id) — exactly the
#             bytes of _merkle_multi_proof_framing(item.entries, item.root,
#             item.proof)
#
# and the leaves become the outer tree's leaves 0 .. leaf_count - 1 in
# batch order, their digests following the standard Merkle leaf rule.
# verify_multi_inclusion_batch_bound checks the outer proof against the
# root with verify_multi_inclusion first; only when the root checks does
# the unchanged batch go through verify_multi_inclusion_batch.


_MULTI_BATCH_BOUND_DOMAIN = b"zkregion/multi-batch/v1"


@dataclass(frozen=True)
class BoundMerkleMultiBatch:
    """A complete multi-inclusion batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a non-empty tuple of
    :class:`MerkleMultiBatchEntry`; ``leaf_count`` — a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``; ``proof`` — the :class:`MerkleMultiProof` whose
    indices cover ``0 .. leaf_count - 1`` without gaps or duplicates. All
    three are positional construction arguments; batches compare by value
    and are immutable.
    """

    entries: tuple[MerkleMultiBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_merkle_multi_leaf(item: MerkleMultiBatchEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`MerkleMultiBatchEntry`.

    The leaf bytes are ``F(D) || F(Q(item))`` with the domain separator
    ``D = b"zkregion/multi-batch/v1"`` and ``F(x)`` the four-byte unsigned
    big-endian length prefix of ``x`` followed by ``x``. ``Q(item)`` is the
    continuous run of the :class:`MerkleMultiReplayGuard` transcript from
    ``F(root)`` through ``S(proof.siblings, id)`` — exactly
    :func:`_merkle_multi_proof_framing` applied to the item's ``entries``,
    ``root`` and ``proof``. The leaf digest then follows the standard
    Merkle leaf rule.
    """
    q = _merkle_multi_proof_framing(item.entries, item.root, item.proof)
    return (
        _frame_length_prefixed(_MULTI_BATCH_BOUND_DOMAIN)
        + _frame_length_prefixed(q)
    )


def verify_multi_inclusion_batch_bound(
    batch: BoundMerkleMultiBatch,
    root: bytes,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundMerkleMultiBatch`.

    The Merkle binding is checked first: every item is encoded to its leaf
    exactly as specified by :func:`_bound_merkle_multi_leaf` and the whole
    batch is checked against ``root`` with :func:`verify_multi_inclusion`.
    ``leaf_count`` must be a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``, and ``proof.indices`` must
    cover ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering;
    an empty batch, a missing item, a count mismatch or any index mismatch
    returns ``False``. Only after the root checks does the batch go through
    :func:`verify_multi_inclusion_batch` unchanged, which reuses its root
    length, index/entries ordering, sibling length and path-walk rules for
    every item in order.

    Type errors — a batch that is not a :class:`BoundMerkleMultiBatch`,
    non-tuple entries, non-:class:`MerkleMultiBatchEntry` items, a
    non-integer or ``bool`` ``leaf_count``, a wrong proof/root object, or
    malformed nested field types (including ``bool`` counts or indices, a
    non-tuple ``indices`` / ``siblings`` / ``entries`` or a non-``bytes``
    root, leaf or sibling) — raise :class:`TypeError`; every other
    invalidity (empty batch, miscount, incomplete indices, an unencodable
    U-framed count, wrong root, tampered leaf bytes or any
    :func:`verify_multi_inclusion_batch` rejection) returns ``False``.
    Inputs are never mutated.
    """
    if not isinstance(batch, BoundMerkleMultiBatch):
        raise TypeError("batch must be a BoundMerkleMultiBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of MerkleMultiBatchEntry"
        )
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
    _check_multi_inclusion_batch_entries_types(entries)

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering
    if not _merkle_multi_batch_replay_encodable(entries):
        return False  # negative or oversized U-framed integers

    leaves = [_bound_merkle_multi_leaf(item) for item in entries]

    # 1) the Merkle root commits to every item leaf, then
    # 2) the unchanged multi-inclusion batch verification checks each item
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_multi_inclusion_batch(entries)


def prove_multi_inclusion_batch_bound(
    entries: Sequence[MerkleMultiBatchEntry],
) -> tuple[BoundMerkleMultiBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundMerkleMultiBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`MerkleMultiBatchEntry` rules as
    :func:`verify_multi_inclusion_batch` and must be non-empty; every
    item is copied into a tuple in its original order with duplicates
    preserved, and the inputs are never mutated. Each item is encoded to
    its outer leaf byte for byte with :func:`_bound_merkle_multi_leaf`;
    the leaf digests, internal nodes and odd-last-node duplication follow
    the existing SHA-256 Merkle protocol — no domain separator, framing or
    field order changes. With ``n = len(entries)``, the complete
    multi-inclusion proof is built with :func:`prove_multi_inclusion`
    over the encoded leaves and the full indices ``tuple(range(n))`` — so
    its ``indices`` cover every leaf and its ``siblings`` are empty — and
    the returned batch carries ``leaf_count = n`` alongside that proof.
    The second return value is the outer tree's :func:`merkle_root` of
    the encoded leaves, which is exactly the root the batch verifies
    under: ``verify_multi_inclusion_batch_bound(batch, root)`` returns
    ``True``. Single-item, odd- and even-sized batches and duplicate
    items are all deterministic and byte for byte compatible with the
    previous manual construction.

    A type preflight over the whole batch raises :class:`TypeError` before
    anything is built; an empty batch, any ``U``-framed integer outside
    uint64 (a proof ``leaf_count`` or index, or any framed sequence
    length), or :func:`verify_multi_inclusion_batch` returning ``False``
    raises :class:`ValueError`.
    """
    items = _check_multi_inclusion_batch_entries_types(entries)
    if not items:
        raise ValueError("entries must not be empty")
    if not _merkle_multi_batch_replay_encodable(items):
        raise ValueError("entries contain an integer that cannot be U-framed")
    if not verify_multi_inclusion_batch(items):
        raise ValueError("entries must pass verify_multi_inclusion_batch")
    ordered = tuple(items)
    leaves = [_bound_merkle_multi_leaf(item) for item in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundMerkleMultiBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


# ---------------------------------------------------------------------------
# Merkle append-only consistency proofs
#
# Same digests and odd-node duplication as the inclusion proofs above. A
# consistency proof shows that the tree committed by ``new_root`` is exactly
# the tree committed by ``old_root`` with extra leaves appended, so the
# verifier needs only the two roots and the proof — never the leaves.
#
# The tree of ``n`` leaves decomposes into the complete subtrees of the
# binary expansion of ``n`` (heights strictly decreasing); the root is
# recovered from these peaks by promoting the rightmost peak through
# self-hashes up to its left neighbour's height and then merging left/right,
# mirroring the odd-node duplication of the layer-by-layer construction.
# Appending a leaf folds into the peak list by binary carry: adjacent
# equal-height peaks merge into one peak one level higher.


@dataclass(frozen=True)
class MerkleConsistencyProof:
    """Append-only consistency proof between two Merkle roots.

    ``old_count`` and ``new_count`` are the leaf counts of the old and new
    trees; ``nodes`` first lists the complete-subtree roots of the binary
    decomposition of the old prefix (decreasing heights), then the digests
    of the appended leaves in order.
    """

    old_count: int
    new_count: int
    nodes: tuple[bytes, ...]


def _peak_heights(count: int) -> list[int]:
    """Heights of the complete subtrees in the binary expansion of ``count``."""
    return [
        bit
        for bit in range(count.bit_length() - 1, -1, -1)
        if count & (1 << bit)
    ]


def _subtree_root(digests: Sequence[bytes], offset: int, size: int) -> bytes:
    """Root of the complete subtree over ``size`` leaf digests at ``offset``."""
    level = list(digests[offset : offset + size])
    while len(level) > 1:
        level = [
            _node_digest(level[position], level[position + 1])
            for position in range(0, len(level), 2)
        ]
    return level[0]


def _peaks_root(peaks: list[tuple[int, bytes]]) -> bytes:
    """Recover the tree root from peaks of strictly decreasing height.

    Starting from the rightmost peak, the accumulator is promoted by
    self-hashing up to the height of its left neighbour and then merged as
    the right child — the peak view of the odd-node duplication rule.
    """
    height, digest = peaks[-1]
    for left_height, left in reversed(peaks[:-1]):
        while height < left_height:
            digest = _node_digest(digest, digest)
            height += 1
        digest = _node_digest(left, digest)
        height = left_height + 1
    return digest


def prove_consistency(leaves: Sequence[bytes], old_count: int) -> MerkleConsistencyProof:
    """Build a :class:`MerkleConsistencyProof` for the ``old_count`` prefix.

    ``leaves`` must be a non-empty sequence of ``bytes`` and ``old_count``
    must satisfy ``1 <= old_count <= len(leaves)``; the proof commits to
    ``new_count = len(leaves)``. ``nodes`` lists the complete-subtree roots
    of the binary decomposition of the old prefix (decreasing heights)
    followed by the digests of the appended leaves in order. Type errors
    (including ``bool`` counts) raise :class:`TypeError`; an empty tree or
    an out-of-range count raises :class:`ValueError`. Inputs are never
    mutated.
    """
    items = _checked_leaves(leaves)
    if not isinstance(old_count, int) or isinstance(old_count, bool):
        raise TypeError("old_count must be an integer")
    if not 1 <= old_count <= len(items):
        raise ValueError("old_count must satisfy 1 <= old_count <= len(leaves)")
    digests = [_leaf_digest(leaf) for leaf in items]
    nodes: list[bytes] = []
    offset = 0
    for height in _peak_heights(old_count):
        size = 1 << height
        nodes.append(_subtree_root(digests, offset, size))
        offset += size
    nodes.extend(digests[old_count:])
    return MerkleConsistencyProof(
        old_count=old_count,
        new_count=len(items),
        nodes=tuple(nodes),
    )


def verify_consistency(
    old_root: bytes,
    new_root: bytes,
    proof: MerkleConsistencyProof,
) -> bool:
    """Check that ``new_root`` commits to ``old_root``'s leaves plus appended ones.

    The old peaks are recombined into a root that must equal ``old_root``;
    the appended leaf digests are then folded in by binary carry
    (equal-height peaks merge) and the resulting root must equal
    ``new_root``. Type errors raise :class:`TypeError`; invalid counts, a
    wrong node count, malformed digest lengths, a missing remainder or any
    root mismatch return False. Inputs are never mutated.
    """
    _check_bytes(old_root, "old_root")
    _check_bytes(new_root, "new_root")
    if not isinstance(proof, MerkleConsistencyProof):
        raise TypeError("proof must be a MerkleConsistencyProof")
    for name in ("old_count", "new_count"):
        value = getattr(proof, name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"proof {name} must be an integer")
    if not isinstance(proof.nodes, tuple):
        raise TypeError("proof nodes must be a tuple of bytes")
    for node in proof.nodes:
        _check_bytes(node, "proof node")
    if len(old_root) != _MERKLE_DIGEST_SIZE or len(new_root) != _MERKLE_DIGEST_SIZE:
        return False
    old_count = proof.old_count
    new_count = proof.new_count
    if old_count < 1 or new_count < old_count:
        return False
    heights = _peak_heights(old_count)
    if len(proof.nodes) != len(heights) + (new_count - old_count):
        return False
    if any(len(node) != _MERKLE_DIGEST_SIZE for node in proof.nodes):
        return False
    old_peaks = list(zip(heights, proof.nodes[: len(heights)]))
    if not hmac.compare_digest(_peaks_root(old_peaks), old_root):
        return False
    peaks = old_peaks
    for digest in proof.nodes[len(heights) :]:
        peaks.append((0, digest))
        while len(peaks) >= 2 and peaks[-2][0] == peaks[-1][0]:
            merged = _node_digest(peaks[-2][1], peaks[-1][1])
            peaks[-2:] = [(peaks[-1][0] + 1, merged)]
    return hmac.compare_digest(_peaks_root(peaks), new_root)


@dataclass(frozen=True)
class MerkleConsistencyBatchEntry:
    """One independent item of a consistency batch verification.

    Fields, in order: ``old_root`` and ``new_root`` (``bytes``) and
    ``proof`` (:class:`MerkleConsistencyProof`) — exactly the arguments
    of :func:`verify_consistency`, in the same order. All three are
    positional construction arguments; entries compare by value and are
    immutable.
    """

    old_root: bytes
    new_root: bytes
    proof: MerkleConsistencyProof


def verify_consistency_batch(entries: Sequence[MerkleConsistencyBatchEntry]) -> bool:
    """Check several independent consistency pairs in one call.

    ``entries`` must be a non-empty, non-``bytes`` / ``bytearray`` /
    ``str`` sequence of :class:`MerkleConsistencyBatchEntry`; an empty
    batch returns ``False`` and lists, tuples and duplicate entries are
    legal. Each entry is checked, in order, with
    :func:`verify_consistency` against its ``old_root``, ``new_root``
    and ``proof`` fields, reusing its root, count, node and append
    rules; any invalid entry returns ``False`` and short-circuiting is
    allowed. Entries are independent of one another: neighbouring
    counts need not chain together, and no hash encoding or
    cryptographic aggregation is added. Type errors in ``entries``, an
    entry or any field (including ``bool`` counts, non-tuple ``nodes``
    or a non-``bytes`` node) raise :class:`TypeError` rather than being
    converted into a batch rejection. Inputs are never mutated.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of MerkleConsistencyBatchEntry")
    items = list(entries)  # copy: inputs are never mutated
    if not items:
        return False
    for position, entry in enumerate(items):
        if not isinstance(entry, MerkleConsistencyBatchEntry):
            raise TypeError(f"entries[{position}] must be a MerkleConsistencyBatchEntry")
        if not verify_consistency(entry.old_root, entry.new_root, entry.proof):
            return False
    return True


# ---------------------------------------------------------------------------
# Merkle-committed consistency batches
#
# A complete consistency batch frozen together with the Merkle multi-inclusion
# proof that commits to every entry. Each Merkle leaf starts from the domain
# separator b"zkregion/consistency-bound/v1" and frames, in order, old_root,
# new_root, old_count, new_count and then every node of the proof. Roots and
# nodes keep their raw bytes; counts are decimal ASCII. Verification first
# checks every leaf against the Merkle root, then runs the unchanged
# consistency batch verification.

_CONSISTENCY_BOUND_DOMAIN = b"zkregion/consistency-bound/v1"


@dataclass(frozen=True)
class BoundConsistencyBatch:
    """A complete consistency batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a non-empty tuple of
    :class:`MerkleConsistencyBatchEntry`; ``leaf_count`` — a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``; ``proof`` — the :class:`MerkleMultiProof` whose
    indices cover ``0 .. leaf_count - 1`` without gaps or duplicates. All
    three are positional construction arguments; batches compare by value
    and are immutable.
    """

    entries: tuple[MerkleConsistencyBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_consistency_leaf(entry: MerkleConsistencyBatchEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`MerkleConsistencyBatchEntry`.

    Items, in order: the domain separator ``b"zkregion/consistency-bound/v1"``,
    ``old_root``, ``new_root``, ``old_count``, ``new_count`` and then every
    node of the proof in its original order. Every item is prefixed with its
    four-byte unsigned big-endian length; the counts are decimal ASCII while
    the roots and nodes are framed as their raw bytes. The leaf digest then
    follows the standard Merkle leaf rule.
    """
    proof = entry.proof
    items = [
        _CONSISTENCY_BOUND_DOMAIN,
        entry.old_root,
        entry.new_root,
        str(proof.old_count).encode("ascii"),
        str(proof.new_count).encode("ascii"),
    ]
    items.extend(proof.nodes)
    leaf = bytearray()
    for item in items:
        leaf += len(item).to_bytes(4, "big")
        leaf += item
    return bytes(leaf)


def verify_consistency_batch_bound(
    batch: BoundConsistencyBatch,
    root: bytes,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundConsistencyBatch`.

    The Merkle binding is checked first: every entry is encoded to its leaf
    exactly as specified by :func:`_bound_consistency_leaf` and the whole
    batch is checked against ``root`` with :func:`verify_multi_inclusion`.
    ``leaf_count`` must be a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``, and ``proof.indices`` must
    cover ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering;
    an empty batch, a missing entry, a count mismatch or any index mismatch
    returns ``False``. Only after the root checks does the batch go through
    :func:`verify_consistency_batch` unchanged, which reuses its root,
    count, node and append rules for every entry in order.

    Type errors — a batch that is not a :class:`BoundConsistencyBatch`,
    non-tuple entries, non-:class:`MerkleConsistencyBatchEntry` items, a
    non-integer or ``bool`` ``leaf_count``, a wrong proof/root object, or
    malformed nested field types (including ``bool`` counts, a non-tuple
    ``nodes`` or a non-``bytes`` root or node) — raise
    :class:`TypeError`; every other invalidity (empty batch, miscount,
    incomplete indices, wrong root, tampered leaf bytes or any
    :func:`verify_consistency_batch` rejection) returns ``False``. Inputs
    are never mutated.
    """
    if not isinstance(batch, BoundConsistencyBatch):
        raise TypeError("batch must be a BoundConsistencyBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of MerkleConsistencyBatchEntry"
        )
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
        if not isinstance(entry, MerkleConsistencyBatchEntry):
            raise TypeError(
                f"entries[{position}] must be a MerkleConsistencyBatchEntry"
            )
        _check_bytes(entry.old_root, f"entries[{position}] old_root")
        _check_bytes(entry.new_root, f"entries[{position}] new_root")
        entry_proof = entry.proof
        if not isinstance(entry_proof, MerkleConsistencyProof):
            raise TypeError(
                f"entries[{position}] proof must be a MerkleConsistencyProof"
            )
        for name in ("old_count", "new_count"):
            value = getattr(entry_proof, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(
                    f"entries[{position}] proof {name} must be an integer"
                )
        if not isinstance(entry_proof.nodes, tuple):
            raise TypeError(
                f"entries[{position}] proof nodes must be a tuple of bytes"
            )
        for node in entry_proof.nodes:
            _check_bytes(node, f"entries[{position}] proof node")

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    leaves = [_bound_consistency_leaf(entry) for entry in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged consistency batch verification checks each proof
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_consistency_batch(entries)


def prove_consistency_batch_bound(
    entries: Sequence[MerkleConsistencyBatchEntry],
) -> tuple[BoundConsistencyBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundConsistencyBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`MerkleConsistencyBatchEntry` rules as
    :func:`verify_consistency_batch` and must be non-empty; every entry is
    copied into a tuple in its original order with duplicates preserved,
    and the inputs are never mutated. Each entry is encoded to its outer
    leaf byte for byte with :func:`_bound_consistency_leaf`; the domain
    separator, length framing, field order and the leaf/internal Merkle
    hashing all stay unchanged. With ``n = len(entries)``, the complete
    multi-inclusion proof is built with :func:`prove_multi_inclusion`
    over the encoded leaves and the full indices ``tuple(range(n))`` — so
    its ``indices`` cover every leaf and its ``siblings`` are empty — and
    the returned batch carries ``leaf_count = n`` alongside that proof.
    The second return value is the outer tree's :func:`merkle_root` of
    the encoded leaves, which is exactly the root the batch verifies
    under: ``verify_consistency_batch_bound(batch, root)`` returns
    ``True``. Single-item, odd- and even-sized batches and duplicate
    entries are all deterministic and byte for byte compatible with the
    previous manual construction.

    A type preflight over the whole batch — every entry and every nested
    field, including ``bool`` counts and later entries — raises
    :class:`TypeError` before anything is built; an empty batch or
    :func:`verify_consistency_batch` returning ``False`` raises
    :class:`ValueError`.
    """
    items = _check_merkle_consistency_batch_entries_types(entries)
    if not items:
        raise ValueError("entries must not be empty")
    if not verify_consistency_batch(items):
        raise ValueError("entries must pass verify_consistency_batch")
    ordered = tuple(items)
    leaves = [_bound_consistency_leaf(entry) for entry in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundConsistencyBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


# ---------------------------------------------------------------------------
# Multi-checkpoint Merkle consistency chains
#
# A chain confirms a whole sequence of increasing checkpoints at once: every
# root is the prefix root of one leaf count, and each adjacent pair of roots
# is linked by the established append-only consistency proof of that segment,
# so one verification shows every checkpoint grew by appending to the
# previous tree. Roots, proofs and digests reuse the existing Merkle
# protocol byte for byte; no new encoding is introduced.


@dataclass(frozen=True)
class MerkleConsistencyChain:
    """A chain of Merkle roots linked by append-only consistency proofs.

    ``roots`` holds one 32-byte Merkle root per checkpoint (the prefix root
    of the leaves confirmed so far) and ``proofs`` holds one
    :class:`MerkleConsistencyProof` per adjacent pair of roots, in order.
    Both fields are positional construction arguments; chains compare by
    value and are immutable.
    """

    roots: tuple[bytes, ...]
    proofs: tuple[MerkleConsistencyProof, ...]


def prove_consistency_chain(
    leaves: Sequence[bytes],
    counts: tuple[int, ...],
) -> MerkleConsistencyChain:
    """Build a :class:`MerkleConsistencyChain` over the ``counts`` prefixes.

    ``leaves`` must be a non-empty sequence of ``bytes`` and ``counts`` a
    tuple of at least two strictly increasing, duplicate-free, non-``bool``
    integers, each satisfying ``1 <= count <= len(leaves)``. ``roots`` is
    the Merkle root of each ``leaves[:count]`` prefix and ``proofs`` the
    :func:`prove_consistency` proof of each adjacent segment, so
    ``proofs[i]`` links ``roots[i]`` to ``roots[i + 1]``. Type errors
    (including ``bool`` counts) raise :class:`TypeError`; an empty tree or
    any violation of the count constraints raises :class:`ValueError`.
    Inputs are never mutated.
    """
    items = _checked_leaves(leaves)
    if not isinstance(counts, tuple):
        raise TypeError("counts must be a tuple of integers")
    for position, count in enumerate(counts):
        if not isinstance(count, int) or isinstance(count, bool):
            raise TypeError(f"counts[{position}] must be an integer")
    if len(counts) < 2:
        raise ValueError("counts must contain at least two checkpoints")
    if any(later <= earlier for earlier, later in zip(counts, counts[1:])):
        raise ValueError("counts must be strictly increasing without duplicates")
    if counts[0] < 1 or counts[-1] > len(items):
        raise ValueError("each count must satisfy 1 <= count <= len(leaves)")
    roots = tuple(merkle_root(items[:count]) for count in counts)
    proofs = tuple(
        prove_consistency(items[:new_count], old_count)
        for old_count, new_count in zip(counts, counts[1:])
    )
    return MerkleConsistencyChain(roots=roots, proofs=proofs)


def verify_consistency_chain(chain: MerkleConsistencyChain) -> bool:
    """Check that every adjacent pair of ``chain.roots`` is append-consistent.

    The chain must hold at least two roots and exactly one proof per
    adjacent pair; each proof's ``old_count`` / ``new_count`` must match
    its neighbouring proofs (``proofs[i].new_count == proofs[i + 1].old_count``)
    and be strictly increasing, and every segment is verified with
    :func:`verify_consistency` against its two adjacent roots. Type errors
    (wrong chain, root, proof or nested field types, including ``bool``
    counts) raise :class:`TypeError`; an empty chain, a wrong root or proof
    count, broken segment chaining or ordering, malformed digest lengths or
    any root or node mismatch returns ``False``. Inputs are never mutated.
    """
    if not isinstance(chain, MerkleConsistencyChain):
        raise TypeError("chain must be a MerkleConsistencyChain")
    roots = chain.roots
    if not isinstance(roots, tuple):
        raise TypeError("chain roots must be a tuple of bytes")
    for position, root in enumerate(roots):
        if not isinstance(root, bytes):
            raise TypeError(f"chain roots[{position}] must be bytes")
    proofs = chain.proofs
    if not isinstance(proofs, tuple):
        raise TypeError("chain proofs must be a tuple of MerkleConsistencyProof")
    for position, proof in enumerate(proofs):
        if not isinstance(proof, MerkleConsistencyProof):
            raise TypeError(
                f"chain proofs[{position}] must be a MerkleConsistencyProof"
            )
        for name in ("old_count", "new_count"):
            value = getattr(proof, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"chain proofs[{position}] {name} must be an integer")
        if not isinstance(proof.nodes, tuple):
            raise TypeError(f"chain proofs[{position}] nodes must be a tuple of bytes")
        for node in proof.nodes:
            if not isinstance(node, bytes):
                raise TypeError(f"chain proofs[{position}] node must be bytes")
    if len(roots) < 2 or len(roots) != len(proofs) + 1:
        return False
    if any(len(root) != _MERKLE_DIGEST_SIZE for root in roots):
        return False
    for proof in proofs:
        if proof.old_count < 1 or proof.new_count <= proof.old_count:
            return False  # counts must be strictly increasing along the chain
    if any(
        later.old_count != earlier.new_count
        for earlier, later in zip(proofs, proofs[1:])
    ):
        return False  # adjacent segments must share their checkpoint count
    return all(
        verify_consistency(roots[position], roots[position + 1], proof)
        for position, proof in enumerate(proofs)
    )


# ---------------------------------------------------------------------------
# Merkle-committed consistency chain batches
#
# A whole batch of MerkleConsistencyChain objects frozen together with the
# Merkle multi-inclusion proof that commits to every chain. Each Merkle leaf
# starts from the domain separator b"zkregion/consistency-chains/v1" and then
# writes, in order, the chain's roots sequence and its proofs sequence; each
# proof segment writes old_count, new_count and its nodes. The two sequence
# headers and the nodes header carry their element counts, every atomic item
# is framed with its four-byte unsigned big-endian length, counts use decimal
# ASCII, and the roots and nodes keep their raw bytes, all in the original
# order with duplicates retained. Verification first checks every leaf
# against the Merkle root, then runs the unchanged per-chain verification.

_CONSISTENCY_CHAINS_BOUND_DOMAIN = b"zkregion/consistency-chains/v1"


@dataclass(frozen=True)
class BoundConsistencyChainBatch:
    """A complete consistency-chain batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``chains`` — a non-empty tuple of
    :class:`MerkleConsistencyChain`; ``leaf_count`` — a positive,
    non-``bool`` integer equal to both ``len(chains)`` and
    ``proof.leaf_count``; ``proof`` — the :class:`MerkleMultiProof` whose
    indices cover ``0 .. leaf_count - 1`` without gaps or duplicates. All
    three are positional construction arguments; batches compare by value
    and are immutable.
    """

    chains: tuple[MerkleConsistencyChain, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_consistency_chain_leaf(chain: MerkleConsistencyChain) -> bytes:
    """Build the Merkle leaf committed for one :class:`MerkleConsistencyChain`.

    The leaf starts with the domain separator
    ``b"zkregion/consistency-chains/v1"``, followed, in order, by the
    ``roots`` sequence and the ``proofs`` sequence. The roots sequence first
    writes its element count and then every root in order; the proofs
    sequence first writes its element count and then every segment, each
    segment writing ``old_count``, ``new_count`` and then its nodes (the
    nodes themselves preceded by their element count). Order and duplicates
    are preserved. Every atomic item is prefixed with its four-byte
    unsigned big-endian length; the counts (sequence and node lengths as
    well as ``old_count`` / ``new_count``) are decimal ASCII, while the
    roots and nodes keep their raw bytes. The leaf digest then follows the
    standard Merkle leaf rule.
    """

    def frame(item: bytes) -> bytes:
        return len(item).to_bytes(4, "big") + item

    leaf = bytearray(frame(_CONSISTENCY_CHAINS_BOUND_DOMAIN))
    # roots: element count first, then every root verbatim
    leaf += frame(str(len(chain.roots)).encode("ascii"))
    for root in chain.roots:
        leaf += frame(root)
    # proofs: element count first, then one segment per proof
    leaf += frame(str(len(chain.proofs)).encode("ascii"))
    for proof in chain.proofs:
        leaf += frame(str(proof.old_count).encode("ascii"))
        leaf += frame(str(proof.new_count).encode("ascii"))
        leaf += frame(str(len(proof.nodes)).encode("ascii"))
        for node in proof.nodes:
            leaf += frame(node)
    return bytes(leaf)


def verify_consistency_chain_batch_bound(
    batch: BoundConsistencyChainBatch,
    root: bytes,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundConsistencyChainBatch`.

    The Merkle binding is checked first: every chain is encoded to its leaf
    exactly as specified by :func:`_bound_consistency_chain_leaf` and the
    whole batch is checked against ``root`` with
    :func:`verify_multi_inclusion`. ``leaf_count`` must be a positive,
    non-``bool`` integer equal to both ``len(chains)`` and
    ``proof.leaf_count``, and ``proof.indices`` must equal
    ``tuple(range(leaf_count))`` — covering ``0 .. leaf_count - 1`` with no
    gaps, duplicates or reordering; an empty batch, a missing chain, a count
    mismatch or any index mismatch returns ``False``. Only after the root
    checks does each chain go through :func:`verify_consistency_chain`
    unchanged, in order.

    Type errors — a batch that is not a :class:`BoundConsistencyChainBatch`,
    non-tuple chains, non-:class:`MerkleConsistencyChain` items, a
    non-integer or ``bool`` ``leaf_count``, a wrong proof/root object, or
    malformed nested field types (including ``bool`` counts, a non-tuple
    ``roots``, ``proofs`` or ``nodes``, or a non-``bytes`` root or node) —
    raise :class:`TypeError`; every other invalidity (empty batch, miscount,
    incomplete indices, wrong root, tampered leaf bytes or any
    :func:`verify_consistency_chain` rejection) returns ``False``. Inputs
    are never mutated.
    """
    if not isinstance(batch, BoundConsistencyChainBatch):
        raise TypeError("batch must be a BoundConsistencyChainBatch")
    _check_bytes(root, "root")
    chains = batch.chains
    if not isinstance(chains, tuple):
        raise TypeError(
            "batch chains must be a tuple of MerkleConsistencyChain"
        )
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
    for position, chain in enumerate(chains):
        if not isinstance(chain, MerkleConsistencyChain):
            raise TypeError(
                f"chains[{position}] must be a MerkleConsistencyChain"
            )
        roots = chain.roots
        if not isinstance(roots, tuple):
            raise TypeError(f"chains[{position}] roots must be a tuple of bytes")
        for root_position, chain_root in enumerate(roots):
            _check_bytes(
                chain_root, f"chains[{position}] roots[{root_position}]"
            )
        chain_proofs = chain.proofs
        if not isinstance(chain_proofs, tuple):
            raise TypeError(
                f"chains[{position}] proofs must be a tuple"
                " of MerkleConsistencyProof"
            )
        for segment, chain_proof in enumerate(chain_proofs):
            if not isinstance(chain_proof, MerkleConsistencyProof):
                raise TypeError(
                    f"chains[{position}] proofs[{segment}]"
                    " must be a MerkleConsistencyProof"
                )
            for name in ("old_count", "new_count"):
                value = getattr(chain_proof, name)
                if not isinstance(value, int) or isinstance(value, bool):
                    raise TypeError(
                        f"chains[{position}] proofs[{segment}] {name}"
                        " must be an integer"
                    )
            if not isinstance(chain_proof.nodes, tuple):
                raise TypeError(
                    f"chains[{position}] proofs[{segment}]"
                    " nodes must be a tuple of bytes"
                )
            for node in chain_proof.nodes:
                _check_bytes(
                    node, f"chains[{position}] proofs[{segment}] node"
                )

    if leaf_count < 1:
        return False
    if leaf_count != len(chains) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    leaves = [_bound_consistency_chain_leaf(chain) for chain in chains]

    # 1) the Merkle root commits to every chain leaf, then
    # 2) the unchanged per-chain verification checks each chain in order
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return all(verify_consistency_chain(chain) for chain in chains)


def verify_consistency_chain_batch(
    chains: Sequence[MerkleConsistencyChain],
) -> bool:
    """Check several independent consistency chains in one call.

    ``chains`` must be a non-empty, non-``bytes`` / ``bytearray`` /
    ``str`` sequence of :class:`MerkleConsistencyChain`; an empty batch
    returns ``False`` and lists, tuples and duplicate chains are legal.
    Each chain is checked, in order, with :func:`verify_consistency_chain`
    exactly as if it had been passed on its own, reusing its root, proof,
    chaining and segment rules; any invalid chain returns ``False`` and
    short-circuiting is allowed. Chains are independent of one another:
    neighbouring checkpoints need not relate, and no hash encoding or
    cryptographic aggregation is added. Type errors in ``chains`` or an
    item (including a non-:class:`MerkleConsistencyChain` item) raise
    :class:`TypeError` rather than being converted into a batch rejection.
    Inputs are never mutated.
    """
    if isinstance(chains, (bytes, bytearray, str)) or not isinstance(chains, Sequence):
        raise TypeError("chains must be a sequence of MerkleConsistencyChain")
    items = list(chains)  # copy: inputs are never mutated
    if not items:
        return False
    for position, chain in enumerate(items):
        if not isinstance(chain, MerkleConsistencyChain):
            raise TypeError(f"chains[{position}] must be a MerkleConsistencyChain")
        if not verify_consistency_chain(chain):
            return False
    return True


def prove_consistency_chain_batch_bound(
    chains: Sequence[MerkleConsistencyChain],
) -> tuple[BoundConsistencyChainBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundConsistencyChainBatch`.

    ``chains`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`MerkleConsistencyChain` rules as
    :func:`verify_consistency_chain_batch` and must be non-empty; every
    chain is copied into a tuple in its original order with duplicates
    preserved, and the inputs are never mutated. Each chain is encoded to
    its outer leaf byte for byte with :func:`_bound_consistency_chain_leaf`;
    the domain separator, sequence and length framing, field order and the
    leaf/internal Merkle hashing all stay unchanged. With
    ``n = len(chains)``, the complete multi-inclusion proof is built with
    :func:`prove_multi_inclusion` over the encoded leaves and the full
    indices ``tuple(range(n))`` — so its ``indices`` cover every leaf and
    its ``siblings`` are empty — and the returned batch carries
    ``leaf_count = n`` alongside that proof. The second return value is
    the outer tree's :func:`merkle_root` of the encoded leaves, which is
    exactly the root the batch verifies under:
    ``verify_consistency_chain_batch_bound(batch, root)`` returns ``True``.
    Single-item, odd- and even-sized batches and duplicate chains are all
    deterministic and byte for byte compatible with the previous manual
    construction.

    A type preflight over the whole batch — every chain and every nested
    field, including ``bool`` counts, non-tuple ``roots`` / ``proofs`` /
    ``nodes`` and later chains — raises :class:`TypeError` before anything
    is built; an empty batch or :func:`verify_consistency_chain_batch`
    returning ``False`` raises :class:`ValueError`.
    """
    items = _check_merkle_consistency_chains_types(chains)
    if not items:
        raise ValueError("chains must not be empty")
    if not verify_consistency_chain_batch(items):
        raise ValueError("chains must pass verify_consistency_chain_batch")
    ordered = tuple(items)
    leaves = [_bound_consistency_chain_leaf(chain) for chain in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundConsistencyChainBatch(
        chains=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


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


def prove_schnorr_batch_bound(
    entries: Sequence[MultiSchnorrEntry],
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[BoundSchnorrBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundSchnorrBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`MultiSchnorrEntry` rules as
    :func:`verify_schnorr_batch` and must be non-empty; every entry is
    copied into a tuple in its original order with duplicates preserved,
    and the inputs are never mutated. Each entry is encoded to its outer
    leaf byte for byte with :func:`_bound_schnorr_leaf`; the domain
    separator, length framing and field order stay unchanged, and the
    leaf digests and internal nodes follow the existing SHA-256 Merkle
    rules. With ``n = len(entries)``, the complete multi-inclusion proof
    is built with :func:`prove_multi_inclusion` over the encoded leaves
    and the full indices ``tuple(range(n))`` — so its ``indices`` cover
    every leaf from zero and its ``siblings`` are empty — and the
    returned batch carries ``leaf_count = n`` alongside that proof. The
    second return value is the outer tree's :func:`merkle_root` of the
    encoded leaves, which is exactly the root the batch verifies under:
    ``verify_bound(batch, root)`` returns ``True``. Single-item, odd- and
    even-sized batches and duplicate entries are all deterministic and
    byte for byte compatible with the previous manual construction.

    A type preflight over the whole batch — every entry and every nested
    field, including ``bool`` integers and later entries — raises
    :class:`TypeError` before anything is built; an empty batch, a
    ``U``-framed batch count outside uint64, a negative leaf integer, or
    :func:`verify_schnorr_batch` returning ``False`` (an invalid inner
    signature) raises :class:`ValueError`. The ``randbelow`` argument is
    passed through to :func:`verify_schnorr_batch` unchanged under its
    randomness contract, so the random source's own exceptions surface
    unchanged.
    """
    items = _check_multi_schnorr_entries_types(entries)
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    if not items:
        raise ValueError("entries must not be empty")
    if not _schnorr_batch_replay_encodable(items):
        raise ValueError("entries contain an integer that cannot be U-framed")
    if not verify_schnorr_batch(items, randbelow=randbelow):
        raise ValueError("entries must pass verify_schnorr_batch")
    ordered = tuple(items)
    leaves = [_bound_schnorr_leaf(entry) for entry in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundSchnorrBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


# ---------------------------------------------------------------------------
# Merkle-committed same-key Schnorr batches
#
# The same-key analogue of BoundSchnorrBatch: a complete batch of
# SchnorrBatchEntry items (message / proof / context only) frozen together
# with the Merkle multi-inclusion proof that commits to every entry. The
# verifier supplies the one fixed public key and group, so each leaf lifts
# an entry into a MultiSchnorrEntry under the verifier's key/group and
# reuses the BoundSchnorr leaf encoding byte for byte. Verification is a
# method of SchnorrVerifier: the Merkle binding is checked first with
# verify_multi_inclusion, and verify_batch runs only once the root passes.


@dataclass(frozen=True)
class SingleKeyBoundBatch:
    """A complete same-key Schnorr batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a tuple of :class:`SchnorrBatchEntry`;
    ``leaf_count`` — a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``; ``proof`` — the
    :class:`MerkleMultiProof` whose indices cover ``0 .. leaf_count - 1``
    without gaps or duplicates. All three are positional construction
    arguments; batches compare by value and are immutable.
    """

    entries: tuple[SchnorrBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


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


def prove_region_batch_bound(
    entries: Sequence[RegionBatchEntry],
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[BoundRegionBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundRegionBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`RegionBatchEntry` rules as
    :func:`verify_region_batch` and must be non-empty; every entry is
    copied into a tuple in its original order with duplicates preserved,
    and the inputs are never mutated. Each entry is encoded to its outer
    leaf byte for byte with :func:`_bound_region_leaf`; the domain
    separator, length framing and field order stay unchanged, and the
    leaf digests and internal nodes follow the existing SHA-256 Merkle
    rules. With ``n = len(entries)``, the complete multi-inclusion proof
    is built with :func:`prove_multi_inclusion` over the encoded leaves
    and the full indices ``tuple(range(n))`` — so its ``indices`` cover
    every leaf from zero and its ``siblings`` are empty — and the
    returned batch carries ``leaf_count = n`` alongside that proof. The
    second return value is the outer tree's :func:`merkle_root` of the
    encoded leaves, which is exactly the root the batch verifies under:
    ``verify_region_bound(batch, root)`` returns ``True``. Single-item,
    odd- and even-sized batches and duplicate entries are all
    deterministic and byte for byte compatible with the previous manual
    construction.

    A type preflight over the whole batch — every entry and every nested
    field, including ``bool`` counts and later entries — raises
    :class:`TypeError` before anything is built; an empty batch, a
    ``U``-framed batch count outside uint64, or
    :func:`verify_region_batch` returning ``False`` (an invalid inner
    region proof) raises :class:`ValueError`. The ``randbelow``
    argument is passed through to :func:`verify_region_batch` unchanged
    under its randomness contract.
    """
    items = _check_region_batch_entries_types(entries)
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    if not items:
        raise ValueError("entries must not be empty")
    if not _region_batch_replay_encodable(items):
        raise ValueError("batch length must be an unsigned 64-bit integer")
    if not verify_region_batch(items, randbelow=randbelow):
        raise ValueError("entries must pass verify_region_batch")
    ordered = tuple(items)
    leaves = [_bound_region_leaf(entry) for entry in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundRegionBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


# ---------------------------------------------------------------------------
# Merkle-committed range batches
#
# A complete range batch frozen together with the Merkle proof that commits
# to every entry. Each Merkle leaf starts from the domain separator
# b"zkregion/range-bound/v1" and frames, in order, the six commitment
# fields, the context and the t / e / s sequences of the proof (each
# sequence framed as its decimal element count followed by every value).
# Verification first checks every leaf against the Merkle root, then runs
# the unchanged range batch verification.

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
    (dataclass field order), the context, then each of the proof's
    ``t`` / ``e`` / ``s`` sequences framed as its decimal element count
    followed by every value. Every item is prefixed with its four-byte
    unsigned big-endian length; integers are encoded as decimal ASCII
    (negative sign kept).
    """
    commitment = entry.commitment
    items = [_RANGE_BOUND_DOMAIN]
    items.extend(
        str(getattr(commitment, name)).encode("ascii")
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
                    f"entries[{position}] proof {field_name} "
                    "must be a tuple of integers"
                )
            for item in field:
                _check_int(
                    item,
                    f"entries[{position}] proof {field_name} entry",
                )
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


def prove_range_batch_bound(
    entries: Sequence[RangeBatchEntry],
    *,
    randbelow: Callable[[int], int] = secrets.randbelow,
) -> tuple[BoundRangeBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundRangeBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`RangeBatchEntry` rules as
    :func:`verify_range_batch` and must be non-empty; every item is
    copied into a tuple in its original order with duplicates preserved,
    and the inputs are never mutated. Each item is encoded to its outer
    leaf byte for byte with :func:`_bound_range_leaf`; the domain
    separator, length framing and field order stay unchanged, and the
    leaf digests and internal nodes follow the existing SHA-256 Merkle
    rules. With ``n = len(entries)``, the complete multi-inclusion proof
    is built with :func:`prove_multi_inclusion` over the encoded leaves
    and the full indices ``tuple(range(n))`` — so its ``indices`` cover
    every leaf from zero and its ``siblings`` are empty — and the
    returned batch carries ``leaf_count = n`` alongside that proof. The
    second return value is the outer tree's :func:`merkle_root` of the
    encoded leaves, which is exactly the root the batch verifies under:
    ``verify_range_bound(batch, root)`` returns ``True``. Single-item,
    odd- and even-sized batches and duplicate items are all
    deterministic and byte for byte compatible with the previous manual
    construction.

    A type preflight over the whole batch — every item and every nested
    field, including ``bool`` counts and later items — raises
    :class:`TypeError` before anything is built; an empty batch, a
    ``U``-framed batch count outside uint64, or
    :func:`verify_range_batch` returning ``False`` (an invalid inner
    range proof) raises :class:`ValueError`. The ``randbelow``
    argument is passed through to :func:`verify_range_batch` unchanged
    under its randomness contract.
    """
    items = _check_range_batch_entries_types(entries)
    if not callable(randbelow):
        raise TypeError("randbelow must be callable")
    if not items:
        raise ValueError("entries must not be empty")
    if not _range_batch_replay_encodable(items):
        raise ValueError("batch length must be an unsigned 64-bit integer")
    if not verify_range_batch(items, randbelow=randbelow):
        raise ValueError("entries must pass verify_range_batch")
    ordered = tuple(items)
    leaves = [_bound_range_leaf(item) for item in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundRangeBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


# ---------------------------------------------------------------------------
# Merkle-committed opening batches
#
# A complete hash-opening batch (BoundOpeningBatch) or Pedersen-opening
# batch (BoundPedersenOpeningBatch) frozen together with the Merkle
# multi-inclusion proof that commits to every entry. Each outer leaf writes
# the entry's opening fields item by item — commitment, value and nonce for
# hash openings; the six commitment fields, value and blinding for Pedersen
# openings — every item prefixed with its four-byte unsigned big-endian
# length and the domain separator written first; integers are decimal ASCII
# with the sign kept. The field run behind the framed domain separator is
# byte for byte the replay guards' Q(entry) framing, and the leaf digests
# and internal nodes follow the existing SHA-256 Merkle rules. Verification
# checks the outer root first and only then delegates to the unchanged bare
# batch verification.

_OPENING_BOUND_DOMAIN = b"zkregion/ob/v1"
_PEDERSEN_OPENING_BOUND_DOMAIN = b"zkregion/pob/v1"


@dataclass(frozen=True)
class BoundOpeningBatch:
    """A complete hash-opening batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a tuple of :class:`OpeningBatchEntry`;
    ``leaf_count`` — a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``; ``proof`` — the
    :class:`MerkleMultiProof` whose indices cover ``0 .. leaf_count - 1``
    without gaps or duplicates. All three are positional construction
    arguments; batches compare by value and are immutable.
    """

    entries: tuple[OpeningBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_opening_leaf(entry: OpeningBatchEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`OpeningBatchEntry`.

    The leaf is the framed domain separator ``b"zkregion/ob/v1"`` followed
    by the entry's ``commitment``, ``value`` and ``nonce`` — the arguments
    of :func:`verify_opening`, in the same order — each prefixed with its
    four-byte unsigned big-endian length. The field run is byte for byte
    the :class:`OpeningBatchReplayGuard` transcript's ``Q(entry)``.
    """
    return _frame_length_prefixed(_OPENING_BOUND_DOMAIN) + _opening_batch_leaf(entry)


def verify_opening_batch_bound(batch: BoundOpeningBatch, root: bytes) -> bool:
    """Verify a Merkle-committed complete :class:`BoundOpeningBatch`.

    The Merkle binding is checked first: every entry is encoded to its leaf
    exactly as specified by :func:`_bound_opening_leaf` and the whole batch
    is checked against ``root`` with :func:`verify_multi_inclusion`.
    ``leaf_count`` must be a positive, non-``bool`` integer equal to both
    ``len(entries)`` and ``proof.leaf_count``, and ``proof.indices`` must
    cover ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering; an
    empty batch, a missing entry, a count mismatch or any index mismatch
    returns ``False``. Only after the root checks does the batch go through
    :func:`verify_opening_batch` unchanged, which rechecks every opening in
    order.

    Type errors — a batch that is not a :class:`BoundOpeningBatch`,
    non-tuple entries, non-:class:`OpeningBatchEntry` items, a non-integer
    or ``bool`` ``leaf_count``, a wrong proof/root object, or malformed
    nested field types (including ``bool`` indices, a non-tuple
    ``indices`` / ``siblings`` or non-``bytes`` commitment, value, nonce or
    sibling) — raise :class:`TypeError`; every other invalidity (empty
    batch, miscount, incomplete indices, wrong root, tampered leaf bytes or
    any :func:`verify_opening_batch` rejection) returns ``False``. Inputs
    are never mutated.
    """
    if not isinstance(batch, BoundOpeningBatch):
        raise TypeError("batch must be a BoundOpeningBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError("batch entries must be a tuple of OpeningBatchEntry")
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
    _check_opening_batch_entries_types(entries)

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    leaves = [_bound_opening_leaf(entry) for entry in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged opening batch verification checks each opening
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_opening_batch(entries)


def prove_opening_batch_bound(
    entries: Sequence[OpeningBatchEntry],
) -> tuple[BoundOpeningBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundOpeningBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`OpeningBatchEntry` rules as
    :func:`verify_opening_batch` and must be non-empty; every item is
    copied into a tuple in its original order with duplicates preserved,
    and the inputs are never mutated. Each item is encoded to its outer
    leaf byte for byte with :func:`_bound_opening_leaf`; the domain
    separator, length framing and field order stay unchanged, and the
    leaf digests and internal nodes follow the existing SHA-256 Merkle
    rules. With ``n = len(entries)``, the complete multi-inclusion proof
    is built with :func:`prove_multi_inclusion` over the encoded leaves
    and the full indices ``tuple(range(n))`` — so its ``indices`` cover
    every leaf from zero and its ``siblings`` are empty — and the
    returned batch carries ``leaf_count = n`` alongside that proof. The
    second return value is the outer tree's :func:`merkle_root` of the
    encoded leaves, which is exactly the root the batch verifies under:
    ``verify_opening_batch_bound(batch, root)`` returns ``True``.
    Single-item, odd- and even-sized batches and duplicate items are all
    deterministic, and repeated constructions are byte for byte
    identical.

    A type preflight over the whole batch — every item and every nested
    field, including later items — raises :class:`TypeError` before
    anything is built; an empty batch, a batch count outside uint64, or
    :func:`verify_opening_batch` returning ``False`` (a mismatching
    commitment, value or nonce) raises :class:`ValueError`.
    """
    items = _check_opening_batch_entries_types(entries)
    if not items:
        raise ValueError("entries must not be empty")
    if not _opening_batch_replay_encodable(items):
        raise ValueError("batch length must be an unsigned 64-bit integer")
    if not verify_opening_batch(items):
        raise ValueError("entries must pass verify_opening_batch")
    ordered = tuple(items)
    leaves = [_bound_opening_leaf(item) for item in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundOpeningBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


@dataclass(frozen=True)
class BoundPedersenOpeningBatch:
    """A complete Pedersen-opening batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a tuple of
    :class:`PedersenOpeningBatchEntry`; ``leaf_count`` — a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``; ``proof`` — the :class:`MerkleMultiProof` whose
    indices cover ``0 .. leaf_count - 1`` without gaps or duplicates. All
    three are positional construction arguments; batches compare by value
    and are immutable.
    """

    entries: tuple[PedersenOpeningBatchEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_pedersen_opening_leaf(entry: PedersenOpeningBatchEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`PedersenOpeningBatchEntry`.

    The leaf is the framed domain separator ``b"zkregion/pob/v1"``
    followed by the commitment's ``element`` / ``lower`` / ``upper`` /
    ``prime`` / ``generator`` / ``h`` fields and the entry's ``value`` and
    ``blinding`` — together the arguments of
    :func:`verify_pedersen_opening`, in the same order. Every integer is
    encoded as decimal ASCII with the sign kept and prefixed with its
    four-byte unsigned big-endian length. The field run is byte for byte
    the :class:`PedersenOpeningBatchReplayGuard` transcript's
    ``Q(entry)``.
    """
    return (
        _frame_length_prefixed(_PEDERSEN_OPENING_BOUND_DOMAIN)
        + _pedersen_opening_batch_leaf(entry)
    )


def verify_pedersen_opening_batch_bound(
    batch: BoundPedersenOpeningBatch,
    root: bytes,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundPedersenOpeningBatch`.

    The Merkle binding is checked first: every entry is encoded to its
    leaf exactly as specified by :func:`_bound_pedersen_opening_leaf` and
    the whole batch is checked against ``root`` with
    :func:`verify_multi_inclusion`. ``leaf_count`` must be a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``, and ``proof.indices`` must cover
    ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering; an
    empty batch, a missing entry, a count mismatch or any index mismatch
    returns ``False``. Only after the root checks does the batch go
    through :func:`verify_pedersen_opening_batch` unchanged, which
    rechecks every opening in order under each commitment's own group
    parameters and declared range.

    Type errors — a batch that is not a
    :class:`BoundPedersenOpeningBatch`, non-tuple entries,
    non-:class:`PedersenOpeningBatchEntry` items, a non-integer or
    ``bool`` ``leaf_count``, a wrong proof/root object, or malformed
    nested field types (including a ``bool`` passed as an integer, a
    non-tuple ``indices`` / ``siblings`` or a non-``bytes`` sibling) —
    raise :class:`TypeError`; every other invalidity (empty batch,
    miscount, incomplete indices, wrong root, tampered leaf bytes or any
    :func:`verify_pedersen_opening_batch` rejection) returns ``False``.
    Inputs are never mutated.
    """
    if not isinstance(batch, BoundPedersenOpeningBatch):
        raise TypeError("batch must be a BoundPedersenOpeningBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of PedersenOpeningBatchEntry"
        )
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
    _check_pedersen_opening_batch_entries_types(entries)

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    leaves = [_bound_pedersen_opening_leaf(entry) for entry in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged Pedersen opening batch verification runs
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_pedersen_opening_batch(entries)


def prove_pedersen_opening_batch_bound(
    entries: Sequence[PedersenOpeningBatchEntry],
) -> tuple[BoundPedersenOpeningBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundPedersenOpeningBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`PedersenOpeningBatchEntry` rules as
    :func:`verify_pedersen_opening_batch` and must be non-empty; every
    item is copied into a tuple in its original order with duplicates
    preserved, and the inputs are never mutated. Each item is encoded to
    its outer leaf byte for byte with
    :func:`_bound_pedersen_opening_leaf`; the domain separator, length
    framing, decimal ASCII integer convention and field order stay
    unchanged, and the leaf digests and internal nodes follow the
    existing SHA-256 Merkle rules. With ``n = len(entries)``, the
    complete multi-inclusion proof is built with
    :func:`prove_multi_inclusion` over the encoded leaves and the full
    indices ``tuple(range(n))`` — so its ``indices`` cover every leaf
    from zero and its ``siblings`` are empty — and the returned batch
    carries ``leaf_count = n`` alongside that proof. The second return
    value is the outer tree's :func:`merkle_root` of the encoded leaves,
    which is exactly the root the batch verifies under:
    ``verify_pedersen_opening_batch_bound(batch, root)`` returns
    ``True``. Single-item, odd- and even-sized batches and duplicate
    items are all deterministic, and repeated constructions are byte for
    byte identical.

    A type preflight over the whole batch — every item and every nested
    field, including ``bool`` integers and later items — raises
    :class:`TypeError` before anything is built; an empty batch, a batch
    count outside uint64, or :func:`verify_pedersen_opening_batch`
    returning ``False`` (an out-of-range parameter, a value outside the
    declared range or an incorrect opening) raises :class:`ValueError`.
    """
    items = _check_pedersen_opening_batch_entries_types(entries)
    if not items:
        raise ValueError("entries must not be empty")
    if not _pedersen_opening_batch_replay_encodable(items):
        raise ValueError("batch length must be an unsigned 64-bit integer")
    if not verify_pedersen_opening_batch(items):
        raise ValueError("entries must pass verify_pedersen_opening_batch")
    ordered = tuple(items)
    leaves = [_bound_pedersen_opening_leaf(item) for item in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundPedersenOpeningBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


# ---------------------------------------------------------------------------
# Merkle-committed complete region-contains batches
#
# A BoundRegionContainsBatch commits a whole RegionContainsEntry batch to a
# Merkle tree: each entry is encoded to its outer leaf (domain separator
# b"zkregion/rcb/v1", then the entry fields in construction order with
# nested objects expanded in dataclass field order, every integer as
# decimal ASCII with the sign kept and every atom length-prefixed), the
# leaves are committed in batch order and the batch carries a complete
# multi-inclusion proof. verify_region_contains_bound checks the root
# first, then delegates to verify_region_contains_batch unchanged;
# prove_region_contains_bound is the canonical constructor.

_REGION_CONTAINS_BOUND_DOMAIN = b"zkregion/rcb/v1"


@dataclass(frozen=True)
class BoundRegionContainsBatch:
    """A complete region-contains batch bound to a Merkle multi-inclusion proof.

    Fields, in order: ``entries`` — a tuple of
    :class:`RegionContainsEntry`; ``leaf_count`` — a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``; ``proof`` — the :class:`MerkleMultiProof` whose
    indices cover ``0 .. leaf_count - 1`` without gaps or duplicates. All
    three are positional construction arguments; batches compare by value
    and are immutable.
    """

    entries: tuple[RegionContainsEntry, ...]
    leaf_count: int
    proof: MerkleMultiProof


def _bound_region_contains_leaf(entry: RegionContainsEntry) -> bytes:
    """Build the Merkle leaf committed for one :class:`RegionContainsEntry`.

    The leaf is the framed domain separator ``b"zkregion/rcb/v1"``
    followed by the entry's fields in construction order: the region's
    ``min_x`` / ``max_x`` / ``min_y`` / ``max_y`` bounds, the x
    commitment's ``element`` / ``lower`` / ``upper`` / ``prime`` /
    ``generator`` / ``h`` fields, the y commitment's six fields in the
    same order, and the entry's ``x`` / ``y`` / ``x_blinding`` /
    ``y_blinding`` — together the arguments of
    :func:`region_contains_committed`, in the same order. Nested objects
    are expanded in dataclass field order; every integer is encoded as
    decimal ASCII with the sign kept and every atom is prefixed with its
    four-byte unsigned big-endian length.
    """
    region = entry.region
    items = [_REGION_CONTAINS_BOUND_DOMAIN]
    items.extend(
        str(bound).encode("ascii")
        for bound in (region.min_x, region.max_x, region.min_y, region.max_y)
    )
    for commitment in (entry.x_commitment, entry.y_commitment):
        items.extend(
            str(getattr(commitment, name)).encode("ascii")
            for name in ("element", "lower", "upper", "prime", "generator", "h")
        )
    items.extend(
        str(value).encode("ascii")
        for value in (entry.x, entry.y, entry.x_blinding, entry.y_blinding)
    )
    leaf = bytearray()
    for item in items:
        leaf += len(item).to_bytes(4, "big")
        leaf += item
    return bytes(leaf)


def _region_contains_batch_encodable(
    entries: Sequence[RegionContainsEntry],
) -> bool:
    """The batch length must fit in an unsigned 64-bit integer.

    Each entry's integers are encoded as decimal ASCII with the sign
    kept, so every integer field frames for any value and no per-entry
    encodability rule is needed.
    """
    return 0 <= len(entries) <= _UINT64_MAX


def verify_region_contains_bound(
    batch: BoundRegionContainsBatch,
    root: bytes,
) -> bool:
    """Verify a Merkle-committed complete :class:`BoundRegionContainsBatch`.

    The Merkle binding is checked first: every entry is encoded to its
    leaf exactly as specified by :func:`_bound_region_contains_leaf` and
    the whole batch is checked against ``root`` with
    :func:`verify_multi_inclusion`. ``leaf_count`` must be a positive,
    non-``bool`` integer equal to both ``len(entries)`` and
    ``proof.leaf_count``, and ``proof.indices`` must cover
    ``0 .. leaf_count - 1`` with no gaps, duplicates or reordering; an
    empty batch, a missing entry, a count mismatch or any index mismatch
    returns ``False``. Only after the root checks does the batch go
    through :func:`verify_region_contains_batch` unchanged, which
    rechecks every entry in order under each commitment's own group
    parameters and declared range.

    Type errors — a batch that is not a
    :class:`BoundRegionContainsBatch`, non-tuple entries,
    non-:class:`RegionContainsEntry` items, a non-integer or ``bool``
    ``leaf_count``, a wrong proof/root object, or malformed nested field
    types (including a ``bool`` passed as an integer, a non-tuple
    ``indices`` / ``siblings`` or a non-``bytes`` sibling) — raise
    :class:`TypeError`; every other invalidity (empty batch, miscount,
    incomplete indices, wrong root, tampered leaf bytes or any
    :func:`verify_region_contains_batch` rejection) returns ``False``.
    Inputs are never mutated.
    """
    if not isinstance(batch, BoundRegionContainsBatch):
        raise TypeError("batch must be a BoundRegionContainsBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of RegionContainsEntry"
        )
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
    _check_region_contains_entries_types(entries)

    if leaf_count < 1:
        return False
    if leaf_count != len(entries) or leaf_count != proof.leaf_count:
        return False
    if proof.indices != tuple(range(leaf_count)):
        return False  # empty coverage, gaps, duplicates or reordering

    leaves = [_bound_region_contains_leaf(entry) for entry in entries]

    # 1) the Merkle root commits to every entry leaf, then
    # 2) the unchanged region-contains batch verification runs
    if not verify_multi_inclusion(list(enumerate(leaves)), proof, root):
        return False
    return verify_region_contains_batch(entries)


def prove_region_contains_bound(
    entries: Sequence[RegionContainsEntry],
) -> tuple[BoundRegionContainsBatch, bytes]:
    """Build a complete, Merkle-committed :class:`BoundRegionContainsBatch`.

    ``entries`` follows the same non-``bytes`` / ``bytearray`` / ``str``
    sequence-of-:class:`RegionContainsEntry` rules as
    :func:`verify_region_contains_batch` and must be non-empty; every
    item is copied into a tuple in its original order with duplicates
    preserved, and the inputs are never mutated. Each item is encoded to
    its outer leaf byte for byte with
    :func:`_bound_region_contains_leaf`; the domain separator, length
    framing, decimal ASCII integer convention and field order stay
    unchanged, and the leaf digests and internal nodes follow the
    existing SHA-256 Merkle rules. With ``n = len(entries)``, the
    complete multi-inclusion proof is built with
    :func:`prove_multi_inclusion` over the encoded leaves and the full
    indices ``tuple(range(n))`` — so its ``indices`` cover every leaf
    from zero and its ``siblings`` are empty — and the returned batch
    carries ``leaf_count = n`` alongside that proof. The second return
    value is the outer tree's :func:`merkle_root` of the encoded leaves,
    which is exactly the root the batch verifies under:
    ``verify_region_contains_bound(batch, root)`` returns ``True``.
    Single-item, odd- and even-sized batches and duplicate items are all
    deterministic, and repeated constructions are byte for byte
    identical.

    A type preflight over the whole batch — every item and every nested
    field, including ``bool`` integers and later items — raises
    :class:`TypeError` before anything is built; an empty batch, a batch
    count outside uint64, or :func:`verify_region_contains_batch`
    returning ``False`` (an opening mismatch, an out-of-range blinding
    or embedded parameter, a declared range that does not match the
    region bounds or a point outside the rectangle) raises
    :class:`ValueError`.
    """
    items = _check_region_contains_entries_types(entries)
    if not items:
        raise ValueError("entries must not be empty")
    if not _region_contains_batch_encodable(items):
        raise ValueError("batch length must be an unsigned 64-bit integer")
    if not verify_region_contains_batch(items):
        raise ValueError("entries must pass verify_region_contains_batch")
    ordered = tuple(items)
    leaves = [_bound_region_contains_leaf(item) for item in ordered]
    root = merkle_root(leaves)
    proof = prove_multi_inclusion(leaves, tuple(range(len(ordered))))
    batch = BoundRegionContainsBatch(
        entries=ordered,
        leaf_count=len(ordered),
        proof=proof,
    )
    return batch, root


# ---------------------------------------------------------------------------
# Per-instance replay protection
#
# A ReplayGuard binds a MultiSchnorrEntry to a caller-chosen session id via a
# ReplayBinding digest; a RangeReplayGuard does the same for a
# RangeBatchEntry and a RegionReplayGuard for a RegionBatchEntry. Bindings
# are single-use and, unless a guard is given an SQLiteReplayStore, local to
# the guard instance:
# bind_once registers a pending binding, check accepts an equal pending
# binding exactly once (verifying the proof first) and then consumes the
# session id; every rejection leaves the id untouched, and an id that is
# pending or already consumed can never be rebound. A store-backed guard
# keeps the same three states in the store under its own key domain (the
# store itself uses b"zr/r/v1"; a RangeReplayGuard views it under
# b"zr/rr/v1"), shared across instances and restarts.
#
# digest = SHA-256(F(D) || F(session_id) || L(entry) || F(E))
#   D = b"zr/r/v1"   (ReplayGuard),  b"zr/rr/v1"  (RangeReplayGuard)
#                     or b"zr/rg/v1"  (RegionReplayGuard)
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   L(entry) = the BoundSchnorr / BoundRange / BoundRegion leaf bytes (see
#              _bound_schnorr_leaf / _bound_range_leaf / _bound_region_leaf),
#              raw, i.e. without an F framing
#   E = b"\x00"                          when expires_at is None
#     = b"\x01" + uint64be(expires_at)   otherwise

_REPLAY_DOMAIN = b"zr/r/v1"
_RANGE_REPLAY_DOMAIN = b"zr/rr/v1"
_RANGE_BATCH_REPLAY_DOMAIN = b"zr/rbr/v1"
_REGION_REPLAY_DOMAIN = b"zr/rg/v1"
_REGION_BATCH_REPLAY_DOMAIN = b"zr/rgbr/v1"
_BOUND_REGION_REPLAY_DOMAIN = b"zr/brg/v1"
_BOUND_RANGE_REPLAY_DOMAIN = b"zr/brr/v1"
_BOUND_SCHNORR_REPLAY_DOMAIN = b"zr/bsr/v1"
_MERKLE_CHAIN_REPLAY_DOMAIN = b"zr/mccr/v1"
_MERKLE_CHAIN_BATCH_REPLAY_DOMAIN = b"zr/mccbr/v1"
_MERKLE_CONSISTENCY_REPLAY_DOMAIN = b"zr/mcr/v1"
_MERKLE_INCLUSION_REPLAY_DOMAIN = b"zr/mir/v1"
_MERKLE_INCLUSION_BATCH_REPLAY_DOMAIN = b"zr/mibr/v1"
_MERKLE_MULTI_REPLAY_DOMAIN = b"zr/mmr/v1"
_MERKLE_MULTI_BATCH_REPLAY_DOMAIN = b"zr/mmb/v1"
_MERKLE_CONSISTENCY_BATCH_REPLAY_DOMAIN = b"zr/mcbr/v1"
_SCHNORR_BATCH_REPLAY_DOMAIN = b"zr/sbr/v1"
_SINGLE_KEY_BATCH_REPLAY_DOMAIN = b"zr/skbr/v1"
_SINGLE_KEY_BOUND_REPLAY_DOMAIN = b"zr/skbbr/v1"
_BOUND_CONSISTENCY_REPLAY_DOMAIN = b"zr/bcbr/v1"
_BOUND_CONSISTENCY_CHAIN_REPLAY_DOMAIN = b"zr/bccbr/v1"
_BOUND_MERKLE_MULTI_BATCH_REPLAY_DOMAIN = b"zr/bmmbr/v1"
_BOUND_MERKLE_INCLUSION_BATCH_REPLAY_DOMAIN = b"zr/bmibr/v1"
_OPENING_BATCH_REPLAY_DOMAIN = b"zr/obr/v1"
_PEDERSEN_OPENING_BATCH_REPLAY_DOMAIN = b"zr/pobr/v1"
_BOUND_OPENING_REPLAY_DOMAIN = b"zr/bobr/v1"
_BOUND_PEDERSEN_OPENING_REPLAY_DOMAIN = b"zr/pbobr/v1"
_UINT64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class ReplayBinding:
    """A single-use replay binding of a session id to an entry.

    Fields, in order: ``session_id`` — a non-empty ``bytes`` identifier;
    ``digest`` — the ``bytes`` binding digest (no fixed length is imposed;
    the guards always store a 32-byte SHA-256 digest); ``expires_at`` — an
    optional non-``bool`` unsigned 64-bit Unix-second expiry. All three are
    positional construction arguments; bindings compare by value and are
    immutable.
    """

    session_id: bytes
    digest: bytes
    expires_at: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, bytes):
            raise TypeError("session_id must be bytes")
        if not self.session_id:
            raise ValueError("session_id must not be empty")
        if not isinstance(self.digest, bytes):
            raise TypeError("digest must be bytes")
        if self.expires_at is not None:
            _check_uint64(self.expires_at, "expires_at")


def _check_uint64(value: object, name: str) -> None:
    """Non-bool integers in the unsigned 64-bit range; bool is rejected."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be a non-bool integer")
    if not 0 <= value <= _UINT64_MAX:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")


def _replay_expiry_bytes(expires_at: int | None) -> bytes:
    if expires_at is None:
        return b"\x00"
    return b"\x01" + expires_at.to_bytes(8, "big")


class _ReplayRegistry:
    """Thread-safe per-instance pending/claimed/consumed session state.

    A session id passes through the states ``pending`` (registered by
    ``bind_once`` but no ``check`` is working on it), ``claimed`` (exactly
    one ``check`` has atomically taken the id and is running its potentially
    long verification) and ``consumed`` (a verification succeeded). Both
    pending and claimed ids reject a rebind or a second concurrent claim, so
    at most one concurrent ``check`` of the same id can win.

    Every method holds the registry lock only for its short dictionary
    mutation; callers release it (via :meth:`claim`) *before* delegating to
    proof verification, so a slow verification of one id never serializes
    checks or binds of a different id.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[bytes, ReplayBinding] = {}
        self._claims: dict[bytes, ReplayBinding] = {}
        self._consumed: set[bytes] = set()

    def register(self, session_id: bytes, binding: ReplayBinding) -> None:
        """Register ``binding`` as pending; the id must not be in use.

        Caller has already validated the arguments, so the duplicate case
        (pending, claimed or consumed) is the only failure and raises
        :class:`ValueError`.
        """
        with self._lock:
            if session_id in self._pending or session_id in self._claims or session_id in self._consumed:
                raise ValueError("session_id is already bound or has been consumed")
            self._pending[session_id] = binding

    def claim(self, session_id: bytes, binding: ReplayBinding) -> bool:
        """Atomically take a pending id iff its stored binding equals ``binding``.

        Returns ``True`` exactly once among concurrent claims of the same id
        and moves the id from pending to claimed. An unknown, consumed,
        already-claimed id or an unequal binding returns ``False`` without
        changing state.
        """
        with self._lock:
            stored = self._pending.get(session_id)
            if stored is None or stored != binding:
                return False
            del self._pending[session_id]
            self._claims[session_id] = stored
            return True

    def commit(self, session_id: bytes) -> None:
        """Move a claimed id to consumed.

        The id is known to be claimed by this caller, so it is discarded
        directly; a missing id is tolerated rather than raising
        :class:`KeyError`.
        """
        with self._lock:
            self._claims.pop(session_id, None)
            self._consumed.add(session_id)

    def release(self, session_id: bytes) -> None:
        """Undo a claim after a rejection or an escaped verification error.

        The id becomes pending again with its original binding. A missing
        claim is tolerated, so an unexpected state never surfaces as
        :class:`KeyError`.
        """
        with self._lock:
            binding = self._claims.pop(session_id, None)
            if binding is not None:
                self._pending[session_id] = binding

    def pending_snapshot(self) -> dict[bytes, ReplayBinding]:
        """A point-in-time copy of the pending bindings (compat/tests)."""
        with self._lock:
            return dict(self._pending)

    def consumed_snapshot(self) -> set[bytes]:
        """A point-in-time copy of the consumed ids (compat/tests)."""
        with self._lock:
            return set(self._consumed)


class SQLiteReplayStore:
    """Persistent, shareable pending/claimed/consumed state for replay guards.

    A store persists the same three states as the in-instance
    :class:`_ReplayRegistry` in an SQLite database file: every row is keyed
    by the three ``bytes`` segments ``namespace``, the guard's domain
    (``b"zr/r/v1"`` for this store itself) and ``session_id``; its value is
    the registered :class:`ReplayBinding`
    (digest and the same ``E`` expiry framing used by the binding digest)
    together with its state. Independent :class:`ReplayGuard` instances
    attached to the same file (including ones opened in another process or
    after a restart) therefore share pending, claimed and consumed ids; two
    stores using different namespaces in the same file never interact. A
    guard for another entry kind (see :class:`RangeReplayGuard`,
    :class:`RangeBatchReplayGuard`,
    :class:`RegionReplayGuard`, :class:`RegionBatchReplayGuard`,
    :class:`BoundRegionReplayGuard`,
    :class:`BoundRangeReplayGuard`, :class:`BoundSchnorrReplayGuard`,
    :class:`SingleKeyBoundReplayGuard`,
    :class:`MerkleConsistencyChainReplayGuard`,
    :class:`MerkleConsistencyReplayGuard`,
    :class:`MerkleInclusionReplayGuard`,
    :class:`MerkleInclusionBatchReplayGuard`,
    :class:`MerkleMultiReplayGuard`,
    :class:`SchnorrBatchReplayGuard`,
    :class:`OpeningBatchReplayGuard` and
    :class:`PedersenOpeningBatchReplayGuard`)
    keeps its rows in the same table under its own domain segment via
    :meth:`_view`, so one store file and namespace can serve several guard
    kinds without their ids colliding.

    A ``check`` writes a fresh random claim token together with the lease
    deadline ``clock() + lease_seconds`` in one short transaction, then runs
    its proof verification without holding any transaction. Only the holder
    of the current token may consume the id; a rejection or an escaped
    verification error restores the id to ``pending`` using that same token.
    When a claim's deadline has passed, a later ``bind_once`` rejects (as it
    does for any live id) while a later ``check`` with an equal binding may
    take the expired claim over with a new token, after which the stale token
    can no longer consume or release anything.

    All mutations are short ``BEGIN IMMEDIATE`` transactions, so concurrent
    instances in other processes are serialized at claim time; SQLite errors
    propagate as :class:`sqlite3.Error`. ``lease_seconds`` must be a positive
    non-``bool`` integer; ``clock`` defaults to integer Unix seconds and,
    when supplied, must be a callable returning a non-``bool`` integer inside
    the unsigned 64-bit range (a value outside it raises :class:`ValueError`).
    """

    _TABLE = "replay_sessions_v1"
    _DOMAIN = _REPLAY_DOMAIN
    _CLAIM_TOKEN_BYTES = 16

    def __init__(
        self,
        path: str,
        namespace: bytes = b"default",
        *,
        lease_seconds: int = 30,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(path, str):
            raise TypeError("path must be a str")
        _check_bytes(namespace, "namespace")
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool):
            raise TypeError("lease_seconds must be a non-bool integer")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._path = path
        self._namespace = namespace
        self._lease_seconds = lease_seconds
        self._clock = clock if clock is not None else self._default_clock
        # One connection per store; the RLock keeps this process's callers
        # out of one another's transactions while BEGIN IMMEDIATE serializes
        # writers in other processes. isolation_level=None puts the
        # connection in autocommit mode so the explicit short transactions
        # below are the only transactions in flight.
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        try:
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(
                f"CREATE TABLE IF NOT EXISTS {self._TABLE} ("
                "namespace BLOB NOT NULL, "
                "domain BLOB NOT NULL, "
                "session_id BLOB NOT NULL, "
                "state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'consumed')), "
                "digest BLOB NOT NULL, "
                "expires_at BLOB NOT NULL, "
                "token BLOB, "
                "claim_expires BLOB, "
                "PRIMARY KEY (namespace, domain, session_id)"
                ") WITHOUT ROWID"
            )
        except BaseException:
            self._connection.close()
            raise

    @staticmethod
    def _default_clock() -> int:
        return int(time.time())

    def _now(self) -> int:
        """Read the clock once, enforcing the non-bool uint64 contract."""
        now = self._clock()
        if not isinstance(now, int) or isinstance(now, bool):
            raise TypeError("clock must return a non-bool integer")
        if not 0 <= now <= _UINT64_MAX:
            raise ValueError("clock value must be an unsigned 64-bit integer")
        return now

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """A short process-locked ``BEGIN IMMEDIATE`` transaction."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _row(self, connection: sqlite3.Connection, session_id: bytes) -> tuple | None:
        return connection.execute(
            f"SELECT state, digest, expires_at, token, claim_expires "
            f"FROM {self._TABLE} WHERE namespace = ? AND domain = ? AND session_id = ?",
            (self._namespace, self._DOMAIN, session_id),
        ).fetchone()

    def register(self, session_id: bytes, binding: ReplayBinding) -> None:
        """Insert ``binding`` as a fresh pending id in one short transaction.

        Any existing row rejects the rebind with :class:`ValueError`: a
        pending id, a claimed id (even one whose lease has expired — only
        :meth:`claim` may take an expired claim over) or a consumed id.
        """
        with self._transaction() as connection:
            row = self._row(connection, session_id)
            if row is not None:
                raise ValueError("session_id is already bound or has been consumed")
            connection.execute(
                f"INSERT INTO {self._TABLE} "
                "(namespace, domain, session_id, state, digest, expires_at, token, claim_expires) "
                "VALUES (?, ?, ?, 'pending', ?, ?, NULL, NULL)",
                (
                    self._namespace,
                    self._DOMAIN,
                    session_id,
                    binding.digest,
                    _replay_expiry_bytes(binding.expires_at),
                ),
            )

    def claim(self, session_id: bytes, binding: ReplayBinding) -> bytes | None:
        """Atomically claim a pending id or an expired, equal claim.

        Returns the opaque claim token on success, otherwise ``None``
        (unknown/consumed id, a live claim held by someone else, or an
        unequal stored binding). The token and ``clock() + lease_seconds``
        are written in the same short transaction; the deadline is stored as
        an unsigned 64-bit big-endian value because SQLite integers are
        signed and lease deadlines may reach the top half of the uint64
        range.
        """
        token = secrets.token_bytes(self._CLAIM_TOKEN_BYTES)
        now = self._now()
        claim_expires = now + self._lease_seconds
        if claim_expires > _UINT64_MAX:
            raise ValueError("claim expiry must be an unsigned 64-bit integer")
        deadline = claim_expires.to_bytes(8, "big")
        with self._transaction() as connection:
            row = self._row(connection, session_id)
            if row is None:
                return None
            state, digest, expiry, _old_token, old_deadline = row
            # The presented binding must equal the stored one whether the id
            # is pending or held by an expired claim; otherwise a check for a
            # different entry could consume an id bound to someone else.
            if digest != binding.digest or expiry != _replay_expiry_bytes(
                binding.expires_at
            ):
                return None
            if state == "consumed":
                return None
            if state == "claimed" and (
                old_deadline is None or now < int.from_bytes(old_deadline, "big")
            ):
                return None
            connection.execute(
                f"UPDATE {self._TABLE} SET state = 'claimed', token = ?, "
                "claim_expires = ? WHERE namespace = ? AND domain = ? AND session_id = ?",
                (token, deadline, self._namespace, self._DOMAIN, session_id),
            )
            return token

    def commit(self, session_id: bytes, token: bytes) -> bool:
        """Move the id claimed with ``token`` to consumed; stale tokens fail."""
        with self._transaction() as connection:
            cursor = connection.execute(
                f"UPDATE {self._TABLE} SET state = 'consumed', token = NULL, "
                "claim_expires = NULL WHERE namespace = ? AND domain = ? "
                "AND session_id = ? AND state = 'claimed' AND token = ?",
                (self._namespace, self._DOMAIN, session_id, token),
            )
            return cursor.rowcount == 1

    def release(self, session_id: bytes, token: bytes) -> bool:
        """Restore the id claimed with ``token`` to pending; stale tokens no-op."""
        with self._transaction() as connection:
            cursor = connection.execute(
                f"UPDATE {self._TABLE} SET state = 'pending', token = NULL, "
                "claim_expires = NULL WHERE namespace = ? AND domain = ? "
                "AND session_id = ? AND state = 'claimed' AND token = ?",
                (self._namespace, self._DOMAIN, session_id, token),
            )
            return cursor.rowcount == 1

    @staticmethod
    def _decode_binding(session_id: bytes, digest: bytes, expiry: bytes) -> ReplayBinding:
        if expiry == b"\x00":
            expires_at = None
        else:
            expires_at = int.from_bytes(expiry[1:], "big")
        return ReplayBinding(session_id, digest, expires_at)

    def pending_snapshot(self) -> dict[bytes, ReplayBinding]:
        """A point-in-time copy of the pending bindings (compat/tests).

        Claims whose lease has expired read as pending, mirroring the
        takeover rule used by :meth:`claim`.
        """
        now = self._now()
        with self._lock:
            rows = self._connection.execute(
                f"SELECT session_id, digest, expires_at, claim_expires "
                f"FROM {self._TABLE} WHERE namespace = ? AND domain = ? "
                "AND (state = 'pending' OR state = 'claimed')",
                (self._namespace, self._DOMAIN),
            ).fetchall()
        result = {}
        for session_id, digest, expiry, claim_expires in rows:
            if claim_expires is not None and now < int.from_bytes(
                claim_expires, "big"
            ):
                continue  # a live claim is not pending
            result[session_id] = self._decode_binding(session_id, digest, expiry)
        return result

    def consumed_snapshot(self) -> set[bytes]:
        """A point-in-time copy of the consumed ids (compat/tests)."""
        with self._lock:
            rows = self._connection.execute(
                f"SELECT session_id FROM {self._TABLE} "
                "WHERE namespace = ? AND domain = ? AND state = 'consumed'",
                (self._namespace, self._DOMAIN),
            ).fetchall()
        return {session_id for (session_id,) in rows}

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._connection.close()

    def _view(self, domain: bytes) -> SQLiteReplayStore:
        """A view of this store whose rows are keyed under ``domain``.

        The view shares the connection, lock, namespace, lease seconds and
        clock of this store; only the domain segment of the row key differs.
        It is the internal mechanism a guard for another entry kind uses to
        keep its state in the same file and namespace under its own domain
        (for example ``b"zr/rr/v1"`` for :class:`RangeReplayGuard`).
        """
        view = object.__new__(SQLiteReplayStore)
        view._path = self._path
        view._namespace = self._namespace
        view._lease_seconds = self._lease_seconds
        view._clock = self._clock
        view._lock = self._lock
        view._connection = self._connection
        view._DOMAIN = domain
        return view


def _replay_digest(
    entry: MultiSchnorrEntry,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute ``SHA-256(F(D) || F(session_id) || L(entry) || F(E))``."""
    transcript = hashlib.sha256()
    transcript.update(len(_REPLAY_DOMAIN).to_bytes(4, "big"))
    transcript.update(_REPLAY_DOMAIN)
    transcript.update(len(session_id).to_bytes(4, "big"))
    transcript.update(session_id)
    transcript.update(_bound_schnorr_leaf(entry))  # raw leaf, no F framing
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(len(expiry).to_bytes(4, "big"))
    transcript.update(expiry)
    return transcript.digest()


def _check_multi_schnorr_entry(entry: object, name: str = "entry") -> MultiSchnorrEntry:
    """Validate a MultiSchnorrEntry and its nested field types."""
    if not isinstance(entry, MultiSchnorrEntry):
        raise TypeError(f"{name} must be a MultiSchnorrEntry")
    _check_int(entry.public_key, f"{name} public_key")
    _check_bytes(entry.message, f"{name} message")
    proof = entry.proof
    if not isinstance(proof, SchnorrProof):
        raise TypeError(f"{name} proof must be a SchnorrProof")
    if (
        not isinstance(proof.commitment, int)
        or isinstance(proof.commitment, bool)
        or not isinstance(proof.response, int)
        or isinstance(proof.response, bool)
    ):
        raise TypeError(f"{name} proof commitment and response must be integers")
    _check_bytes(entry.context, f"{name} context")
    _check_int(entry.prime, f"{name} prime")
    _check_int(entry.generator, f"{name} generator")
    return entry


def _multi_schnorr_entry_is_encodable(entry: MultiSchnorrEntry) -> bool:
    """The BoundSchnorr leaf encodes integers unsignedly; negatives cannot be framed."""
    return min(
        entry.prime,
        entry.generator,
        entry.public_key,
        entry.proof.commitment,
        entry.proof.response,
    ) >= 0


class ReplayGuard:
    """Per-instance, single-use replay protection for Schnorr entries.

    A fresh guard has no registrations. :meth:`bind_once` registers a pending
    :class:`ReplayBinding` for a session id, :meth:`check` accepts an equal
    pending binding exactly once and then marks the id consumed. By default
    both the pending and the consumed state live on this guard instance and
    are never shared between instances; passing an :class:`SQLiteReplayStore`
    as ``store`` instead keeps the state in that store, so guards attached to
    the same store namespace share pending, claimed and consumed ids across
    independent instances and process restarts.

    Concurrent ``check`` calls for the same session id are resolved by an
    atomic claim (the in-instance registry lock, or the store's short
    transaction and unique claim token): at most one call claims the pending
    id and proceeds to the (potentially slow) signature verification; every
    other call sees the id as in-flight or consumed and returns ``False``.
    The claim is held only as per-id state, never as a global lock, so
    verifying one id does not block checks or binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = store
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entry: MultiSchnorrEntry,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to ``entry``.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp. A session id that
        is already pending, being checked or has been consumed raises
        :class:`ValueError`; wrong argument types raise :class:`TypeError`
        (an empty id or an out-of-range expiry raise :class:`ValueError`).
        Inputs are never mutated.
        """
        _check_multi_schnorr_entry(entry)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _multi_schnorr_entry_is_encodable(entry):
            raise ValueError("entry integer fields must be non-negative")
        binding = ReplayBinding(
            session_id,
            _replay_digest(entry, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entry: MultiSchnorrEntry,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for ``entry``.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before any verification runs, so among
        concurrent calls for the same id at most one can return ``True``.
        The entry's proof is then checked with a :class:`SchnorrVerifier`
        built from the entry's own public key and group parameters, via
        :meth:`SchnorrVerifier.verify_proof` with ``entry.message``,
        ``entry.proof`` and ``entry.context`` unchanged. For a binding with
        an expiry, ``now >= expires_at`` makes the check fail; ``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` unsigned 64-bit integer.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, expiry, bad group parameters or a failing
        proof) returns ``False``, releases any claim and leaves the
        registration pending and untouched. Verification runs without any
        lock held, so different ids are never serialized by it. Type errors
        raise :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_multi_schnorr_entry(entry)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _multi_schnorr_entry_is_encodable(entry):
            return False  # negative integers cannot be encoded into the bound leaf
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(entry, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _replay_digest(entry, session_id, binding.expires_at),
            ):
                return False  # the presented entry is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            try:
                verifier = SchnorrVerifier(
                    entry.public_key, prime=entry.prime, generator=entry.generator
                )
                accepted = verifier.verify_proof(
                    entry.message, entry.proof, context=entry.context
                )
            except ValueError:
                return False  # invalid embedded public key or group parameters
            if not accepted:
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to the pending state; after commit() the claim is gone and this
            # is a no-op, leaving the id consumed.
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entry: MultiSchnorrEntry,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over); verification runs with no transaction held; only the
        token returned by the winning claim can consume the id, and every
        rejection or escaped error restores the id to pending with that same
        token. A stale token (a claim taken over while verification ran)
        neither consumes nor restores anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _replay_digest(entry, session_id, binding.expires_at),
            ):
                return False  # the presented entry is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            try:
                verifier = SchnorrVerifier(
                    entry.public_key, prime=entry.prime, generator=entry.generator
                )
                accepted = verifier.verify_proof(
                    entry.message, entry.proof, context=entry.context
                )
            except ValueError:
                return False  # invalid embedded public key or group parameters
            if not accepted:
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


def _range_replay_digest(
    entry: RangeBatchEntry,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute ``SHA-256(F(D) || F(session_id) || L(entry) || F(E))``."""
    transcript = hashlib.sha256()
    transcript.update(len(_RANGE_REPLAY_DOMAIN).to_bytes(4, "big"))
    transcript.update(_RANGE_REPLAY_DOMAIN)
    transcript.update(len(session_id).to_bytes(4, "big"))
    transcript.update(session_id)
    transcript.update(_bound_range_leaf(entry))  # raw leaf, no F framing
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(len(expiry).to_bytes(4, "big"))
    transcript.update(expiry)
    return transcript.digest()


def _check_range_batch_entry(entry: object, name: str = "entry") -> RangeBatchEntry:
    """Validate a RangeBatchEntry and its nested field types."""
    if not isinstance(entry, RangeBatchEntry):
        raise TypeError(f"{name} must be a RangeBatchEntry")
    commitment = entry.commitment
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError(f"{name} commitment must be a PedersenCommitment")
    _check_commitment_fields(commitment)
    proof = entry.proof
    if not isinstance(proof, RangeProof):
        raise TypeError(f"{name} proof must be a RangeProof")
    for field_name in ("t", "e", "s"):
        field = getattr(proof, field_name)
        if not isinstance(field, tuple):
            raise TypeError(f"{name} proof {field_name} must be a tuple of integers")
        for item in field:
            _check_int(item, f"{name} proof {field_name} entry")
    _check_bytes(entry.context, f"{name} context")
    return entry


class RangeReplayGuard:
    """Single-use replay protection for range-proof entries.

    A fresh guard has no registrations. :meth:`bind_once` registers a pending
    :class:`ReplayBinding` for a session id, :meth:`check` accepts an equal
    pending binding exactly once and then marks the id consumed. By default
    both the pending and the consumed state live on this guard instance and
    are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in that
    store under the ``b"zr/rr/v1"`` key domain, so range guards attached to
    the same store namespace share pending, claimed and consumed ids across
    independent instances and process restarts.

    As with :class:`ReplayGuard`, concurrent checks of the same id are
    decided by an atomic claim taken before the range proof is verified (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the verification runs without any lock or transaction
    held, so different ids are never serialized.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_RANGE_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entry: RangeBatchEntry,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to ``entry``.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp. A session id that
        is already pending, being checked or has been consumed raises
        :class:`ValueError`; wrong argument types raise :class:`TypeError`
        (an empty id or an out-of-range expiry raise :class:`ValueError`).
        Inputs are never mutated.
        """
        _check_range_batch_entry(entry)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        binding = ReplayBinding(
            session_id,
            _range_replay_digest(entry, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entry: RangeBatchEntry,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for ``entry``.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before verification, so among concurrent
        calls for the same id at most one can return ``True``. The entry's
        range proof is then checked with :func:`verify_range` called with
        ``entry.commitment``, ``entry.proof`` and ``entry.context`` in field
        order, unchanged. For a binding with an expiry,
        ``now >= expires_at`` makes the check fail; ``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` unsigned
        64-bit integer.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry or a failing range
        proof) returns ``False``, releases any claim and leaves the
        registration pending. Verification runs without a lock, so other
        ids are never blocked. Type errors raise :class:`TypeError`; an
        out-of-range ``now`` raises :class:`ValueError`. Inputs are never
        mutated.
        """
        _check_range_batch_entry(entry)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(entry, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _range_replay_digest(entry, session_id, binding.expires_at),
            ):
                return False  # the presented entry is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_range(entry.commitment, entry.proof, entry.context):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entry: RangeBatchEntry,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over); verification runs with no transaction held; only the
        token returned by the winning claim can consume the id, and every
        rejection or escaped error restores the id to pending with that same
        token. A stale token (a claim taken over while verification ran)
        neither consumes nor restores anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _range_replay_digest(entry, session_id, binding.expires_at),
            ):
                return False  # the presented entry is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_range(entry.commitment, entry.proof, entry.context):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


def _region_replay_digest(
    entry: RegionBatchEntry,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute ``SHA-256(F(D) || F(session_id) || L(entry) || F(E))``."""
    transcript = hashlib.sha256()
    transcript.update(len(_REGION_REPLAY_DOMAIN).to_bytes(4, "big"))
    transcript.update(_REGION_REPLAY_DOMAIN)
    transcript.update(len(session_id).to_bytes(4, "big"))
    transcript.update(session_id)
    transcript.update(_bound_region_leaf(entry))  # raw leaf, no F framing
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(len(expiry).to_bytes(4, "big"))
    transcript.update(expiry)
    return transcript.digest()


def _check_region_batch_entry(entry: object, name: str = "entry") -> RegionBatchEntry:
    """Validate a RegionBatchEntry and its nested field types."""
    if not isinstance(entry, RegionBatchEntry):
        raise TypeError(f"{name} must be a RegionBatchEntry")
    x_commitment = entry.x_commitment
    y_commitment = entry.y_commitment
    if not isinstance(x_commitment, PedersenCommitment):
        raise TypeError(f"{name} x_commitment must be a PedersenCommitment")
    if not isinstance(y_commitment, PedersenCommitment):
        raise TypeError(f"{name} y_commitment must be a PedersenCommitment")
    _check_commitment_fields(x_commitment)
    _check_commitment_fields(y_commitment)
    region = entry.region
    if not isinstance(region, Region):
        raise TypeError(f"{name} region must be a Region")
    _check_region_fields(region)
    proof = entry.proof
    if not isinstance(proof, RegionProof):
        raise TypeError(f"{name} proof must be a RegionProof")
    if not isinstance(proof.x_proof, RangeProof):
        raise TypeError(f"{name} proof x_proof must be a RangeProof")
    if not isinstance(proof.y_proof, RangeProof):
        raise TypeError(f"{name} proof y_proof must be a RangeProof")
    for axis_name, sub_proof in (("x", proof.x_proof), ("y", proof.y_proof)):
        for field_name in ("t", "e", "s"):
            field = getattr(sub_proof, field_name)
            if not isinstance(field, tuple):
                raise TypeError(
                    f"{name} {axis_name}_proof {field_name} must be a tuple of integers"
                )
            for item in field:
                _check_int(item, f"{name} {axis_name}_proof {field_name} entry")
    _check_bytes(entry.context, f"{name} context")
    return entry


class RegionReplayGuard:
    """Single-use replay protection for region-proof entries.

    A fresh guard has no registrations. :meth:`bind_once` registers a pending
    :class:`ReplayBinding` for a session id, :meth:`check` accepts an equal
    pending binding exactly once and then marks the id consumed. By default
    both the pending and the consumed state live on this guard instance and
    are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in that
    store under the ``b"zr/rg/v1"`` key domain, so region guards attached to
    the same store namespace share pending, claimed and consumed ids across
    independent instances and process restarts.

    As with the other single-entry guards, concurrent checks of the same id
    are decided by an atomic claim taken before the region proof is
    verified (the in-instance registry lock, or the store's short
    transaction and unique claim token); the verification runs without any
    lock or transaction held, so different ids are never serialized.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_REGION_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entry: RegionBatchEntry,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to ``entry``.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp. A session id that
        is already pending, being checked or has been consumed raises
        :class:`ValueError`; wrong argument types raise :class:`TypeError`
        (an empty id or an out-of-range expiry raise :class:`ValueError`).
        Inputs are never mutated.
        """
        _check_region_batch_entry(entry)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        binding = ReplayBinding(
            session_id,
            _region_replay_digest(entry, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entry: RegionBatchEntry,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for ``entry``.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before verification, so among concurrent
        calls for the same id at most one can return ``True``. The entry's
        region proof is then checked with :func:`verify_region` called in
        field order with ``entry.x_commitment``, ``entry.y_commitment``,
        ``entry.region``, ``entry.proof`` and ``entry.context``, unchanged.
        For a binding with an expiry, ``now >= expires_at`` makes the check
        fail; ``now`` defaults to the current Unix seconds and must otherwise
        be a non-``bool`` unsigned 64-bit integer.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, a substituted entry field,
        expiry or a failing region proof) returns ``False``, releases any
        claim and leaves the registration pending. Verification runs without
        a lock, so other ids are never blocked. Type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_region_batch_entry(entry)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(entry, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _region_replay_digest(entry, session_id, binding.expires_at),
            ):
                return False  # the presented entry is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_region(
                entry.x_commitment,
                entry.y_commitment,
                entry.region,
                entry.proof,
                entry.context,
            ):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entry: RegionBatchEntry,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over); verification runs with no transaction held; only the
        token returned by the winning claim can consume the id, and every
        rejection or escaped error restores the id to pending with that same
        token. A stale token (a claim taken over while verification ran)
        neither consumes nor restores anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _region_replay_digest(entry, session_id, binding.expires_at),
            ):
                return False  # the presented entry is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_region(
                entry.x_commitment,
                entry.y_commitment,
                entry.region,
                entry.proof,
                entry.context,
            ):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Per-instance replay protection for Merkle-committed region batches
#
# A BoundRegionReplayGuard binds a whole BoundRegionBatch together with the
# Merkle root it is claimed under to a caller-chosen session id, reusing the
# ReplayBinding type. Like the other guards the binding is single-use and
# local to the guard instance: bind_once registers a pending binding, check
# recomputes the digest, checks the expiry, delegates the actual root and
# proof verification to verify_region_bound (passing the random source
# through unchanged) and consumes the id only on full success; every
# rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(entry_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/brg/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(entry) = the BoundRegion leaf bytes (_bound_region_leaf), raw under F
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _frame_length_prefixed(item: bytes) -> bytes:
    """``F(item)``: a four-byte unsigned big-endian length prefix plus item."""
    return len(item).to_bytes(4, "big") + item


def _uint64_be(value: int) -> bytes:
    """``U(value)``: an eight-byte unsigned big-endian encoding."""
    return value.to_bytes(8, "big", signed=False)


def _bound_region_replay_encodable(batch: BoundRegionBatch) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    ``batch.leaf_count``, ``batch.proof.leaf_count`` and every proof index
    are written with ``U`` (eight-byte unsigned big-endian); a negative or
    larger-than-uint64 value cannot be framed. Everything else (the
    decimal-ASCII region leaves, raw sibling bytes, the root) encodes for
    any value, so no additional encodability rule is needed.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _bound_region_replay_digest(
    batch: BoundRegionBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundRegion replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(entry))`` per entry in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_REGION_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for entry in batch.entries:  # entries order, each BoundRegion leaf under F
        transcript.update(_frame_length_prefixed(_bound_region_leaf(entry)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_region_batch_types(batch: object, root: object) -> None:
    """Validate BoundRegionBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_region_bound`: the batch must
    be a :class:`BoundRegionBatch` whose entries tuple holds nestedly
    well-typed :class:`RegionBatchEntry` objects, whose ``leaf_count`` is a
    non-``bool`` integer and whose proof is a well-typed
    :class:`MerkleMultiProof`; ``root`` must be ``bytes``. Structural and
    value problems (coverage, digest lengths, ranges) are left to
    :func:`verify_region_bound` at check time.
    """
    if not isinstance(batch, BoundRegionBatch):
        raise TypeError("batch must be a BoundRegionBatch")
    _check_bytes(root, "root")
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


class BoundRegionReplayGuard:
    """Single-use replay protection for a Merkle-committed region batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundRegionBatch` together with the Merkle ``root`` it is
    claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_region_bound` with the random source passed
    through — and then marks the id consumed. By default both the pending
    and the consumed state live on this guard instance and are never shared
    between instances; passing an :class:`SQLiteReplayStore` as ``store``
    instead keeps the state in that store under the ``b"zr/brg/v1"`` key
    domain, so bound-region guards attached to the same store namespace
    share pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the (potentially slow) delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_BOUND_REGION_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundRegionBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        integers (``leaf_count`` and the proof indices) must likewise fit in
        uint64. A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested field
        types raise :class:`TypeError`; an empty id, an out-of-uint64 expiry
        or framed integer, or a rebind raise :class:`ValueError`. Inputs are
        never mutated.
        """
        _check_bound_region_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_region_replay_encodable(batch):
            raise ValueError("leaf_count and proof indices must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_region_replay_digest(batch, root, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundRegionBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to :func:`verify_region_bound`
        with ``randbelow`` passed through unchanged, under that function's
        root, structure and randomness contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or :func:`verify_region_bound` returning ``False``)
        returns ``False``, releases the claim and leaves the registration
        pending. An exception escaping the delegated verification (such as
        the :class:`TypeError` / :class:`ValueError` raised by a bad
        ``randbelow``) likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors (including a non-callable ``randbelow``) raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_region_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_region_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_region_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_region_bound(batch, root, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundRegionBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_region_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_region_bound(batch, root, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Merkle-committed range batches
#
# A BoundRangeReplayGuard binds a whole BoundRangeBatch together with the
# Merkle root it is claimed under to a caller-chosen session id, reusing the
# ReplayBinding type and, byte for byte, the F / U / S framing and the E
# expiry encoding of BoundRegionReplayGuard; only the domain separator and
# the per-entry leaves differ. Like the other bound guards the binding is
# single-use: without a store the state is local to the guard instance,
# while an SQLiteReplayStore keeps pending, claimed and consumed ids in the
# store under b"zr/brr/v1", shared across instances, processes and restarts.
# bind_once registers a pending binding, check recomputes the digest, checks
# the expiry, delegates the actual root and proof verification to
# verify_range_bound (passing the random source through unchanged) and
# consumes the id only on full success; every rejection leaves the id
# untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(entry_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/brr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(entry) = the BoundRange leaf bytes (_bound_range_leaf), raw under F
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _bound_range_replay_encodable(batch: BoundRangeBatch) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    Mirrors :func:`_bound_region_replay_encodable`:
    ``batch.leaf_count``, ``batch.proof.leaf_count`` and every proof index
    are written with ``U`` (eight-byte unsigned big-endian); a negative or
    larger-than-uint64 value cannot be framed. The decimal-ASCII range
    leaves, the raw sibling bytes and the root encode for any value.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _bound_range_replay_digest(
    batch: BoundRangeBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundRange replay binding digest.

    Byte-for-byte the :func:`_bound_region_replay_digest` framing with the
    BoundRange replay domain and the BoundRange (rather than BoundRegion)
    leaves. Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(entry))`` per entry in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_RANGE_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for entry in batch.entries:  # entries order, each BoundRange leaf under F
        transcript.update(_frame_length_prefixed(_bound_range_leaf(entry)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_range_batch_types(batch: object, root: object) -> None:
    """Validate BoundRangeBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_range_bound`: the batch must
    be a :class:`BoundRangeBatch` whose entries tuple holds nestedly
    well-typed :class:`RangeBatchEntry` objects, whose ``leaf_count`` is a
    non-``bool`` integer and whose proof is a well-typed
    :class:`MerkleMultiProof`; ``root`` must be ``bytes``. Structural and
    value problems (coverage, digest lengths, ranges) are left to
    :func:`verify_range_bound` at check time.
    """
    if not isinstance(batch, BoundRangeBatch):
        raise TypeError("batch must be a BoundRangeBatch")
    _check_bytes(root, "root")
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
                    f"entries[{position}] proof {field_name} "
                    "must be a tuple of integers"
                )
            for item in field:
                _check_int(
                    item,
                    f"entries[{position}] proof {field_name} entry",
                )
        _check_bytes(entry.context, f"entries[{position}] context")


class BoundRangeReplayGuard:
    """Single-use replay protection for a Merkle-committed range batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundRangeBatch` together with the Merkle ``root`` it is
    claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_range_bound` with the random source passed
    through — and then marks the id consumed. The digest reuses the
    :class:`BoundRegionReplayGuard` framing byte for byte, with only the
    domain separator (``b"zr/brr/v1"``) and the per-entry leaves changed
    to the BoundRange leaves. By default both the pending and the consumed
    state live on this guard instance and are never shared between
    instances; passing an :class:`SQLiteReplayStore` as ``store`` instead
    keeps the state in that store under the ``b"zr/brr/v1"`` key domain,
    so bound-range guards attached to the same store namespace share
    pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the (potentially slow) delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_BOUND_RANGE_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundRangeBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        integers (``leaf_count`` and the proof indices) must likewise fit in
        uint64. A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested field
        types raise :class:`TypeError`; an empty id, an out-of-uint64 expiry
        or framed integer, or a rebind raise :class:`ValueError`. Inputs are
        never mutated.
        """
        _check_bound_range_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_range_replay_encodable(batch):
            raise ValueError("leaf_count and proof indices must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_range_replay_digest(batch, root, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundRangeBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to :func:`verify_range_bound`
        with ``randbelow`` passed through unchanged, under that function's
        root, structure and randomness contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or :func:`verify_range_bound` returning ``False``)
        returns ``False``, releases the claim and leaves the registration
        pending. An exception escaping the delegated verification (such as
        the :class:`TypeError` / :class:`ValueError` raised by a bad
        ``randbelow``) likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors (including a non-callable ``randbelow``) raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_range_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_range_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_range_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_range_bound(batch, root, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundRangeBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_range_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_range_bound(batch, root, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Merkle-committed Schnorr batches
#
# A BoundSchnorrReplayGuard binds a whole BoundSchnorrBatch together with the
# Merkle root it is claimed under to a caller-chosen session id, reusing the
# ReplayBinding type and, byte for byte, the F / U / S framing and the E
# expiry encoding of BoundRegionReplayGuard; only the domain separator and
# the per-entry leaves differ. Like the other bound guards the binding is
# single-use: without a store the state is local to the guard instance,
# while an SQLiteReplayStore keeps pending, claimed and consumed ids in the
# store under b"zr/bsr/v1", shared across instances, processes and restarts.
# bind_once registers a pending binding, check recomputes the digest, checks
# the expiry, delegates the actual root and signature verification to
# verify_bound (passing the random source through unchanged) and consumes
# the id only on full success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(entry_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/bsr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(entry) = the BoundSchnorr leaf bytes (_bound_schnorr_leaf), raw under F
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _bound_schnorr_replay_encodable(batch: BoundSchnorrBatch) -> bool:
    """Every U-framed integer and every leaf integer must be non-negative.

    ``batch.leaf_count``, ``batch.proof.leaf_count`` and every proof index
    are written with ``U`` (eight-byte unsigned big-endian); a negative or
    larger-than-uint64 value cannot be framed. Each :class:`L(entry)`
    BoundSchnorr leaf encodes its five integers (``prime``, ``generator``,
    ``public_key`` and the proof commitment / response) with the shortest
    unsigned big-endian encoding, so a negative integer cannot be framed
    either. The raw sibling bytes and the root encode for any value.
    """
    proof = batch.proof
    framed = [batch.leaf_count, proof.leaf_count, *proof.indices]
    if not all(0 <= value <= _UINT64_MAX for value in framed):
        return False
    for entry in batch.entries:
        if min(
            entry.prime,
            entry.generator,
            entry.public_key,
            entry.proof.commitment,
            entry.proof.response,
        ) < 0:
            return False
    return True


def _bound_schnorr_replay_digest(
    batch: BoundSchnorrBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundSchnorr replay binding digest.

    Byte-for-byte the :func:`_bound_region_replay_digest` framing with the
    BoundSchnorr replay domain and the BoundSchnorr (rather than
    BoundRegion) leaves. Writes, in order: ``F(D)``, ``F(session_id)``,
    ``F(root)``, ``F(U(batch.leaf_count))``, one ``F(L(entry))`` per entry
    in batch order, then ``F(U(proof.leaf_count))``,
    ``S(proof.indices, U)``, ``S(proof.siblings, identity)`` and ``F(E)``.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_SCHNORR_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for entry in batch.entries:  # entries order, each BoundSchnorr leaf under F
        transcript.update(_frame_length_prefixed(_bound_schnorr_leaf(entry)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_schnorr_batch_types(batch: object, root: object) -> None:
    """Validate BoundSchnorrBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_bound`: the batch must be a
    :class:`BoundSchnorrBatch` whose entries tuple holds nestedly
    well-typed :class:`MultiSchnorrEntry` objects, whose ``leaf_count`` is
    a non-``bool`` integer and whose proof is a well-typed
    :class:`MerkleMultiProof`; ``root`` must be ``bytes``. Structural and
    value problems (coverage, digest lengths, ranges) are left to
    :func:`verify_bound` at check time.
    """
    if not isinstance(batch, BoundSchnorrBatch):
        raise TypeError("batch must be a BoundSchnorrBatch")
    _check_bytes(root, "root")
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


class BoundSchnorrReplayGuard:
    """Single-use replay protection for a Merkle-committed Schnorr batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundSchnorrBatch` together with the Merkle ``root`` it is
    claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_bound` with the random source passed
    through — and then marks the id consumed. The digest reuses the
    :class:`BoundRegionReplayGuard` framing byte for byte, with only the
    domain separator (``b"zr/bsr/v1"``) and the per-entry leaves changed
    to the BoundSchnorr leaves. By default both the pending and the
    consumed state live on this guard instance and are never shared
    between instances; passing an :class:`SQLiteReplayStore` as ``store``
    instead keeps the state in that store under the ``b"zr/bsr/v1"`` key
    domain, so bound-schnorr guards attached to the same store namespace
    share pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the (potentially slow) delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_BOUND_SCHNORR_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundSchnorrBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        integers (``leaf_count`` and the proof indices) must fit in uint64
        and every BoundSchnorr leaf integer (``prime``, ``generator``,
        ``public_key`` and the proof commitment / response) must be
        non-negative. A session id that is already pending, being checked
        or consumed raises :class:`ValueError`. Wrong argument or nested
        field types raise :class:`TypeError`; an empty id, an
        out-of-uint64 expiry or framed integer, a negative leaf integer or
        a rebind raise :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_schnorr_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_schnorr_replay_encodable(batch):
            raise ValueError(
                "leaf_count, proof indices and leaf integers must be non-negative "
                "unsigned integers"
            )
        binding = ReplayBinding(
            session_id,
            _bound_schnorr_replay_digest(batch, root, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundSchnorrBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to :func:`verify_bound` with
        ``randbelow`` passed through unchanged, under that function's root,
        structure and randomness contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, a negative leaf integer, a
        non-32-byte root or sibling, or :func:`verify_bound` returning
        ``False``) returns ``False``, releases the claim and leaves the
        registration pending. An exception escaping the delegated
        verification (such as the :class:`TypeError` / :class:`ValueError`
        raised by a bad ``randbelow``) likewise releases the claim and then
        propagates unchanged, leaving the id usable. With a store backend,
        only the holder of the current claim token can consume the id (an
        expired claim may be taken over by a later equal ``check``); a stale
        token neither consumes nor restores anything. Verification runs
        without any lock or transaction held, so other ids are never
        serialized. Argument type errors (including a non-callable
        ``randbelow``) raise :class:`TypeError`; an out-of-range ``now``
        raises :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_schnorr_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_schnorr_replay_encodable(batch):
            return False  # negative or oversized framed/leaf integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_schnorr_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_bound(batch, root, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundSchnorrBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_schnorr_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_bound(batch, root, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Merkle-committed same-key Schnorr batches
#
# A SingleKeyBoundReplayGuard binds a whole SingleKeyBoundBatch together with
# the Merkle root it is claimed under to a caller-chosen session id, reusing
# the ReplayBinding type and, byte for byte, the F / U / S framing and the E
# expiry encoding of BoundSchnorrReplayGuard; only the domain separator and
# the per-entry leaves differ. The guard is constructed with one fixed
# public_key and group (prime / generator), and the per-entry leaves are the
# BoundSchnorr leaf raw bytes (_bound_schnorr_leaf) that entries commit under
# that fixed key and group — the same bytes
# SchnorrVerifier.verify_bound_batch recomputes. Without a store the state
# is local to the guard instance, while an SQLiteReplayStore keeps pending,
# claimed and consumed ids in the store under b"zr/skbbr/v1", shared across
# instances, processes and restarts. bind_once registers a pending binding,
# check recomputes the digest, checks the expiry, delegates the actual root
# and signature verification to the fixed verifier's verify_bound_batch
# (passing the random source through unchanged) and consumes the id only on
# full success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(entry_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/skbbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(entry) = the BoundSchnorr leaf bytes (_bound_schnorr_leaf) built from a
#       MultiSchnorrEntry carrying this guard's fixed public_key, prime and
#       generator together with the entry's message, proof and context
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _check_single_key_bound_batch_types(batch: object, root: object) -> None:
    """Validate SingleKeyBoundBatch argument types for the replay guard.

    Mirrors the type checks of :meth:`SchnorrVerifier.verify_bound_batch`:
    the batch must be a :class:`SingleKeyBoundBatch` whose entries tuple
    holds nestedly well-typed :class:`SchnorrBatchEntry` objects, whose
    ``leaf_count`` is a non-``bool`` integer and whose proof is a
    well-typed :class:`MerkleMultiProof`; ``root`` must be ``bytes``.
    Structural and value problems (coverage, digest lengths, ranges) are
    left to :meth:`~SchnorrVerifier.verify_bound_batch` at check time.
    """
    if not isinstance(batch, SingleKeyBoundBatch):
        raise TypeError("batch must be a SingleKeyBoundBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError("batch entries must be a tuple of SchnorrBatchEntry")
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
        if not isinstance(entry, SchnorrBatchEntry):
            raise TypeError(f"entries[{position}] must be a SchnorrBatchEntry")
        _check_bytes(entry.message, f"entries[{position}] message")
        _check_bytes(entry.context, f"entries[{position}] context")
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


def _single_key_bound_replay_encodable(batch: SingleKeyBoundBatch) -> bool:
    """Every U-framed integer and every leaf integer must be non-negative.

    ``batch.leaf_count``, ``batch.proof.leaf_count`` and every proof index
    are written with ``U`` (eight-byte unsigned big-endian); a negative or
    larger-than-uint64 value cannot be framed. Each :class:`L(entry)`
    BoundSchnorr leaf encodes the proof commitment / response with the
    shortest unsigned big-endian encoding, so a negative integer cannot be
    framed either. The guard's own ``prime`` / ``generator`` /
    ``public_key`` are validated at construction, and the raw sibling bytes
    and the root encode for any value.
    """
    proof = batch.proof
    framed = [batch.leaf_count, proof.leaf_count, *proof.indices]
    if not all(0 <= value <= _UINT64_MAX for value in framed):
        return False
    for entry in batch.entries:
        if min(entry.proof.commitment, entry.proof.response) < 0:
            return False
    return True


def _single_key_bound_replay_digest(
    batch: SingleKeyBoundBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
    *,
    public_key: int,
    prime: int,
    generator: int,
) -> bytes:
    """Compute the same-key BoundSchnorr replay binding digest.

    Byte-for-byte the :func:`_bound_schnorr_replay_digest` framing with the
    same-key BoundSchnorr replay domain and leaves built from the
    :class:`SchnorrBatchEntry` items under the fixed public key and group.
    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(entry))`` per entry in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_SINGLE_KEY_BOUND_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for entry in batch.entries:  # entries order, each fixed-key leaf under F
        transcript.update(
            _frame_length_prefixed(
                _single_key_batch_leaf(entry, public_key, prime, generator)
            )
        )
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class SingleKeyBoundReplayGuard:
    """Single-use replay protection for a Merkle-committed same-key batch.

    The guard is bound to one fixed ``public_key`` and group (``prime`` /
    ``generator``, defaulting to :data:`DEFAULT_PRIME` /
    :data:`DEFAULT_GENERATOR`); the batch it protects is a
    :class:`SingleKeyBoundBatch` whose entries are
    :class:`SchnorrBatchEntry` items verified under that fixed key and
    group. A fresh guard has no registrations. :meth:`bind_once` registers
    a pending :class:`ReplayBinding` that commits a whole
    :class:`SingleKeyBoundBatch` together with the Merkle ``root`` it is
    claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to the fixed verifier's
    :meth:`~SchnorrVerifier.verify_bound_batch` with the random source
    passed through — and then marks the id consumed. The digest reuses the
    :class:`BoundSchnorrReplayGuard` framing byte for byte, with only the
    domain separator (``b"zr/skbbr/v1"``) and the per-entry leaves
    changed: each leaf is the BoundSchnorr leaf raw bytes built with this
    guard's fixed public key and group parameters. By default both the
    pending and the consumed state live on this guard instance and are
    never shared between instances; passing an :class:`SQLiteReplayStore`
    as ``store`` instead keeps the state in that store under the
    ``b"zr/skbbr/v1"`` key domain, so same-key bound guards attached to the
    same store namespace share pending, claimed and consumed ids across
    independent instances, processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the (potentially slow) delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(
        self,
        public_key: int,
        *,
        prime: int = DEFAULT_PRIME,
        generator: int = DEFAULT_GENERATOR,
        store: SQLiteReplayStore | None = None,
    ) -> None:
        _check_int(public_key, "public_key")
        _check_int(prime, "prime")
        _check_int(generator, "generator")
        # The fixed verifier carries the group-value range checks.
        self._verifier = SchnorrVerifier(public_key, prime=prime, generator=generator)
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._public_key = public_key
        self._prime = prime
        self._generator = generator
        self._store = (
            None
            if store is None
            else store._view(_SINGLE_KEY_BOUND_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def public_key(self) -> int:
        return self._public_key

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def _digest(
        self,
        batch: SingleKeyBoundBatch,
        root: bytes,
        session_id: bytes,
        expires_at: int | None,
    ) -> bytes:
        """The binding digest over the batch/root under this guard's key/group."""
        return _single_key_bound_replay_digest(
            batch,
            root,
            session_id,
            expires_at,
            public_key=self._public_key,
            prime=self._prime,
            generator=self._generator,
        )

    def bind_once(
        self,
        batch: SingleKeyBoundBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        integers (``leaf_count`` and the proof indices) must fit in uint64
        and every leaf integer (the proof commitment / response) must be
        non-negative. A session id that is already pending, being checked
        or consumed raises :class:`ValueError`. Wrong argument or nested
        field types raise :class:`TypeError`; an empty id, an
        out-of-uint64 expiry or framed integer, a negative leaf integer or
        a rebind raise :class:`ValueError`. Inputs are never mutated.
        """
        _check_single_key_bound_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _single_key_bound_replay_encodable(batch):
            raise ValueError(
                "leaf_count, proof indices and leaf integers must be non-negative "
                "unsigned integers"
            )
        binding = ReplayBinding(
            session_id,
            self._digest(batch, root, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: SingleKeyBoundBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root`` under this guard's fixed public key
        and group; for a binding with an expiry, ``now >= expires_at`` makes
        the check fail (``now`` defaults to the current Unix seconds and
        must otherwise be a non-``bool`` uint64). Only then is the
        batch/root handed to the fixed verifier's
        :meth:`~SchnorrVerifier.verify_bound_batch` with ``randbelow``
        passed through unchanged, under that method's root, structure and
        randomness contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, a negative leaf integer, a
        non-32-byte root or sibling, or ``verify_bound_batch`` returning
        ``False``) returns ``False``, releases the claim and leaves the
        registration pending. An exception escaping the delegated
        verification (such as the :class:`TypeError` / :class:`ValueError`
        raised by a bad ``randbelow``) likewise releases the claim and then
        propagates unchanged, leaving the id usable. With a store backend,
        only the holder of the current claim token can consume the id (an
        expired claim may be taken over by a later equal ``check``); a
        stale token neither consumes nor restores anything. Verification
        runs without any lock or transaction held, so other ids are never
        serialized. Argument type errors (including a non-callable
        ``randbelow``) raise :class:`TypeError`; an out-of-range ``now``
        raises :class:`ValueError`. Inputs are never mutated.
        """
        _check_single_key_bound_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _single_key_bound_replay_encodable(batch):
            return False  # negative or oversized framed/leaf integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                self._digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not self._verifier.verify_bound_batch(batch, root, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: SingleKeyBoundBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                self._digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not self._verifier.verify_bound_batch(batch, root, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for multi-checkpoint Merkle consistency chains
#
# A MerkleConsistencyChainReplayGuard binds a whole MerkleConsistencyChain
# (its ordered roots and ordered consistency proofs) to a caller-chosen
# session id, reusing the ReplayBinding type and, byte for byte, the F / U /
# S framing and the E expiry encoding of the Bound guards. Like the other
# guards the binding is single-use: without a store the state is local to
# the guard instance, while an SQLiteReplayStore keeps pending, claimed and
# consumed ids in the store under b"zr/mccr/v1", shared across instances,
# processes and restarts. bind_once registers a pending binding, check
# recomputes the digest, checks the expiry, delegates the chain verification
# to verify_consistency_chain and consumes the id only on full success;
# every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(roots, id) || S(proofs, P) || F(E)
# )
#   D = b"zr/mccr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   id(x) = x, i.e. a root digest is framed raw under F
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   P(p) = F(U(p.old_count)) || F(U(p.new_count)) || S(p.nodes, id)
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _merkle_chain_proof_framing(proof: MerkleConsistencyProof) -> bytes:
    """``P(p) = F(U(p.old_count)) || F(U(p.new_count)) || S(p.nodes, id)``."""
    material = bytearray()
    material += _frame_length_prefixed(_uint64_be(proof.old_count))
    material += _frame_length_prefixed(_uint64_be(proof.new_count))
    # S(p.nodes, id) = F(U(|nodes|)) || Σ F(node)
    material += _frame_length_prefixed(_uint64_be(len(proof.nodes)))
    for node in proof.nodes:
        material += _frame_length_prefixed(node)
    return bytes(material)


def _merkle_chain_replay_encodable(chain: MerkleConsistencyChain) -> bool:
    """Every U-framed count must fit in unsigned 64 bits.

    The proof counts (``old_count`` / ``new_count``) and the tuple lengths
    written by the S sequences are encoded with ``U``; the raw root and node
    bytes need no encodability rule.
    """
    values = [len(chain.roots), len(chain.proofs)]
    for proof in chain.proofs:
        values.extend((proof.old_count, proof.new_count, len(proof.nodes)))
    return all(0 <= value <= _UINT64_MAX for value in values)


def _merkle_chain_replay_digest(
    chain: MerkleConsistencyChain,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-consistency-chain replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(roots, id)``,
    ``S(proofs, P)`` and ``F(E)``; roots keep their chain order and proofs
    keep theirs, and each proof's nodes keep theirs.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_CHAIN_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(roots, id) = F(U(|roots|)) || Σ F(root)
    transcript.update(_frame_length_prefixed(_uint64_be(len(chain.roots))))
    for root in chain.roots:
        transcript.update(_frame_length_prefixed(root))
    # S(proofs, P) = F(U(|proofs|)) || Σ F(P(proof))
    transcript.update(_frame_length_prefixed(_uint64_be(len(chain.proofs))))
    for proof in chain.proofs:
        transcript.update(_frame_length_prefixed(_merkle_chain_proof_framing(proof)))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_merkle_consistency_chain_types(chain: object) -> None:
    """Validate MerkleConsistencyChain argument types for the replay guard.

    Mirrors the type checks of :func:`verify_consistency_chain`: the chain
    must be a :class:`MerkleConsistencyChain` whose ``roots`` tuple holds
    ``bytes`` and whose ``proofs`` tuple holds well-typed
    :class:`MerkleConsistencyProof` objects (non-``bool`` integer counts and
    a tuple-of-bytes ``nodes``). Structural and value problems (root/proof
    counts, chaining, digest lengths) are left to
    :func:`verify_consistency_chain` at check time.
    """
    if not isinstance(chain, MerkleConsistencyChain):
        raise TypeError("chain must be a MerkleConsistencyChain")
    roots = chain.roots
    if not isinstance(roots, tuple):
        raise TypeError("chain roots must be a tuple of bytes")
    for position, root in enumerate(roots):
        _check_bytes(root, f"chain roots[{position}]")
    proofs = chain.proofs
    if not isinstance(proofs, tuple):
        raise TypeError("chain proofs must be a tuple of MerkleConsistencyProof")
    for position, proof in enumerate(proofs):
        if not isinstance(proof, MerkleConsistencyProof):
            raise TypeError(
                f"chain proofs[{position}] must be a MerkleConsistencyProof"
            )
        for name in ("old_count", "new_count"):
            value = getattr(proof, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(
                    f"chain proofs[{position}] {name} must be an integer"
                )
        if not isinstance(proof.nodes, tuple):
            raise TypeError(
                f"chain proofs[{position}] nodes must be a tuple of bytes"
            )
        for node in proof.nodes:
            _check_bytes(node, f"chain proofs[{position}] node")


class MerkleConsistencyChainReplayGuard:
    """Single-use replay protection for a multi-checkpoint consistency chain.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`MerkleConsistencyChain` — its ordered roots and its ordered
    :class:`MerkleConsistencyProof` objects — to a session id; :meth:`check`
    accepts an equal pending binding exactly once, recomputing the binding
    digest, checking the expiry and delegating to
    :func:`verify_consistency_chain`, and then marks the id consumed. The
    digest frames the chain under
    ``SHA-256(F(D) || F(session_id) || S(roots, id) || S(proofs, P) || F(E))``
    with domain ``b"zr/mccr/v1"``, reusing the F / U / S framing and the E
    expiry encoding of the other Bound guards byte for byte. By default both
    the pending and the consumed state live on this guard instance and are
    never shared between instances; passing an :class:`SQLiteReplayStore` as
    ``store`` instead keeps the state in that store under the
    ``b"zr/mccr/v1"`` key domain, so chain guards attached to the same store
    namespace share pending, claimed and consumed ids across independent
    instances, processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated chain verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a chain being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_MERKLE_CHAIN_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        chain: MerkleConsistencyChain,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to ``chain``.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; every U-framed
        count (the proof ``old_count`` / ``new_count`` values and the tuple
        lengths) must likewise fit in uint64. A session id that is already
        pending, being checked or consumed raises :class:`ValueError`.
        Wrong argument or nested field types raise :class:`TypeError`; an
        empty id, an out-of-uint64 expiry or framed count, or a rebind raise
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_merkle_consistency_chain_types(chain)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_chain_replay_encodable(chain):
            raise ValueError("proof counts and tuple lengths must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _merkle_chain_replay_digest(chain, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        chain: MerkleConsistencyChain,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the chain.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``chain``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the chain handed to :func:`verify_consistency_chain`,
        which checks the root/proof counts, segment chaining and every
        adjacent root.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, or
        :func:`verify_consistency_chain` returning ``False``) returns
        ``False``, releases the claim and leaves the registration pending.
        An exception escaping the delegated verification likewise releases
        the claim and then propagates unchanged, leaving the id usable. With
        a store backend, only the holder of the current claim token can
        consume the id (an expired claim may be taken over by a later equal
        ``check``); a stale token neither consumes nor restores anything.
        Verification runs without any lock or transaction held, so other ids
        are never serialized. Argument type errors raise :class:`TypeError`;
        an out-of-range ``now`` raises :class:`ValueError`. Inputs are never
        mutated.
        """
        _check_merkle_consistency_chain_types(chain)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _merkle_chain_replay_encodable(chain):
            return False  # negative or oversized U-framed counts
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(chain, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_chain_replay_digest(chain, session_id, binding.expires_at),
            ):
                return False  # the presented chain is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_chain(chain):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        chain: MerkleConsistencyChain,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_chain_replay_digest(chain, session_id, binding.expires_at),
            ):
                return False  # the presented chain is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_chain(chain):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for batches of multi-checkpoint Merkle consistency chains
#
# A MerkleConsistencyChainBatchReplayGuard binds a whole non-empty batch of
# MerkleConsistencyChain objects — the same sequence shape accepted by
# verify_consistency_chain_batch (order and duplicates preserved) — to a
# caller-chosen session id, reusing the ReplayBinding type and, byte for
# byte, the F / U / S framing and the E expiry encoding of the other batch
# guards. Like them the binding is single-use: without a store the state is
# local to the guard instance, while an SQLiteReplayStore keeps pending,
# claimed and consumed ids in the store under b"zr/mccbr/v1", shared across
# instances, processes and restarts. bind_once registers a pending binding,
# check claims the id atomically, recomputes the digest, checks the expiry,
# delegates the batch verification to verify_consistency_chain_batch and
# consumes the id only on full success; every rejection leaves the id
# untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(chains, L) || F(E)
# )
#   D = b"zr/mccbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   L(chain) = the existing BoundConsistencyChain leaf bytes
#              (_bound_consistency_chain_leaf), raw under F — the existing
#              b"zkregion/consistency-chains/v1" leaf encoding
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The chains keep their batch order, duplicates included; chains are never
# dropped or reordered.


def _check_merkle_consistency_chains_types(
    chains: object,
) -> list[MerkleConsistencyChain]:
    """Validate the consistency-chain-batch ``chains`` argument types.

    Mirrors the sequence and nested type rules of
    :func:`verify_consistency_chain_batch`: ``chains`` must be a
    non-``bytes`` / ``bytearray`` / ``str`` sequence of
    :class:`MerkleConsistencyChain` objects whose ``roots`` tuple holds
    ``bytes`` and whose ``proofs`` tuple holds well-typed
    :class:`MerkleConsistencyProof` objects (non-``bool`` integer counts and
    a tuple-of-bytes ``nodes``). The chains are copied into a fresh list so
    the inputs are never mutated; an empty batch is left for
    :meth:`MerkleConsistencyChainBatchReplayGuard.bind_once` to reject with
    :class:`ValueError`, and structural/value problems (root/proof counts,
    segment chaining, digest lengths) are left to
    :func:`verify_consistency_chain_batch` at check time.
    """
    if isinstance(chains, (bytes, bytearray, str)) or not isinstance(chains, Sequence):
        raise TypeError("chains must be a sequence of MerkleConsistencyChain")
    items: list[MerkleConsistencyChain] = []
    for position, chain in enumerate(chains):
        if not isinstance(chain, MerkleConsistencyChain):
            raise TypeError(
                f"chains[{position}] must be a MerkleConsistencyChain"
            )
        _check_merkle_consistency_chain_types(chain)
        items.append(chain)
    return items


def _merkle_chain_batch_replay_encodable(
    chains: Sequence[MerkleConsistencyChain],
) -> bool:
    """The outer S sequence writes the batch count with U; it must fit uint64.

    Each chain is framed as the existing BoundConsistencyChain leaf, whose
    counts are decimal ASCII and whose raw bytes sit under four-byte F
    framing, so the chain internals add no further encodability rule.
    """
    return 0 <= len(chains) <= _UINT64_MAX


def _merkle_chain_batch_replay_digest(
    chains: Sequence[MerkleConsistencyChain],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-consistency-chain-batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(chains, L)`` and
    ``F(E)``; ``L(chain)`` is the existing BoundConsistencyChain leaf raw
    bytes and the chains keep their batch order (duplicates included).
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_CHAIN_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(chains, L) = F(U(|chains|)) || Σ F(L(chain))
    transcript.update(_frame_length_prefixed(_uint64_be(len(chains))))
    for chain in chains:
        transcript.update(_frame_length_prefixed(_bound_consistency_chain_leaf(chain)))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class MerkleConsistencyChainBatchReplayGuard:
    """Single-use replay protection for a batch of consistency chains.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`MerkleConsistencyChain` objects — the same sequence shape
    accepted by :func:`verify_consistency_chain_batch`, kept in the given
    order with duplicates preserved — to a session id; :meth:`check`
    accepts an equal pending binding exactly once, claiming the id first
    and then recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_consistency_chain_batch`, and marks the id
    consumed only on full success. The digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(chains, L) || F(E))`` with domain
    ``b"zr/mccbr/v1"``, where ``L(chain)`` is the existing
    BoundConsistencyChain leaf raw bytes (the same bytes
    :func:`_bound_consistency_chain_leaf` builds for
    :func:`verify_consistency_chain_batch_bound`); the F / U / S framing
    and the E expiry encoding are reused byte for byte from the other
    replay guards. By default both the pending and the consumed state live
    on this guard instance and are never shared between instances; passing
    an :class:`SQLiteReplayStore` as ``store`` instead keeps the state in
    that store under the ``b"zr/mccbr/v1"`` key domain, so chain-batch
    guards attached to the same store namespace share pending, claimed and
    consumed ids across independent instances, processes and process
    restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_MERKLE_CHAIN_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        chains: Sequence[MerkleConsistencyChain],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``chains`` must be a
        non-string, non-empty sequence of :class:`MerkleConsistencyChain`
        objects following the same sequence and nested type rules as
        :func:`verify_consistency_chain_batch`: every chain's ``roots``
        tuple holds ``bytes`` and its ``proofs`` tuple holds well-typed
        :class:`MerkleConsistencyProof` objects; chains are kept in the
        given order with duplicates preserved and no chain dropped.
        ``session_id`` must be non-empty ``bytes`` and ``expires_at`` must
        be either ``None`` or a non-``bool`` unsigned 64-bit Unix-second
        timestamp; the ``U``-framed batch length must fit in uint64. A
        session id that is already pending, being checked or consumed
        raises :class:`ValueError`. Wrong argument or nested field types
        (including ``bool`` counts) raise :class:`TypeError`; an empty
        batch or empty id, an out-of-uint64 expiry or batch length, or a
        rebind raise :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_merkle_consistency_chains_types(chains)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("chains must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_chain_batch_replay_encodable(items):
            raise ValueError("batch length must be an unsigned 64-bit integer")
        binding = ReplayBinding(
            session_id,
            _merkle_chain_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        chains: Sequence[MerkleConsistencyChain],
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``chains`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_consistency_chain_batch`, which checks every chain
        independently with :func:`verify_consistency_chain`.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, an empty batch, or
        :func:`verify_consistency_chain_batch` returning ``False``) returns
        ``False``, releases the claim and leaves the registration pending.
        An exception escaping the delegated verification likewise releases
        the claim and then propagates unchanged, leaving the id usable.
        With a store backend, only the holder of the current claim token
        can consume the id (an expired claim may be taken over by a later
        equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held,
        so other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_merkle_consistency_chains_types(chains)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not items or not _merkle_chain_batch_replay_encodable(items):
            return False  # an empty batch or an oversized U-framed batch length
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_chain_batch_replay_digest(
                    items, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_chain_batch(items):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        chains: Sequence[MerkleConsistencyChain],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_chain_batch_replay_digest(
                    chains, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_chain_batch(chains):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for single-segment Merkle consistency proofs
#
# A MerkleConsistencyReplayGuard binds one MerkleConsistencyProof together
# with the old and new Merkle roots it links to a caller-chosen session id,
# reusing the ReplayBinding type and, byte for byte, the F / U / S framing
# and the E expiry encoding of the Bound guards. Like the other guards the
# binding is single-use: without a store the state is local to the guard
# instance, while an SQLiteReplayStore keeps pending, claimed and consumed
# ids in the store under b"zr/mcr/v1", shared across instances, processes
# and restarts. bind_once registers a pending binding, check recomputes the
# digest, checks the expiry, delegates the consistency verification to
# verify_consistency and consumes the id only on full success; every
# rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(old_root) || F(new_root)
#     || F(U(proof.old_count)) || F(U(proof.new_count))
#     || S(proof.nodes, id) || F(E)
# )
#   D = b"zr/mcr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   id(x) = x, i.e. a node digest is framed raw under F, order preserved
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _merkle_consistency_replay_encodable(proof: MerkleConsistencyProof) -> bool:
    """Every U-framed count must fit in unsigned 64 bits.

    The proof counts (``old_count`` / ``new_count``) and the ``nodes`` tuple
    length written by the S sequence are encoded with ``U``; the raw root
    and node bytes need no encodability rule.
    """
    values = [proof.old_count, proof.new_count, len(proof.nodes)]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _merkle_consistency_replay_digest(
    old_root: bytes,
    new_root: bytes,
    proof: MerkleConsistencyProof,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-consistency replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(old_root)``,
    ``F(new_root)``, ``F(U(proof.old_count))``, ``F(U(proof.new_count))``,
    ``S(proof.nodes, id)`` and ``F(E)``; the nodes keep their proof order.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_CONSISTENCY_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(old_root))
    transcript.update(_frame_length_prefixed(new_root))
    transcript.update(_frame_length_prefixed(_uint64_be(proof.old_count)))
    transcript.update(_frame_length_prefixed(_uint64_be(proof.new_count)))
    # S(proof.nodes, id) = F(U(|nodes|)) || Σ F(node)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.nodes))))
    for node in proof.nodes:
        transcript.update(_frame_length_prefixed(node))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_merkle_consistency_proof_types(
    old_root: object,
    new_root: object,
    proof: object,
) -> None:
    """Validate consistency-proof argument types for the replay guard.

    Mirrors the type checks of :func:`verify_consistency`: both roots must
    be ``bytes`` and ``proof`` must be a :class:`MerkleConsistencyProof`
    with non-``bool`` integer counts and a tuple-of-bytes ``nodes``.
    Structural and value problems (count ranges, node count, digest
    lengths) are left to :func:`verify_consistency` at check time.
    """
    _check_bytes(old_root, "old_root")
    _check_bytes(new_root, "new_root")
    if not isinstance(proof, MerkleConsistencyProof):
        raise TypeError("proof must be a MerkleConsistencyProof")
    for name in ("old_count", "new_count"):
        value = getattr(proof, name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"proof {name} must be an integer")
    if not isinstance(proof.nodes, tuple):
        raise TypeError("proof nodes must be a tuple of bytes")
    for node in proof.nodes:
        _check_bytes(node, "proof node")


class MerkleConsistencyReplayGuard:
    """Single-use replay protection for one Merkle consistency proof.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a single
    :class:`MerkleConsistencyProof` together with the ``old_root`` and
    ``new_root`` it links; :meth:`check` accepts an equal pending binding
    exactly once, recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_consistency`, and then marks the id
    consumed. The digest frames the proof under
    ``SHA-256(F(D) || F(session_id) || F(old_root) || F(new_root) ||``
    ``F(U(old_count)) || F(U(new_count)) || S(nodes, id) || F(E))`` with
    domain ``b"zr/mcr/v1"``, reusing the F / U / S framing and the E expiry
    encoding of the Bound guards byte for byte. By default both the pending
    and the consumed state live on this guard instance and are never shared
    between instances; passing an :class:`SQLiteReplayStore` as ``store``
    instead keeps the state in that store under the ``b"zr/mcr/v1"`` key
    domain, so consistency guards attached to the same store namespace
    share pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a proof being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_MERKLE_CONSISTENCY_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        old_root: bytes,
        new_root: bytes,
        proof: MerkleConsistencyProof,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the proof.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        counts (``proof.old_count`` / ``proof.new_count``) must likewise fit
        in uint64. A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested field
        types raise :class:`TypeError`; an empty id, an out-of-uint64 expiry
        or framed count, or a rebind raise :class:`ValueError`. Inputs are
        never mutated.
        """
        _check_merkle_consistency_proof_types(old_root, new_root, proof)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_consistency_replay_encodable(proof):
            raise ValueError("proof counts must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _merkle_consistency_replay_digest(
                old_root, new_root, proof, session_id, expires_at
            ),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        old_root: bytes,
        new_root: bytes,
        proof: MerkleConsistencyProof,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the roots and proof.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``old_root`` / ``new_root`` / ``proof``; for a binding
        with an expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then are the roots and proof handed to
        :func:`verify_consistency`, which recombines the old peaks, folds in
        the appended leaf digests and checks both roots.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, or
        :func:`verify_consistency` returning ``False``) returns ``False``,
        releases the claim and leaves the registration pending. An exception
        escaping the delegated verification likewise releases the claim and
        then propagates unchanged, leaving the id usable. With a store
        backend, only the holder of the current claim token can consume the
        id (an expired claim may be taken over by a later equal ``check``);
        a stale token neither consumes nor restores anything. Verification
        runs without any lock or transaction held, so other ids are never
        serialized. Argument type errors raise :class:`TypeError`; an
        out-of-range ``now`` raises :class:`ValueError`. Inputs are never
        mutated.
        """
        _check_merkle_consistency_proof_types(old_root, new_root, proof)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _merkle_consistency_replay_encodable(proof):
            return False  # negative or oversized U-framed counts
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(
                old_root, new_root, proof, binding, session_id, current
            )
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_consistency_replay_digest(
                    old_root, new_root, proof, session_id, binding.expires_at
                ),
            ):
                return False  # the presented roots/proof are not the ones bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency(old_root, new_root, proof):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        old_root: bytes,
        new_root: bytes,
        proof: MerkleConsistencyProof,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_consistency_replay_digest(
                    old_root, new_root, proof, session_id, binding.expires_at
                ),
            ):
                return False  # the presented roots/proof are not the ones bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency(old_root, new_root, proof):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for single-leaf Merkle inclusion proofs
#
# A MerkleInclusionReplayGuard binds one MerkleProof together with the leaf
# it places and the Merkle root it claims inclusion under to a caller-chosen
# session id, reusing the ReplayBinding type and, byte for byte, the
# F / U / S framing and the E expiry encoding of the Bound and consistency
# guards. Like the other guards the binding is single-use: without a store
# the state is local to the guard instance, while an SQLiteReplayStore keeps
# pending, claimed and consumed ids in the store under b"zr/mir/v1", shared
# across instances, processes and restarts. bind_once registers a pending
# binding, check recomputes the digest, checks the expiry, delegates the
# inclusion verification to verify_inclusion and consumes the id only on
# full success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(leaf) || F(root)
#     || F(U(proof.index)) || S(proof.siblings, id) || F(E)
# )
#   D = b"zr/mir/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   id(x) = x, i.e. a sibling digest is framed raw under F, order preserved
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _merkle_inclusion_replay_encodable(proof: MerkleProof) -> bool:
    """Every U-framed count must fit in unsigned 64 bits.

    The proof ``index`` and the ``siblings`` tuple length written by the S
    sequence are encoded with ``U``; the raw leaf, root and sibling bytes
    need no encodability rule.
    """
    values = [proof.index, len(proof.siblings)]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _merkle_inclusion_proof_framing(
    leaf: bytes,
    root: bytes,
    proof: MerkleProof,
) -> bytes:
    """The continuous single-leaf segment ``F(leaf) || F(root) ||``
    ``F(U(proof.index)) || S(proof.siblings, id)``.

    This is the run of the single-inclusion guard transcript from
    ``F(leaf)`` up to and including the siblings sequence; the batch
    guard reuses these exact bytes as each entry's ``Q`` framing.
    """
    material = bytearray()
    material += _frame_length_prefixed(leaf)
    material += _frame_length_prefixed(root)
    material += _frame_length_prefixed(_uint64_be(proof.index))
    # S(proof.siblings, id) = F(U(|siblings|)) || Σ F(sibling)
    material += _frame_length_prefixed(_uint64_be(len(proof.siblings)))
    for sibling in proof.siblings:
        material += _frame_length_prefixed(sibling)
    return bytes(material)


def _merkle_inclusion_replay_digest(
    leaf: bytes,
    root: bytes,
    proof: MerkleProof,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-inclusion replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(leaf)``, ``F(root)``,
    ``F(U(proof.index))``, ``S(proof.siblings, id)`` and ``F(E)``; the
    siblings keep their leaf-to-root proof order. The leaf-through-siblings
    run is :func:`_merkle_inclusion_proof_framing`.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_INCLUSION_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_merkle_inclusion_proof_framing(leaf, root, proof))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_merkle_inclusion_proof_types(
    leaf: object,
    root: object,
    proof: object,
) -> None:
    """Validate inclusion-proof argument types for the replay guard.

    Mirrors the type checks of :func:`verify_inclusion`: the leaf and root
    must be ``bytes`` and ``proof`` must be a :class:`MerkleProof` with a
    non-``bool`` integer ``index`` and a tuple-of-bytes ``siblings``.
    Structural and value problems (digest lengths, a negative index or an
    index/path structure that cannot match a real tree) are left to
    :func:`verify_inclusion` at check time.
    """
    _check_bytes(leaf, "leaf")
    _check_bytes(root, "root")
    if not isinstance(proof, MerkleProof):
        raise TypeError("proof must be a MerkleProof")
    if not isinstance(proof.index, int) or isinstance(proof.index, bool):
        raise TypeError("proof index must be an integer")
    if not isinstance(proof.siblings, tuple):
        raise TypeError("proof siblings must be a tuple of bytes")
    for position, sibling in enumerate(proof.siblings):
        _check_bytes(sibling, f"proof siblings[{position}]")


class MerkleInclusionReplayGuard:
    """Single-use replay protection for one single-leaf Merkle inclusion proof.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a single
    :class:`MerkleProof` together with the ``leaf`` it places and the
    Merkle ``root`` it claims inclusion under; :meth:`check` accepts an
    equal pending binding exactly once, recomputing the binding digest,
    checking the expiry and delegating to :func:`verify_inclusion`, and then
    marks the id consumed. The digest frames the proof under
    ``SHA-256(F(D) || F(session_id) || F(leaf) || F(root) ||``
    ``F(U(index)) || S(siblings, id) || F(E))`` with domain
    ``b"zr/mir/v1"``, reusing the F / U / S framing and the E expiry
    encoding of the Bound and consistency guards byte for byte. By default
    both the pending and the consumed state live on this guard instance and
    are never shared between instances; passing an :class:`SQLiteReplayStore`
    as ``store`` instead keeps the state in that store under the
    ``b"zr/mir/v1"`` key domain, so inclusion guards attached to the same
    store namespace share pending, claimed and consumed ids across
    independent instances, processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a proof being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_MERKLE_INCLUSION_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        leaf: bytes,
        root: bytes,
        proof: MerkleProof,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the proof.

        Returns the frozen :class:`ReplayBinding`. ``leaf``, ``root`` and
        ``session_id`` must be ``bytes`` (only the session id is required to
        be non-empty), ``proof`` must be a :class:`MerkleProof` whose
        ``index`` is a non-``bool`` integer and whose ``siblings`` is a
        tuple of ``bytes``, and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        values (``proof.index`` and the siblings tuple length) must likewise
        fit in uint64. A session id that is already pending, being checked
        or consumed raises :class:`ValueError`. Wrong argument or nested
        field types raise :class:`TypeError`; an empty id, an out-of-uint64
        expiry or framed value, or a rebind raise :class:`ValueError`.
        Inputs are never mutated.
        """
        _check_merkle_inclusion_proof_types(leaf, root, proof)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_inclusion_replay_encodable(proof):
            raise ValueError("proof index must be an unsigned 64-bit integer")
        binding = ReplayBinding(
            session_id,
            _merkle_inclusion_replay_digest(
                leaf, root, proof, session_id, expires_at
            ),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        leaf: bytes,
        root: bytes,
        proof: MerkleProof,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the leaf, root and proof.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``leaf`` / ``root`` / ``proof``; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now`` defaults
        to the current Unix seconds and must otherwise be a non-``bool``
        uint64). Only then are the leaf, proof and root handed to
        :func:`verify_inclusion`, which hashes the leaf, walks the sibling
        path by the index parity and compares the recomputed root.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, or
        :func:`verify_inclusion` returning ``False``) returns ``False``,
        releases the claim and leaves the registration pending. An exception
        escaping the delegated verification likewise releases the claim and
        then propagates unchanged, leaving the id usable. With a store
        backend, only the holder of the current claim token can consume the
        id (an expired claim may be taken over by a later equal ``check``);
        a stale token neither consumes nor restores anything. Verification
        runs without any lock or transaction held, so other ids are never
        serialized. Argument type errors raise :class:`TypeError`; an
        out-of-range ``now`` raises :class:`ValueError`. Inputs are never
        mutated.
        """
        _check_merkle_inclusion_proof_types(leaf, root, proof)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _merkle_inclusion_replay_encodable(proof):
            return False  # negative or oversized U-framed index
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(
                leaf, root, proof, binding, session_id, current
            )
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_inclusion_replay_digest(
                    leaf, root, proof, session_id, binding.expires_at
                ),
            ):
                return False  # the presented leaf/root/proof are not the ones bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_inclusion(leaf, proof, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        leaf: bytes,
        root: bytes,
        proof: MerkleProof,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_inclusion_replay_digest(
                    leaf, root, proof, session_id, binding.expires_at
                ),
            ):
                return False  # the presented leaf/root/proof are not the ones bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_inclusion(leaf, proof, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for batches of single-leaf Merkle inclusion proofs
#
# A MerkleInclusionBatchReplayGuard binds a whole non-empty batch of
# MerkleInclusionBatchEntry items — the same sequence shape accepted by
# verify_inclusion_batch (order and duplicates preserved) — to a
# caller-chosen session id, reusing the ReplayBinding type and, byte for
# byte, the F / U / S framing and the E expiry encoding of the other batch
# guards. Like them the binding is single-use: without a store the state is
# local to the guard instance, while an SQLiteReplayStore keeps pending,
# claimed and consumed ids in the store under b"zr/mibr/v1", shared across
# instances, processes and restarts. bind_once registers a pending binding,
# check claims the id atomically, recomputes the digest, checks the expiry,
# delegates the batch verification to verify_inclusion_batch and consumes the
# id only on full success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(entries, Q) || F(E)
# )
#   D = b"zr/mibr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   Q(entry) is the continuous run of the single-leaf inclusion guard
#   transcript, from F(leaf) through S(proof.siblings, id):
#     F(leaf) || F(root) || F(U(proof.index)) || S(proof.siblings, id)
#   i.e. the bytes of _merkle_inclusion_proof_framing(leaf, root, proof)
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _merkle_inclusion_batch_replay_encodable(
    entries: Sequence[MerkleInclusionBatchEntry],
) -> bool:
    """Every U-framed count must fit in unsigned 64 bits.

    The batch length written by the outer S sequence, each proof's
    ``index`` and each ``siblings`` tuple length are encoded with ``U``;
    the raw leaf, root and sibling bytes need no encodability rule.
    """
    values: list[int] = [len(entries)]
    for entry in entries:
        values.extend((entry.proof.index, len(entry.proof.siblings)))
    return all(0 <= value <= _UINT64_MAX for value in values)


def _merkle_inclusion_batch_replay_digest(
    entries: Sequence[MerkleInclusionBatchEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-inclusion-batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, Q)`` and
    ``F(E)``; the entries keep their batch order (duplicates included)
    and each proof's siblings keep their leaf-to-root order.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_INCLUSION_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, Q) = F(U(|entries|)) || Σ F(Q(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        q = _merkle_inclusion_proof_framing(entry.leaf, entry.root, entry.proof)
        transcript.update(_frame_length_prefixed(q))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class MerkleInclusionBatchReplayGuard:
    """Single-use replay protection for a batch of inclusion proofs.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`MerkleInclusionBatchEntry` items — the same sequence shape
    accepted by :func:`verify_inclusion_batch` — to a session id;
    :meth:`check` accepts an equal pending binding exactly once,
    recomputing the binding digest, checking the expiry and delegating to
    :func:`verify_inclusion_batch`, and then marks the id consumed. The
    digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(entries, Q) || F(E))`` with
    domain ``b"zr/mibr/v1"``, where each entry's ``Q`` is the continuous
    run of the single-leaf :class:`MerkleInclusionReplayGuard` transcript
    from ``F(leaf)`` through ``S(proof.siblings, id)`` — i.e.
    ``F(leaf) || F(root) || F(U(proof.index)) || S(proof.siblings, id)``;
    the F / U / S framing and the E expiry encoding are reused byte for
    byte from the Bound, consistency and single-inclusion guards. By
    default both the pending and the consumed state live on this guard
    instance and are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in
    that store under the ``b"zr/mibr/v1"`` key domain, so batch guards
    attached to the same store namespace share pending, claimed and
    consumed ids across independent instances, processes and process
    restarts.

    Concurrent checks of the same id are decided by an atomic claim
    taken before the digest/expiry work and the delegated batch
    verification (the in-instance registry lock, or the store's short
    transaction and unique claim token); the claim is per-id registry
    state rather than a global lock, so a batch being verified under one
    id never serializes checks or binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_MERKLE_INCLUSION_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[MerkleInclusionBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of
        :class:`MerkleInclusionBatchEntry` objects (``bytes`` leaf / root
        and a well-typed :class:`MerkleProof` each), kept in the given
        order with duplicates preserved and no item dropped;
        ``session_id`` must be non-empty ``bytes`` and ``expires_at``
        must be either ``None`` or a non-``bool`` unsigned 64-bit
        Unix-second timestamp. Every U-framed count (the proof
        ``index`` values and the batch / ``siblings`` tuple lengths)
        must likewise fit in uint64. A session id that is already
        pending, being checked or consumed raises :class:`ValueError`.
        Wrong argument or nested field types (including a ``bool``
        index) raise :class:`TypeError`; an empty batch or empty id, an
        out-of-uint64 expiry or framed count, or a rebind raise
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_inclusion_batch_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_inclusion_batch_replay_encodable(items):
            raise ValueError("proof index and tuple lengths must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _merkle_inclusion_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[MerkleInclusionBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_inclusion_batch`, which preflights every entry's
        nested types and checks each single-leaf inclusion independently.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, an empty batch
        or :func:`verify_inclusion_batch` returning ``False``) returns
        ``False``, releases the claim and leaves the registration
        pending. An exception escaping the delegated verification
        likewise releases the claim and then propagates unchanged,
        leaving the id usable. With a store backend, only the holder of
        the current claim token can consume the id (an expired claim
        may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs
        without any lock or transaction held, so other ids are never
        serialized. Argument type errors raise :class:`TypeError`; an
        out-of-range ``now`` raises :class:`ValueError`. Inputs are
        never mutated.
        """
        items = _check_inclusion_batch_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not items or not _merkle_inclusion_batch_replay_encodable(items):
            return False  # an empty batch or a negative/oversized U-framed index
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_inclusion_batch_replay_digest(
                    items, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_inclusion_batch(items):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[MerkleInclusionBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_inclusion_batch_replay_digest(
                    entries, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_inclusion_batch(entries):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for compact Merkle multi-inclusion proofs
#
# A MerkleMultiReplayGuard binds one MerkleMultiProof together with the
# (index, leaf) entries it places and the Merkle root it claims inclusion
# under to a caller-chosen session id, reusing the ReplayBinding type and,
# byte for byte, the F / U / S framing and the E expiry encoding of the
# Bound, consistency and single-inclusion guards. Like the other guards the
# binding is single-use: without a store the state is local to the guard
# instance, while an SQLiteReplayStore keeps pending, claimed and consumed
# ids in the store under b"zr/mmr/v1", shared across instances, processes
# and restarts. bind_once registers a pending binding, check recomputes the
# digest, checks the expiry, delegates the multi-inclusion verification to
# verify_multi_inclusion and consumes the id only on full success; every
# rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root)
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(entries, Q) || S(proof.siblings, id) || F(E)
# )
#   D = b"zr/mmr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   id(x) = x, i.e. a sibling digest is framed raw under F, order preserved
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   entries are (index, leaf) pairs in the exact order of proof.indices, and
#   Q((index, leaf)) = F(U(index)) || F(leaf)
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _check_merkle_multi_entries_types(
    entries: object,
) -> list[tuple[int, bytes]]:
    """Validate the multi-inclusion ``entries`` argument types.

    Mirrors the type checks of :func:`verify_multi_inclusion`: ``entries``
    must be a non-string sequence of two-item ``(index, leaf)`` pairs whose
    index is a non-``bool`` integer and whose leaf is ``bytes``. The pairs
    are copied into a fresh list so the inputs are never mutated. Order,
    range and count problems are left to
    :func:`verify_multi_inclusion` at check time.
    """
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
    return pairs


def _check_merkle_multi_proof_types(proof: object) -> None:
    """Validate a multi-inclusion proof argument type for the replay guard.

    Mirrors the type checks of :func:`verify_multi_inclusion`: ``proof``
    must be a :class:`MerkleMultiProof` with a non-``bool`` integer
    ``leaf_count``, a tuple of non-``bool`` integer ``indices`` and a
    tuple-of-bytes ``siblings``. Structural and value problems (a
    non-positive leaf count, empty or out-of-order indices, malformed
    digest lengths, an index out of range) are left to
    :func:`verify_multi_inclusion` at check time.
    """
    if not isinstance(proof, MerkleMultiProof):
        raise TypeError("proof must be a MerkleMultiProof")
    if not isinstance(proof.leaf_count, int) or isinstance(proof.leaf_count, bool):
        raise TypeError("proof leaf_count must be an integer")
    if not isinstance(proof.indices, tuple):
        raise TypeError("proof indices must be a tuple of integers")
    for position, index in enumerate(proof.indices):
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError(f"proof indices[{position}] must be an integer")
    if not isinstance(proof.siblings, tuple):
        raise TypeError("proof siblings must be a tuple of bytes")
    for position, sibling in enumerate(proof.siblings):
        _check_bytes(sibling, f"proof siblings[{position}]")


def _merkle_multi_replay_encodable(
    entries: Sequence[tuple[int, bytes]],
    proof: MerkleMultiProof,
) -> bool:
    """Every U-framed count must fit in unsigned 64 bits.

    ``proof.leaf_count``, every proof index and every entry index, and the
    tuple lengths written by the three S sequences are encoded with ``U``;
    the raw root, sibling and leaf bytes need no encodability rule.
    """
    values = [
        proof.leaf_count,
        len(proof.indices),
        len(entries),
        len(proof.siblings),
        *proof.indices,
        *(index for index, _leaf in entries),
    ]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _merkle_multi_proof_framing(
    entries: Sequence[tuple[int, bytes]],
    root: bytes,
    proof: MerkleMultiProof,
) -> bytes:
    """The continuous multi-inclusion segment ``F(root) ||``
    ``F(U(proof.leaf_count)) || S(proof.indices, U) || S(entries, Q) ||``
    ``S(proof.siblings, id)``.

    This is the run of the multi-inclusion guard transcript from
    ``F(root)`` up to and including the siblings sequence; the batch
    guard reuses these exact bytes as each item's ``Q`` framing.
    """
    material = bytearray()
    material += _frame_length_prefixed(root)
    material += _frame_length_prefixed(_uint64_be(proof.leaf_count))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    material += _frame_length_prefixed(_uint64_be(len(proof.indices)))
    for index in proof.indices:
        material += _frame_length_prefixed(_uint64_be(index))
    # S(entries, Q) = F(U(|entries|)) || Σ F(F(U(index)) || F(leaf))
    material += _frame_length_prefixed(_uint64_be(len(entries)))
    for index, leaf in entries:
        pair = _frame_length_prefixed(_uint64_be(index)) + _frame_length_prefixed(leaf)
        material += _frame_length_prefixed(pair)
    # S(proof.siblings, id) = F(U(|siblings|)) || Σ F(sibling)
    material += _frame_length_prefixed(_uint64_be(len(proof.siblings)))
    for sibling in proof.siblings:
        material += _frame_length_prefixed(sibling)
    return bytes(material)


def _merkle_multi_replay_digest(
    entries: Sequence[tuple[int, bytes]],
    root: bytes,
    proof: MerkleMultiProof,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-multi-inclusion replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``,
    :func:`_merkle_multi_proof_framing` (``F(root)`` through
    ``S(proof.siblings, id)``) and ``F(E)``; each entry is an
    ``(index, leaf)`` pair, the indices keep their proof order and the
    siblings their level-by-level leaf-to-root proof order.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_MULTI_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_merkle_multi_proof_framing(entries, root, proof))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class MerkleMultiReplayGuard:
    """Single-use replay protection for one compact Merkle multi-inclusion proof.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a
    :class:`MerkleMultiProof` together with the ``(index, leaf)`` entries
    it places and the Merkle ``root`` it claims inclusion under;
    :meth:`check` accepts an equal pending binding exactly once,
    recomputing the binding digest, checking the expiry and delegating to
    :func:`verify_multi_inclusion`, and then marks the id consumed. The
    digest frames the proof under
    ``SHA-256(F(D) || F(session_id) || F(root) || F(U(proof.leaf_count))``
    ``|| S(proof.indices, U) || S(entries, Q) || S(proof.siblings, id) ||``
    ``F(E))`` with domain ``b"zr/mmr/v1"``, where each entry is an
    ``(index, leaf)`` pair framed as ``Q = F(U(index)) || F(leaf)`` in the
    exact order of ``proof.indices``; the F / U / S framing and the E
    expiry encoding are reused byte for byte from the Bound, consistency
    and single-inclusion guards. By default both the pending and the
    consumed state live on this guard instance and are never shared
    between instances; passing an :class:`SQLiteReplayStore` as ``store``
    instead keeps the state in that store under the ``b"zr/mmr/v1"`` key
    domain, so multi-inclusion guards attached to the same store namespace
    share pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a proof being verified under one id never serializes checks
    or binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = None if store is None else store._view(_MERKLE_MULTI_REPLAY_DOMAIN)
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[tuple[int, bytes]],
        root: bytes,
        proof: MerkleMultiProof,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the proof.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string sequence of ``(index, leaf)`` pairs (a non-``bool``
        integer index and ``bytes`` leaf each), ``root`` and
        ``session_id`` must be ``bytes`` (only the session id is required
        to be non-empty) and ``proof`` must be a :class:`MerkleMultiProof`
        with a non-``bool`` integer ``leaf_count``, a tuple of
        non-``bool`` integer ``indices`` and a tuple-of-bytes
        ``siblings``. ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        values (``proof.leaf_count``, every proof and entry index and the
        three sequence lengths) must likewise fit in uint64. The entries
        are expected in the exact order of ``proof.indices``; order,
        range and count problems are left to
        :func:`verify_multi_inclusion` at check time. A session id that is
        already pending, being checked or consumed raises
        :class:`ValueError`. Wrong argument or nested field types raise
        :class:`TypeError`; an empty id, an out-of-uint64 expiry or framed
        value, or a rebind raise :class:`ValueError`. Inputs are never
        mutated.
        """
        pairs = _check_merkle_multi_entries_types(entries)
        _check_bytes(root, "root")
        _check_merkle_multi_proof_types(proof)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_multi_replay_encodable(pairs, proof):
            raise ValueError("proof counts and indices must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _merkle_multi_replay_digest(pairs, root, proof, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[tuple[int, bytes]],
        root: bytes,
        proof: MerkleMultiProof,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the entries, root and proof.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``entries`` / ``root`` / ``proof``; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now`` defaults
        to the current Unix seconds and must otherwise be a non-``bool``
        uint64). Only then are the entries, proof and root handed to
        :func:`verify_multi_inclusion`, which hashes the leaves, rebuilds
        the missing siblings level by level and compares the recomputed
        root.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, or
        :func:`verify_multi_inclusion` returning ``False``) returns
        ``False``, releases the claim and leaves the registration pending.
        An exception escaping the delegated verification likewise releases
        the claim and then propagates unchanged, leaving the id usable.
        With a store backend, only the holder of the current claim token
        can consume the id (an expired claim may be taken over by a later
        equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held,
        so other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        pairs = _check_merkle_multi_entries_types(entries)
        _check_bytes(root, "root")
        _check_merkle_multi_proof_types(proof)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _merkle_multi_replay_encodable(pairs, proof):
            return False  # negative or oversized U-framed counts or indices
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(
                pairs, root, proof, binding, session_id, current
            )
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_multi_replay_digest(
                    pairs, root, proof, session_id, binding.expires_at
                ),
            ):
                return False  # the presented entries/root/proof are not the ones bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_multi_inclusion(pairs, proof, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[tuple[int, bytes]],
        root: bytes,
        proof: MerkleMultiProof,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_multi_replay_digest(
                    entries, root, proof, session_id, binding.expires_at
                ),
            ):
                return False  # the presented entries/root/proof are not the ones bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_multi_inclusion(entries, proof, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for batches of independent compact multi-inclusion proofs
#
# A MerkleMultiBatchReplayGuard binds a whole non-empty batch of
# MerkleMultiBatchEntry items — the same sequence shape accepted by
# verify_multi_inclusion_batch (order and duplicates preserved) — to a
# caller-chosen session id, reusing the ReplayBinding type and, byte for
# byte, the F / U / S framing and the E expiry encoding of the other
# guards. Like them the binding is single-use: without a store the state
# is local to the guard instance, while an SQLiteReplayStore keeps
# pending, claimed and consumed ids in the store under b"zr/mmb/v1",
# shared across instances, processes and restarts. bind_once registers a
# pending binding, check claims the id atomically, recomputes the digest,
# checks the expiry, delegates the batch verification to
# verify_multi_inclusion_batch and consumes the id only on full success;
# every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(batch, Q) || F(E)
# )
#   D = b"zr/mmb/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   Q(item) is the continuous run of the multi-inclusion guard
#   transcript from F(root) through S(proof.siblings, id):
#     F(root) || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(item.entries, Q_e) || S(proof.siblings, id)
#   where each entry pair is framed as Q_e = F(U(index)) || F(leaf),
#   i.e. the bytes of _merkle_multi_proof_framing
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The batch keeps its given order, including duplicates; items are never
# dropped or reordered.


def _merkle_multi_batch_replay_encodable(
    batch: Sequence[MerkleMultiBatchEntry],
) -> bool:
    """Every U-framed count must fit in unsigned 64 bits.

    The batch length written by the outer S sequence and, per item,
    ``proof.leaf_count``, the proof ``indices`` / item ``entries`` /
    ``siblings`` tuple lengths and every proof and entry index are
    encoded with ``U``; the raw root, sibling and leaf bytes need no
    encodability rule.
    """
    values: list[int] = [len(batch)]
    for item in batch:
        proof = item.proof
        values.extend(
            (
                proof.leaf_count,
                len(proof.indices),
                len(item.entries),
                len(proof.siblings),
            )
        )
        values.extend(proof.indices)
        values.extend(index for index, _leaf in item.entries)
    return all(0 <= value <= _UINT64_MAX for value in values)


def _merkle_multi_batch_replay_digest(
    batch: Sequence[MerkleMultiBatchEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-multi-inclusion-batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(batch, Q)`` and
    ``F(E)``; the items keep their batch order (duplicates included),
    each item's ``(index, leaf)`` pairs keep their proof-indices order
    and each proof's siblings keep their level-by-level leaf-to-root
    order.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_MULTI_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(batch, Q) = F(U(|batch|)) || Σ F(Q(item))
    transcript.update(_frame_length_prefixed(_uint64_be(len(batch))))
    for item in batch:
        q = _merkle_multi_proof_framing(item.entries, item.root, item.proof)
        transcript.update(_frame_length_prefixed(q))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class MerkleMultiBatchReplayGuard:
    """Single-use replay protection for a batch of multi-inclusion proofs.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch
    of :class:`MerkleMultiBatchEntry` items — the same sequence shape
    accepted by :func:`verify_multi_inclusion_batch` — to a session id;
    :meth:`check` accepts an equal pending binding exactly once,
    recomputing the binding digest, checking the expiry and delegating
    to :func:`verify_multi_inclusion_batch`, and then marks the id
    consumed. The digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(batch, Q) || F(E))`` with
    domain ``b"zr/mmb/v1"``, where each item's ``Q`` is the continuous
    run of the multi-inclusion :class:`MerkleMultiReplayGuard`
    transcript from ``F(root)`` through ``S(proof.siblings, id)`` — i.e.
    ``F(root) || F(U(proof.leaf_count)) || S(proof.indices, U) ||``
    ``S(entries, Q_e) || S(proof.siblings, id)`` with each entry pair
    framed as ``Q_e = F(U(index)) || F(leaf)``; the F / U / S framing
    and the E expiry encoding are reused byte for byte from the other
    guards. By default both the pending and the consumed state live on
    this guard instance and are never shared between instances; passing
    an :class:`SQLiteReplayStore` as ``store`` instead keeps the state
    in that store under the ``b"zr/mmb/v1"`` key domain, so batch
    guards attached to the same store namespace share pending, claimed
    and consumed ids across independent instances, processes and
    process restarts.

    Concurrent checks of the same id are decided by an atomic claim
    taken before the digest/expiry work and the delegated batch
    verification (the in-instance registry lock, or the store's short
    transaction and unique claim token); the claim is per-id registry
    state rather than a global lock, so a batch being verified under
    one id never serializes checks or binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_MERKLE_MULTI_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: Sequence[MerkleMultiBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``batch`` must be a
        non-string, non-empty sequence of
        :class:`MerkleMultiBatchEntry` objects (each a tuple of
        ``(index, leaf)`` pairs, a well-typed
        :class:`MerkleMultiProof` and ``bytes`` root), kept in the given
        order with duplicates preserved and no item dropped;
        ``session_id`` must be non-empty ``bytes`` and ``expires_at``
        must be either ``None`` or a non-``bool`` unsigned 64-bit
        Unix-second timestamp. Every U-framed count (the proof
        ``leaf_count`` / index values, the entry indices and the batch
        / proof / entries tuple lengths) must likewise fit in uint64.
        A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested
        field types (including a ``bool`` count or index) raise
        :class:`TypeError`; an empty batch or empty id, an
        out-of-uint64 expiry or framed count, or a rebind raise
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_multi_inclusion_batch_entries_types(batch)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("batch must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_multi_batch_replay_encodable(items):
            raise ValueError(
                "proof counts, indices and tuple lengths must be unsigned "
                "64-bit integers"
            )
        binding = ReplayBinding(
            session_id,
            _merkle_multi_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: Sequence[MerkleMultiBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``batch`` in its given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_multi_inclusion_batch`, which preflights every
        item's nested types and checks each multi-inclusion proof
        independently.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, an empty batch
        or :func:`verify_multi_inclusion_batch` returning ``False``)
        returns ``False``, releases the claim and leaves the
        registration pending. An exception escaping the delegated
        verification likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only
        the holder of the current claim token can consume the id (an
        expired claim may be taken over by a later equal ``check``); a
        stale token neither consumes nor restores anything.
        Verification runs without any lock or transaction held, so
        other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_multi_inclusion_batch_entries_types(batch)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not items or not _merkle_multi_batch_replay_encodable(items):
            return False  # an empty batch or negative/oversized U-framed values
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_multi_batch_replay_digest(
                    items, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_multi_inclusion_batch(items):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: Sequence[MerkleMultiBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_multi_batch_replay_digest(
                    batch, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_multi_inclusion_batch(batch):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for batches of independent Merkle consistency proofs
#
# A MerkleConsistencyBatchReplayGuard binds a whole non-empty batch of
# MerkleConsistencyBatchEntry items (the same sequence shape accepted by
# verify_consistency_batch) to a caller-chosen session id, reusing the
# ReplayBinding type and, byte for byte, the F / U / S framing and the E
# expiry encoding of the Bound guards. Like the other guards the binding is
# single-use: without a store the state is local to the guard instance,
# while an SQLiteReplayStore keeps pending, claimed and consumed ids in the
# store under b"zr/mcbr/v1", shared across instances, processes and
# restarts. bind_once registers a pending binding, check recomputes the
# digest, checks the expiry, delegates the batch verification to
# verify_consistency_batch and consumes the id only on full success; every
# rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(entries, Q) || F(E)
# )
#   each entry framed as
#     Q(e) = F(old_root) || F(new_root) || F(U(old_count))
#            || F(U(new_count)) || S(nodes, id)
#   D = b"zr/mcbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   id(x) = x, i.e. a node digest is framed raw under F, order preserved
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The batch and every proof's nodes keep their given order, including
# duplicates; entries are never dropped or reordered.


def _check_merkle_consistency_batch_entries_types(
    entries: object,
) -> list[MerkleConsistencyBatchEntry]:
    """Validate the consistency-batch ``entries`` argument types.

    Mirrors the type checks of :func:`verify_consistency_batch`: ``entries``
    must be a non-``bytes`` / ``bytearray`` / ``str`` sequence of
    :class:`MerkleConsistencyBatchEntry` objects whose ``old_root`` /
    ``new_root`` are ``bytes`` and whose ``proof`` is a
    :class:`MerkleConsistencyProof` with non-``bool`` integer counts and a
    tuple-of-bytes ``nodes``. The entries are copied into a fresh list so
    the inputs are never mutated; an empty batch is left for
    :meth:`MerkleConsistencyBatchReplayGuard.bind_once` to reject with
    :class:`ValueError`, and structural/value problems (count ranges, node
    count and digest lengths) are left to :func:`verify_consistency_batch`
    at check time.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of MerkleConsistencyBatchEntry")
    items: list[MerkleConsistencyBatchEntry] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, MerkleConsistencyBatchEntry):
            raise TypeError(
                f"entries[{position}] must be a MerkleConsistencyBatchEntry"
            )
        _check_bytes(entry.old_root, f"entries[{position}] old_root")
        _check_bytes(entry.new_root, f"entries[{position}] new_root")
        proof = entry.proof
        if not isinstance(proof, MerkleConsistencyProof):
            raise TypeError(
                f"entries[{position}] proof must be a MerkleConsistencyProof"
            )
        for name in ("old_count", "new_count"):
            value = getattr(proof, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(
                    f"entries[{position}] proof {name} must be an integer"
                )
        if not isinstance(proof.nodes, tuple):
            raise TypeError(
                f"entries[{position}] proof nodes must be a tuple of bytes"
            )
        for node in proof.nodes:
            _check_bytes(node, f"entries[{position}] proof node")
        items.append(entry)
    return items


def _merkle_consistency_batch_item_framing(entry: MerkleConsistencyBatchEntry) -> bytes:
    """``Q(e) = F(old_root) || F(new_root) || F(U(old_count)) ||``
    ``F(U(new_count)) || S(nodes, id)`` for one batch entry."""
    proof = entry.proof
    material = bytearray()
    material += _frame_length_prefixed(entry.old_root)
    material += _frame_length_prefixed(entry.new_root)
    material += _frame_length_prefixed(_uint64_be(proof.old_count))
    material += _frame_length_prefixed(_uint64_be(proof.new_count))
    # S(proof.nodes, id) = F(U(|nodes|)) || Σ F(node)
    material += _frame_length_prefixed(_uint64_be(len(proof.nodes)))
    for node in proof.nodes:
        material += _frame_length_prefixed(node)
    return bytes(material)


def _merkle_consistency_batch_replay_encodable(
    entries: Sequence[MerkleConsistencyBatchEntry],
) -> bool:
    """Every U-framed count must fit in unsigned 64 bits.

    The batch length written by the outer S sequence, each proof's
    ``old_count`` / ``new_count`` and each ``nodes`` tuple length are
    encoded with ``U``; the raw root and node bytes need no encodability
    rule.
    """
    values: list[int] = [len(entries)]
    for entry in entries:
        values.extend(
            (entry.proof.old_count, entry.proof.new_count, len(entry.proof.nodes))
        )
    return all(0 <= value <= _UINT64_MAX for value in values)


def _merkle_consistency_batch_replay_digest(
    entries: Sequence[MerkleConsistencyBatchEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Merkle-consistency-batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, Q)`` and
    ``F(E)``; the entries keep their batch order (duplicates included) and
    each proof's nodes keep theirs.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_MERKLE_CONSISTENCY_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, Q) = F(U(|entries|)) || Σ F(Q(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        transcript.update(
            _frame_length_prefixed(_merkle_consistency_batch_item_framing(entry))
        )
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class MerkleConsistencyBatchReplayGuard:
    """Single-use replay protection for a batch of consistency proofs.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`MerkleConsistencyBatchEntry` items — the same sequence shape
    accepted by :func:`verify_consistency_batch` — to a session id;
    :meth:`check` accepts an equal pending binding exactly once,
    recomputing the binding digest, checking the expiry and delegating to
    :func:`verify_consistency_batch`, and then marks the id consumed. The
    digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(entries, Q) || F(E))`` with domain
    ``b"zr/mcbr/v1"``, where each entry is framed as
    ``Q = F(old_root) || F(new_root) || F(U(old_count)) ||``
    ``F(U(new_count)) || S(nodes, id)`` in the exact given batch order; the
    F / U / S framing and the E expiry encoding are reused byte for byte
    from the Bound and consistency guards. By default both the pending and
    the consumed state live on this guard instance and are never shared
    between instances; passing an :class:`SQLiteReplayStore` as ``store``
    instead keeps the state in that store under the ``b"zr/mcbr/v1"`` key
    domain, so batch guards attached to the same store namespace share
    pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_MERKLE_CONSISTENCY_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[MerkleConsistencyBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of
        :class:`MerkleConsistencyBatchEntry` objects (``bytes`` roots and a
        well-typed :class:`MerkleConsistencyProof` each), kept in the given
        order with duplicates preserved and no item dropped; ``session_id``
        must be non-empty ``bytes`` and ``expires_at`` must be either
        ``None`` or a non-``bool`` unsigned 64-bit Unix-second timestamp.
        Every U-framed count (the proof ``old_count`` / ``new_count``
        values and the batch / ``nodes`` tuple lengths) must likewise fit
        in uint64. A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested
        field types (including ``bool`` counts) raise :class:`TypeError`;
        an empty batch or empty id, an out-of-uint64 expiry or framed
        count, or a rebind raise :class:`ValueError`. Inputs are never
        mutated.
        """
        items = _check_merkle_consistency_batch_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _merkle_consistency_batch_replay_encodable(items):
            raise ValueError("proof counts and tuple lengths must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _merkle_consistency_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[MerkleConsistencyBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_consistency_batch`, which checks every entry's roots
        and append-only proof independently.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, or
        :func:`verify_consistency_batch` returning ``False``) returns
        ``False``, releases the claim and leaves the registration pending.
        An exception escaping the delegated verification likewise releases
        the claim and then propagates unchanged, leaving the id usable.
        With a store backend, only the holder of the current claim token
        can consume the id (an expired claim may be taken over by a later
        equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held,
        so other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_merkle_consistency_batch_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not items or not _merkle_consistency_batch_replay_encodable(items):
            return False  # an empty batch or negative/oversized U-framed counts
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_consistency_batch_replay_digest(
                    items, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_batch(items):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[MerkleConsistencyBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _merkle_consistency_batch_replay_digest(
                    entries, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_batch(entries):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for multi-key Schnorr batches
#
# A SchnorrBatchReplayGuard binds a whole non-empty batch of
# MultiSchnorrEntry items — the same sequence shape accepted by
# verify_schnorr_batch (order and duplicates preserved) — to a caller-chosen
# session id, reusing the ReplayBinding type and, byte for byte, the F / U /
# S framing and the E expiry encoding of the other batch guards. Like them
# the binding is single-use: without a store the state is local to the guard
# instance, while an SQLiteReplayStore keeps pending, claimed and consumed
# ids in the store under b"zr/sbr/v1", shared across instances, processes
# and restarts. bind_once registers a pending binding, check claims the id
# atomically, recomputes the digest, checks the expiry, delegates the batch
# verification to verify_schnorr_batch with randbelow passed through
# unchanged and consumes the id only on full success; every rejection
# leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(entries, Q) || F(E)
# )
#   D = b"zr/sbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   Q(e) = the existing BoundSchnorr leaf raw bytes for e (_bound_schnorr_leaf)
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _check_multi_schnorr_entries_types(
    entries: object,
) -> list[MultiSchnorrEntry]:
    """Validate the Schnorr-batch ``entries`` argument types.

    Mirrors the sequence and nested type rules of
    :func:`verify_schnorr_batch`: ``entries`` must be a non-``bytes`` /
    ``bytearray`` / ``str`` sequence of :class:`MultiSchnorrEntry` objects
    whose six fields are nestedly well-typed (non-``bool`` integers for
    ``public_key`` / ``prime`` / ``generator`` and the proof commitment /
    response, ``bytes`` for ``message`` / ``context`` and a
    :class:`SchnorrProof`). The entries are copied into a fresh list so the
    inputs are never mutated; an empty batch is left for
    :meth:`SchnorrBatchReplayGuard.bind_once` to reject with
    :class:`ValueError`, and structural/value problems (group parameters,
    field ranges) are left to :func:`verify_schnorr_batch` at check time.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of MultiSchnorrEntry")
    items: list[MultiSchnorrEntry] = []
    for position, entry in enumerate(entries):
        items.append(_check_multi_schnorr_entry(entry, f"entries[{position}]"))
    return items


def _schnorr_batch_replay_encodable(entries: Sequence[MultiSchnorrEntry]) -> bool:
    """The batch length must fit in uint64 and every leaf integer be framed.

    The outer ``S`` sequence writes the batch count with ``U`` (eight-byte
    unsigned big-endian), and each :class:`MultiSchnorrEntry` is framed as
    the existing BoundSchnorr leaf, whose five integers (``prime``,
    ``generator``, ``public_key`` and the proof commitment / response) use
    the shortest unsigned big-endian encoding; a count outside uint64 or a
    negative leaf integer cannot be framed.
    """
    if not 0 <= len(entries) <= _UINT64_MAX:
        return False
    for entry in entries:
        if min(
            entry.prime,
            entry.generator,
            entry.public_key,
            entry.proof.commitment,
            entry.proof.response,
        ) < 0:
            return False
    return True


def _schnorr_batch_replay_digest(
    entries: Sequence[MultiSchnorrEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the multi-key Schnorr batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, Q)`` and
    ``F(E)``; ``Q(entry)`` is the existing BoundSchnorr leaf raw bytes and
    the entries keep their batch order (duplicates included).
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_SCHNORR_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, Q) = F(U(|entries|)) || Σ F(Q(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        transcript.update(_frame_length_prefixed(_bound_schnorr_leaf(entry)))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class SchnorrBatchReplayGuard:
    """Single-use replay protection for a multi-key :class:`MultiSchnorrEntry` batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`MultiSchnorrEntry` items — the same sequence shape accepted by
    :func:`verify_schnorr_batch`, kept in the given order with duplicates
    preserved — to a session id; :meth:`check` accepts an equal pending
    binding exactly once, recomputing the binding digest, checking the
    expiry and delegating to :func:`verify_schnorr_batch` with the random
    source passed through unchanged, and then marks the id consumed. The
    digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(entries, Q) || F(E))`` with domain
    ``b"zr/sbr/v1"``, where ``Q(entry)`` is the existing BoundSchnorr leaf
    raw bytes (the same bytes :func:`_bound_schnorr_leaf` builds for
    :func:`verify_bound`); the F / U / S framing and the E expiry encoding
    are reused byte for byte from the other replay guards. By default both
    the pending and the consumed state live on this guard instance and are
    never shared between instances; passing an :class:`SQLiteReplayStore`
    as ``store`` instead keeps the state in that store under the
    ``b"zr/sbr/v1"`` key domain, so batch guards attached to the same store
    namespace share pending, claimed and consumed ids across independent
    instances, processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_SCHNORR_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[MultiSchnorrEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of :class:`MultiSchnorrEntry`
        objects following the same sequence and nested type rules as
        :func:`verify_schnorr_batch`: every entry's ``public_key``,
        ``message``, ``proof`` (a :class:`SchnorrProof` with non-``bool``
        integer commitment / response), ``context``, ``prime`` and
        ``generator`` are type-checked; entries are kept in the given order
        with duplicates preserved and no item dropped. ``session_id`` must
        be non-empty ``bytes`` and ``expires_at`` must be either ``None`` or
        a non-``bool`` unsigned 64-bit Unix-second timestamp; the
        ``U``-framed batch length must fit in uint64 and every BoundSchnorr
        leaf integer (``prime``, ``generator``, ``public_key`` and the proof
        commitment / response) must be non-negative. A session id that is
        already pending, being checked or consumed raises
        :class:`ValueError`. Wrong argument or nested field types
        (including ``bool`` integers) raise :class:`TypeError`; an empty
        batch or empty id, an out-of-uint64 expiry or batch length, a
        negative leaf integer or a rebind raise :class:`ValueError`.
        Inputs are never mutated.
        """
        items = _check_multi_schnorr_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _schnorr_batch_replay_encodable(items):
            raise ValueError(
                "batch length and leaf integers must be non-negative unsigned integers"
            )
        binding = ReplayBinding(
            session_id,
            _schnorr_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[MultiSchnorrEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_schnorr_batch` with ``randbelow`` passed through
        unchanged, under that function's sequence, structure and
        randomness contract: it is called once per structurally valid
        entry as ``randbelow(prime - 1)``, a non-callable source or a
        non-integer result raises :class:`TypeError` and a coefficient
        outside ``[0, prime - 1)`` raises :class:`ValueError`.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a negative leaf
        integer, or :func:`verify_schnorr_batch` returning ``False``)
        returns ``False``, releases the claim and leaves the registration
        pending. An exception escaping the delegated verification (such as
        the :class:`TypeError` / :class:`ValueError` raised by a bad
        ``randbelow``) likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors (including a non-callable ``randbelow``)
        raise :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_multi_schnorr_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _schnorr_batch_replay_encodable(items):
            return False  # an oversized batch or negative leaf integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _schnorr_batch_replay_digest(items, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_schnorr_batch(items, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[MultiSchnorrEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _schnorr_batch_replay_digest(entries, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_schnorr_batch(entries, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# SingleKeyBatchGuard binds a whole batch of SchnorrBatchEntry items — all
# made for one fixed public key and group — to one session id. Without a
# store the pending/claimed/consumed states are local to the guard instance,
# while an SQLiteReplayStore keeps pending, claimed and consumed ids in the
# store under b"zr/skbr/v1", shared across instances, processes and restarts.
# bind_once registers a pending binding, check claims the id atomically,
# recomputes the digest, checks the expiry, delegates the batch verification
# to the fixed SchnorrVerifier's verify_batch with randbelow passed through
# unchanged and consumes the id only on full success; every rejection leaves
# the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(entries, L) || F(E)
# )
#   D = b"zr/skbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   L(e) = the BoundSchnorr leaf raw bytes built for e with this guard's
#          public key and group parameters (_bound_schnorr_leaf)
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _check_schnorr_batch_entries_types(
    entries: object,
) -> list[SchnorrBatchEntry]:
    """Validate the single-key Schnorr-batch ``entries`` argument types.

    Mirrors the sequence and nested type rules of
    :meth:`SchnorrVerifier.verify_batch`: ``entries`` must be a
    non-``bytes`` / ``bytearray`` / ``str`` sequence of
    :class:`SchnorrBatchEntry` objects whose ``message`` / ``context`` are
    ``bytes`` and whose ``proof`` is a :class:`SchnorrProof` with
    non-``bool`` integer commitment / response. The entries are copied into
    a fresh list so the inputs are never mutated; an empty batch is left
    for :meth:`SingleKeyBatchGuard.bind_once` to reject with
    :class:`ValueError`, and structural/value problems (out-of-range
    commitments, negative responses) are left to
    :meth:`SchnorrVerifier.verify_batch` at check time.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of SchnorrBatchEntry")
    items: list[SchnorrBatchEntry] = []
    for position, entry in enumerate(entries):
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
        items.append(entry)
    return items


def _single_key_batch_leaf(
    entry: SchnorrBatchEntry,
    public_key: int,
    prime: int,
    generator: int,
) -> bytes:
    """The BoundSchnorr leaf raw bytes for ``entry`` under one fixed key/group.

    The leaf is built byte for byte by :func:`_bound_schnorr_leaf` from a
    :class:`MultiSchnorrEntry` carrying the guard's ``public_key``,
    ``prime`` and ``generator`` together with the entry's ``message``,
    ``proof`` and ``context``.
    """
    return _bound_schnorr_leaf(
        MultiSchnorrEntry(
            public_key, entry.message, entry.proof, entry.context, prime, generator
        )
    )


def _single_key_batch_replay_encodable(entries: Sequence[SchnorrBatchEntry]) -> bool:
    """The batch length must fit in uint64 and every leaf integer be framed.

    The outer ``S`` sequence writes the batch count with ``U`` (eight-byte
    unsigned big-endian), and each leaf frames the proof commitment /
    response with the shortest unsigned big-endian encoding; a count
    outside uint64 or a negative leaf integer cannot be framed. The guard's
    own ``prime`` / ``generator`` / ``public_key`` are validated positive
    at construction, so only the proof integers can be negative here.
    """
    if not 0 <= len(entries) <= _UINT64_MAX:
        return False
    for entry in entries:
        if min(entry.proof.commitment, entry.proof.response) < 0:
            return False
    return True


def _single_key_batch_replay_digest(
    entries: Sequence[SchnorrBatchEntry],
    session_id: bytes,
    expires_at: int | None,
    *,
    public_key: int,
    prime: int,
    generator: int,
) -> bytes:
    """Compute the single-key Schnorr batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, L)`` and
    ``F(E)``; ``L(entry)`` is the BoundSchnorr leaf raw bytes built with
    the guard's public key and group parameters, and the entries keep
    their batch order (duplicates included).
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_SINGLE_KEY_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, L) = F(U(|entries|)) || Σ F(L(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        leaf = _single_key_batch_leaf(entry, public_key, prime, generator)
        transcript.update(_frame_length_prefixed(leaf))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class SingleKeyBatchGuard:
    """Single-use replay protection for a same-key :class:`SchnorrBatchEntry` batch.

    The guard is bound to one fixed ``public_key`` and group (``prime`` /
    ``generator``, defaulting to :data:`DEFAULT_PRIME` /
    :data:`DEFAULT_GENERATOR`); every batch it checks is verified by the
    :class:`SchnorrVerifier` constructed once from those parameters.
    :meth:`bind_once` registers a pending :class:`ReplayBinding` that
    commits a whole non-empty batch of :class:`SchnorrBatchEntry` items —
    the same sequence shape accepted by
    :meth:`SchnorrVerifier.verify_batch`, kept in the given order with
    duplicates preserved — to a session id; :meth:`check` accepts an equal
    pending binding exactly once, recomputing the binding digest, checking
    the expiry and delegating to the fixed verifier's
    :meth:`~SchnorrVerifier.verify_batch` with the random source passed
    through unchanged, and then marks the id consumed. The digest frames
    the batch under ``SHA-256(F(D) || F(session_id) || S(entries, L) ||
    F(E))`` with domain ``b"zr/skbr/v1"``, where ``L(entry)`` is the
    existing BoundSchnorr leaf raw bytes built with this guard's public
    key and group parameters (the same bytes :func:`_bound_schnorr_leaf`
    builds for :func:`verify_bound`); the F / U / S framing and the E
    expiry encoding are reused byte for byte from the other replay guards.
    By default both the pending and the consumed state live on this guard
    instance and are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in
    that store under the ``b"zr/skbr/v1"`` key domain, so batch guards
    attached to the same store namespace share pending, claimed and
    consumed ids across independent instances, processes and process
    restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification
    (the in-instance registry lock, or the store's short transaction and
    unique claim token); the claim is per-id registry state rather than a
    global lock, so a batch being verified under one id never serializes
    checks or binds of other ids.
    """

    def __init__(
        self,
        public_key: int,
        *,
        prime: int = DEFAULT_PRIME,
        generator: int = DEFAULT_GENERATOR,
        store: SQLiteReplayStore | None = None,
    ) -> None:
        _check_int(public_key, "public_key")
        _check_int(prime, "prime")
        _check_int(generator, "generator")
        # The fixed verifier carries the group-value range checks.
        self._verifier = SchnorrVerifier(public_key, prime=prime, generator=generator)
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._public_key = public_key
        self._prime = prime
        self._generator = generator
        self._store = (
            None
            if store is None
            else store._view(_SINGLE_KEY_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def public_key(self) -> int:
        return self._public_key

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def _digest(
        self,
        entries: Sequence[SchnorrBatchEntry],
        session_id: bytes,
        expires_at: int | None,
    ) -> bytes:
        """The binding digest over ``entries`` under this guard's key/group."""
        return _single_key_batch_replay_digest(
            entries,
            session_id,
            expires_at,
            public_key=self._public_key,
            prime=self._prime,
            generator=self._generator,
        )

    def bind_once(
        self,
        entries: Sequence[SchnorrBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of :class:`SchnorrBatchEntry`
        objects following the same sequence and nested type rules as
        :meth:`SchnorrVerifier.verify_batch`: every entry's ``message``
        and ``context`` are ``bytes`` and its ``proof`` is a
        :class:`SchnorrProof` with non-``bool`` integer commitment /
        response; entries are kept in the given order with duplicates
        preserved and no item dropped. ``session_id`` must be non-empty
        ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the
        ``U``-framed batch length must fit in uint64 and every leaf
        integer (the proof commitment / response) must be non-negative. A
        session id that is already pending, being checked or consumed
        raises :class:`ValueError`. Wrong argument or nested field types
        (including ``bool`` integers) raise :class:`TypeError`; an empty
        batch or empty id, an out-of-uint64 expiry or batch length, a
        negative leaf integer or a rebind raise :class:`ValueError`.
        Inputs are never mutated.
        """
        items = _check_schnorr_batch_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _single_key_batch_replay_encodable(items):
            raise ValueError(
                "batch length and leaf integers must be non-negative unsigned integers"
            )
        binding = ReplayBinding(
            session_id,
            self._digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[SchnorrBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to the fixed
        verifier's :meth:`SchnorrVerifier.verify_batch` with ``randbelow``
        passed through unchanged, under that method's sequence, structure
        and randomness contract: it is called once per structurally valid
        entry as ``randbelow(prime - 1)``, a non-callable source or a
        non-integer result raises :class:`TypeError` and a coefficient
        outside ``[0, prime - 1)`` raises :class:`ValueError`.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, an empty batch, a
        negative leaf integer, or the delegated batch verification
        returning ``False``) returns ``False``, releases the claim and
        leaves the registration pending. An exception escaping the
        delegated verification (such as the :class:`TypeError` /
        :class:`ValueError` raised by a bad ``randbelow``) likewise
        releases the claim and then propagates unchanged, leaving the id
        usable. With a store backend, only the holder of the current claim
        token can consume the id (an expired claim may be taken over by a
        later equal ``check``); a stale token neither consumes nor
        restores anything. Verification runs without any lock or
        transaction held, so other ids are never serialized. Argument type
        errors (including a non-callable ``randbelow``) raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_schnorr_batch_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _single_key_batch_replay_encodable(items):
            return False  # an oversized batch or negative leaf integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                self._digest(items, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not self._verifier.verify_batch(items, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[SchnorrBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                self._digest(entries, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not self._verifier.verify_batch(entries, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# RangeBatchReplayGuard binds a whole batch of RangeBatchEntry items to one
# session id. Without a store the pending/claimed/consumed states are local
# to the guard instance, while an SQLiteReplayStore keeps pending, claimed
# and consumed ids in the store under b"zr/rbr/v1", shared across instances,
# processes and restarts. bind_once registers a pending binding, check claims
# the id atomically, recomputes the digest, checks the expiry, delegates the
# batch verification to verify_range_batch with randbelow passed through
# unchanged and consumes the id only on full success; every rejection
# leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(entries, L) || F(E)
# )
#   D = b"zr/rbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   L(e) = the existing BoundRange leaf raw bytes for e (_bound_range_leaf)
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _check_range_batch_entries_types(
    entries: object,
) -> list[RangeBatchEntry]:
    """Validate the range-batch ``entries`` argument types.

    Mirrors the sequence and nested type rules of
    :func:`verify_range_batch`: ``entries`` must be a non-``bytes`` /
    ``bytearray`` / ``str`` sequence of :class:`RangeBatchEntry` objects
    whose :class:`PedersenCommitment`, :class:`RangeProof` ``t`` / ``e`` /
    ``s`` integer tuples and ``context`` are nestedly well-typed. The
    entries are copied into a fresh list so the inputs are never mutated;
    an empty batch is left for
    :meth:`RangeBatchReplayGuard.bind_once` to reject with
    :class:`ValueError`, and structural/value problems are left to
    :func:`verify_range_batch` at check time.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of RangeBatchEntry")
    items: list[RangeBatchEntry] = []
    for position, entry in enumerate(entries):
        items.append(_check_range_batch_entry(entry, f"entries[{position}]"))
    return items


def _range_batch_replay_encodable(entries: Sequence[RangeBatchEntry]) -> bool:
    """The S-framed batch length must fit in an unsigned 64-bit integer.

    The outer ``S`` sequence writes the batch count with ``U`` (eight-byte
    unsigned big-endian). Each entry is framed as the existing BoundRange
    leaf, whose integers are encoded as decimal ASCII with the sign kept,
    so every integer field frames for any value and no per-entry
    encodability rule is needed.
    """
    return 0 <= len(entries) <= _UINT64_MAX


def _range_batch_replay_digest(
    entries: Sequence[RangeBatchEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the range-batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, L)`` and
    ``F(E)``; ``L(entry)`` is the existing BoundRange leaf raw bytes and
    the entries keep their batch order (duplicates included).
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_RANGE_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, L) = F(U(|entries|)) || Σ F(L(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        transcript.update(_frame_length_prefixed(_bound_range_leaf(entry)))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class RangeBatchReplayGuard:
    """Single-use replay protection for a batch of :class:`RangeBatchEntry`.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`RangeBatchEntry` items — the same sequence shape accepted by
    :func:`verify_range_batch`, kept in the given order with duplicates
    preserved — to a session id; :meth:`check` accepts an equal pending
    binding exactly once, recomputing the binding digest, checking the
    expiry and delegating to :func:`verify_range_batch` with the random
    source passed through unchanged, and then marks the id consumed. The
    digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(entries, L) || F(E))`` with domain
    ``b"zr/rbr/v1"``, where ``L(entry)`` is the existing BoundRange leaf
    raw bytes (the same bytes :func:`_bound_range_leaf` builds for
    :func:`verify_range_bound`); the F / U / S framing and the E expiry
    encoding are reused byte for byte from the other replay guards. By
    default both the pending and the consumed state live on this guard
    instance and are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in
    that store under the ``b"zr/rbr/v1"`` key domain, so batch guards
    attached to the same store namespace share pending, claimed and
    consumed ids across independent instances, processes and process
    restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_RANGE_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[RangeBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of :class:`RangeBatchEntry` objects
        following the same sequence and nested type rules as
        :func:`verify_range_batch`: every entry's :class:`PedersenCommitment`
        six integer fields, its :class:`RangeProof` ``t`` / ``e`` / ``s``
        integer tuples and its ``context`` are type-checked; entries are
        kept in the given order with duplicates preserved and no item
        dropped. ``session_id`` must be non-empty ``bytes`` and
        ``expires_at`` must be either ``None`` or a non-``bool`` unsigned
        64-bit Unix-second timestamp; the ``U``-framed batch length must
        fit in uint64. A session id that is already pending, being checked
        or consumed raises :class:`ValueError`. Wrong argument or nested
        field types (including ``bool`` integers) raise :class:`TypeError`;
        an empty batch or empty id, an out-of-uint64 expiry or batch length
        or a rebind raise :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_range_batch_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _range_batch_replay_encodable(items):
            raise ValueError("batch length must be an unsigned 64-bit integer")
        binding = ReplayBinding(
            session_id,
            _range_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[RangeBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_range_batch` with ``randbelow`` passed through
        unchanged, under that function's sequence, structure and
        randomness contract: it is called once per structurally valid
        range-proof branch as ``randbelow(prime - 1)``, a non-callable
        source or a non-integer result raises :class:`TypeError` and a
        coefficient outside ``[0, prime - 1)`` raises :class:`ValueError`.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, an empty batch or
        :func:`verify_range_batch` returning ``False``) returns ``False``,
        releases the claim and leaves the registration pending. An
        exception escaping the delegated verification (such as the
        :class:`TypeError` / :class:`ValueError` raised by a bad
        ``randbelow``) likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors (including a non-callable ``randbelow``)
        raise :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_range_batch_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _range_batch_replay_encodable(items):
            return False  # an oversized batch
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _range_batch_replay_digest(items, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_range_batch(items, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[RangeBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _range_batch_replay_digest(entries, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_range_batch(entries, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


def _check_region_batch_entries_types(
    entries: object,
) -> list[RegionBatchEntry]:
    """Validate the region-batch ``entries`` argument types.

    Mirrors the sequence and nested type rules of
    :func:`verify_region_batch`: ``entries`` must be a non-``bytes`` /
    ``bytearray`` / ``str`` sequence of :class:`RegionBatchEntry` objects
    whose two :class:`PedersenCommitment` objects, :class:`Region`,
    :class:`RegionProof` ``x_proof`` / ``y_proof`` ``t`` / ``e`` / ``s``
    integer tuples and ``context`` are nestedly well-typed. The entries are
    copied into a fresh list so the inputs are never mutated; an empty batch
    is left for :meth:`RegionBatchReplayGuard.bind_once` to reject with
    :class:`ValueError`, and structural/value problems are left to
    :func:`verify_region_batch` at check time.
    """
    if isinstance(entries, (bytes, bytearray, str)) or not isinstance(entries, Sequence):
        raise TypeError("entries must be a sequence of RegionBatchEntry")
    items: list[RegionBatchEntry] = []
    for position, entry in enumerate(entries):
        items.append(_check_region_batch_entry(entry, f"entries[{position}]"))
    return items


def _region_batch_replay_encodable(entries: Sequence[RegionBatchEntry]) -> bool:
    """The S-framed batch length must fit in an unsigned 64-bit integer.

    The outer ``S`` sequence writes the batch count with ``U`` (eight-byte
    unsigned big-endian). Each entry is framed as the existing BoundRegion
    leaf, whose integers are encoded as decimal ASCII with the sign kept,
    so every integer field frames for any value and no per-entry
    encodability rule is needed.
    """
    return 0 <= len(entries) <= _UINT64_MAX


def _region_batch_replay_digest(
    entries: Sequence[RegionBatchEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the region-batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, L)`` and
    ``F(E)``; ``L(entry)`` is the existing BoundRegion leaf raw bytes and
    the entries keep their batch order (duplicates included).
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_REGION_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, L) = F(U(|entries|)) || Σ F(L(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        transcript.update(_frame_length_prefixed(_bound_region_leaf(entry)))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class RegionBatchReplayGuard:
    """Single-use replay protection for a batch of :class:`RegionBatchEntry`.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`RegionBatchEntry` items — the same sequence shape accepted by
    :func:`verify_region_batch`, kept in the given order with duplicates
    preserved — to a session id; :meth:`check` accepts an equal pending
    binding exactly once, recomputing the binding digest, checking the
    expiry and delegating to :func:`verify_region_batch` with the random
    source passed through unchanged, and then marks the id consumed. The
    digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(entries, L) || F(E))`` with domain
    ``b"zr/rgbr/v1"``, where ``L(entry)`` is the existing BoundRegion leaf
    raw bytes (the same bytes :func:`_bound_region_leaf` builds for
    :func:`verify_region_bound`); the F / U / S framing and the E expiry
    encoding are reused byte for byte from the other replay guards. By
    default both the pending and the consumed state live on this guard
    instance and are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in that
    store under the ``b"zr/rgbr/v1"`` key domain, so batch guards attached
    to the same store namespace share pending, claimed and consumed ids
    across independent instances, processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_REGION_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[RegionBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of :class:`RegionBatchEntry` objects
        following the same sequence and nested type rules as
        :func:`verify_region_batch`: every entry's two
        :class:`PedersenCommitment` six integer fields, its :class:`Region`
        four bounds, its :class:`RegionProof` ``x_proof`` / ``y_proof``
        ``t`` / ``e`` / ``s`` integer tuples and its ``context`` are
        type-checked; entries are kept in the given order with duplicates
        preserved and no item dropped. ``session_id`` must be non-empty
        ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the ``U``-framed
        batch length must fit in uint64. A session id that is already
        pending, being checked or consumed raises :class:`ValueError`.
        Wrong argument or nested field types (including ``bool`` integers)
        raise :class:`TypeError`; an empty batch or empty id, an
        out-of-uint64 expiry or batch length or a rebind raise
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_region_batch_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _region_batch_replay_encodable(items):
            raise ValueError("batch length must be an unsigned 64-bit integer")
        binding = ReplayBinding(
            session_id,
            _region_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[RegionBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
        randbelow: Callable[[int], int] = secrets.randbelow,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_region_batch` with ``randbelow`` passed through
        unchanged, under that function's sequence, structure and
        randomness contract: it is called once per structurally valid
        range-proof branch as ``randbelow(prime - 1)``, a non-callable
        source or a non-integer result raises :class:`TypeError` and a
        coefficient outside ``[0, prime - 1)`` raises :class:`ValueError`.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, an empty batch or
        :func:`verify_region_batch` returning ``False``) returns ``False``,
        releases the claim and leaves the registration pending. An
        exception escaping the delegated verification (such as the
        :class:`TypeError` / :class:`ValueError` raised by a bad
        ``randbelow``) likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors (including a non-callable ``randbelow``)
        raise :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_region_batch_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if not callable(randbelow):
            raise TypeError("randbelow must be callable")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _region_batch_replay_encodable(items):
            return False  # an oversized batch
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current, randbelow)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _region_batch_replay_digest(items, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_region_batch(items, randbelow=randbelow):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[RegionBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
        randbelow: Callable[[int], int],
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _region_batch_replay_digest(entries, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_region_batch(entries, randbelow=randbelow):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Merkle-committed consistency batches
#
# A BoundConsistencyReplayGuard binds a whole BoundConsistencyBatch together
# with the Merkle root it is claimed under to a caller-chosen session id,
# reusing the ReplayBinding type and, byte for byte, the F / U / S framing
# and the E expiry encoding of BoundRegionReplayGuard; only the domain
# separator and the per-entry leaves differ. Like the other bound guards the
# binding is single-use: without a store the state is local to the guard
# instance, while an SQLiteReplayStore keeps pending, claimed and consumed
# ids in the store under b"zr/bcbr/v1", shared across instances, processes
# and restarts. bind_once registers a pending binding, check recomputes the
# digest, checks the expiry, delegates the batch verification to
# verify_consistency_batch_bound and consumes the id only on full success;
# every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(entry_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/bcbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(entry) = the BoundConsistency leaf bytes (_bound_consistency_leaf),
#              raw under F
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The entries keep their batch order, duplicates included; entries are never
# dropped or reordered.


def _bound_consistency_replay_encodable(batch: BoundConsistencyBatch) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    ``batch.leaf_count``, ``batch.proof.leaf_count`` and every proof index
    are written with ``U`` (eight-byte unsigned big-endian); a negative or
    larger-than-uint64 value cannot be framed. Everything else (the
    consistency leaves, raw sibling bytes, the root) encodes for any value,
    so no additional encodability rule is needed.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _bound_consistency_replay_digest(
    batch: BoundConsistencyBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundConsistency replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(entry))`` per entry in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_CONSISTENCY_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for entry in batch.entries:  # entries order, each BoundConsistency leaf under F
        transcript.update(_frame_length_prefixed(_bound_consistency_leaf(entry)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_consistency_batch_types(batch: object, root: object) -> None:
    """Validate BoundConsistencyBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_consistency_batch_bound`: the
    batch must be a :class:`BoundConsistencyBatch` whose entries tuple holds
    nestedly well-typed :class:`MerkleConsistencyBatchEntry` objects, whose
    ``leaf_count`` is a non-``bool`` integer and whose proof is a well-typed
    :class:`MerkleMultiProof`; ``root`` must be ``bytes``. Structural and
    value problems (coverage, counts, digest lengths) are left to
    :func:`verify_consistency_batch_bound` at check time.
    """
    if not isinstance(batch, BoundConsistencyBatch):
        raise TypeError("batch must be a BoundConsistencyBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of MerkleConsistencyBatchEntry"
        )
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
        if not isinstance(entry, MerkleConsistencyBatchEntry):
            raise TypeError(
                f"entries[{position}] must be a MerkleConsistencyBatchEntry"
            )
        _check_bytes(entry.old_root, f"entries[{position}] old_root")
        _check_bytes(entry.new_root, f"entries[{position}] new_root")
        entry_proof = entry.proof
        if not isinstance(entry_proof, MerkleConsistencyProof):
            raise TypeError(
                f"entries[{position}] proof must be a MerkleConsistencyProof"
            )
        for name in ("old_count", "new_count"):
            value = getattr(entry_proof, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(
                    f"entries[{position}] proof {name} must be an integer"
                )
        if not isinstance(entry_proof.nodes, tuple):
            raise TypeError(
                f"entries[{position}] proof nodes must be a tuple of bytes"
            )
        for node in entry_proof.nodes:
            _check_bytes(node, f"entries[{position}] proof node")


class BoundConsistencyReplayGuard:
    """Single-use replay protection for a Merkle-committed consistency batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundConsistencyBatch` together with the Merkle ``root`` it is
    claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_consistency_batch_bound` — and then marks
    the id consumed. By default both the pending and the consumed state
    live on this guard instance and are never shared between instances;
    passing an :class:`SQLiteReplayStore` as ``store`` instead keeps the
    state in that store under the ``b"zr/bcbr/v1"`` key domain, so
    bound-consistency guards attached to the same store namespace share
    pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_BOUND_CONSISTENCY_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundConsistencyBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        integers (``leaf_count`` and the proof indices) must likewise fit in
        uint64. A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested field
        types raise :class:`TypeError`; an empty id, an out-of-uint64 expiry
        or framed integer, or a rebind raise :class:`ValueError`. Inputs are
        never mutated.
        """
        _check_bound_consistency_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_consistency_replay_encodable(batch):
            raise ValueError("leaf_count and proof indices must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_consistency_replay_digest(batch, root, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundConsistencyBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to
        :func:`verify_consistency_batch_bound` under that function's root,
        structure and batch contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or :func:`verify_consistency_batch_bound` returning
        ``False``) returns ``False``, releases the claim and leaves the
        registration pending. An exception escaping the delegated
        verification likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors raise :class:`TypeError`; an out-of-range
        ``now`` raises :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_consistency_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_consistency_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_consistency_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_batch_bound(batch, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundConsistencyBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_consistency_replay_digest(batch, root, session_id, binding.expires_at),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_batch_bound(batch, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# A BoundConsistencyChainReplayGuard binds a whole
# BoundConsistencyChainBatch together with the Merkle root it is claimed
# under to a caller-chosen session id, reusing the ReplayBinding type and,
# byte for byte, the F / U / S framing and the E expiry encoding of
# BoundConsistencyReplayGuard; only the domain separator and the per-chain
# leaves differ. Like the other bound guards the binding is single-use:
# without a store the state is local to the guard instance, while an
# SQLiteReplayStore keeps pending, claimed and consumed ids in the store
# under b"zr/bccbr/v1", shared across instances, processes and restarts.
# bind_once registers a pending binding, check recomputes the digest,
# checks the expiry, delegates the batch verification to
# verify_consistency_chain_batch_bound and consumes the id only on full
# success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(chain_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/bccbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(chain) = the BoundConsistencyChain leaf bytes
#              (_bound_consistency_chain_leaf), raw under F — the existing
#              b"zkregion/consistency-chains/v1" leaf encoding
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The chains keep their batch order, duplicates included; chains are never
# dropped or reordered, and the outer MerkleMultiProof's three fields are
# all bound verbatim.


def _bound_consistency_chain_replay_encodable(
    batch: BoundConsistencyChainBatch,
) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    ``batch.leaf_count``, ``batch.proof.leaf_count`` and every proof index
    are written with ``U`` (eight-byte unsigned big-endian); a negative or
    larger-than-uint64 value cannot be framed. Everything else (the chain
    leaves with their decimal-ASCII counts, raw sibling bytes, the root)
    encodes for any value, so no additional encodability rule is needed.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _bound_consistency_chain_replay_digest(
    batch: BoundConsistencyChainBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundConsistencyChain replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(chain))`` per chain in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_CONSISTENCY_CHAIN_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for chain in batch.chains:  # chains order, each consistency-chain leaf under F
        transcript.update(_frame_length_prefixed(_bound_consistency_chain_leaf(chain)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_consistency_chain_batch_types(
    batch: object, root: object
) -> None:
    """Validate BoundConsistencyChainBatch argument types for the guard.

    Mirrors the type checks of :func:`verify_consistency_chain_batch_bound`:
    the batch must be a :class:`BoundConsistencyChainBatch` whose chains
    tuple holds nestedly well-typed :class:`MerkleConsistencyChain`
    objects, whose ``leaf_count`` is a non-``bool`` integer and whose proof
    is a well-typed :class:`MerkleMultiProof`; ``root`` must be ``bytes``.
    Structural and value problems (coverage, counts, digest lengths) are
    left to :func:`verify_consistency_chain_batch_bound` at check time.
    """
    if not isinstance(batch, BoundConsistencyChainBatch):
        raise TypeError("batch must be a BoundConsistencyChainBatch")
    _check_bytes(root, "root")
    chains = batch.chains
    if not isinstance(chains, tuple):
        raise TypeError(
            "batch chains must be a tuple of MerkleConsistencyChain"
        )
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
    for position, chain in enumerate(chains):
        if not isinstance(chain, MerkleConsistencyChain):
            raise TypeError(
                f"chains[{position}] must be a MerkleConsistencyChain"
            )
        roots = chain.roots
        if not isinstance(roots, tuple):
            raise TypeError(f"chains[{position}] roots must be a tuple of bytes")
        for root_position, chain_root in enumerate(roots):
            _check_bytes(chain_root, f"chains[{position}] roots[{root_position}]")
        chain_proofs = chain.proofs
        if not isinstance(chain_proofs, tuple):
            raise TypeError(
                f"chains[{position}] proofs must be a tuple"
                " of MerkleConsistencyProof"
            )
        for segment, chain_proof in enumerate(chain_proofs):
            if not isinstance(chain_proof, MerkleConsistencyProof):
                raise TypeError(
                    f"chains[{position}] proofs[{segment}]"
                    " must be a MerkleConsistencyProof"
                )
            for name in ("old_count", "new_count"):
                value = getattr(chain_proof, name)
                if not isinstance(value, int) or isinstance(value, bool):
                    raise TypeError(
                        f"chains[{position}] proofs[{segment}] {name}"
                        " must be an integer"
                    )
            if not isinstance(chain_proof.nodes, tuple):
                raise TypeError(
                    f"chains[{position}] proofs[{segment}]"
                    " nodes must be a tuple of bytes"
                )
            for node in chain_proof.nodes:
                _check_bytes(
                    node, f"chains[{position}] proofs[{segment}] node"
                )


class BoundConsistencyChainReplayGuard:
    """Single-use replay protection for a Merkle-committed chain batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundConsistencyChainBatch` together with the Merkle ``root``
    it is claimed under; :meth:`check` accepts an equal pending binding
    exactly once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_consistency_chain_batch_bound` — and then
    marks the id consumed. By default both the pending and the consumed
    state live on this guard instance and are never shared between
    instances; passing an :class:`SQLiteReplayStore` as ``store`` instead
    keeps the state in that store under the ``b"zr/bccbr/v1"`` key domain,
    so bound-consistency-chain guards attached to the same store namespace
    share pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_BOUND_CONSISTENCY_CHAIN_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundConsistencyChainBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; the U-framed
        integers (``leaf_count`` and the proof indices) must likewise fit in
        uint64. A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested field
        types raise :class:`TypeError`; an empty id, an out-of-uint64 expiry
        or framed integer, or a rebind raise :class:`ValueError`. Inputs are
        never mutated.
        """
        _check_bound_consistency_chain_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_consistency_chain_replay_encodable(batch):
            raise ValueError("leaf_count and proof indices must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_consistency_chain_replay_digest(
                batch, root, session_id, expires_at
            ),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundConsistencyChainBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id at
        most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to
        :func:`verify_consistency_chain_batch_bound` under that function's
        root, structure and batch contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or
        :func:`verify_consistency_chain_batch_bound` returning ``False``)
        returns ``False``, releases the claim and leaves the registration
        pending. An exception escaping the delegated verification likewise
        releases the claim and then propagates unchanged, leaving the id
        usable. With a store backend, only the holder of the current claim
        token can consume the id (an expired claim may be taken over by a
        later equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held, so
        other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_consistency_chain_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_consistency_chain_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_consistency_chain_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_chain_batch_bound(batch, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundConsistencyChainBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_consistency_chain_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_consistency_chain_batch_bound(batch, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# A BoundMerkleMultiBatchReplayGuard binds a whole BoundMerkleMultiBatch
# together with the Merkle root it is claimed under to a caller-chosen
# session id, reusing the ReplayBinding type and, byte for byte, the
# F / U / S framing, the E expiry encoding and the SHA-256 formula of
# BoundConsistencyReplayGuard; only the domain separator and the per-item
# leaves differ. Like the other bound guards the binding is single-use:
# without a store the state is local to the guard instance, while an
# SQLiteReplayStore keeps pending, claimed and consumed ids in the store
# under b"zr/bmmbr/v1", shared across instances, processes and restarts.
# bind_once registers a pending binding, check recomputes the digest,
# checks the expiry, delegates the batch verification to
# verify_multi_inclusion_batch_bound and consumes the id only on full
# success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(item_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/bmmbr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(item) = the BoundMerkleMultiBatch leaf bytes
#             (_bound_merkle_multi_leaf), raw under F — the existing
#             b"zkregion/multi-batch/v1" outer-leaf encoding, i.e.
#             F(b"zkregion/multi-batch/v1") || F(Q(item)) with Q(item) the
#             MerkleMultiReplayGuard framing from F(root) through the
#             siblings sequence
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The items keep their batch order, duplicates included; items are never
# dropped or reordered, and the outer MerkleMultiProof's three fields are
# all bound verbatim.


def _bound_merkle_multi_batch_replay_encodable(
    batch: BoundMerkleMultiBatch,
) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    The outer transcript frames ``batch.leaf_count``,
    ``batch.proof.leaf_count`` and every outer proof index with ``U``; each
    per-item leaf ``L(item)`` additionally U-frames that item's
    ``proof.leaf_count``, its proof/entry indices and its sequence lengths
    (see :func:`_merkle_multi_batch_replay_encodable`). A negative or
    larger-than-uint64 value anywhere cannot be framed. The raw root,
    sibling and leaf bytes encode for any value, so no further
    encodability rule is needed.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    if not all(0 <= value <= _UINT64_MAX for value in values):
        return False
    return _merkle_multi_batch_replay_encodable(batch.entries)


def _bound_merkle_multi_batch_replay_digest(
    batch: BoundMerkleMultiBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundMerkleMultiBatch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(item))`` per item in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``. This is byte for byte
    the :func:`_bound_consistency_replay_digest` formula with the domain
    ``b"zr/bmmbr/v1"`` and :func:`_bound_merkle_multi_leaf` bytes as the
    per-item leaves.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_MERKLE_MULTI_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for item in batch.entries:  # entries order, each bound multi-batch leaf under F
        transcript.update(_frame_length_prefixed(_bound_merkle_multi_leaf(item)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_merkle_multi_batch_types(batch: object, root: object) -> None:
    """Validate BoundMerkleMultiBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_multi_inclusion_batch_bound`:
    the batch must be a :class:`BoundMerkleMultiBatch` whose entries tuple
    holds nestedly well-typed :class:`MerkleMultiBatchEntry` objects, whose
    ``leaf_count`` is a non-``bool`` integer and whose proof is a
    well-typed :class:`MerkleMultiProof`; ``root`` must be ``bytes``.
    Structural and value problems (coverage, counts, digest lengths) are
    left to :func:`verify_multi_inclusion_batch_bound` at check time.
    """
    if not isinstance(batch, BoundMerkleMultiBatch):
        raise TypeError("batch must be a BoundMerkleMultiBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of MerkleMultiBatchEntry"
        )
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
    _check_multi_inclusion_batch_entries_types(entries)


class BoundMerkleMultiBatchReplayGuard:
    """Single-use replay protection for a Merkle-committed multi-inclusion batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundMerkleMultiBatch` together with the Merkle ``root`` it is
    claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_multi_inclusion_batch_bound` — and then
    marks the id consumed. By default both the pending and the consumed
    state live on this guard instance and are never shared between
    instances; passing an :class:`SQLiteReplayStore` as ``store`` instead
    keeps the state in that store under the ``b"zr/bmmbr/v1"`` key domain,
    so bound-multi-batch guards attached to the same store namespace share
    pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_BOUND_MERKLE_MULTI_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundMerkleMultiBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Returns the frozen :class:`ReplayBinding`. ``session_id`` must be
        non-empty ``bytes`` and ``expires_at`` must be either ``None`` or a
        non-``bool`` unsigned 64-bit Unix-second timestamp; every U-framed
        integer (the outer ``leaf_count`` / ``proof.leaf_count`` / proof
        indices and, inside each per-item leaf, the item proof
        ``leaf_count``, indices and sequence lengths) must likewise fit in
        uint64. A session id that is already pending, being checked or
        consumed raises :class:`ValueError`. Wrong argument or nested field
        types raise :class:`TypeError`; an empty id, an out-of-uint64
        expiry or framed integer, or a rebind raise :class:`ValueError`.
        Inputs are never mutated.
        """
        _check_bound_merkle_multi_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_merkle_multi_batch_replay_encodable(batch):
            raise ValueError("leaf_count, indices and framed counts must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_merkle_multi_batch_replay_digest(
                batch, root, session_id, expires_at
            ),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundMerkleMultiBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to
        :func:`verify_multi_inclusion_batch_bound` under that function's
        root, structure and batch contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or
        :func:`verify_multi_inclusion_batch_bound` returning ``False``)
        returns ``False``, releases the claim and leaves the registration
        pending. An exception escaping the delegated verification likewise
        releases the claim and then propagates unchanged, leaving the id
        usable. With a store backend, only the holder of the current claim
        token can consume the id (an expired claim may be taken over by a
        later equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held,
        so other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_merkle_multi_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_merkle_multi_batch_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_merkle_multi_batch_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_multi_inclusion_batch_bound(batch, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundMerkleMultiBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_merkle_multi_batch_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_multi_inclusion_batch_bound(batch, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Merkle-committed complete single-leaf inclusion batches
#
# A BoundMerkleInclusionBatchReplayGuard binds a whole
# BoundMerkleInclusionBatch together with the Merkle root it is claimed under
# to a caller-chosen session id, reusing the ReplayBinding type and, byte for
# byte, the F / U / S framing, the E expiry encoding and the SHA-256 formula
# of BoundConsistencyReplayGuard; only the domain separator and the per-item
# leaves differ. Like the other bound guards the binding is single-use:
# without a store the state is local to the guard instance, while an
# SQLiteReplayStore keeps pending, claimed and consumed ids in the store
# under b"zr/bmibr/v1", shared across instances, processes and restarts.
# bind_once registers a pending binding, check recomputes the digest,
# checks the expiry, delegates the batch verification to
# verify_inclusion_batch_bound and consumes the id only on full success;
# every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(item_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/bmibr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(item) = the complete single-leaf inclusion-batch outer-leaf bytes
#             (_bound_merkle_inclusion_leaf), raw under F — the existing
#             b"zkregion/inclusion-batch/v1" outer-leaf encoding, i.e.
#             F(b"zkregion/inclusion-batch/v1") || F(Q(item)) with Q(item)
#             the MerkleInclusionReplayGuard framing from F(leaf) through
#             the siblings sequence
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The items keep their batch order, duplicates included; items are never
# dropped or reordered, and the outer MerkleMultiProof's three fields are
# all bound verbatim.


def _bound_merkle_inclusion_batch_replay_encodable(
    batch: BoundMerkleInclusionBatch,
) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    The outer transcript frames ``batch.leaf_count``,
    ``batch.proof.leaf_count`` and every outer proof index with ``U``; each
    per-item leaf ``L(item)`` additionally U-frames that item's inner
    ``proof.index`` and its siblings sequence length (see
    :func:`_merkle_inclusion_batch_replay_encodable`, which also frames the
    batch length). A negative or larger-than-uint64 value anywhere cannot
    be framed. The raw root, sibling and leaf bytes encode for any value, so
    no further encodability rule is needed.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    if not all(0 <= value <= _UINT64_MAX for value in values):
        return False
    return _merkle_inclusion_batch_replay_encodable(batch.entries)


def _bound_merkle_inclusion_batch_replay_digest(
    batch: BoundMerkleInclusionBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundMerkleInclusionBatch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(item))`` per item in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``. This is byte for byte
    the :func:`_bound_consistency_replay_digest` formula with the domain
    ``b"zr/bmibr/v1"`` and :func:`_bound_merkle_inclusion_leaf` bytes as
    the per-item leaves.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_MERKLE_INCLUSION_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for item in batch.entries:  # entries order, each bound inclusion-batch leaf under F
        transcript.update(_frame_length_prefixed(_bound_merkle_inclusion_leaf(item)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_merkle_inclusion_batch_types(batch: object, root: object) -> None:
    """Validate BoundMerkleInclusionBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_inclusion_batch_bound`: the
    batch must be a :class:`BoundMerkleInclusionBatch` whose entries tuple
    holds nestedly well-typed :class:`MerkleInclusionBatchEntry` objects,
    whose ``leaf_count`` is a non-``bool`` integer and whose proof is a
    well-typed :class:`MerkleMultiProof`; ``root`` must be ``bytes``.
    Structural and value problems (coverage, counts, digest lengths) are
    left to :func:`verify_inclusion_batch_bound` at check time.
    """
    if not isinstance(batch, BoundMerkleInclusionBatch):
        raise TypeError("batch must be a BoundMerkleInclusionBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of MerkleInclusionBatchEntry"
        )
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
    _check_inclusion_batch_entries_types(entries)


class BoundMerkleInclusionBatchReplayGuard:
    """Single-use replay protection for a Merkle-committed inclusion batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundMerkleInclusionBatch` together with the Merkle ``root`` it
    is claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_inclusion_batch_bound` — and then marks the
    id consumed. By default both the pending and the consumed state live on
    this guard instance and are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in that
    store under the ``b"zr/bmibr/v1"`` key domain, so bound-inclusion-batch
    guards attached to the same store namespace share pending, claimed and
    consumed ids across independent instances, processes and process
    restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_BOUND_MERKLE_INCLUSION_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundMerkleInclusionBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Only registers the pending binding after a full preflight; no
        verification is run. Returns the frozen :class:`ReplayBinding`.
        ``session_id`` must be non-empty ``bytes`` and ``expires_at`` must
        be either ``None`` or a non-``bool`` unsigned 64-bit Unix-second
        timestamp; every U-framed integer (the outer ``leaf_count`` /
        ``proof.leaf_count`` / proof indices and, inside each per-item leaf,
        the inner proof ``index`` and siblings sequence length, plus the
        batch length) must likewise fit in uint64. A session id that is
        already pending, being checked or consumed raises
        :class:`ValueError`. Wrong argument or nested field types raise
        :class:`TypeError`; an empty id, an out-of-uint64 expiry or framed
        integer, or a rebind raise :class:`ValueError`. Inputs are never
        mutated.
        """
        _check_bound_merkle_inclusion_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_merkle_inclusion_batch_replay_encodable(batch):
            raise ValueError("leaf_count, indices and framed counts must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_merkle_inclusion_batch_replay_digest(
                batch, root, session_id, expires_at
            ),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundMerkleInclusionBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to
        :func:`verify_inclusion_batch_bound` under that function's root,
        structure and batch contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or :func:`verify_inclusion_batch_bound` returning
        ``False``) returns ``False``, releases the claim and leaves the
        registration pending. An exception escaping the delegated
        verification likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors raise :class:`TypeError`; an out-of-range
        ``now`` raises :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_merkle_inclusion_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_merkle_inclusion_batch_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_merkle_inclusion_batch_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_inclusion_batch_bound(batch, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundMerkleInclusionBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_merkle_inclusion_batch_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_inclusion_batch_bound(batch, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for hash-commitment opening batches
#
# An OpeningBatchReplayGuard binds a whole non-empty batch of
# OpeningBatchEntry items — the same sequence shape accepted by
# verify_opening_batch (order and duplicates preserved) — to a caller-chosen
# session id, reusing the ReplayBinding type and, byte for byte, the F / U /
# S framing and the E expiry encoding of the other batch guards. Like them
# the binding is single-use: without a store the state is local to the guard
# instance, while an SQLiteReplayStore keeps pending, claimed and consumed
# ids in the store under b"zr/obr/v1", shared across instances, processes
# and restarts. bind_once registers a pending binding, check claims the id
# atomically, recomputes the digest, checks the expiry, delegates the batch
# verification to verify_opening_batch and consumes the id only on full
# success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(entries, Q) || F(E)
# )
#   D = b"zr/obr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   Q(e) = F(e.commitment) || F(e.value) || F(e.nonce) — the entry fields in
#          verify_opening argument order, raw bytes under F
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _opening_batch_leaf(entry: OpeningBatchEntry) -> bytes:
    """Frame one :class:`OpeningBatchEntry` as raw leaf bytes.

    The leaf is the entry's ``commitment``, ``value`` and ``nonce`` — the
    arguments of :func:`verify_opening`, in the same order — each prefixed
    with its four-byte unsigned big-endian length.
    """
    leaf = bytearray()
    for item in (entry.commitment, entry.value, entry.nonce):
        leaf += len(item).to_bytes(4, "big")
        leaf += item
    return bytes(leaf)


def _opening_batch_replay_encodable(
    entries: Sequence[OpeningBatchEntry],
) -> bool:
    """The S-framed batch length must fit in an unsigned 64-bit integer.

    The outer ``S`` sequence writes the batch count with ``U`` (eight-byte
    unsigned big-endian). Every entry field is raw bytes and frames for any
    value, so no per-entry encodability rule is needed.
    """
    return 0 <= len(entries) <= _UINT64_MAX


def _opening_batch_replay_digest(
    entries: Sequence[OpeningBatchEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the hash-opening batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, Q)`` and
    ``F(E)``; ``Q(entry)`` frames the entry's ``commitment`` / ``value`` /
    ``nonce`` in :func:`verify_opening` argument order and the entries keep
    their batch order (duplicates included).
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_OPENING_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, Q) = F(U(|entries|)) || Σ F(Q(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        transcript.update(_frame_length_prefixed(_opening_batch_leaf(entry)))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class OpeningBatchReplayGuard:
    """Single-use replay protection for a hash-commitment opening batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`OpeningBatchEntry` items — the same sequence shape accepted by
    :func:`verify_opening_batch`, kept in the given order with duplicates
    preserved — to a session id; :meth:`check` accepts an equal pending
    binding exactly once, recomputing the binding digest, checking the
    expiry and delegating to :func:`verify_opening_batch`, and then marks
    the id consumed. The digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(entries, Q) || F(E))`` with domain
    ``b"zr/obr/v1"``, where ``Q(entry)`` frames the entry's ``commitment`` /
    ``value`` / ``nonce`` raw bytes in :func:`verify_opening` argument
    order; the F / U / S framing and the E expiry encoding are reused byte
    for byte from the other replay guards. By default both the pending and
    the consumed state live on this guard instance and are never shared
    between instances; passing an :class:`SQLiteReplayStore` as ``store``
    instead keeps the state in that store under the ``b"zr/obr/v1"`` key
    domain, so batch guards attached to the same store namespace share
    pending, claimed and consumed ids across independent instances,
    processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_OPENING_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[OpeningBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of :class:`OpeningBatchEntry`
        objects following the same sequence and nested type rules as
        :func:`verify_opening_batch`: every entry's ``commitment``,
        ``value`` and ``nonce`` must be ``bytes``; entries are kept in the
        given order with duplicates preserved and no item dropped.
        ``session_id`` must be non-empty ``bytes`` and ``expires_at`` must
        be either ``None`` or a non-``bool`` unsigned 64-bit Unix-second
        timestamp; the ``U``-framed batch length must fit in uint64. A
        session id that is already pending, being checked or consumed
        raises :class:`ValueError`. Wrong argument or nested field types
        raise :class:`TypeError`; an empty batch or empty id, an
        out-of-uint64 expiry or batch length, or a rebind raise
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_opening_batch_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _opening_batch_replay_encodable(items):
            raise ValueError("batch length must fit in an unsigned 64-bit integer")
        binding = ReplayBinding(
            session_id,
            _opening_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[OpeningBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_opening_batch` under that function's sequence and
        nested type contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, or
        :func:`verify_opening_batch` returning ``False``) returns
        ``False``, releases the claim and leaves the registration pending.
        An exception escaping the delegated verification likewise releases
        the claim and then propagates unchanged, leaving the id usable.
        With a store backend, only the holder of the current claim token
        can consume the id (an expired claim may be taken over by a later
        equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held,
        so other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_opening_batch_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _opening_batch_replay_encodable(items):
            return False  # an oversized batch cannot be framed
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _opening_batch_replay_digest(items, session_id, binding.expires_at),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_opening_batch(items):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[OpeningBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _opening_batch_replay_digest(
                    entries, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_opening_batch(entries):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Pedersen opening batches
#
# A PedersenOpeningBatchReplayGuard binds a whole non-empty batch of
# PedersenOpeningBatchEntry items — the same sequence shape accepted by
# verify_pedersen_opening_batch (order and duplicates preserved) — to a
# caller-chosen session id, reusing the ReplayBinding type and, byte for
# byte, the F / U / S framing and the E expiry encoding of the other batch
# guards. Like them the binding is single-use: without a store the state is
# local to the guard instance, while an SQLiteReplayStore keeps pending,
# claimed and consumed ids in the store under b"zr/pobr/v1", shared across
# instances, processes and restarts. bind_once registers a pending binding,
# check claims the id atomically, recomputes the digest, checks the expiry,
# delegates the batch verification to verify_pedersen_opening_batch and
# consumes the id only on full success; every rejection leaves the id
# untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || S(entries, Q) || F(E)
# )
#   D = b"zr/pobr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   Q(e) = the run of F(str(i)) over the entry's eight integers — the six
#          commitment fields in dataclass order, then value and blinding,
#          i.e. verify_pedersen_opening argument order — each integer as
#          decimal ASCII with the sign kept (the BoundRange leaf convention)
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise


def _pedersen_opening_batch_leaf(entry: PedersenOpeningBatchEntry) -> bytes:
    """Frame one :class:`PedersenOpeningBatchEntry` as raw leaf bytes.

    The leaf is the commitment's ``element`` / ``lower`` / ``upper`` /
    ``prime`` / ``generator`` / ``h`` fields followed by the entry's
    ``value`` and ``blinding`` — together the arguments of
    :func:`verify_pedersen_opening`, in the same order. Every integer is
    encoded as decimal ASCII with the sign kept (the same convention as the
    BoundRange leaf, so negative values and lowers frame fine) and prefixed
    with its four-byte unsigned big-endian length.
    """
    commitment = entry.commitment
    items = [
        str(getattr(commitment, name)).encode("ascii")
        for name in ("element", "lower", "upper", "prime", "generator", "h")
    ]
    items.append(str(entry.value).encode("ascii"))
    items.append(str(entry.blinding).encode("ascii"))
    leaf = bytearray()
    for item in items:
        leaf += len(item).to_bytes(4, "big")
        leaf += item
    return bytes(leaf)


def _pedersen_opening_batch_replay_encodable(
    entries: Sequence[PedersenOpeningBatchEntry],
) -> bool:
    """The S-framed batch length must fit in an unsigned 64-bit integer.

    The outer ``S`` sequence writes the batch count with ``U`` (eight-byte
    unsigned big-endian). Each entry's integers are encoded as decimal
    ASCII with the sign kept, so every integer field frames for any value
    and no per-entry encodability rule is needed.
    """
    return 0 <= len(entries) <= _UINT64_MAX


def _pedersen_opening_batch_replay_digest(
    entries: Sequence[PedersenOpeningBatchEntry],
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the Pedersen opening batch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``S(entries, Q)`` and
    ``F(E)``; ``Q(entry)`` frames the commitment's six fields and the
    entry's ``value`` / ``blinding`` in :func:`verify_pedersen_opening`
    argument order and the entries keep their batch order (duplicates
    included).
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_PEDERSEN_OPENING_BATCH_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    # S(entries, Q) = F(U(|entries|)) || Σ F(Q(entry))
    transcript.update(_frame_length_prefixed(_uint64_be(len(entries))))
    for entry in entries:
        transcript.update(_frame_length_prefixed(_pedersen_opening_batch_leaf(entry)))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


class PedersenOpeningBatchReplayGuard:
    """Single-use replay protection for a Pedersen opening batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole non-empty batch of
    :class:`PedersenOpeningBatchEntry` items — the same sequence shape
    accepted by :func:`verify_pedersen_opening_batch`, kept in the given
    order with duplicates preserved — to a session id; :meth:`check`
    accepts an equal pending binding exactly once, recomputing the binding
    digest, checking the expiry and delegating to
    :func:`verify_pedersen_opening_batch`, and then marks the id consumed.
    The digest frames the batch under
    ``SHA-256(F(D) || F(session_id) || S(entries, Q) || F(E))`` with domain
    ``b"zr/pobr/v1"``, where ``Q(entry)`` frames the commitment's six
    integer fields and the entry's ``value`` / ``blinding`` as decimal
    ASCII (sign kept) in :func:`verify_pedersen_opening` argument order;
    the F / U / S framing and the E expiry encoding are reused byte for
    byte from the other replay guards. By default both the pending and the
    consumed state live on this guard instance and are never shared between
    instances; passing an :class:`SQLiteReplayStore` as ``store`` instead
    keeps the state in that store under the ``b"zr/pobr/v1"`` key domain,
    so batch guards attached to the same store namespace share pending,
    claimed and consumed ids across independent instances, processes and
    process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_PEDERSEN_OPENING_BATCH_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        entries: Sequence[PedersenOpeningBatchEntry],
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to the batch.

        Returns the frozen :class:`ReplayBinding`. ``entries`` must be a
        non-string, non-empty sequence of :class:`PedersenOpeningBatchEntry`
        objects following the same sequence and nested type rules as
        :func:`verify_pedersen_opening_batch`: every entry's ``commitment``
        must be a :class:`PedersenCommitment` with non-``bool`` integer
        fields and its ``value`` / ``blinding`` non-``bool`` integers;
        entries are kept in the given order with duplicates preserved and
        no item dropped. ``session_id`` must be non-empty ``bytes`` and
        ``expires_at`` must be either ``None`` or a non-``bool`` unsigned
        64-bit Unix-second timestamp; the ``U``-framed batch length must
        fit in uint64. A session id that is already pending, being checked
        or consumed raises :class:`ValueError`. Wrong argument or nested
        field types (including ``bool`` integers) raise :class:`TypeError`;
        an empty batch or empty id, an out-of-uint64 expiry or batch
        length, or a rebind raise :class:`ValueError`. Inputs are never
        mutated.
        """
        items = _check_pedersen_opening_batch_entries_types(entries)
        _check_bytes(session_id, "session_id")
        if not items:
            raise ValueError("entries must not be empty")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _pedersen_opening_batch_replay_encodable(items):
            raise ValueError("batch length must fit in an unsigned 64-bit integer")
        binding = ReplayBinding(
            session_id,
            _pedersen_opening_batch_replay_digest(items, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        entries: Sequence[PedersenOpeningBatchEntry],
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``entries`` in their given order; for a binding with an
        expiry, ``now >= expires_at`` makes the check fail (``now``
        defaults to the current Unix seconds and must otherwise be a
        non-``bool`` uint64). Only then is the batch handed to
        :func:`verify_pedersen_opening_batch` under that function's
        sequence and nested type contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, or
        :func:`verify_pedersen_opening_batch` returning ``False``) returns
        ``False``, releases the claim and leaves the registration pending.
        An exception escaping the delegated verification likewise releases
        the claim and then propagates unchanged, leaving the id usable.
        With a store backend, only the holder of the current claim token
        can consume the id (an expired claim may be taken over by a later
        equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held,
        so other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        items = _check_pedersen_opening_batch_entries_types(entries)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _pedersen_opening_batch_replay_encodable(items):
            return False  # an oversized batch cannot be framed
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(items, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _pedersen_opening_batch_replay_digest(
                    items, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_pedersen_opening_batch(items):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        entries: Sequence[PedersenOpeningBatchEntry],
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _pedersen_opening_batch_replay_digest(
                    entries, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_pedersen_opening_batch(entries):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Merkle-committed complete hash-opening batches
#
# A BoundOpeningReplayGuard binds a whole BoundOpeningBatch together with
# the Merkle root it is claimed under to a caller-chosen session id, reusing
# the ReplayBinding type and, byte for byte, the F / U / S framing, the E
# expiry encoding and the SHA-256 formula of BoundMerkleInclusionBatchReplayGuard;
# only the domain separator and the per-item leaves differ. Like the other
# bound guards the binding is single-use: without a store the state is local
# to the guard instance, while an SQLiteReplayStore keeps pending, claimed
# and consumed ids in the store under b"zr/bobr/v1", shared across
# instances, processes and restarts. bind_once registers a pending binding,
# check claims the id atomically, recomputes the digest, checks the expiry,
# delegates the batch verification to verify_opening_batch_bound and
# consumes the id only on full success; every rejection leaves the id
# untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(entry_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/bobr/v1"
#   F(x) = four-byte unsigned big-endian length prefix of x, followed by x
#   U(n) = eight-byte unsigned big-endian encoding of n
#   S(a, f) = F(U(|a|)) || Σ F(f(a_i))
#   L(entry) = the complete bound hash-opening outer-leaf bytes
#              (_bound_opening_leaf), raw under F — the existing
#              b"zkregion/ob/v1" outer-leaf encoding, i.e.
#              F(b"zkregion/ob/v1") || F(commitment) || F(value) || F(nonce)
#   E is the same expiry encoding as the other guards:
#     b"\x00" when expires_at is None, b"\x01" + uint64be(expires_at) otherwise
#
# The entries keep their batch order, duplicates included; entries are never
# dropped or reordered, and the outer MerkleMultiProof's three fields are
# all bound verbatim.


def _bound_opening_replay_encodable(batch: BoundOpeningBatch) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    The outer transcript frames ``batch.leaf_count``,
    ``batch.proof.leaf_count`` and every outer proof index with ``U``; a
    negative or larger-than-uint64 value cannot be framed. Every per-entry
    field is raw bytes and frames for any value, so no per-entry
    encodability rule is needed.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _bound_opening_replay_digest(
    batch: BoundOpeningBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundOpeningBatch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(entry))`` per entry in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``. This is byte for byte
    the :func:`_bound_merkle_inclusion_batch_replay_digest` formula with
    the domain ``b"zr/bobr/v1"`` and :func:`_bound_opening_leaf` bytes as
    the per-item leaves.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_OPENING_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for entry in batch.entries:  # entries order, each bound opening leaf under F
        transcript.update(_frame_length_prefixed(_bound_opening_leaf(entry)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_opening_batch_types(batch: object, root: object) -> None:
    """Validate BoundOpeningBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_opening_batch_bound`: the
    batch must be a :class:`BoundOpeningBatch` whose entries tuple holds
    nestedly well-typed :class:`OpeningBatchEntry` objects, whose
    ``leaf_count`` is a non-``bool`` integer and whose proof is a
    well-typed :class:`MerkleMultiProof`; ``root`` must be ``bytes``.
    Structural and value problems (coverage, counts, digest lengths) are
    left to :func:`verify_opening_batch_bound` at check time.
    """
    if not isinstance(batch, BoundOpeningBatch):
        raise TypeError("batch must be a BoundOpeningBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError("batch entries must be a tuple of OpeningBatchEntry")
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
    _check_opening_batch_entries_types(entries)


class BoundOpeningReplayGuard:
    """Single-use replay protection for a Merkle-committed hash-opening batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundOpeningBatch` together with the Merkle ``root`` it is
    claimed under; :meth:`check` accepts an equal pending binding exactly
    once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_opening_batch_bound` — and then marks the
    id consumed. By default both the pending and the consumed state live on
    this guard instance and are never shared between instances; passing an
    :class:`SQLiteReplayStore` as ``store`` instead keeps the state in that
    store under the ``b"zr/bobr/v1"`` key domain, so bound-opening-batch
    guards attached to the same store namespace share pending, claimed and
    consumed ids across independent instances, processes and process
    restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_BOUND_OPENING_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundOpeningBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Only registers the pending binding after a full preflight; no
        verification is run. Returns the frozen :class:`ReplayBinding`.
        ``session_id`` must be non-empty ``bytes`` and ``expires_at`` must
        be either ``None`` or a non-``bool`` unsigned 64-bit Unix-second
        timestamp; every U-framed integer (the outer ``leaf_count`` /
        ``proof.leaf_count`` and proof indices, plus the batch length) must
        likewise fit in uint64. A session id that is already pending, being
        checked or consumed raises :class:`ValueError`. Wrong argument or
        nested field types raise :class:`TypeError`; an empty id, an
        out-of-uint64 expiry or framed integer, or a rebind raise
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_opening_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_opening_replay_encodable(batch):
            raise ValueError("leaf_count, indices and framed counts must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_opening_replay_digest(batch, root, session_id, expires_at),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundOpeningBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to
        :func:`verify_opening_batch_bound` under that function's root,
        structure and batch contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or :func:`verify_opening_batch_bound` returning
        ``False``) returns ``False``, releases the claim and leaves the
        registration pending. An exception escaping the delegated
        verification likewise releases the claim and then propagates
        unchanged, leaving the id usable. With a store backend, only the
        holder of the current claim token can consume the id (an expired
        claim may be taken over by a later equal ``check``); a stale token
        neither consumes nor restores anything. Verification runs without
        any lock or transaction held, so other ids are never serialized.
        Argument type errors raise :class:`TypeError`; an out-of-range
        ``now`` raises :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_opening_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_opening_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_opening_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_opening_batch_bound(batch, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundOpeningBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_opening_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_opening_batch_bound(batch, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)


# ---------------------------------------------------------------------------
# Replay protection for Merkle-committed complete Pedersen-opening batches
#
# A BoundPedersenOpeningReplayGuard binds a whole
# BoundPedersenOpeningBatch together with the Merkle root it is claimed
# under to a caller-chosen session id, reusing the ReplayBinding type and,
# byte for byte, the F / U / S framing, the E expiry encoding and the
# SHA-256 formula of BoundOpeningReplayGuard; only the domain separator and
# the per-item leaves differ. Like the other bound guards the binding is
# single-use: without a store the state is local to the guard instance,
# while an SQLiteReplayStore keeps pending, claimed and consumed ids in the
# store under b"zr/pbobr/v1", shared across instances, processes and
# restarts. bind_once registers a pending binding, check claims the id
# atomically, recomputes the digest, checks the expiry, delegates the batch
# verification to verify_pedersen_opening_batch_bound and consumes the id
# only on full success; every rejection leaves the id untouched.
#
# digest = SHA-256(
#     F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
#     || Σ_i F(L(entry_i))
#     || F(U(proof.leaf_count)) || S(proof.indices, U)
#     || S(proof.siblings, λx.x) || F(E)
# )
#   D = b"zr/pbobr/v1"
#   L(entry) = the complete bound Pedersen-opening outer-leaf bytes
#              (_bound_pedersen_opening_leaf), raw under F — the existing
#              b"zkregion/pob/v1" outer-leaf encoding, i.e.
#              F(b"zkregion/pob/v1") || Q(entry) with Q(entry) the
#              PedersenOpeningBatchReplayGuard framing of the commitment's
#              six integer fields followed by value and blinding
#
# The entries keep their batch order, duplicates included, and the outer
# MerkleMultiProof's three fields are all bound verbatim.


def _bound_pedersen_opening_replay_encodable(
    batch: BoundPedersenOpeningBatch,
) -> bool:
    """Every U-framed integer must fit in unsigned 64 bits.

    The outer transcript frames ``batch.leaf_count``,
    ``batch.proof.leaf_count`` and every outer proof index with ``U``; a
    negative or larger-than-uint64 value cannot be framed. Each entry's
    integers are encoded as decimal ASCII with the sign kept, so every
    integer field frames for any value and no per-entry encodability rule
    is needed.
    """
    proof = batch.proof
    values = [batch.leaf_count, proof.leaf_count, *proof.indices]
    return all(0 <= value <= _UINT64_MAX for value in values)


def _bound_pedersen_opening_replay_digest(
    batch: BoundPedersenOpeningBatch,
    root: bytes,
    session_id: bytes,
    expires_at: int | None,
) -> bytes:
    """Compute the BoundPedersenOpeningBatch replay binding digest.

    Writes, in order: ``F(D)``, ``F(session_id)``, ``F(root)``,
    ``F(U(batch.leaf_count))``, one ``F(L(entry))`` per entry in batch
    order, then ``F(U(proof.leaf_count))``, ``S(proof.indices, U)``,
    ``S(proof.siblings, identity)`` and ``F(E)``. This is byte for byte
    the :func:`_bound_opening_replay_digest` formula with the domain
    ``b"zr/pbobr/v1"`` and :func:`_bound_pedersen_opening_leaf` bytes as
    the per-item leaves.
    """
    transcript = hashlib.sha256()
    transcript.update(_frame_length_prefixed(_BOUND_PEDERSEN_OPENING_REPLAY_DOMAIN))
    transcript.update(_frame_length_prefixed(session_id))
    transcript.update(_frame_length_prefixed(root))
    transcript.update(_frame_length_prefixed(_uint64_be(batch.leaf_count)))
    for entry in batch.entries:  # entries order, each bound Pedersen opening leaf under F
        transcript.update(_frame_length_prefixed(_bound_pedersen_opening_leaf(entry)))
    proof = batch.proof
    transcript.update(_frame_length_prefixed(_uint64_be(proof.leaf_count)))
    # S(proof.indices, U) = F(U(|indices|)) || Σ F(U(index))
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.indices))))
    for index in proof.indices:
        transcript.update(_frame_length_prefixed(_uint64_be(index)))
    # S(proof.siblings, λx.x) = F(U(|siblings|)) || Σ F(sibling)
    transcript.update(_frame_length_prefixed(_uint64_be(len(proof.siblings))))
    for sibling in proof.siblings:
        transcript.update(_frame_length_prefixed(sibling))
    expiry = _replay_expiry_bytes(expires_at)
    transcript.update(_frame_length_prefixed(expiry))
    return transcript.digest()


def _check_bound_pedersen_opening_batch_types(batch: object, root: object) -> None:
    """Validate BoundPedersenOpeningBatch argument types for the replay guard.

    Mirrors the type checks of :func:`verify_pedersen_opening_batch_bound`:
    the batch must be a :class:`BoundPedersenOpeningBatch` whose entries
    tuple holds nestedly well-typed :class:`PedersenOpeningBatchEntry`
    objects, whose ``leaf_count`` is a non-``bool`` integer and whose
    proof is a well-typed :class:`MerkleMultiProof`; ``root`` must be
    ``bytes``. Structural and value problems (coverage, counts, digest
    lengths) are left to :func:`verify_pedersen_opening_batch_bound` at
    check time.
    """
    if not isinstance(batch, BoundPedersenOpeningBatch):
        raise TypeError("batch must be a BoundPedersenOpeningBatch")
    _check_bytes(root, "root")
    entries = batch.entries
    if not isinstance(entries, tuple):
        raise TypeError(
            "batch entries must be a tuple of PedersenOpeningBatchEntry"
        )
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
    _check_pedersen_opening_batch_entries_types(entries)


class BoundPedersenOpeningReplayGuard:
    """Single-use replay protection for a Merkle-committed Pedersen-opening batch.

    A fresh guard has no registrations. :meth:`bind_once` registers a
    pending :class:`ReplayBinding` that commits a whole
    :class:`BoundPedersenOpeningBatch` together with the Merkle ``root``
    it is claimed under; :meth:`check` accepts an equal pending binding
    exactly once — recomputing the binding digest, checking the expiry and
    delegating to :func:`verify_pedersen_opening_batch_bound` — and then
    marks the id consumed. By default both the pending and the consumed
    state live on this guard instance and are never shared between
    instances; passing an :class:`SQLiteReplayStore` as ``store`` instead
    keeps the state in that store under the ``b"zr/pbobr/v1"`` key domain,
    so bound-Pedersen-opening-batch guards attached to the same store
    namespace share pending, claimed and consumed ids across independent
    instances, processes and process restarts.

    Concurrent checks of the same id are decided by an atomic claim taken
    before the digest/expiry work and the delegated batch verification (the
    in-instance registry lock, or the store's short transaction and unique
    claim token); the claim is per-id registry state rather than a global
    lock, so a batch being verified under one id never serializes checks or
    binds of other ids.
    """

    def __init__(self, *, store: SQLiteReplayStore | None = None) -> None:
        if store is not None and not isinstance(store, SQLiteReplayStore):
            raise TypeError("store must be an SQLiteReplayStore")
        self._store = (
            None
            if store is None
            else store._view(_BOUND_PEDERSEN_OPENING_REPLAY_DOMAIN)
        )
        self._registry = None if store is not None else _ReplayRegistry()

    @property
    def _pending(self) -> dict[bytes, ReplayBinding]:
        if self._store is not None:
            return self._store.pending_snapshot()
        return self._registry.pending_snapshot()

    @property
    def _consumed(self) -> set[bytes]:
        if self._store is not None:
            return self._store.consumed_snapshot()
        return self._registry.consumed_snapshot()

    def bind_once(
        self,
        batch: BoundPedersenOpeningBatch,
        root: bytes,
        session_id: bytes,
        *,
        expires_at: int | None = None,
    ) -> ReplayBinding:
        """Register this instance's binding of ``session_id`` to a batch/root.

        Only registers the pending binding after a full preflight; no
        verification is run. Returns the frozen :class:`ReplayBinding`.
        ``session_id`` must be non-empty ``bytes`` and ``expires_at`` must
        be either ``None`` or a non-``bool`` unsigned 64-bit Unix-second
        timestamp; every U-framed integer (the outer ``leaf_count`` /
        ``proof.leaf_count`` and proof indices, plus the batch length) must
        likewise fit in uint64. A session id that is already pending, being
        checked or consumed raises :class:`ValueError`. Wrong argument or
        nested field types (including ``bool`` integers) raise
        :class:`TypeError`; an empty id, an out-of-uint64 expiry or framed
        integer, or a rebind raise :class:`ValueError`. Inputs are never
        mutated.
        """
        _check_bound_pedersen_opening_batch_types(batch, root)
        _check_bytes(session_id, "session_id")
        if not session_id:
            raise ValueError("session_id must not be empty")
        if expires_at is not None:
            _check_uint64(expires_at, "expires_at")
        if not _bound_pedersen_opening_replay_encodable(batch):
            raise ValueError("leaf_count, indices and framed counts must be unsigned 64-bit integers")
        binding = ReplayBinding(
            session_id,
            _bound_pedersen_opening_replay_digest(
                batch, root, session_id, expires_at
            ),
            expires_at,
        )
        if self._store is not None:
            self._store.register(session_id, binding)
        else:
            self._registry.register(session_id, binding)
        return binding

    def check(
        self,
        batch: BoundPedersenOpeningBatch,
        root: bytes,
        binding: ReplayBinding,
        *,
        now: int | None = None,
    ) -> bool:
        """Verify and consume the pending binding for the batch/root.

        ``binding`` must be the equal, still-pending :class:`ReplayBinding`
        previously registered on this guard for ``binding.session_id``. The
        id is claimed atomically before the digest/expiry work and the
        delegated verification, so among concurrent calls for the same id
        at most one can return ``True``. The digest is recomputed over the
        presented ``batch`` / ``root``; for a binding with an expiry,
        ``now >= expires_at`` makes the check fail (``now`` defaults to the
        current Unix seconds and must otherwise be a non-``bool`` uint64).
        Only then is the batch/root handed to
        :func:`verify_pedersen_opening_batch_bound` under that function's
        root, structure and batch contract.

        Only a fully successful check consumes the session id; every
        rejection (unknown or consumed id, a claim lost to a concurrent
        check, unequal binding, digest mismatch, expiry, a non-32-byte root
        or sibling, or
        :func:`verify_pedersen_opening_batch_bound` returning ``False``)
        returns ``False``, releases the claim and leaves the registration
        pending. An exception escaping the delegated verification likewise
        releases the claim and then propagates unchanged, leaving the id
        usable. With a store backend, only the holder of the current claim
        token can consume the id (an expired claim may be taken over by a
        later equal ``check``); a stale token neither consumes nor restores
        anything. Verification runs without any lock or transaction held,
        so other ids are never serialized. Argument type errors raise
        :class:`TypeError`; an out-of-range ``now`` raises
        :class:`ValueError`. Inputs are never mutated.
        """
        _check_bound_pedersen_opening_batch_types(batch, root)
        if not isinstance(binding, ReplayBinding):
            raise TypeError("binding must be a ReplayBinding")
        if now is None:
            current = int(time.time())
        else:
            _check_uint64(now, "now")
            current = now
        if not _bound_pedersen_opening_replay_encodable(batch):
            return False  # negative or oversized U-framed integers
        session_id = binding.session_id
        if self._store is not None:
            return self._check_with_store(batch, root, binding, session_id, current)
        if not self._registry.claim(session_id, binding):
            return False  # unknown id, already consumed, claimed, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_pedersen_opening_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_pedersen_opening_batch_bound(batch, root):
                return False
            self._registry.commit(session_id)
            committed = True
            return True
        finally:
            if not committed:
                self._registry.release(session_id)

    def _check_with_store(
        self,
        batch: BoundPedersenOpeningBatch,
        root: bytes,
        binding: ReplayBinding,
        session_id: bytes,
        current: int,
    ) -> bool:
        """The store-backed claim/verify/consume flow for :meth:`check`.

        The claim is taken in one short transaction (or an expired claim is
        taken over and issued a fresh random token); verification runs with
        no transaction held; only the token returned by the winning claim
        can consume the id, and every rejection or escaped error restores
        the id to pending with that same token. A stale token (a claim
        taken over while verification ran) neither consumes nor restores
        anything.
        """
        token = self._store.claim(session_id, binding)
        if token is None:
            return False  # unknown id, already consumed, live claim, or unequal binding
        committed = False
        try:
            if not hmac.compare_digest(
                binding.digest,
                _bound_pedersen_opening_replay_digest(
                    batch, root, session_id, binding.expires_at
                ),
            ):
                return False  # the presented batch/root is not the one originally bound
            if binding.expires_at is not None and current >= binding.expires_at:
                return False  # expired: rejection does not consume the id
            if not verify_pedersen_opening_batch_bound(batch, root):
                return False
            if not self._store.commit(session_id, token):
                return False  # the lease expired and another check took over
            committed = True
            return True
        finally:
            # A False result, an expiry or an escaped error hands the id back
            # to pending, but only while the current token still owns it;
            # after commit() (or a takeover) the token is stale and this is a
            # no-op, leaving the id consumed or re-claimed by the new owner.
            if not committed:
                self._store.release(session_id, token)
