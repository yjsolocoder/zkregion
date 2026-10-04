"""Structure rules for the proof objects nested inside proof bundles.

The region and convex-polygon bundles share the same on-the-wire bodies
for :class:`~zkregion.PedersenCommitment`, :class:`~zkregion.Region`,
:class:`~zkregion.RangeProof` and :class:`~zkregion.WideRangeProof`, so
their encode-side type checks and decode-side shape/value checks live
here once, on top of the generic primitives in
:mod:`zkregion._bundle_wire`. This module is still format-level: it
rebuilds nested proof objects and enforces their wire shapes, but it
never runs a verification equation.
"""

from __future__ import annotations

from . import (
    _MAX_RANGE_VALUES,
    _MAX_WIDE_RANGE_BITS,
    PedersenCommitment,
    RangeProof,
    Region,
    WideRangeProof,
)
from ._bundle_wire import BundleWireReader, frame, int_body, tuple_body


# ---------------------------------------------------------------------------
# Encoding: structured bodies, in the fixed dataclass field order
# ---------------------------------------------------------------------------


def commitment_body(commitment: PedersenCommitment) -> bytes:
    """A PedersenCommitment body: its six integer fields, in field order."""
    return tuple_body(
        [
            int_body(getattr(commitment, name))
            for name in ("element", "lower", "upper", "prime", "generator", "h")
        ]
    )


def region_body(region: Region) -> bytes:
    """A Region body: its four bounds in field order (min_x, max_x, min_y, max_y)."""
    return tuple_body(
        [
            int_body(getattr(region, name))
            for name in ("min_x", "max_x", "min_y", "max_y")
        ]
    )


def range_proof_body(proof: RangeProof) -> bytes:
    """A RangeProof body: three integer tuples ``(t, e, s)``, in field order."""
    return tuple_body(
        [
            tuple_body([int_body(item) for item in proof.t]),
            tuple_body([int_body(item) for item in proof.e]),
            tuple_body([int_body(item) for item in proof.s]),
        ]
    )


def wide_range_proof_body(proof: WideRangeProof) -> bytes:
    """A WideRangeProof body: commitments plus challenge/response integer pairs."""
    return tuple_body(
        [
            tuple_body([int_body(item) for item in proof.commitments]),
            tuple_body(
                [
                    tuple_body([int_body(pair[0]), int_body(pair[1])])
                    for pair in proof.challenges
                ]
            ),
            tuple_body(
                [
                    tuple_body([int_body(pair[0]), int_body(pair[1])])
                    for pair in proof.responses
                ]
            ),
        ]
    )


# ---------------------------------------------------------------------------
# Encoding: nested type checks (value validity is decided elsewhere)
# ---------------------------------------------------------------------------


def check_int(value: object, name: str) -> None:
    """Bundle integers are non-bool ints, like the rest of the public API."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")


def check_commitment(commitment: object, name: str) -> None:
    if not isinstance(commitment, PedersenCommitment):
        raise TypeError(f"{name} must be a PedersenCommitment")
    for field_name in ("element", "lower", "upper", "prime", "generator", "h"):
        check_int(getattr(commitment, field_name), f"{name} {field_name}")


def check_region(region: object, *, enforce_order: bool) -> None:
    if not isinstance(region, Region):
        raise TypeError("region must be a Region")
    for field_name in ("min_x", "max_x", "min_y", "max_y"):
        check_int(getattr(region, field_name), f"region {field_name}")
    if enforce_order and (
        region.min_x > region.max_x or region.min_y > region.max_y
    ):
        raise ValueError("region bounds must satisfy min <= max on each axis")


def check_range_proof(proof: object, name: str) -> None:
    if not isinstance(proof, RangeProof):
        raise TypeError(f"{name} must be a RangeProof")
    for field_name in ("t", "e", "s"):
        field = getattr(proof, field_name)
        if not isinstance(field, tuple):
            raise TypeError(f"{name} {field_name} must be a tuple of integers")
        for position, item in enumerate(field):
            check_int(item, f"{name} {field_name}[{position}]")


def check_wide_range_proof(proof: object, name: str) -> None:
    if not isinstance(proof, WideRangeProof):
        raise TypeError(f"{name} must be a WideRangeProof")
    if not isinstance(proof.commitments, tuple):
        raise TypeError(f"{name} commitments must be a tuple of integers")
    for position, item in enumerate(proof.commitments):
        check_int(item, f"{name} commitments[{position}]")
    for field_name in ("challenges", "responses"):
        field = getattr(proof, field_name)
        if not isinstance(field, tuple):
            raise TypeError(f"{name} {field_name} must be a tuple of integer pairs")
        for index, pair in enumerate(field):
            if not isinstance(pair, tuple):
                raise TypeError(
                    f"{name} {field_name} must be a tuple of integer pairs"
                )
            if len(pair) != 2:
                raise TypeError(
                    f"{name} {field_name}[{index}] must be an integer pair"
                )
            check_int(pair[0], f"{name} {field_name}[{index}][0]")
            check_int(pair[1], f"{name} {field_name}[{index}][1]")


# ---------------------------------------------------------------------------
# Decoding: strict reader for the shared nested proof bodies
# ---------------------------------------------------------------------------


class ProofBodyReader(BundleWireReader):
    """Envelope reader that can rebuild shared commitments and sub-proofs."""

    def commitment(self, what: str) -> PedersenCommitment:
        body = self.frame(what)
        inner = ProofBodyReader(body)
        count = inner.tuple_cardinality(what)
        if count != 6:
            raise ValueError(f"{what} commitment must have exactly six fields")
        values = [
            inner.int_value(f"{what} {name}")
            for name in ("element", "lower", "upper", "prime", "generator", "h")
        ]
        if not inner.at_end():
            raise ValueError(f"{what} commitment has trailing data")
        element, lower, upper, prime, generator, h = values
        if prime <= 3:
            raise ValueError(f"{what} prime must be greater than 3")
        if not 1 < generator < prime:
            raise ValueError(f"{what} generator must satisfy 1 < generator < prime")
        if not 1 < h < prime:
            raise ValueError(f"{what} h must satisfy 1 < h < prime")
        if not 0 < element < prime:
            raise ValueError(f"{what} element must satisfy 0 < element < prime")
        if lower > upper:
            raise ValueError(f"{what} lower must not exceed upper")
        if upper - lower >= prime - 1:
            raise ValueError(f"{what} range width must be smaller than prime - 1")
        return PedersenCommitment(*values)

    def region(self) -> Region:
        body = self.frame("region")
        inner = ProofBodyReader(body)
        count = inner.tuple_cardinality("region")
        if count != 4:
            raise ValueError("region must have exactly four bounds")
        min_x, max_x, min_y, max_y = (
            inner.int_value(f"region {name}")
            for name in ("min_x", "max_x", "min_y", "max_y")
        )
        if not inner.at_end():
            raise ValueError("region has trailing data")
        return Region(min_x=min_x, max_x=max_x, min_y=min_y, max_y=max_y)

    def range_proof(self, what: str) -> RangeProof:
        body = self.frame(what)
        inner = ProofBodyReader(body)
        count = inner.tuple_cardinality(what)
        if count != 3:
            raise ValueError(f"{what} range proof must have exactly three fields")
        t = inner.integer_tuple(f"{what} t")
        e = inner.integer_tuple(f"{what} e")
        s = inner.integer_tuple(f"{what} s")
        if not inner.at_end():
            raise ValueError(f"{what} range proof has trailing data")
        size = len(t)
        if not (1 <= size <= _MAX_RANGE_VALUES) or not (
            len(e) == size and len(s) == size
        ):
            raise ValueError(
                f"{what} range proof fields must be equal-length tuples of "
                f"1..{_MAX_RANGE_VALUES} integers"
            )
        return RangeProof(t=t, e=e, s=s)

    def wide_range_proof(self, what: str) -> WideRangeProof:
        body = self.frame(what)
        inner = ProofBodyReader(body)
        count = inner.tuple_cardinality(what)
        if count != 3:
            raise ValueError(f"{what} wide range proof must have three fields")
        commitments = inner.integer_tuple(f"{what} commitments")
        pairs: dict[str, list[tuple[int, int]]] = {}
        for field_name in ("challenges", "responses"):
            pair_body = inner.frame(f"{what} {field_name}")
            pair_reader = ProofBodyReader(pair_body)
            pair_count = pair_reader.tuple_cardinality(f"{what} {field_name}")
            decoded_pairs: list[tuple[int, int]] = []
            for index in range(pair_count):
                item_body = pair_reader.frame(f"{what} {field_name}[{index}]")
                item_reader = ProofBodyReader(item_body)
                item_count = item_reader.tuple_cardinality(
                    f"{what} {field_name}[{index}]"
                )
                if item_count != 2:
                    raise ValueError(
                        f"{what} {field_name}[{index}] must be an integer pair"
                    )
                first = item_reader.int_value(f"{what} {field_name}[{index}][0]")
                second = item_reader.int_value(f"{what} {field_name}[{index}][1]")
                if not item_reader.at_end():
                    raise ValueError(
                        f"{what} {field_name}[{index}] has trailing data"
                    )
                decoded_pairs.append((first, second))
            if not pair_reader.at_end():
                raise ValueError(f"{what} {field_name} has trailing data")
            pairs[field_name] = decoded_pairs
        if not inner.at_end():
            raise ValueError(f"{what} wide range proof has trailing data")
        width = len(commitments)
        if not (
            1 <= width <= _MAX_WIDE_RANGE_BITS
            and len(pairs["challenges"]) == width
            and len(pairs["responses"]) == width
        ):
            raise ValueError(
                f"{what} wide range proof must hold 1..{_MAX_WIDE_RANGE_BITS} "
                "matching bit entries"
            )
        return WideRangeProof(
            commitments=commitments,
            challenges=tuple(pairs["challenges"]),
            responses=tuple(pairs["responses"]),
        )
