"""Generic wire primitives shared by every versioned proof bundle.

This module owns only the *format* layer common to the bundle envelopes:
four-byte big-endian length frames, sign-prefixed shortest big-endian
integers, tuples with an explicit four-byte cardinality, and a strict
cursor (:class:`BundleWireReader`) over encoded payloads. It knows
nothing about commitments, regions, polygons, Merkle proofs or any other
specific proof structure — those rules live in the per-bundle modules
that compose these primitives.

Wire conventions (the framing-header integers themselves are unsigned
big-endian)::

    frame(x)  = uint32be(len(body)) || body
    int body  = sign (1 = non-negative, 255 = negative) ||
                shortest big-endian magnitude   (zero encodes as 01 00)
    tuple     = uint32be(cardinality) || frame(item_0) || ...

Anything truncated, out of bounds, non-canonical or carrying trailing
bytes raises :class:`ValueError`; callers reject non-``bytes`` input
themselves with :class:`TypeError` before constructing a reader.
"""

from __future__ import annotations

from collections.abc import Sequence

INT_SIGN_POSITIVE = 1
INT_SIGN_NEGATIVE = 255


def frame(body: bytes) -> bytes:
    """One length-prefixed envelope item: four-byte length plus body."""
    return len(body).to_bytes(4, "big") + body


def int_body(value: int) -> bytes:
    """Canonical signed arbitrary-precision integer body (no length frame)."""
    sign = INT_SIGN_POSITIVE if value >= 0 else INT_SIGN_NEGATIVE
    magnitude = abs(value)
    return bytes((sign,)) + magnitude.to_bytes(
        max(1, (magnitude.bit_length() + 7) // 8), "big"
    )


def tuple_body(items: Sequence[bytes]) -> bytes:
    """A tuple body: four-byte cardinality followed by the framed items."""
    body = len(items).to_bytes(4, "big")
    for item in items:
        body += frame(item)
    return body


class BundleWireReader:
    """Cursor over an envelope payload with strict bounds checking.

    Every read validates its length prefix before returning; any
    truncation or overflow raises :class:`ValueError`. Callers compose
    the generic :meth:`frame` / :meth:`int_value` /
    :meth:`tuple_cardinality` reads with their own structural checks and
    are responsible for ensuring the payload is consumed exactly.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self._offset + size > len(self._data):
            raise ValueError("truncated region proof bundle payload")
        chunk = self._data[self._offset : self._offset + size]
        self._offset += size
        return chunk

    def byte(self, what: str) -> int:
        return self.take(1)[0]

    def expect(self, expected: bytes, what: str) -> None:
        actual = self.take(len(expected))
        if actual != expected:
            raise ValueError(f"invalid {what}")

    def uint32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def frame(self, what: str) -> bytes:
        length = self.uint32()
        return self.take(length)

    def at_end(self) -> bool:
        return self._offset == len(self._data)

    def int_value(self, what: str) -> int:
        body = self.frame(what)
        if len(body) < 2:
            raise ValueError(f"{what} integer is too short")
        sign = body[0]
        if sign not in (INT_SIGN_POSITIVE, INT_SIGN_NEGATIVE):
            raise ValueError(f"{what} integer has an unknown sign byte")
        magnitude = int.from_bytes(body[1:], "big")
        # Canonical shortest form: no leading zero magnitude bytes and no
        # negative zero.
        if body[1] == 0 and len(body) > 2:
            raise ValueError(f"{what} integer is not in canonical form")
        if sign == INT_SIGN_NEGATIVE and magnitude == 0:
            raise ValueError(f"{what} integer uses a non-canonical negative zero")
        return -magnitude if sign == INT_SIGN_NEGATIVE else magnitude

    def tuple_cardinality(self, what: str) -> int:
        return int.from_bytes(self.take(4), "big")

    def integer_tuple(self, what: str) -> tuple[int, ...]:
        """Read a framed body that is exactly one tuple of integers."""
        body = self.frame(what)
        inner = BundleWireReader(body)
        count = inner.tuple_cardinality(what)
        items = [inner.int_value(f"{what}[{i}]") for i in range(count)]
        if not inner.at_end():
            raise ValueError(f"{what} tuple has trailing data")
        return tuple(items)
