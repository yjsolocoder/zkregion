"""Versioned binary envelope for convex polygon membership proofs.

A :class:`ConvexPolygonProofBundle` freezes the five public inputs of
:func:`~zkregion.verify_convex_polygon` (both commitments, the polygon,
the external context and the
:class:`~zkregion.ConvexPolygonRegionProof`). The generic wire rules
live in :mod:`zkregion._bundle_wire` and the shared commitment /
sub-proof structure rules in :mod:`zkregion._bundle_proofs`; this
module owns only the polygon-specific rules: there is no proof-type
tag, the polygon body is a tuple of canonical ``(x, y)`` vertex pairs
(rotations and reversals of one boundary share one encoding, via the
same canonicalization the
:class:`~zkregion.ConvexPolygonRegion` constructor uses), and the proof
body is a three-item tuple — the :class:`~zkregion.RangeProof` for the
x axis, the one for the y axis, then one
:class:`~zkregion.WideRangeProof` per polygon edge in canonical
boundary order.

Layout::

    magic (4) || version (1)
    frame(x_commitment) || frame(y_commitment) || frame(polygon)
    frame(context) || frame(proof)
"""

from __future__ import annotations

from dataclasses import dataclass

from . import (
    ConvexPolygonRegion,
    ConvexPolygonRegionProof,
    PedersenCommitment,
    _check_convex_polygon_input_types,
    _normalize_polygon_vertices,
    verify_convex_polygon,
)
from ._bundle_proofs import (
    ProofBodyReader,
    check_commitment,
    check_range_proof,
    check_wide_range_proof,
    commitment_body,
    range_proof_body,
    wide_range_proof_body,
)
from ._bundle_wire import frame, int_body, tuple_body

MAGIC = b"zrgp"
VERSION = 1


@dataclass(frozen=True)
class ConvexPolygonProofBundle:
    """A versioned, canonical binary envelope for one convex polygon proof.

    Fields, in the fixed wire order: ``x_commitment`` / ``y_commitment``
    (:class:`PedersenCommitment`), ``polygon``
    (:class:`ConvexPolygonRegion`), ``context`` (``bytes``) and ``proof``
    (a :class:`ConvexPolygonRegionProof`). Bundles are positional
    construction arguments, compare by value and are immutable;
    construction performs no validation — use
    :func:`encode_convex_polygon_proof_bundle` /
    :func:`decode_convex_polygon_proof_bundle` /
    :func:`verify_convex_polygon_proof_bundle` to check.
    """

    x_commitment: PedersenCommitment
    y_commitment: PedersenCommitment
    polygon: ConvexPolygonRegion
    context: bytes
    proof: ConvexPolygonRegionProof


def _polygon_body(polygon: ConvexPolygonRegion) -> bytes:
    """A polygon body: a tuple of canonical ``(x, y)`` vertex pairs."""
    vertices = _normalize_polygon_vertices(polygon.vertices)
    return tuple_body(
        [
            tuple_body([int_body(vertex[0]), int_body(vertex[1])])
            for vertex in vertices
        ]
    )


def _polygon_proof_body(proof: ConvexPolygonRegionProof) -> bytes:
    """The convex polygon proof body: x/y range proofs then edge wide proofs."""
    return tuple_body(
        [
            range_proof_body(proof.x_proof),
            range_proof_body(proof.y_proof),
            tuple_body(
                [wide_range_proof_body(edge_proof) for edge_proof in proof.edge_proofs]
            ),
        ]
    )


def _check_polygon(polygon: object) -> None:
    """Type-check a polygon and re-run canonicalization for value validity.

    Wrong object or vertex element types raise :class:`TypeError`; a
    forged polygon whose vertices fail the constructor rules raises
    :class:`ValueError`.
    """
    if not isinstance(polygon, ConvexPolygonRegion):
        raise TypeError("polygon must be a ConvexPolygonRegion")
    # Re-runs every constructor rule (types, count, convexity, simplicity)
    # and yields the canonical sequence; the encoded bytes always carry
    # canonical vertices even for an object forged bypassing __post_init__.
    _normalize_polygon_vertices(polygon.vertices)


def _check_polygon_proof(proof: object) -> None:
    """Validate the nested types of a :class:`ConvexPolygonRegionProof`."""
    if not isinstance(proof, ConvexPolygonRegionProof):
        raise TypeError("proof must be a ConvexPolygonRegionProof")
    check_range_proof(proof.x_proof, "proof x_proof")
    check_range_proof(proof.y_proof, "proof y_proof")
    if not isinstance(proof.edge_proofs, tuple):
        raise TypeError("proof edge_proofs must be a tuple of WideRangeProof")
    for position, edge_proof in enumerate(proof.edge_proofs):
        check_wide_range_proof(edge_proof, f"proof edge_proofs[{position}]")


class _PolygonProofReader(ProofBodyReader):
    """Strict envelope reader with polygon and polygon-proof constructors."""

    def polygon(self) -> ConvexPolygonRegion:
        body = self.frame("polygon")
        inner = _PolygonProofReader(body)
        count = inner.tuple_cardinality("polygon")
        vertices: list[tuple[int, int]] = []
        for index in range(count):
            vertex_body = inner.frame(f"polygon vertices[{index}]")
            vertex_reader = _PolygonProofReader(vertex_body)
            vertex_count = vertex_reader.tuple_cardinality(
                f"polygon vertices[{index}]"
            )
            if vertex_count != 2:
                raise ValueError(
                    f"polygon vertices[{index}] must be an (x, y) integer pair"
                )
            x_coord = vertex_reader.int_value(f"polygon vertices[{index}] x")
            y_coord = vertex_reader.int_value(f"polygon vertices[{index}] y")
            if not vertex_reader.at_end():
                raise ValueError(f"polygon vertices[{index}] has trailing data")
            vertices.append((x_coord, y_coord))
        if not inner.at_end():
            raise ValueError("polygon tuple has trailing data")
        # The constructor enforces every polygon rule (fewer than three
        # vertices, repeats, collinear triples, concavity, self-intersection)
        # and canonicalizes rotations and reversals of one boundary.
        return ConvexPolygonRegion(tuple(vertices))

    def polygon_proof(self, edge_count: int) -> ConvexPolygonRegionProof:
        body = self.frame("proof")
        inner = _PolygonProofReader(body)
        count = inner.tuple_cardinality("proof")
        if count != 3:
            raise ValueError(
                "convex polygon proof must have exactly three fields"
            )
        x_proof = inner.range_proof("polygon proof x_proof")
        y_proof = inner.range_proof("polygon proof y_proof")
        edge_body = inner.frame("polygon proof edge_proofs")
        edge_reader = _PolygonProofReader(edge_body)
        declared_edges = edge_reader.tuple_cardinality("polygon proof edge_proofs")
        if declared_edges != edge_count:
            raise ValueError(
                "polygon proof edge_proofs count must equal the number of "
                "polygon edges"
            )
        edge_proofs = tuple(
            edge_reader.wide_range_proof(f"polygon proof edge_proofs[{index}]")
            for index in range(declared_edges)
        )
        if not edge_reader.at_end():
            raise ValueError("polygon proof edge_proofs has trailing data")
        if not inner.at_end():
            raise ValueError("polygon proof has trailing data")
        return ConvexPolygonRegionProof(
            x_proof=x_proof,
            y_proof=y_proof,
            edge_proofs=edge_proofs,
        )


def encode_convex_polygon_proof_bundle(
    bundle: ConvexPolygonProofBundle,
) -> bytes:
    """Encode a :class:`ConvexPolygonProofBundle` into its canonical envelope.

    The output starts with the four-byte magic ``b"zrgp"`` and a one-byte
    format version, followed by the five fields in fixed order
    (``x_commitment``, ``y_commitment``, ``polygon``, ``context`` and
    ``proof``); each item is length-prefixed with a four-byte big-endian
    header and every structured body carries an explicit tuple
    cardinality, exactly as in :func:`encode_region_proof_bundle`. The
    polygon is written through its canonical vertex sequence, and the
    proof body holds the two bounding-box :class:`RangeProof` objects
    (x then y) followed by one :class:`WideRangeProof` per polygon edge
    in canonical boundary order. The same bundle object always encodes to
    the same byte string; distinct fields, contexts or sub-proofs always
    produce distinct bytes. The function returns ``bytes`` only and never
    writes to the file system or a database.

    A wrong object or field type (including a ``bool`` integer, a
    non-tuple proof field or a wide-proof pair that is not a two-tuple)
    raises :class:`TypeError`. A forged polygon whose vertices fail the
    :class:`ConvexPolygonRegion` constructor rules raises
    :class:`ValueError`.
    """
    if not isinstance(bundle, ConvexPolygonProofBundle):
        raise TypeError("bundle must be a ConvexPolygonProofBundle")
    check_commitment(bundle.x_commitment, "x_commitment")
    check_commitment(bundle.y_commitment, "y_commitment")
    _check_polygon(bundle.polygon)
    if not isinstance(bundle.context, bytes):
        raise TypeError("context must be bytes")
    _check_polygon_proof(bundle.proof)
    out = bytearray()
    out += MAGIC
    out += bytes((VERSION,))
    out += frame(commitment_body(bundle.x_commitment))
    out += frame(commitment_body(bundle.y_commitment))
    out += frame(_polygon_body(bundle.polygon))
    out += frame(bundle.context)
    out += frame(_polygon_proof_body(bundle.proof))
    return bytes(out)


def decode_convex_polygon_proof_bundle(
    data: bytes,
) -> ConvexPolygonProofBundle:
    """Decode a canonical envelope back into a :class:`ConvexPolygonProofBundle`.

    ``data`` must be exactly the output of
    :func:`encode_convex_polygon_proof_bundle`: the magic ``b"zrgp"``, a
    known format version and the five fields in their fixed order with
    valid length prefixes, tuple cardinalities and integer sign bytes.
    The polygon vertices are rebuilt through the
    :class:`ConvexPolygonRegion` constructor, so rotations and reversals
    of one boundary decode to the same canonical region; an illegal
    polygon (too few vertices, repeats, collinear triples, concavity or
    self-intersection) is rejected. The payload must be consumed
    completely with no trailing bytes and the proof must carry exactly
    one edge :class:`WideRangeProof` per polygon edge in boundary order.
    A truncated input, an out-of-bounds length, an unknown version, a
    non-canonical integer, illegal commitment field values, an illegal
    polygon, a mismatched sub-proof shape or trailing bytes raises
    :class:`ValueError`; a non-``bytes`` input raises :class:`TypeError`.
    A decoded bundle compares equal field-for-field to the original.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    reader = _PolygonProofReader(data)
    reader.expect(MAGIC, "convex polygon proof bundle magic")
    version = reader.byte("format version")
    if version != VERSION:
        raise ValueError("unknown convex polygon proof bundle format version")
    x_commitment = reader.commitment("x_commitment")
    y_commitment = reader.commitment("y_commitment")
    polygon = reader.polygon()
    context = reader.frame("context")
    proof = reader.polygon_proof(len(polygon.vertices))
    if not reader.at_end():
        raise ValueError("trailing data after convex polygon proof bundle payload")
    return ConvexPolygonProofBundle(
        x_commitment=x_commitment,
        y_commitment=y_commitment,
        polygon=polygon,
        context=context,
        proof=proof,
    )


def verify_convex_polygon_proof_bundle(bundle: ConvexPolygonProofBundle) -> bool:
    """Verify the proof carried by a :class:`ConvexPolygonProofBundle`.

    Verification follows :func:`verify_convex_polygon` exactly, using only
    the two :class:`PedersenCommitment` objects, the
    :class:`ConvexPolygonRegion`, the :class:`ConvexPolygonRegionProof`
    and the ``context`` — never coordinates or blinding factors. Every
    nested type is checked across the *whole* envelope first (including a
    ``bool`` integer, a non-tuple proof field or a non-``bytes``
    context), so a proof-field type error raises :class:`TypeError` even
    when the envelope also carries a forged, geometrically invalid
    polygon — illegal geometry must never mask a wrong type. Every other
    failure — an illegal polygon shape with well-typed vertices,
    mismatched group parameters or declared ranges, a context mismatch,
    swapped commitments or axes, a different polygon, a tampered edge
    proof or a failed verification equation — returns ``False``.
    Encoding and then decoding a bundle preserves the verification
    verdict.
    """
    if not isinstance(bundle, ConvexPolygonProofBundle):
        raise TypeError("bundle must be a ConvexPolygonProofBundle")
    # Complete every nested type check (commitments, polygon vertices,
    # both RangeProofs, every WideRangeProof and context) before any
    # semantic verdict, so geometric invalidity cannot shadow a wrong
    # type sitting later in the envelope.
    _check_convex_polygon_input_types(
        bundle.x_commitment,
        bundle.y_commitment,
        bundle.polygon,
        bundle.proof,
        bundle.context,
    )
    return verify_convex_polygon(
        bundle.x_commitment,
        bundle.y_commitment,
        bundle.polygon,
        bundle.proof,
        bundle.context,
    )
