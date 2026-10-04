"""Versioned binary envelope for region membership proofs.

A :class:`RegionProofBundle` freezes the five verification-relevant
objects (both :class:`~zkregion.PedersenCommitment` objects, the
:class:`~zkregion.Region`, the external context and the
:class:`~zkregion.RegionProof` / :class:`~zkregion.RegionWideProof`)
into a self-describing byte string. The generic wire rules (frames,
canonical integers, tuples) live in :mod:`zkregion._bundle_wire`; the
shared commitment / sub-proof structure rules live in
:mod:`zkregion._bundle_proofs`. This module owns only what is specific
to this envelope: its magic and version, the one-byte proof-type tag
that keeps narrow and wide proofs byte-distinguishable, and the rule
that the proof body is always the two axis sub-proofs in ``(x, y)``
order.

Layout (all integers in the framing headers are unsigned big-endian)::

    magic (4) || version (1) || proof_type (1)
    frame(x_commitment) || frame(y_commitment) || frame(region)
    frame(context) || frame(proof)
"""

from __future__ import annotations

from dataclasses import dataclass

from . import (
    PedersenCommitment,
    Region,
    RegionProof,
    RegionWideProof,
    RangeProof,
    WideRangeProof,
    verify_region,
    verify_region_wide,
)
from ._bundle_proofs import (
    ProofBodyReader,
    check_commitment,
    check_range_proof,
    check_region,
    check_wide_range_proof,
    commitment_body,
    range_proof_body,
    region_body,
    wide_range_proof_body,
)
from ._bundle_wire import BundleWireReader, frame, tuple_body

MAGIC = b"zrgn"
VERSION = 1
PROOF_TYPE_REGION = 1
PROOF_TYPE_REGION_WIDE = 2


@dataclass(frozen=True)
class RegionProofBundle:
    """A versioned, canonical binary envelope for one region proof.

    Fields, in the fixed wire order: ``x_commitment`` / ``y_commitment``
    (:class:`PedersenCommitment`), ``region`` (:class:`Region`),
    ``context`` (``bytes``) and ``proof`` (a :class:`RegionProof` or
    :class:`RegionWideProof`). Bundles are positional construction
    arguments, compare by value and are immutable; construction performs no
    validation — use :func:`encode_region_proof_bundle` /
    :func:`verify_region_proof_bundle` to check.
    """

    x_commitment: PedersenCommitment
    y_commitment: PedersenCommitment
    region: Region
    context: bytes
    proof: RegionProof | RegionWideProof


def _proof_body(proof: RegionProof | RegionWideProof) -> tuple[int, bytes]:
    """Return ``(proof_type_tag, proof body)`` for the bundle payload.

    The proof body is a two-item tuple (the x then the y axis sub-proof);
    the type tag lives in the envelope header next to the format version.
    """
    if isinstance(proof, RegionProof):
        body = tuple_body(
            [
                range_proof_body(proof.x_proof),
                range_proof_body(proof.y_proof),
            ]
        )
        return PROOF_TYPE_REGION, body
    body = tuple_body(
        [
            wide_range_proof_body(proof.x_proof),
            wide_range_proof_body(proof.y_proof),
        ]
    )
    return PROOF_TYPE_REGION_WIDE, body


class _RegionProofReader(ProofBodyReader):
    """Strict envelope reader with the region-proof tag dispatch."""

    def proof(self, tag: int) -> RegionProof | RegionWideProof:
        body = self.frame("proof")
        inner = _RegionProofReader(body)
        count = inner.tuple_cardinality("proof")
        if count != 2:
            raise ValueError("proof must have exactly two axis sub-proofs")
        if tag == PROOF_TYPE_REGION:
            x_proof = inner.range_proof("region proof x_proof")
            y_proof = inner.range_proof("region proof y_proof")
            if not inner.at_end():
                raise ValueError("region proof has trailing data")
            return RegionProof(x_proof=x_proof, y_proof=y_proof)
        if tag == PROOF_TYPE_REGION_WIDE:
            x_proof = inner.wide_range_proof("region wide proof x_proof")
            y_proof = inner.wide_range_proof("region wide proof y_proof")
            if not inner.at_end():
                raise ValueError("region wide proof has trailing data")
            return RegionWideProof(x_proof=x_proof, y_proof=y_proof)
        raise ValueError("unknown region proof bundle proof type")


def encode_region_proof_bundle(bundle: RegionProofBundle) -> bytes:
    """Encode a :class:`RegionProofBundle` into its canonical byte envelope.

    The same bundle object always encodes to the same byte string. The
    output starts with the four-byte magic ``b"zrgn"``, a one-byte format
    version and a one-byte proof-type tag, followed by the five fields in
    fixed order (``x_commitment``, ``y_commitment``, ``region``,
    ``context``, ``proof``); each item is length-prefixed with a four-byte
    big-endian header. Arbitrary-precision integers (including negative
    bounds) carry a sign byte and a shortest big-endian magnitude; tuples
    carry an explicit cardinality. The function returns ``bytes`` only and
    never writes to the file system or a database.

    A wrong object or field type (including a ``bool`` integer, a
    non-tuple proof field, a wide-proof pair that is not a two-tuple, or a
    proof that is neither a :class:`RegionProof` nor a
    :class:`RegionWideProof`) raises :class:`TypeError`. A region with
    ``min > max`` on an axis cannot be built through the public
    :class:`Region` constructor; if such an object is forged bypassing the
    constructor, it is rejected with :class:`ValueError`.
    """
    if not isinstance(bundle, RegionProofBundle):
        raise TypeError("bundle must be a RegionProofBundle")
    check_commitment(bundle.x_commitment, "x_commitment")
    check_commitment(bundle.y_commitment, "y_commitment")
    check_region(bundle.region, enforce_order=True)
    if not isinstance(bundle.context, bytes):
        raise TypeError("context must be bytes")
    proof = bundle.proof
    if isinstance(proof, RegionProof):
        check_range_proof(proof.x_proof, "proof x_proof")
        check_range_proof(proof.y_proof, "proof y_proof")
    elif isinstance(proof, RegionWideProof):
        check_wide_range_proof(proof.x_proof, "proof x_proof")
        check_wide_range_proof(proof.y_proof, "proof y_proof")
    else:
        raise TypeError("proof must be a RegionProof or RegionWideProof")
    proof_type, proof_body = _proof_body(proof)
    out = bytearray()
    out += MAGIC
    out += bytes((VERSION, proof_type))
    out += frame(commitment_body(bundle.x_commitment))
    out += frame(commitment_body(bundle.y_commitment))
    out += frame(region_body(bundle.region))
    out += frame(bundle.context)
    out += frame(proof_body)
    return bytes(out)


def decode_region_proof_bundle(data: bytes) -> RegionProofBundle:
    """Decode a canonical envelope back into a :class:`RegionProofBundle`.

    ``data`` must be exactly the output of
    :func:`encode_region_proof_bundle`: the magic, a known format version
    and proof-type tag, and the five fields in their fixed order with
    valid length prefixes, tuple cardinalities and integer sign bytes.
    The payload must be consumed completely with no trailing bytes. A
    truncated input, an out-of-bounds length, an unknown version or proof
    type, a non-canonical integer, an illegal region or an unexpected
    nested proof shape raises :class:`ValueError`; a non-``bytes`` input
    raises :class:`TypeError`. A decoded bundle compares equal field-for-
    field to the original and a :class:`RegionProof` payload can never be
    rebuilt as a :class:`RegionWideProof` (or vice versa).
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    reader = _RegionProofReader(data)
    reader.expect(MAGIC, "region proof bundle magic")
    version = reader.byte("format version")
    if version != VERSION:
        raise ValueError("unknown region proof bundle format version")
    tag = reader.byte("proof type")
    if tag not in (PROOF_TYPE_REGION, PROOF_TYPE_REGION_WIDE):
        raise ValueError("unknown region proof bundle proof type")
    x_commitment = reader.commitment("x_commitment")
    y_commitment = reader.commitment("y_commitment")
    region = reader.region()
    context = reader.frame("context")
    proof = reader.proof(tag)
    if not reader.at_end():
        raise ValueError("trailing data after region proof bundle payload")
    return RegionProofBundle(
        x_commitment=x_commitment,
        y_commitment=y_commitment,
        region=region,
        context=context,
        proof=proof,
    )


def verify_region_proof_bundle(bundle: RegionProofBundle) -> bool:
    """Verify the proof carried by a :class:`RegionProofBundle`.

    Verification follows the existing single-proof semantics exactly,
    dispatching on the ``proof`` type: :class:`RegionProof` is checked with
    :func:`verify_region` and :class:`RegionWideProof` with
    :func:`verify_region_wide`, using only the two
    :class:`PedersenCommitment` objects, the :class:`Region` and the
    ``context`` — never coordinates or blinding factors. A wrong object or
    field type (including a proof of neither region-proof type) raises
    :class:`TypeError`; every other failure — a declared range mismatch,
    a context mismatch, swapped axes or commitments, a tampered proof or a
    failed verification equation — returns ``False``. Encoding and then
    decoding a bundle preserves the verification verdict.
    """
    if not isinstance(bundle, RegionProofBundle):
        raise TypeError("bundle must be a RegionProofBundle")
    check_commitment(bundle.x_commitment, "x_commitment")
    check_commitment(bundle.y_commitment, "y_commitment")
    # Types only: illegal interval values are decided (False) by the
    # delegated single-proof verifiers, never raised here.
    check_region(bundle.region, enforce_order=False)
    if not isinstance(bundle.context, bytes):
        raise TypeError("context must be bytes")
    proof = bundle.proof
    if isinstance(proof, RegionProof):
        return verify_region(
            bundle.x_commitment,
            bundle.y_commitment,
            bundle.region,
            proof,
            bundle.context,
        )
    if isinstance(proof, RegionWideProof):
        return verify_region_wide(
            bundle.x_commitment,
            bundle.y_commitment,
            bundle.region,
            proof,
            bundle.context,
        )
    raise TypeError("proof must be a RegionProof or RegionWideProof")
