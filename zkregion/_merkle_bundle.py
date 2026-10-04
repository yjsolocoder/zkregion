"""Versioned binary envelope for Merkle multi-inclusion proofs.

A :class:`MerkleMultiProofBundle` freezes the three arguments of
:func:`~zkregion.verify_multi_inclusion` (root, proof, entries) into one
immutable object that can be encoded into a self-contained byte string,
shipped across processes and verified again after decoding. The generic
wire rules live in :mod:`zkregion._bundle_wire`; this module owns only
the Merkle-specific structure — its own magic and version, the three-item
proof body ``(leaf_count, indices, siblings)`` and the two-item
``(index, leaf)`` entry pairs — and deliberately keeps format validity
and proof validity apart: representable but semantically inconsistent
bundles (duplicate, out-of-range or mismatched indices) still round-trip,
and are rejected with ``False`` only by
:func:`verify_merkle_multi_proof_bundle`.

Encoding is a pure function of the field values: the same bundle always
maps to the same bytes, indices and leaf entries keep their exact order,
and decoding those bytes rebuilds an equal bundle.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import (
    MerkleMultiProof,
    _check_bytes,
    verify_multi_inclusion,
)
from ._bundle_wire import BundleWireReader, frame, int_body, tuple_body

MAGIC = b"zmmp"
VERSION = 1


@dataclass(frozen=True)
class MerkleMultiProofBundle:
    """A versioned, canonical binary envelope for one multi-inclusion proof.

    Fields, in the fixed wire order: ``root`` (``bytes``), ``proof``
    (:class:`MerkleMultiProof`) and ``entries``
    (``tuple[tuple[int, bytes], ...]`` of ``(index, leaf)`` pairs in the
    exact order of ``proof.indices``). Bundles are positional construction
    arguments, compare by value and are immutable; construction performs no
    validation — use :func:`encode_merkle_multi_proof_bundle` /
    :func:`verify_merkle_multi_proof_bundle` to check.
    """

    root: bytes
    proof: MerkleMultiProof
    entries: tuple[tuple[int, bytes], ...]


def _check_proof_types(proof: object) -> None:
    """Type-check a bundle ``proof`` field (values are decided elsewhere)."""
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


def _check_entries_types(entries: object) -> None:
    """Type-check a bundle ``entries`` field (values are decided elsewhere)."""
    if not isinstance(entries, tuple):
        raise TypeError("entries must be a tuple of (index, leaf) pairs")
    for position, entry in enumerate(entries):
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise TypeError(f"entries[{position}] must be an (index, leaf) pair")
        index, leaf = entry
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError(f"entries[{position}] index must be an integer")
        if not isinstance(leaf, bytes):
            raise TypeError(f"entries[{position}] leaf must be bytes")


def encode_merkle_multi_proof_bundle(bundle: MerkleMultiProofBundle) -> bytes:
    """Encode a :class:`MerkleMultiProofBundle` into its canonical byte envelope.

    The same bundle object always encodes to the same byte string. The
    output starts with the four-byte magic ``b"zmmp"`` and a one-byte
    format version, followed by the three fields in fixed order
    (``root``, ``proof``, ``entries``); each item is length-prefixed with
    a four-byte big-endian header. The proof body is the three-item tuple
    ``(leaf_count, indices, siblings)`` and each entry the two-item tuple
    ``(index, leaf)``; integers (including out-of-range or negative
    values) carry a sign byte and a shortest big-endian magnitude, tuples
    carry an explicit cardinality and ``bytes`` items are framed raw. The
    function returns ``bytes`` only and never writes to the file system or
    a database.

    Only types are checked: a wrong object or field type (including a
    ``bool`` integer, a non-tuple ``indices``/``siblings``/``entries``
    field or an entry that is not an ``(index, leaf)`` pair) raises
    :class:`TypeError`. A bundle whose proof is semantically inconsistent
    (misordered or duplicate indices, an entries/indices mismatch, an
    out-of-range index, a non-positive ``leaf_count``) still encodes to
    ``bytes``; those cases are decided by
    :func:`verify_merkle_multi_proof_bundle`.
    """
    if not isinstance(bundle, MerkleMultiProofBundle):
        raise TypeError("bundle must be a MerkleMultiProofBundle")
    if not isinstance(bundle.root, bytes):
        raise TypeError("root must be bytes")
    _check_proof_types(bundle.proof)
    _check_entries_types(bundle.entries)
    proof = bundle.proof
    proof_body = tuple_body(
        [
            int_body(proof.leaf_count),
            tuple_body([int_body(index) for index in proof.indices]),
            tuple_body(list(proof.siblings)),
        ]
    )
    entries_body = tuple_body(
        [
            tuple_body([int_body(index), leaf])
            for index, leaf in bundle.entries
        ]
    )
    out = bytearray()
    out += MAGIC
    out += bytes((VERSION,))
    out += frame(bundle.root)
    out += frame(proof_body)
    out += frame(entries_body)
    return bytes(out)


class _MerkleBundleReader(BundleWireReader):
    """Strict envelope reader with the multi-proof and entries bodies."""

    def proof(self) -> MerkleMultiProof:
        """Read the framed proof body: ``(leaf_count, indices, siblings)``."""
        body = self.frame("proof")
        inner = _MerkleBundleReader(body)
        count = inner.tuple_cardinality("proof")
        if count != 3:
            raise ValueError("proof must have exactly three fields")
        leaf_count = inner.int_value("proof leaf_count")
        indices = inner.integer_tuple("proof indices")
        siblings_body = inner.frame("proof siblings")
        siblings_reader = _MerkleBundleReader(siblings_body)
        sibling_count = siblings_reader.tuple_cardinality("proof siblings")
        siblings = tuple(
            siblings_reader.frame(f"proof siblings[{position}]")
            for position in range(sibling_count)
        )
        if not siblings_reader.at_end():
            raise ValueError("proof siblings tuple has trailing data")
        if not inner.at_end():
            raise ValueError("proof has trailing data")
        return MerkleMultiProof(
            leaf_count=leaf_count, indices=indices, siblings=siblings
        )

    def entries(self) -> tuple[tuple[int, bytes], ...]:
        """Read the framed entries body: a tuple of ``(index, leaf)`` pairs."""
        body = self.frame("entries")
        inner = _MerkleBundleReader(body)
        count = inner.tuple_cardinality("entries")
        entries: list[tuple[int, bytes]] = []
        for position in range(count):
            entry_body = inner.frame(f"entries[{position}]")
            entry_reader = _MerkleBundleReader(entry_body)
            entry_count = entry_reader.tuple_cardinality(f"entries[{position}]")
            if entry_count != 2:
                raise ValueError(f"entries[{position}] must be an (index, leaf) pair")
            index = entry_reader.int_value(f"entries[{position}] index")
            leaf = entry_reader.frame(f"entries[{position}] leaf")
            if not entry_reader.at_end():
                raise ValueError(f"entries[{position}] has trailing data")
            entries.append((index, leaf))
        if not inner.at_end():
            raise ValueError("entries tuple has trailing data")
        return tuple(entries)


def decode_merkle_multi_proof_bundle(data: bytes) -> MerkleMultiProofBundle:
    """Decode a canonical envelope back into a :class:`MerkleMultiProofBundle`.

    ``data`` must be exactly the output of
    :func:`encode_merkle_multi_proof_bundle`: the magic, a known format
    version, and the three fields in their fixed order with valid length
    prefixes, tuple cardinalities and canonical integers. The payload must
    be consumed completely with no trailing bytes. A truncated input, an
    out-of-bounds length, an unknown version, a non-canonical integer, a
    malformed tuple shape or trailing bytes raises :class:`ValueError`; a
    non-``bytes`` input raises :class:`TypeError`. Decoding checks the
    encoding only: a representable bundle whose proof does not verify
    still decodes successfully, and the decoded bundle compares equal
    field-for-field to the original.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    reader = _MerkleBundleReader(data)
    reader.expect(MAGIC, "merkle multi proof bundle magic")
    version = reader.byte("format version")
    if version != VERSION:
        raise ValueError("unknown merkle multi proof bundle format version")
    root = reader.frame("root")
    proof = reader.proof()
    entries = reader.entries()
    if not reader.at_end():
        raise ValueError("trailing data after merkle multi proof bundle payload")
    return MerkleMultiProofBundle(root=root, proof=proof, entries=entries)


def verify_merkle_multi_proof_bundle(bundle: MerkleMultiProofBundle) -> bool:
    """Verify the proof carried by a :class:`MerkleMultiProofBundle`.

    Verification reuses the existing multi-inclusion semantics exactly:
    the bundle's ``entries``, ``proof`` and ``root`` are handed to
    :func:`verify_multi_inclusion`, which checks the root and digest
    sizes, the strictly increasing duplicate-free ``proof.indices``
    against ``proof.leaf_count``, the exact entries/indices
    correspondence and the sibling consumption. A wrong object or field
    type (including a ``bool`` integer or a non-tuple field) raises
    :class:`TypeError`; every semantic inconsistency — a tampered leaf or
    root, duplicate or misordered indices, an out-of-range index, a
    miscounted entries list, a spliced or truncated sibling sequence —
    returns ``False``. Encoding and then decoding a bundle preserves the
    verification verdict.
    """
    if not isinstance(bundle, MerkleMultiProofBundle):
        raise TypeError("bundle must be a MerkleMultiProofBundle")
    if not isinstance(bundle.root, bytes):
        raise TypeError("root must be bytes")
    _check_proof_types(bundle.proof)
    _check_entries_types(bundle.entries)
    return verify_multi_inclusion(bundle.entries, bundle.proof, bundle.root)
