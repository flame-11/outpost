"""Reassembly of data sent as indexed lookups.

A sender splits the data into chunks and encodes each chunk on its own as lowercase hex or
unpadded lowercase base32 (both survive the letter-case changes resolvers make). One lookup
carries one chunk, in one or more labels, followed by a label holding the chunk's index, and
that index label sits immediately left of the pair label:

    <data>[.<data>...].<index>.<token>-<channel_id>.<zone>

`<index>` is decimal from 0. Resolvers retry, so an index may arrive more than once.
"""

import base64
import binascii
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from outpost.records import DnsRecord

Encoding = Literal["hex", "base32"]


@dataclass(frozen=True, slots=True)
class Assembled:
    """`data` joins the decoded chunks in index order, skipping `missing` and `undecodable` ones.

    `missing` are indices below the highest one present that never arrived; `undecodable` are
    indices whose every copy failed to decode.
    """

    data: bytes
    present: tuple[int, ...]
    missing: tuple[int, ...]
    undecodable: tuple[int, ...]


def assemble(records: Iterable[DnsRecord], token: str, encoding: Encoding) -> Assembled:
    """Records of other tokens, and lookups without a data label and an index label, are ignored."""
    chunks: dict[int, bytes | None] = {}
    for record in records:
        if record.token != token:
            continue
        labels = record.prefix.split(".")
        if len(labels) < 2 or not labels[-1].isascii() or not labels[-1].isdigit():
            continue
        index = int(labels[-1])
        if chunks.get(index) is None:
            chunks[index] = _decode("".join(labels[:-1]), encoding)
    present = tuple(sorted(chunks))
    highest = present[-1] if present else -1
    return Assembled(
        data=b"".join(chunk for _, chunk in sorted(chunks.items()) if chunk is not None),
        present=present,
        missing=tuple(index for index in range(highest + 1) if index not in chunks),
        undecodable=tuple(index for index in present if chunks[index] is None),
    )


def _decode(text: str, encoding: Encoding) -> bytes | None:
    try:
        if encoding == "hex":
            return bytes.fromhex(text)
        return base64.b32decode(text.upper() + "=" * (-len(text) % 8))
    except (ValueError, binascii.Error):
        return None
