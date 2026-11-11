"""Reassembly of data sent as indexed lookups: `<data>[.<data>...].<index>.<token>-<channel>.<zone>`."""

import base64

from outpost.assemble import assemble
from outpost.records import DnsRecord

CHANNEL = "k3v7x2mq6c4a"


def lookup(prefix: str, token: str = "x1") -> DnsRecord:
    name = f"{prefix}.{token}-{CHANNEL}.oob.example" if prefix else f"{token}-{CHANNEL}.oob.example"
    return DnsRecord(
        v=1,
        protocol="dns",
        channel_id=CHANNEL,
        token=token,
        prefix=prefix,
        name=name,
        source_ip="198.51.100.53",
        source_port=40213,
        received_at="2026-11-11T08:15:29.871Z",
        qname=name,
        qtype="A",
        transport="udp",
    )


def b32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()


def test_hex_chunks_are_joined_in_index_order_whatever_the_arrival_order() -> None:
    chunks = [b"first ", b"second ", b"third"]
    records = [lookup(f"{chunks[i].hex()}.{i}") for i in (2, 0, 1)]
    result = assemble(records, "x1", "hex")
    assert result.data == b"first second third"
    assert result.present == (0, 1, 2)
    assert result.missing == ()


def test_unpadded_base32_chunks_of_any_length_decode() -> None:
    chunks = [b"a", b"bc", b"def", b"ghij", b"klmno", b"pqrstu"]
    records = [lookup(f"{b32(chunk)}.{i}") for i, chunk in enumerate(chunks)]
    assert assemble(records, "x1", "base32").data == b"".join(chunks)


def test_a_chunk_may_span_several_data_labels() -> None:
    data = bytes(range(90))
    text = data.hex()  # 180 characters, more than one 63-byte label holds
    prefix = ".".join(text[i : i + 60] for i in range(0, len(text), 60))
    result = assemble([lookup(f"{prefix}.0")], "x1", "hex")
    assert result.data == data


def test_duplicates_from_resolver_retries_count_once() -> None:
    records = [lookup("6161.0"), lookup("6262.1"), lookup("6161.0"), lookup("6262.1"), lookup("6262.1")]
    result = assemble(records, "x1", "hex")
    assert result.data == b"aabb"
    assert result.present == (0, 1)


def test_gaps_below_the_highest_index_are_missing_and_skipped() -> None:
    records = [lookup("61.0"), lookup("63.2"), lookup("66.5")]
    result = assemble(records, "x1", "hex")
    assert result.present == (0, 2, 5)
    assert result.missing == (1, 3, 4)
    assert result.data == b"acf"


def test_decoding_ignores_letter_case_changes() -> None:
    data = b"\x00\xffcase test\x10"
    hex_upper = lookup(f"{data.hex().upper()}.0")
    b32_mixed = lookup(f"{''.join(c.upper() if i % 2 else c for i, c in enumerate(b32(data)))}.0")
    assert assemble([hex_upper], "x1", "hex").data == data
    assert assemble([b32_mixed], "x1", "base32").data == data


def test_other_tokens_and_lookups_without_an_index_label_are_ignored() -> None:
    records = [
        lookup("6161.0"),
        lookup("ffff.1", token="other"),
        lookup(""),  # the bare host name, e.g. a first probe
        lookup("6262"),  # one label: no data before the index
        lookup("6363.abc"),  # not a decimal index
    ]
    result = assemble(records, "x1", "hex")
    assert result.data == b"aa"
    assert result.present == (0,)


def test_no_records_give_empty_data() -> None:
    result = assemble([], "x1", "hex")
    assert (result.data, result.present, result.missing) == (b"", (), ())


def test_a_chunk_that_does_not_decode_is_reported_and_left_out() -> None:
    records = [lookup("6161.0"), lookup("zz.1"), lookup("6363.2")]
    result = assemble(records, "x1", "hex")
    assert result.data == b"aacc"
    assert result.undecodable == (1,)
    assert result.missing == ()
