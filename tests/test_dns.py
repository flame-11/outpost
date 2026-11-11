"""CONTRACT section 2 (name server table), section 3 (DNS_SOURCE_RATE) and section 6 (dns record)."""

from pathlib import Path

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
from conftest import PUBLIC_IPV4, ZONE, Stack, open_stack

from outpost import schema
from outpost.config import Limits


def ask(stack: Stack, name: str, rdtype: str | int, source: str = "198.51.100.1") -> dns.message.Message:
    wire = stack.responder.respond(dns.message.make_query(name, rdtype).to_wire(), source, 40000, "udp")
    assert wire is not None
    return dns.message.from_wire(wire)


def soa_in_authority(response: dns.message.Message) -> bool:
    return any(rrset.rdtype == dns.rdatatype.SOA and rrset.name.to_text() == f"{ZONE}." for rrset in response.authority)


async def test_a_for_any_name_in_the_zone(stack: Stack) -> None:
    for name in (ZONE, f"x.{ZONE}", f"deep.er.t1-aaaaaaaaaaaa.{ZONE}", f"ns1.{ZONE}"):
        response = ask(stack, name, "A")
        assert response.rcode() == dns.rcode.NOERROR
        assert response.flags & dns.flags.AA
        assert not response.flags & dns.flags.RA
        (rrset,) = response.answer
        assert [rdata.to_text() for rdata in rrset] == [PUBLIC_IPV4]
        assert rrset.ttl == 60


async def test_aaaa_is_no_data_without_ipv6(stack: Stack) -> None:
    response = ask(stack, f"x.{ZONE}", "AAAA")
    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer == []
    assert soa_in_authority(response)


async def test_aaaa_answers_the_configured_ipv6(tmp_path: Path) -> None:
    async with open_stack(tmp_path, public_ipv6="2001:db8::10") as stack:
        (rrset,) = ask(stack, f"x.{ZONE}", "AAAA").answer
        assert [rdata.to_text() for rdata in rrset] == ["2001:db8::10"]
        assert rrset.ttl == 60


async def test_mx_for_any_name(stack: Stack) -> None:
    for name in (ZONE, f"m1-aaaaaaaaaaaa.{ZONE}"):
        (rrset,) = ask(stack, name, "MX").answer
        assert [rdata.to_text() for rdata in rrset] == [f"10 mx.{ZONE}."]
        assert rrset.ttl == 60


async def test_ns_and_soa_at_the_zone(stack: Stack) -> None:
    (ns,) = ask(stack, ZONE, "NS").answer
    assert sorted(rdata.to_text() for rdata in ns) == [f"ns1.{ZONE}.", f"ns2.{ZONE}."]
    (soa,) = ask(stack, ZONE, "SOA").answer
    assert soa.rdtype == dns.rdatatype.SOA
    assert soa[0].mname.to_text() == f"ns1.{ZONE}."


async def test_ns_and_soa_below_the_zone_are_no_data(stack: Stack) -> None:
    for rdtype in ("NS", "SOA"):
        response = ask(stack, f"x.{ZONE}", rdtype)
        assert response.rcode() == dns.rcode.NOERROR
        assert response.answer == []
        assert soa_in_authority(response)


async def test_acme_challenge_txt_has_no_values_without_certificate_component(stack: Stack) -> None:
    response = ask(stack, f"_acme-challenge.{ZONE}", "TXT")
    assert response.rcode() == dns.rcode.NOERROR
    assert response.answer == []


async def test_other_types_are_no_data_with_soa(stack: Stack) -> None:
    for rdtype in ("TXT", "CAA", "SRV", "ANY", 65280):
        response = ask(stack, f"x.{ZONE}", rdtype)
        assert response.rcode() == dns.rcode.NOERROR
        assert response.answer == []
        assert soa_in_authority(response)


async def test_outside_the_zone_is_refused(stack: Stack) -> None:
    for name in ("example.com", f"t1-aaaaaaaaaaaa.{ZONE}.evil.example", "test"):
        response = ask(stack, name, "A")
        assert response.rcode() == dns.rcode.REFUSED
        assert response.answer == []


async def test_lookup_on_a_channel_is_recorded(stack: Stack) -> None:
    channel = await stack.register()
    qname = f"Data.T1-{channel.channel_id.upper()}.{ZONE}"
    ask(stack, qname, "A", source="198.51.100.7")
    ask(stack, f"t2-{channel.channel_id}.{ZONE}", 65280, source="198.51.100.7")
    await stack.recorder.idle()
    page = await stack.records(channel)
    first, second = (channel.open(r["sealed"]) for r in page["records"])
    assert [r["seq"] for r in page["records"]] == [1, 2]
    assert first.protocol == "dns"
    assert (first.token, first.prefix, first.channel_id) == ("t1", "data", channel.channel_id)
    assert first.name == qname.lower()
    assert first.qname == qname
    assert (first.qtype, first.transport, first.source_ip, first.source_port) == ("A", "udp", "198.51.100.7", 40000)
    assert first.received_at == page["records"][0]["received_at"]
    assert second.qtype == "TYPE65280"


async def test_unknown_channel_and_reserved_names_store_nothing(stack: Stack) -> None:
    channel = await stack.register()
    for name in (f"t1-aaaaaaaaaaaa.{ZONE}", ZONE, f"ns1.{ZONE}", f"x.t1-{channel.channel_id}.other.example"):
        ask(stack, name, "A")
    await stack.recorder.idle()
    assert (await stack.records(channel))["records"] == []


async def test_dns_source_rate_leaves_queries_unanswered(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(dns_source_rate=3)) as stack:
        wire = dns.message.make_query(f"x.{ZONE}", "A").to_wire()
        answers = [stack.responder.respond(wire, "198.51.100.9", 1, "udp") for _ in range(4)]
        assert [a is not None for a in answers] == [True, True, True, False]
        assert stack.responder.respond(wire, "198.51.100.10", 1, "udp") is not None


async def test_acme_challenge_txt_answers_the_current_values(stack: Stack) -> None:
    name = f"_acme-challenge.{ZONE}"
    empty = ask(stack, name, "TXT")
    assert (empty.rcode(), empty.answer) == (dns.rcode.NOERROR, [])
    assert soa_in_authority(empty)

    connection = schema.connect(stack.settings.data_dir)  # the hook writes from its own process
    schema.add_challenge(connection, name, "value-one", "2026-11-11T00:00:00.000Z")
    schema.add_challenge(connection, name, "value-two", "2026-11-11T00:00:01.000Z")
    stack.challenges.set(await stack.db.challenge_values())
    response = ask(stack, name.upper(), "TXT")
    assert response.flags & dns.flags.AA
    (rrset,) = response.answer
    assert sorted(b"".join(rdata.strings) for rdata in rrset) == [b"value-one", b"value-two"]
    assert rrset.ttl == 0
    assert ask(stack, f"x.{name}", "TXT").answer == []  # only the name itself

    schema.remove_challenge(connection, name, "value-one")
    stack.challenges.set(await stack.db.challenge_values())
    (rrset,) = ask(stack, name, "TXT").answer
    assert [b"".join(rdata.strings) for rdata in rrset] == [b"value-two"]
    schema.remove_challenge(connection, name, "value-two")
    connection.close()
    stack.challenges.set(await stack.db.challenge_values())
    assert ask(stack, name, "TXT").answer == []
    await stack.recorder.idle()
