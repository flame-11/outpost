"""The name server (CONTRACT section 2): authoritative for one zone, UDP and TCP, no recursion."""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import Protocol

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.TXT import TXT

from outpost.addresses import address_from_dns
from outpost.config import Limits, Settings
from outpost.rates import RateWindow
from outpost.recorder import Capture, Recorder
from outpost.records import DnsRecord, format_time, utc_now
from outpost.schema import challenge_name

log = logging.getLogger("outpost.dns")

TTL = 60
CHALLENGE_TTL = 0  # a validator must never see an earlier value
SPF_TEXT = "v=spf1 -all"  # no host in the zone sends mail
DMARC_TEXT = "v=DMARC1; p=reject"
TCP_IDLE_SECONDS = 10.0
CHALLENGE_POLL_SECONDS = 1.0


class ChallengeValues:
    """The `_acme-challenge` TXT values, as the ACME hook last wrote them to the store (in memory,
    so an answer never waits on the disk)."""

    def __init__(self) -> None:
        self._values: dict[str, tuple[str, ...]] = {}

    def set(self, values: dict[str, tuple[str, ...]]) -> None:
        self._values = values

    def at(self, name: str) -> tuple[str, ...]:
        return self._values.get(name, ())


class DnsResponder:
    """Builds the answer for one query and hands an interaction that names a channel to the
    recorder. Returns None when the query is not answered."""

    def __init__(
        self, settings: Settings, limits: Limits, recorder: Recorder, challenges: ChallengeValues | None = None
    ) -> None:
        self._zone = dns.name.from_text(settings.zone)
        self._challenges = challenges or ChallengeValues()
        self._challenge_name = dns.name.from_text(challenge_name(settings.zone))
        self._ipv4 = settings.public_ipv4
        self._ipv6 = settings.public_ipv6
        self._recorder = recorder
        self._rate = RateWindow(limits.dns_source_rate, 1.0)
        zone = self._zone.to_text()
        self._soa_text = f"ns1.{zone} hostmaster.{zone} 1 3600 600 86400 {TTL}"
        self._ns_texts = (f"ns1.{zone}", f"ns2.{zone}")
        self._mx_text = f"10 mx.{zone}"

    def respond(self, wire: bytes, source_ip: str, source_port: int, transport: str) -> bytes | None:
        if not self._rate.allows(source_ip):
            return None
        try:
            query = dns.message.from_wire(wire)
        except Exception:  # untrusted bytes: any parse failure means no answer
            return None
        if query.flags & dns.flags.QR:
            return None
        self._rate.add(source_ip)
        response = dns.message.make_response(query)
        if query.opcode() != dns.opcode.QUERY:
            response.set_rcode(dns.rcode.NOTIMP)
        elif len(query.question) != 1:
            response.set_rcode(dns.rcode.FORMERR)
        else:
            question = query.question[0]
            if question.rdclass != dns.rdataclass.IN or not question.name.is_subdomain(self._zone):
                response.set_rcode(dns.rcode.REFUSED)
            else:
                self._answer(response, question.name, question.rdtype)
                self._capture(question.name, question.rdtype, source_ip, source_port, transport)
        return response.to_wire()

    def _answer(self, response: dns.message.Message, qname: dns.name.Name, rdtype: int) -> None:
        response.flags |= dns.flags.AA
        at_apex = qname == self._zone
        rrset: dns.rrset.RRset | None = None
        if rdtype == dns.rdatatype.A:
            rrset = dns.rrset.from_text(qname, TTL, "IN", "A", self._ipv4)
        elif rdtype == dns.rdatatype.AAAA and self._ipv6 is not None:
            rrset = dns.rrset.from_text(qname, TTL, "IN", "AAAA", self._ipv6)
        elif rdtype == dns.rdatatype.MX:
            rrset = dns.rrset.from_text(qname, TTL, "IN", "MX", self._mx_text)
        elif rdtype == dns.rdatatype.NS and at_apex:
            rrset = dns.rrset.from_text(qname, TTL, "IN", "NS", *self._ns_texts)
        elif rdtype == dns.rdatatype.SOA and at_apex:
            rrset = dns.rrset.from_text(qname, TTL, "IN", "SOA", self._soa_text)
        elif rdtype == dns.rdatatype.TXT and qname == self._challenge_name:
            values = self._challenges.at(qname.to_text(omit_final_dot=True).lower())
            if values:
                rdatas = [TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [value.encode()]) for value in values]
                rrset = dns.rrset.from_rdata_list(qname, CHALLENGE_TTL, rdatas)
        elif rdtype == dns.rdatatype.TXT:
            text = self._policy_text(qname)
            if text is not None:
                rdata = TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [text.encode()])
                rrset = dns.rrset.from_rdata_list(qname, TTL, [rdata])
        if rrset is not None:
            response.answer.append(rrset)
        else:
            response.authority.append(dns.rrset.from_text(self._zone, TTL, "IN", "SOA", self._soa_text))

    def _policy_text(self, qname: dns.name.Name) -> str | None:
        """SPF on every name without an underscore label; DMARC at `_dmarc.` followed by such a name."""
        labels = [label.decode("ascii", "replace").lower() for label in qname.relativize(self._zone).labels]
        if labels and labels[0] == "_dmarc":
            return DMARC_TEXT if not any(label.startswith("_") for label in labels[1:]) else None
        return SPF_TEXT if not any(label.startswith("_") for label in labels) else None

    def _capture(self, qname: dns.name.Name, rdtype: int, source_ip: str, source_port: int, transport: str) -> None:
        address = address_from_dns(qname, self._zone)
        if address is None or not self._recorder.knows(address.channel_id):
            return
        received_at = format_time(utc_now())
        record = DnsRecord(
            v=1,
            protocol="dns",
            channel_id=address.channel_id,
            token=address.token,
            prefix=address.prefix,
            name=address.name,
            source_ip=source_ip,
            source_port=source_port,
            received_at=received_at,
            qname=qname.to_text(omit_final_dot=True),
            qtype=dns.rdatatype.to_text(rdtype),
            transport="tcp" if transport == "tcp" else "udp",
        )
        self._recorder.submit(
            Capture(
                channel_id=address.channel_id,
                source_ip=source_ip,
                received_at=received_at,
                plaintext=record.model_dump_json().encode(),
            )
        )


async def challenge_loop(db: "ChallengeSource", challenges: ChallengeValues) -> None:
    """Keep `challenges` equal to the store's values; the hook runs in another process."""
    while True:
        challenges.set(await db.challenge_values())
        await asyncio.sleep(CHALLENGE_POLL_SECONDS)


class ChallengeSource(Protocol):
    async def challenge_values(self) -> dict[str, tuple[str, ...]]: ...


class DnsUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, responder: DnsResponder) -> None:
        self._responder = responder
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        answer = self._responder.respond(data, str(addr[0]), int(addr[1]), "udp")
        if answer is not None and self._transport is not None:
            self._transport.sendto(answer, addr)

    def error_received(self, exc: Exception) -> None:
        log.debug("udp error: %s", type(exc).__name__)


def dns_tcp_handler(
    responder: DnsResponder,
) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        source_ip, source_port = str(peer[0]), int(peer[1])
        try:
            while True:
                async with asyncio.timeout(TCP_IDLE_SECONDS):
                    length = int.from_bytes(await reader.readexactly(2), "big")
                    wire = await reader.readexactly(length)
                answer = responder.respond(wire, source_ip, source_port, "tcp")
                if answer is None:
                    break
                writer.write(len(answer).to_bytes(2, "big") + answer)
                await writer.drain()
        except (asyncio.IncompleteReadError, TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    return handle
