"""Helpers for the client tests: interactions put straight into an in-process stack, and a transport
that routes the client library's calls to the stack's API."""

import base64
from email.message import EmailMessage

import dns.message
import httpx
from conftest import ZONE, Stack

from outpost.config import Limits
from outpost.recorder import Capture
from outpost.records import HttpRecord, SmtpRecord, format_time, utc_now

API = "http://api.test"
OPEN_LIMITS = Limits(source_rate=100_000, channel_rate=100_000, dns_source_rate=100_000)


class StackTransport(httpx.AsyncBaseTransport):
    """Sends each request through the stack's own client (an ASGI transport to the API)."""

    def __init__(self, stack: Stack) -> None:
        self._client = stack.client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._client.send(request)
        return httpx.Response(response.status_code, headers=response.headers, content=response.content)


async def lookup(stack: Stack, name: str, qtype: str = "A", source_ip: str = "198.51.100.53") -> None:
    """A query for `name` as the name server receives it from a resolver."""
    wire = dns.message.make_query(name, qtype).to_wire()
    assert stack.responder.respond(wire, source_ip, 40000, "udp") is not None
    await stack.recorder.idle()


async def web_request(stack: Stack, channel_id: str, token: str, raw: bytes, *, method: str, target: str) -> None:
    host = f"{token}-{channel_id}.{ZONE}"
    await _submit(
        stack,
        HttpRecord(
            v=1,
            protocol="http",
            channel_id=channel_id,
            token=token,
            prefix="",
            name=host,
            source_ip="203.0.113.7",
            source_port=51234,
            received_at=format_time(utc_now()),
            port=80,
            tls=False,
            sni=None,
            method=method,
            target=target,
            host=host,
            raw_b64=base64.b64encode(raw).decode(),
            truncated=False,
        ),
    )


async def mail(stack: Stack, channel_id: str, token: str, message: EmailMessage | bytes) -> None:
    raw = message if isinstance(message, bytes) else message.as_bytes()
    domain = f"{token}-{channel_id}.{ZONE}"
    await _submit(
        stack,
        SmtpRecord(
            v=1,
            protocol="smtp",
            channel_id=channel_id,
            token=token,
            prefix="",
            name=domain,
            source_ip="192.0.2.25",
            source_port=40125,
            received_at=format_time(utc_now()),
            helo="mail.sender.example",
            mail_from="sender@sender.example",
            rcpt_to=f"probe@{domain}",
            tls=False,
            raw_b64=base64.b64encode(raw).decode(),
        ),
    )


def sample_message() -> EmailMessage:
    """Text and HTML alternatives, an encoded subject, and a binary attachment."""
    message = EmailMessage()
    message["From"] = "Sender <sender@sender.example>"
    message["To"] = "probe@oob.test"
    message["Subject"] = "Grüße aus Köln"
    message.set_content("Hallo, schöne Grüße.\n", charset="iso-8859-1", cte="quoted-printable")
    message.add_alternative("<p>Hallo</p>\n", subtype="html")
    message.add_attachment(bytes(range(256)), maintype="application", subtype="octet-stream", filename="data.bin")
    return message


async def _submit(stack: Stack, record: HttpRecord | SmtpRecord) -> None:
    stack.recorder.submit(
        Capture(
            channel_id=record.channel_id,
            source_ip=record.source_ip,
            received_at=record.received_at,
            plaintext=record.model_dump_json().encode(),
        )
    )
    await stack.recorder.idle()
