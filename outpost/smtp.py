"""The mail receiver (aiosmtpd): accepts messages for channel addresses and records them, sealed.

A recipient is accepted when its domain names an existing channel; the local part is free. One
record per accepted recipient. It never relays, sends or answers mail, and offers no AUTH, VRFY
or EXPN. STARTTLS is offered while a certificate is loaded.
"""

import asyncio
import base64
import logging
import ssl
from collections.abc import Callable
from typing import Any

from aiosmtpd.smtp import SMTP, Envelope, Session

from outpost.addresses import Address, address_from_text
from outpost.config import Limits, Settings
from outpost.recorder import Capture, Drop, Recorder
from outpost.records import SmtpRecord, format_time, utc_now
from outpost.tls import Certificates

TIMEOUT_SECONDS = 60.0
NOT_IMPLEMENTED = "502 5.5.1 Command not implemented"
UNKNOWN_RECIPIENT = "550 5.1.1 Recipient address rejected"
TOO_MANY_RECIPIENTS = "452 4.5.3 Too many recipients"
TOO_BIG = "552 5.3.4 Message too big"
# aiosmtpd's own answers to a message over its data_size_limit, before and after DATA.
_SIZE_REFUSALS = ("552 Error: Too much mail data", "552 Error: message size exceeds fixed maximum message size")

logging.getLogger("mail.log").setLevel(logging.WARNING)  # aiosmtpd logs peers at INFO


class MailHandler:
    """aiosmtpd hooks."""

    def __init__(self, settings: Settings, limits: Limits, recorder: Recorder) -> None:
        self._zone = settings.zone
        self._limits = limits
        self._recorder = recorder

    def address(self, recipient: str) -> Address | None:
        _, at, domain = recipient.rpartition("@")
        if not at:
            return None
        address = address_from_text(domain, self._zone)
        if address is None or not self._recorder.knows(address.channel_id):
            return None
        return address

    async def handle_EHLO(
        self, server: SMTP, session: Session, envelope: Envelope, hostname: str, responses: list[str]
    ) -> list[str]:
        session.host_name = hostname
        return [line for line in responses if not line.startswith("250-AUTH")]

    async def handle_RCPT(
        self, server: SMTP, session: Session, envelope: Envelope, address: str, rcpt_options: list[str]
    ) -> str:
        if len(envelope.rcpt_tos) >= self._limits.mail_max_rcpt:
            return TOO_MANY_RECIPIENTS
        if self.address(address) is None:
            return UNKNOWN_RECIPIENT
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 OK"

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        received_at = format_time(utc_now())
        content = envelope.original_content or b""
        raw_b64 = base64.b64encode(content).decode("ascii")
        peer = session.peer
        source_ip, source_port = (str(peer[0]), int(peer[1])) if isinstance(peer, tuple) else ("", 0)
        for recipient in envelope.rcpt_tos:
            address = self.address(recipient)
            if address is None:
                continue
            record = SmtpRecord(
                v=1,
                protocol="smtp",
                channel_id=address.channel_id,
                token=address.token,
                prefix=address.prefix,
                name=address.name,
                source_ip=source_ip,
                source_port=source_port,
                received_at=received_at,
                helo=session.host_name or "",
                mail_from=envelope.mail_from or "",
                rcpt_to=recipient,
                tls=session.ssl is not None,
                raw_b64=raw_b64,
            )
            self._recorder.submit(
                Capture(
                    channel_id=address.channel_id,
                    source_ip=source_ip,
                    received_at=received_at,
                    plaintext=record.model_dump_json().encode(),
                )
            )
        return "250 2.0.0 OK"

    def refused_too_big(self, envelope: Envelope | None) -> None:
        """A message over MAIL_MAX_BYTES is not stored; it counts as dropped on each recipient."""
        for recipient in envelope.rcpt_tos if envelope is not None else ():
            address = self.address(recipient)
            if address is not None:
                self._recorder.submit(Drop(channel_id=address.channel_id))


class MailSession(SMTP):
    """aiosmtpd with Outpost's answers for the commands it does not serve and for the size cap."""

    def __init__(self, handler: MailHandler, **kwargs: Any) -> None:
        super().__init__(handler, **kwargs)
        self._outpost_handler = handler

    async def push(self, status: Any) -> None:
        text = status.decode() if isinstance(status, bytes) else str(status)
        if text in _SIZE_REFUSALS:
            if text == _SIZE_REFUSALS[0]:
                self._outpost_handler.refused_too_big(self.envelope)
            status = TOO_BIG
        await super().push(status)

    async def smtp_AUTH(self, arg: str) -> None:
        await self.push(NOT_IMPLEMENTED)

    async def smtp_VRFY(self, arg: str) -> None:
        await self.push(NOT_IMPLEMENTED)

    async def smtp_EXPN(self, arg: str) -> None:
        await self.push(NOT_IMPLEMENTED)


def mail_session_factory(
    settings: Settings, limits: Limits, recorder: Recorder, certificates: Certificates | None
) -> Callable[[], MailSession]:
    handler = MailHandler(settings, limits, recorder)
    tls_context: ssl.SSLContext | None = certificates.server_context() if certificates is not None else None

    def build() -> MailSession:
        loaded = certificates is not None and certificates.loaded
        return MailSession(
            handler,
            data_size_limit=limits.mail_max_bytes,
            hostname=settings.mail_host,
            ident="ESMTP",
            tls_context=tls_context if loaded else None,
            timeout=TIMEOUT_SECONDS,
            auth_exclude_mechanism=["LOGIN", "PLAIN"],
            loop=asyncio.get_running_loop(),
        )

    return build
