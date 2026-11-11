"""The mail receiver: recipients whose domain names a channel are accepted, others refused; the size
and recipient caps; AUTH, VRFY and EXPN refused; STARTTLS with a loaded certificate; one sealed
record per accepted recipient; nothing relayed."""

import asyncio
import base64
import contextlib
import hashlib
import smtplib
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from conftest import API_KEY, ZONE, Stack, client_tls_context, make_certificate, make_settings, open_stack

from outpost.config import Limits
from outpost.sealing import new_key_pair
from outpost.server import BoundPorts, run
from outpost.smtp import mail_session_factory
from outpost.tls import Certificates

MESSAGE = b"From: a@sender.example\r\nTo: x\r\nSubject: probe\r\n\r\nbody line\r\n"


@contextlib.asynccontextmanager
async def mail_listening(stack: Stack, certificates: Certificates | None = None) -> AsyncIterator[int]:
    loop = asyncio.get_running_loop()
    factory = mail_session_factory(stack.settings, stack.limits, stack.recorder, certificates)
    server = await loop.create_server(factory, "127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()


def session(port: int) -> smtplib.SMTP:
    return smtplib.SMTP("127.0.0.1", port, local_hostname="client.sender.example", timeout=10)


def converse(port: int, steps: list[tuple[str, str]]) -> list[tuple[int, bytes]]:
    """Run raw commands; returns each reply."""
    with session(port) as client:
        replies = []
        for command, argument in steps:
            replies.append(client.docmd(command, argument))
        return replies


async def test_greeting_and_ehlo_without_auth(stack: Stack) -> None:
    async with mail_listening(stack) as port:

        def check() -> tuple[bytes, int, bytes]:
            client = smtplib.SMTP(timeout=10)
            code, greeting = client.connect("127.0.0.1", port)
            assert code == 220
            ehlo_code, features = client.ehlo("client.sender.example")
            client.quit()
            return greeting, ehlo_code, features

        greeting, code, features = await asyncio.to_thread(check)
    assert greeting == f"mx.{ZONE} ESMTP".encode()
    assert code == 250
    assert b"AUTH" not in features and b"STARTTLS" not in features


async def test_recipients_accepted_only_for_existing_channels(stack: Stack) -> None:
    channel = await stack.register()
    async with mail_listening(stack) as port:
        replies = await asyncio.to_thread(
            converse,
            port,
            [
                ("EHLO", "client.sender.example"),
                ("MAIL", "FROM:<a@sender.example>"),
                ("RCPT", f"TO:<anyone@t1-{channel.channel_id}.{ZONE}>"),
                ("RCPT", f"TO:<anyone@sub.t2-{channel.channel_id}.{ZONE}>"),
                ("RCPT", f"TO:<anyone@t1-aaaaaaaaaaaa.{ZONE}>"),
                ("RCPT", f"TO:<anyone@{ZONE}>"),
                ("RCPT", f"TO:<anyone@mx.{ZONE}>"),
                ("RCPT", "TO:<anyone@elsewhere.example>"),
                ("RCPT", "TO:<postmaster>"),
            ],
        )
    codes = [code for code, _ in replies[2:]]
    assert codes == [250, 250, 550, 550, 550, 550, 550]
    assert all(text.startswith(b"5.1.1") for code, text in replies[2:] if code == 550)


async def test_more_than_ten_recipients_are_refused(stack: Stack) -> None:
    channel = await stack.register()
    steps = [("EHLO", "c.example"), ("MAIL", "FROM:<a@sender.example>")]
    steps += [("RCPT", f"TO:<r{index}@t{index}-{channel.channel_id}.{ZONE}>") for index in range(11)]
    async with mail_listening(stack) as port:
        replies = await asyncio.to_thread(converse, port, steps)
    codes = [code for code, _ in replies[2:]]
    assert codes[:10] == [250] * 10
    assert codes[10] >= 400


async def test_auth_vrfy_expn_are_not_implemented(stack: Stack) -> None:
    channel = await stack.register()
    async with mail_listening(stack) as port:
        replies = await asyncio.to_thread(
            converse,
            port,
            [
                ("EHLO", "c.example"),
                ("AUTH", "PLAIN AGFAYg=="),
                ("VRFY", f"a@t1-{channel.channel_id}.{ZONE}"),
                ("EXPN", "list"),
            ],
        )
    assert [code for code, _ in replies[1:]] == [502, 502, 502]


async def test_message_is_one_sealed_record_per_accepted_recipient(stack: Stack) -> None:
    first, second = await stack.register(), await stack.register()
    recipients = [f"Box@Up.T1-{first.channel_id}.{ZONE}", f"other@t2-{second.channel_id}.{ZONE}"]
    async with mail_listening(stack) as port:

        def send() -> dict[str, tuple[int, bytes]]:
            with session(port) as client:
                return client.sendmail("Sender@Sender.example", [*recipients, "x@elsewhere.example"], MESSAGE)

        refused = await asyncio.to_thread(send)
    assert list(refused) == ["x@elsewhere.example"]
    await stack.recorder.idle()
    (one,) = (await stack.records(first))["records"]
    (two,) = (await stack.records(second))["records"]
    record = first.open(one["sealed"])
    assert record.protocol == "smtp"
    assert (record.channel_id, record.token, record.prefix) == (first.channel_id, "t1", "up")
    assert record.name == f"up.t1-{first.channel_id}.{ZONE}"
    assert (record.helo, record.mail_from, record.rcpt_to) == (
        "client.sender.example",
        "Sender@Sender.example",
        recipients[0],
    )
    assert record.tls is False
    assert record.source_ip == "127.0.0.1" and record.source_port > 0
    assert base64.b64decode(record.raw_b64) == MESSAGE
    other = second.open(two["sealed"])
    assert (other.rcpt_to, other.token, other.raw_b64) == (recipients[1], "t2", record.raw_b64)


async def test_oversized_message_is_refused_and_counted_as_dropped(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(mail_max_bytes=1000)) as stack:
        channel = await stack.register()
        async with mail_listening(stack) as port:

            def send() -> tuple[int, bytes]:
                with session(port) as client:
                    client.ehlo()
                    client.mail("a@sender.example")
                    client.rcpt(f"r@t1-{channel.channel_id}.{ZONE}")
                    return client.data(b"Subject: big\r\n\r\n" + (b"x" * 78 + b"\r\n") * 30)

            code, text = await asyncio.to_thread(send)
        assert (code, text.split()[0]) == (552, b"5.3.4")
        await stack.recorder.idle()
        status = (await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)).json()
        assert (status["held_records"], status["dropped_total"]) == (0, 1)


async def test_starttls_with_a_loaded_certificate(stack: Stack, tmp_path: Path) -> None:
    channel = await stack.register()
    certificates = Certificates(make_certificate(tmp_path / "certs"))
    async with mail_listening(stack, certificates) as port:

        def offered() -> bool:
            with session(port) as client:
                client.ehlo()
                return client.has_extn("starttls")

        assert not await asyncio.to_thread(offered)  # no certificate loaded yet
        assert await certificates.reload_if_changed()

        def send() -> tuple[bool, bytes]:
            with session(port) as client:
                client.ehlo()
                assert client.has_extn("starttls")
                client.starttls(context=client_tls_context())
                client.ehlo()
                features = str(client.esmtp_features).encode()
                client.sendmail("a@sender.example", [f"r@t3-{channel.channel_id}.{ZONE}"], MESSAGE)
                return client.has_extn("starttls"), features

        again, features = await asyncio.to_thread(send)
    assert not again and b"auth" not in features
    await stack.recorder.idle()
    (sealed,) = (await stack.records(channel))["records"]
    assert channel.open(sealed["sealed"]).tls is True


async def test_rate_limits_apply_to_mail(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(source_rate=1)) as stack:
        channel = await stack.register()
        async with mail_listening(stack) as port:

            def send_twice() -> None:
                with session(port) as client:
                    for _ in range(2):
                        client.sendmail("a@sender.example", [f"r@t1-{channel.channel_id}.{ZONE}"], MESSAGE)

            await asyncio.to_thread(send_twice)
        await stack.recorder.idle()
        status = (await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)).json()
        assert (status["held_records"], status["dropped_total"]) == (1, 1)


@pytest.mark.parametrize("command", ["MAIL", "RCPT", "DATA"])
async def test_mail_commands_need_helo_first(stack: Stack, command: str) -> None:
    async with mail_listening(stack) as port:
        ((code, _),) = await asyncio.to_thread(converse, port, [(command, "")])
    assert code >= 500


async def test_server_runs_the_mail_receiver_and_reports_it(tmp_path: Path) -> None:
    paths = make_certificate(tmp_path / "operator")
    settings = make_settings(
        tmp_path / "data", smtp=True, smtp_port=0, tls="files", tls_cert=paths.cert, tls_key=paths.key, https_port=0
    )
    stop = asyncio.Event()
    ready: asyncio.Future[BoundPorts] = asyncio.get_running_loop().create_future()
    server = asyncio.create_task(run(settings, Limits(), stop, on_ready=ready.set_result))
    try:
        ports = await asyncio.wait_for(ready, timeout=10)
        assert ports.smtp is not None
        async with httpx.AsyncClient(base_url=f"https://127.0.0.1:{ports.api}", verify=client_tls_context()) as api:
            keys = new_key_pair()
            registered = await api.post(
                "/v1/channels",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json={
                    "public_key": base64.b64encode(keys.public_key).decode(),
                    "secret_sha256": hashlib.sha256(b"s").hexdigest(),
                },
            )
            assert registered.json()["listeners"] == ["dns", "http", "https", "smtp"]
            channel_id = registered.json()["channel_id"]
            smtp_port = ports.smtp

            def send() -> None:
                with session(smtp_port) as client:
                    client.starttls(context=client_tls_context())
                    client.sendmail("a@sender.example", [f"r@t1-{channel_id}.{ZONE}"], MESSAGE)

            await asyncio.to_thread(send)
            for _ in range(50):
                status = await api.get(f"/v1/channels/{channel_id}", headers={"Authorization": "Bearer s"})
                if status.json()["held_records"] == 1:
                    break
                await asyncio.sleep(0.1)
            assert status.json()["held_records"] == 1
    finally:
        stop.set()
        await asyncio.wait_for(server, timeout=10)
