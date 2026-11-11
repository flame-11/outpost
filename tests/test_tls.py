"""The certificate and HTTPS: the web listener behind TLS (pair from Host, else from the server
name), the API over TLS, and a reload when the certificate files change."""

import asyncio
import contextlib
import os
import ssl
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from conftest import (
    API_KEY,
    ZONE,
    Stack,
    certificate_serial,
    client_tls_context,
    make_certificate,
    make_settings,
)

from outpost.config import ConfigError, Limits
from outpost.http import FIXED_ANSWER, HttpListener
from outpost.server import BoundPorts, run
from outpost.tls import Certificates, watch_certificates


@contextlib.asynccontextmanager
async def https_listening(stack: Stack, certificates: Certificates) -> AsyncIterator[int]:
    listener = HttpListener(
        stack.settings, stack.limits, stack.recorder, stack.db if stack.settings.responses else None, tls=True
    )
    server = await asyncio.start_server(listener.handler(), "127.0.0.1", 0, ssl=certificates.server_context())
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()


async def https_send(port: int, data: bytes, server_name: str | None) -> tuple[bytes, bytes]:
    """The answer and the server's certificate (DER)."""
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=client_tls_context(), server_hostname=server_name or ""
    )
    certificate = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    writer.write(data)
    await writer.drain()
    answer = await asyncio.wait_for(reader.read(), timeout=10)
    writer.close()
    return answer, certificate


async def loaded(paths_dir: Path, serial: int = 1) -> Certificates:
    certificates = Certificates(make_certificate(paths_dir, serial=serial))
    assert await certificates.reload_if_changed()
    return certificates


async def test_https_pair_from_host(stack: Stack, tmp_path: Path) -> None:
    channel = await stack.register()
    certificates = await loaded(tmp_path / "certs")
    host = f"t1-{channel.channel_id}.{ZONE}"
    async with https_listening(stack, certificates) as port:
        answer, _ = await https_send(port, f"GET /s HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(), f"other.{ZONE}")
        assert answer == FIXED_ANSWER
    await stack.recorder.idle()
    (sealed,) = (await stack.records(channel))["records"]
    record = channel.open(sealed["sealed"])
    assert record.protocol == "http"
    assert (record.tls, record.sni, record.port) == (True, f"other.{ZONE}", port)
    assert (record.token, record.host, record.target) == ("t1", host, "/s")


async def test_https_pair_from_the_server_name_without_host(stack: Stack, tmp_path: Path) -> None:
    channel = await stack.register()
    certificates = await loaded(tmp_path / "certs")
    sni = f"up.t2-{channel.channel_id}.{ZONE}"
    async with https_listening(stack, certificates) as port:
        answer, _ = await https_send(port, b"GET / HTTP/1.0\r\n\r\n", sni)
        assert answer == FIXED_ANSWER
        await https_send(port, b"GET / HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n", sni)  # Host outside the zone
        await https_send(port, b"GET / HTTP/1.0\r\n\r\n", None)  # neither: not stored
    await stack.recorder.idle()
    records = [channel.open(r["sealed"]) for r in (await stack.records(channel))["records"]]
    assert [(r.token, r.prefix, r.sni, r.tls) for r in records] == [("t2", "up", sni, True)] * 2
    assert [r.host for r in records] == [None, "192.0.2.10"]


async def test_https_speaks_http_1_1_only(stack: Stack, tmp_path: Path) -> None:
    certificates = await loaded(tmp_path / "certs")
    async with https_listening(stack, certificates) as port:
        for offered, selected in ((["h2", "http/1.1"], "http/1.1"), (["h2"], None)):
            context = client_tls_context()
            context.set_alpn_protocols(offered)
            _, writer = await asyncio.open_connection("127.0.0.1", port, ssl=context, server_hostname=ZONE)
            assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == selected
            writer.close()


async def test_certificate_reload_on_file_change_without_restart(stack: Stack, tmp_path: Path) -> None:
    certificates = await loaded(tmp_path / "certs", serial=1)
    async with https_listening(stack, certificates) as port:
        _, first = await https_send(port, b"GET / HTTP/1.0\r\n\r\n", ZONE)
        assert certificate_serial(first) == 1
        assert not await certificates.reload_if_changed()  # unchanged files
        make_certificate(tmp_path / "certs", serial=2)
        os.utime(tmp_path / "certs" / "fullchain.pem", ns=(1, 1))  # a change even within one clock tick
        assert await certificates.reload_if_changed()
        _, second = await https_send(port, b"GET / HTTP/1.0\r\n\r\n", ZONE)
        assert certificate_serial(second) == 2


async def test_files_that_do_not_load_keep_the_loaded_certificate(stack: Stack, tmp_path: Path) -> None:
    certificates = await loaded(tmp_path / "certs", serial=1)
    (tmp_path / "certs" / "privkey.pem").write_bytes(b"not a key")
    assert not await certificates.reload_if_changed()
    async with https_listening(stack, certificates) as port:
        _, served = await https_send(port, b"GET / HTTP/1.0\r\n\r\n", ZONE)
        assert certificate_serial(served) == 1
    make_certificate(tmp_path / "certs", serial=3)
    assert await certificates.reload_if_changed()  # tried again, and taken once the pair loads


async def test_the_watch_task_reloads(tmp_path: Path) -> None:
    certificates = await loaded(tmp_path / "certs", serial=1)
    watcher = asyncio.create_task(watch_certificates(certificates, interval=0.05))
    try:
        stamp = certificates._stamp
        make_certificate(tmp_path / "certs", serial=4)
        os.utime(tmp_path / "certs" / "fullchain.pem", ns=(2, 2))
        for _ in range(100):
            if certificates._stamp != stamp:
                break
            await asyncio.sleep(0.05)
        assert certificates._stamp != stamp
    finally:
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher


@contextlib.asynccontextmanager
async def serving(settings: object, limits: Limits | None = None) -> AsyncIterator[BoundPorts]:
    stop = asyncio.Event()
    ready: asyncio.Future[BoundPorts] = asyncio.get_running_loop().create_future()
    server = asyncio.create_task(run(settings, limits or Limits(), stop, on_ready=ready.set_result))  # type: ignore[arg-type]
    try:
        yield await asyncio.wait_for(ready, timeout=10)
    finally:
        stop.set()
        await asyncio.wait_for(server, timeout=10)


async def test_server_with_files_serves_https_and_the_api_over_tls(tmp_path: Path) -> None:
    paths = make_certificate(tmp_path / "operator")
    settings = make_settings(tmp_path / "data", tls="files", tls_cert=paths.cert, tls_key=paths.key, https_port=0)
    async with serving(settings) as ports:
        assert ports.https is not None
        api = f"https://127.0.0.1:{ports.api}"
        async with httpx.AsyncClient(base_url=api, verify=client_tls_context()) as client:
            assert (await client.get("/v1/health")).json()["status"] == "ok"
            import base64
            import hashlib

            from outpost.sealing import new_key_pair

            keys = new_key_pair()
            registered = await client.post(
                "/v1/channels",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json={
                    "public_key": base64.b64encode(keys.public_key).decode(),
                    "secret_sha256": hashlib.sha256(b"s").hexdigest(),
                },
            )
            assert registered.status_code == 201
            assert registered.json()["listeners"] == ["dns", "http", "https"]
            channel_id = registered.json()["channel_id"]
            answer, _ = await https_send(
                ports.https, f"GET / HTTP/1.1\r\nHost: a1-{channel_id}.{ZONE}\r\n\r\n".encode(), f"api.{ZONE}"
            )
            assert answer == FIXED_ANSWER
            for _ in range(50):
                status = await client.get(f"/v1/channels/{channel_id}", headers={"Authorization": "Bearer s"})
                if status.json()["held_records"] == 1:
                    break
                await asyncio.sleep(0.1)
            assert status.json()["held_records"] == 1
        with pytest.raises(httpx.HTTPError):
            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{ports.api}") as plain:
                await plain.get("/v1/health")


async def test_files_mode_fails_at_start_when_the_files_do_not_load(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path / "data", tls="files", tls_cert=tmp_path / "none.pem", tls_key=tmp_path / "none.key", https_port=0
    )
    with pytest.raises(ConfigError, match="OUTPOST_TLS_CERT"):
        await run(settings, Limits(), asyncio.Event())


async def test_no_handshake_before_a_certificate_is_loaded(stack: Stack, tmp_path: Path) -> None:
    certificates = Certificates(make_certificate(tmp_path))  # files present, not loaded yet
    async with https_listening(stack, certificates) as port:
        with pytest.raises((ssl.SSLError, ConnectionError)):
            await https_send(port, b"GET / HTTP/1.0\r\n\r\n", ZONE)
