"""CONTRACT section 2 (web listener), section 3 (HTTP_MAX_BYTES, HTTP_READ_SECONDS), section 6 (http record)."""

import asyncio
import base64
import contextlib
from collections.abc import AsyncIterator
from pathlib import Path

from conftest import ZONE, Stack, open_stack

from outpost.config import Limits

FIXED = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


@contextlib.asynccontextmanager
async def listening(stack: Stack) -> AsyncIterator[int]:
    server = await asyncio.start_server(stack.web.handler(), "127.0.0.1", 0)
    try:
        yield int(server.sockets[0].getsockname()[1])
    finally:
        server.close()


async def send(port: int, data: bytes, *, close_write: bool = False) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    if close_write:
        writer.write_eof()
    answer = await asyncio.wait_for(reader.read(), timeout=15)
    writer.close()
    return answer


async def test_same_fixed_answer_for_everything(stack: Stack) -> None:
    channel = await stack.register()
    requests = [
        f"GET / HTTP/1.1\r\nHost: t1-{channel.channel_id}.{ZONE}\r\n\r\n".encode(),
        f"DELETE /a/b?c=d HTTP/1.1\r\nHost: t1-aaaaaaaaaaaa.{ZONE}\r\n\r\n".encode(),
        b"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc",
        b"\x16\x03\x01garbage\r\n\r\n",
    ]
    async with listening(stack) as port:
        for request in requests:
            assert await send(port, request) == FIXED


async def test_request_on_a_channel_is_recorded(stack: Stack) -> None:
    channel = await stack.register()
    host = f"Up.T2-{channel.channel_id}.{ZONE}:8080"
    request = f"POST /c?q=1 HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\n\r\nx=1".encode()
    async with listening(stack) as port:
        assert await send(port, request) == FIXED
    await stack.recorder.idle()
    (sealed,) = (await stack.records(channel))["records"]
    record = channel.open(sealed["sealed"])
    assert record.protocol == "http"
    assert (record.token, record.prefix, record.name) == ("t2", "up", f"up.t2-{channel.channel_id}.{ZONE}")
    assert (record.method, record.target, record.host) == ("POST", "/c?q=1", host)
    assert (record.tls, record.sni, record.truncated, record.port) == (False, None, False, port)
    assert base64.b64decode(record.raw_b64) == request
    assert record.source_ip == "127.0.0.1"


async def test_chunked_body_is_read_to_its_end(stack: Stack) -> None:
    channel = await stack.register()
    request = (
        f"POST / HTTP/1.1\r\nHost: t3-{channel.channel_id}.{ZONE}\r\nTransfer-Encoding: chunked\r\n\r\n"
        "3\r\nabc\r\n0\r\n\r\n"
    ).encode()
    async with listening(stack) as port:
        assert await asyncio.wait_for(send(port, request), timeout=5) == FIXED
    await stack.recorder.idle()
    (sealed,) = (await stack.records(channel))["records"]
    assert base64.b64decode(channel.open(sealed["sealed"]).raw_b64) == request


async def test_request_past_http_max_bytes_is_truncated(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(http_max_bytes=100)) as stack:
        channel = await stack.register()
        head = f"POST / HTTP/1.1\r\nHost: t4-{channel.channel_id}.{ZONE}\r\nContent-Length: 500\r\n\r\n".encode()
        request = head + b"z" * 500
        async with listening(stack) as port:
            assert await send(port, request) == FIXED
        await stack.recorder.idle()
        (sealed,) = (await stack.records(channel))["records"]
        record = channel.open(sealed["sealed"])
        assert record.truncated is True
        assert base64.b64decode(record.raw_b64) == request[:100]


async def test_request_of_exactly_http_max_bytes_is_not_truncated(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(http_max_bytes=200)) as stack:
        channel = await stack.register()
        head = f"POST / HTTP/1.1\r\nHost: t5-{channel.channel_id}.{ZONE}\r\nContent-Length: ".encode()
        body_length = 200 - len(head) - len(b"NNN\r\n\r\n")
        request = head + f"{body_length:03d}\r\n\r\n".encode() + b"y" * body_length
        assert len(request) == 200
        async with listening(stack) as port:
            assert await send(port, request) == FIXED
        await stack.recorder.idle()
        (sealed,) = (await stack.records(channel))["records"]
        assert channel.open(sealed["sealed"]).truncated is False


async def test_what_arrived_within_http_read_seconds_is_recorded(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(http_read_seconds=0.5)) as stack:
        channel = await stack.register()
        partial = f"POST / HTTP/1.1\r\nHost: t6-{channel.channel_id}.{ZONE}\r\nContent-Length: 50\r\n\r\nonly".encode()
        async with listening(stack) as port:
            loop = asyncio.get_running_loop()
            started = loop.time()
            assert await send(port, partial) == FIXED
            assert loop.time() - started < 5
        await stack.recorder.idle()
        (sealed,) = (await stack.records(channel))["records"]
        record = channel.open(sealed["sealed"])
        assert base64.b64decode(record.raw_b64) == partial
        assert record.method == "POST"


async def test_unreadable_request_line_is_null(stack: Stack) -> None:
    channel = await stack.register()
    request = f"\x01\x02\r\nHost: t7-{channel.channel_id}.{ZONE}\r\n\r\n".encode()
    async with listening(stack) as port:
        assert await send(port, request) == FIXED
    await stack.recorder.idle()
    (sealed,) = (await stack.records(channel))["records"]
    record = channel.open(sealed["sealed"])
    assert (record.method, record.target) == (None, None)


async def test_unknown_channel_and_other_hosts_store_nothing(stack: Stack) -> None:
    channel = await stack.register()
    requests = [
        f"GET / HTTP/1.1\r\nHost: t1-aaaaaaaaaaaa.{ZONE}\r\n\r\n".encode(),
        f"GET / HTTP/1.1\r\nHost: t1-{channel.channel_id}.other.example\r\n\r\n".encode(),
        f"GET /t1-{channel.channel_id}.{ZONE} HTTP/1.1\r\n\r\n".encode(),  # no Host
        f"GET / HTTP/1.1\r\nHost: api.{ZONE}\r\n\r\n".encode(),
    ]
    async with listening(stack) as port:
        for request in requests:
            assert await send(port, request) == FIXED
    await stack.recorder.idle()
    assert (await stack.records(channel))["records"] == []
