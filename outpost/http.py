"""The web listener (CONTRACT section 2): reads raw bytes, answers, closes. The answer is the
response the channel set for the request's token and path (section 9), else a fixed empty 200.

No HTTP library parses the request: a malformed request is exactly what should be recorded. The
same listener serves HTTPS behind a TLS front context; there the pair comes from `Host`, else
from the server name the client sent.
"""

import asyncio
import base64
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from outpost.addresses import Address, address_from_text
from outpost.config import Limits, Settings
from outpost.recorder import Capture, Recorder
from outpost.records import HttpRecord, format_time, utc_now
from outpost.responses import RequestFacts, ServedResponse, request_path
from outpost.tls import server_name

FIXED_ANSWER = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_READ_CHUNK = 65_536


@dataclass(frozen=True, slots=True)
class RequestHead:
    method: str | None
    target: str | None
    host: str | None
    facts: RequestFacts


class ResponseSource(Protocol):
    def response_for(self, channel_id: str, token: str, path: str | None, now: str) -> ServedResponse | None: ...


def _split_head(data: bytes) -> tuple[bytes, bytes] | None:
    for separator in (b"\r\n\r\n", b"\n\n"):
        end = data.find(separator)
        if end >= 0:
            return data[:end], data[end + len(separator) :]
    return None


def _header_lines(head: bytes) -> list[bytes]:
    return [line.rstrip(b"\r") for line in head.split(b"\n")]


def _header(lines: list[bytes], name: bytes) -> bytes | None:
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == name:
            return value.strip()
    return None


def _ascii(value: bytes | None) -> str | None:
    if value is None:
        return None
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        return None


def read_head(data: bytes) -> RequestHead:
    """Request line and `Host` of what arrived; None for any part that is not readable."""
    split = _split_head(data)
    head = split[0] if split is not None else data
    lines = _header_lines(head)
    method = target = None
    parts = lines[0].split(b" ") if lines else []
    if len(parts) == 3 and parts[2].startswith(b"HTTP/"):
        method, target = _ascii(parts[0]) or None, _ascii(parts[1]) or None
    host = _ascii(_header(lines, b"host"))
    private_network = _ascii(_header(lines, b"access-control-request-private-network"))
    facts = RequestFacts(
        method=method,
        origin=_ascii(_header(lines, b"origin")),
        preflight_method=_ascii(_header(lines, b"access-control-request-method")),
        preflight_headers=_ascii(_header(lines, b"access-control-request-headers")),
        private_network=private_network is not None and private_network.lower() == "true",
    )
    return RequestHead(method=method, target=target, host=host, facts=facts)


def request_complete(data: bytes) -> bool:
    """True once the head and the body its headers announce have arrived."""
    split = _split_head(data)
    if split is None:
        return False
    head, body = split
    lines = _header_lines(head)
    encoding = _header(lines, b"transfer-encoding")
    if encoding is not None and b"chunked" in encoding.lower():
        return _chunked_complete(body)
    length = _header(lines, b"content-length")
    if length is not None and length.isdigit():
        return len(body) >= int(length)
    return True


def _chunked_complete(body: bytes) -> bool:
    position = 0
    while True:
        line_end = body.find(b"\r\n", position)
        if line_end < 0:
            return False
        size_text = body[position:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return True  # malformed: nothing more worth waiting for
        if size < 0:
            return True
        if size == 0:
            rest = body[line_end + 2 :]
            return rest.startswith(b"\r\n") or b"\r\n\r\n" in rest
        position = line_end + 2 + size + 2
        if position > len(body):
            return False


def host_without_port(host: str) -> str:
    if host.startswith("["):
        return host  # an IPv6 literal is never in the zone
    name, sep, port = host.rpartition(":")
    return name if sep and port.isdigit() else host


class HttpListener:
    """`responses` is None when the instance serves none (OUTPOST_RESPONSES off)."""

    def __init__(
        self,
        settings: Settings,
        limits: Limits,
        recorder: Recorder,
        responses: ResponseSource | None = None,
        *,
        tls: bool = False,
    ) -> None:
        self._zone = settings.zone
        self._limits = limits
        self._recorder = recorder
        self._responses = responses
        self._tls = tls

    def handler(self) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
        return self._handle

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        local = writer.get_extra_info("sockname")
        sni = server_name(writer.get_extra_info("ssl_object")) if self._tls else None
        try:
            data, truncated = await self._read(reader)
            answer = (
                self._answer_and_capture(data, truncated, str(peer[0]), int(peer[1]), int(local[1]), sni)
                if data
                else FIXED_ANSWER
            )
            with contextlib.suppress(ConnectionError):
                writer.write(answer)
                await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def _read(self, reader: asyncio.StreamReader) -> tuple[bytes, bool]:
        """What arrived within HTTP_READ_SECONDS, at most HTTP_MAX_BYTES, and whether more was sent."""
        data = bytearray()
        limit = self._limits.http_max_bytes
        with contextlib.suppress(TimeoutError, ConnectionError):
            async with asyncio.timeout(self._limits.http_read_seconds):
                while True:
                    chunk = await reader.read(_READ_CHUNK)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > limit:
                        del data[limit:]
                        return bytes(data), True
                    if request_complete(bytes(data)):
                        break
        return bytes(data), False

    def _answer_and_capture(
        self, data: bytes, truncated: bool, source_ip: str, source_port: int, port: int, sni: str | None
    ) -> bytes:
        """Record the request when it names a known channel, and return its answer."""
        head = read_head(data)
        address = address_from_text(host_without_port(head.host), self._zone) if head.host is not None else None
        if address is None and sni is not None:
            address = address_from_text(sni, self._zone)
        if address is None or not self._recorder.knows(address.channel_id):
            return FIXED_ANSWER
        received_at = format_time(utc_now())
        served = self._response(address, head, received_at)
        self._capture(data, truncated, head, address, served, received_at, source_ip, source_port, port, sni)
        return served.render(head.facts) if served is not None else FIXED_ANSWER

    def _response(self, address: Address, head: RequestHead, now: str) -> ServedResponse | None:
        if self._responses is None:
            return None
        return self._responses.response_for(address.channel_id, address.token, request_path(head.target), now)

    def _capture(
        self,
        data: bytes,
        truncated: bool,
        head: RequestHead,
        address: Address,
        served: ServedResponse | None,
        received_at: str,
        source_ip: str,
        source_port: int,
        port: int,
        sni: str | None,
    ) -> None:
        record = HttpRecord(
            v=1,
            protocol="http",
            channel_id=address.channel_id,
            token=address.token,
            prefix=address.prefix,
            name=address.name,
            source_ip=source_ip,
            source_port=source_port,
            received_at=received_at,
            port=port,
            tls=self._tls,
            sni=sni,
            method=head.method,
            target=head.target,
            host=head.host,
            raw_b64=base64.b64encode(data).decode("ascii"),
            truncated=truncated,
            response_id=served.response_id if served is not None else None,
        )
        self._recorder.submit(
            Capture(
                channel_id=address.channel_id,
                source_ip=source_ip,
                received_at=received_at,
                plaintext=record.model_dump_json().encode(),
            )
        )
