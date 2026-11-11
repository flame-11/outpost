import asyncio
import base64
import contextlib
import hashlib
import json
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from pathlib import Path

import httpx
import pytest

from outpost.api import ApiContext, create_app
from outpost.config import Limits, Settings
from outpost.dns import DnsResponder
from outpost.http import HttpListener
from outpost.recorder import Capture, Notifier, Recorder
from outpost.records import OPENED_RECORD, DnsRecord, HttpRecord, format_time, utc_now
from outpost.sealing import KeyPair, new_key_pair, open_sealed
from outpost.store import Database

ZONE = "oob.test"
PUBLIC_IPV4 = "192.0.2.10"
API_KEY = "dev-api-key-for-tests"
EXAMPLES = Path(__file__).resolve().parent.parent / "contract" / "v1" / "examples"


def example(name: str) -> dict[str, object]:
    return json.loads((EXAMPLES / name).read_text())


def make_settings(data_dir: Path, **changes: object) -> Settings:
    settings = Settings(
        zone=ZONE,
        public_ipv4=PUBLIC_IPV4,
        public_ipv6=None,
        bind_ip="127.0.0.1",
        api_key_sha256=hashlib.sha256(API_KEY.encode()).hexdigest(),
        retention_days=90,
        store_max_bytes=21_474_836_480,
        dns_port=0,
        http_port=0,
        api_port=0,
        data_dir=data_dir,
    )
    return replace(settings, **changes)  # type: ignore[arg-type]


@dataclass
class Channel:
    channel_id: str
    keys: KeyPair
    secret: str

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.secret}"}

    def open(self, sealed_b64: str) -> DnsRecord | HttpRecord:
        return OPENED_RECORD.validate_json(open_sealed(self.keys.private_key, base64.b64decode(sealed_b64)))


@dataclass
class Stack:
    settings: Settings
    limits: Limits
    db: Database
    recorder: Recorder
    notifier: Notifier
    client: httpx.AsyncClient
    responder: DnsResponder
    web: HttpListener

    async def register(self) -> Channel:
        keys = new_key_pair()
        secret = secrets.token_hex(32)
        response = await self.client.post(
            "/v1/channels",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={
                "public_key": base64.b64encode(keys.public_key).decode(),
                "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
            },
        )
        assert response.status_code == 201, response.text
        return Channel(channel_id=response.json()["channel_id"], keys=keys, secret=secret)

    async def records(self, channel: Channel, **params: int) -> dict[str, object]:
        response = await self.client.get(
            f"/v1/channels/{channel.channel_id}/records", params=params, headers=channel.auth
        )
        assert response.status_code == 200, response.text
        return response.json()


def capture_for(channel: Channel, token: str = "t1", source_ip: str = "198.51.100.1", raw: bytes = b"GET /") -> Capture:
    """A web request on `channel`, as the web listener hands it to the recorder."""
    received_at = format_time(utc_now())
    record = HttpRecord(
        v=1,
        protocol="http",
        channel_id=channel.channel_id,
        token=token,
        prefix="",
        name=f"{token}-{channel.channel_id}.{ZONE}",
        source_ip=source_ip,
        source_port=1234,
        received_at=received_at,
        port=80,
        tls=False,
        sni=None,
        method="GET",
        target="/",
        host=f"{token}-{channel.channel_id}.{ZONE}",
        raw_b64=base64.b64encode(raw).decode(),
        truncated=False,
    )
    return Capture(
        channel_id=channel.channel_id,
        source_ip=source_ip,
        received_at=received_at,
        plaintext=record.model_dump_json().encode(),
    )


async def put(
    stack: Stack, channel: Channel, count: int, *, source_ip: str = "198.51.100.1", raw: bytes = b"GET /"
) -> None:
    for index in range(count):
        stack.recorder.submit(capture_for(channel, token=f"t{index}", source_ip=source_ip, raw=raw))
    await stack.recorder.idle()


@contextlib.asynccontextmanager
async def open_stack(data_dir: Path, limits: Limits | None = None, **changes: object) -> AsyncIterator[Stack]:
    settings = make_settings(data_dir, **changes)
    limits = limits or Limits()
    db = await Database.open(data_dir / "outpost.sqlite3", limits, settings.store_max_bytes)
    notifier = Notifier()
    recorder = Recorder(db, limits, notifier)
    app = create_app(ApiContext(settings=settings, limits=limits, db=db, notifier=notifier))
    transport = httpx.ASGITransport(app=app)
    recorder_task = asyncio.create_task(recorder.run())
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as client:
            yield Stack(
                settings=settings,
                limits=limits,
                db=db,
                recorder=recorder,
                notifier=notifier,
                client=client,
                responder=DnsResponder(settings, limits, recorder),
                web=HttpListener(settings, limits, recorder),
            )
    finally:
        recorder_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await recorder_task
        await db.close()


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    async with open_stack(tmp_path) as opened:
        yield opened
