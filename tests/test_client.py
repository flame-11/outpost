"""The client library against an in-process Outpost API, and against answers of the API additions."""

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from client_support import API, OPEN_LIMITS, StackTransport, lookup, mail, sample_message, web_request
from conftest import API_KEY, ZONE, Stack, open_stack

from outpost.client import (
    OutpostError,
    SealedRecord,
    channel_state,
    delete_channel,
    fetch_record,
    key_file_path,
    load_key_file,
    open_record,
    pull,
    register,
)
from outpost.records import DnsRecord, HttpRecord, SmtpRecord


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    async with open_stack(tmp_path / "data", limits=OPEN_LIMITS) as opened:
        yield opened


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture
async def http(stack: Stack) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=StackTransport(stack)) as client:
        yield client


async def all_records(http: httpx.AsyncClient, key_file: object, **options: int) -> list[SealedRecord]:
    return [record async for record in pull(http, key_file, **options)]  # type: ignore[arg-type]


async def test_register_writes_a_private_key_file_under_outpost_home(home: Path, http: httpx.AsyncClient) -> None:
    path = key_file_path("default")
    assert path == home / "channels" / "default.json"
    key_file, answer = await register(http, API, API_KEY, path)
    assert (path.stat().st_mode & 0o777) == 0o600
    saved = json.loads(path.read_text())
    assert saved["api"] == API
    assert saved["channel_id"] == answer.channel_id == key_file.channel_id
    assert {"private_key", "secret"} <= saved.keys()
    assert answer.zone == ZONE
    assert answer.listeners == ["dns", "http"]
    assert (answer.source_rate, answer.channel_rate) == (100_000, 100_000)  # the test instance's limits


async def test_a_repeat_registration_keeps_the_channel(home: Path, http: httpx.AsyncClient) -> None:
    path = key_file_path("again")
    first, _ = await register(http, API, API_KEY, path)
    second, _ = await register(http, API, API_KEY, path)
    assert first == second


async def test_an_explicit_key_file_path_works(tmp_path: Path, http: httpx.AsyncClient) -> None:
    path = tmp_path / "elsewhere" / "channel.json"
    key_file, _ = await register(http, API, API_KEY, path)
    assert load_key_file(path) == key_file


async def test_a_bad_label_is_an_invalid_request(home: Path) -> None:
    with pytest.raises(OutpostError) as caught:
        key_file_path("../escape")
    assert caught.value.code == "invalid_request"


async def test_channel_state_counts_held_records(home: Path, stack: Stack, http: httpx.AsyncClient) -> None:
    key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
    await lookup(stack, f"a1-{key_file.channel_id}.{ZONE}")
    state = await channel_state(http, key_file)
    assert (state.channel_id, state.held_records, state.last_seq) == (key_file.channel_id, 1, 1)


async def test_pull_follows_more_across_pages(home: Path, stack: Stack, http: httpx.AsyncClient) -> None:
    key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
    for index in range(7):
        await lookup(stack, f"p{index}-{key_file.channel_id}.{ZONE}")
    records = await all_records(http, key_file, limit=2)
    assert [record.seq for record in records] == [1, 2, 3, 4, 5, 6, 7]
    assert [record.seq for record in await all_records(http, key_file, after=5, limit=2)] == [6, 7]


async def test_pull_waits_for_a_record_that_arrives(home: Path, stack: Stack, http: httpx.AsyncClient) -> None:
    key_file, _ = await register(http, API, API_KEY, key_file_path("default"))

    async def later() -> None:
        await asyncio.sleep(0.3)
        await lookup(stack, f"w1-{key_file.channel_id}.{ZONE}")

    arrival = asyncio.create_task(later())
    records = await all_records(http, key_file, wait=5)
    await arrival
    assert [open_record(key_file, record).token for record in records] == ["w1"]


async def test_open_record_opens_all_three_kinds(home: Path, stack: Stack, http: httpx.AsyncClient) -> None:
    key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
    channel_id = key_file.channel_id
    assert channel_id is not None
    await lookup(stack, f"Pre.D1-{channel_id}.{ZONE}", "TXT")
    await web_request(stack, channel_id, "h1", b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n", method="GET", target="/x")
    await mail(stack, channel_id, "m1", sample_message())
    opened = [open_record(key_file, record) for record in await all_records(http, key_file)]
    dns_record, http_record, smtp_record = opened
    assert isinstance(dns_record, DnsRecord)
    assert (dns_record.token, dns_record.prefix, dns_record.qtype) == ("d1", "pre", "TXT")
    assert isinstance(http_record, HttpRecord) and http_record.target == "/x"
    assert isinstance(smtp_record, SmtpRecord) and smtp_record.rcpt_to.startswith("probe@m1-")


async def test_a_record_sealed_to_another_key_is_unreadable(home: Path, stack: Stack, http: httpx.AsyncClient) -> None:
    key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
    other, _ = await register(http, API, API_KEY, key_file_path("other"))
    await lookup(stack, f"u1-{key_file.channel_id}.{ZONE}")
    (record,) = await all_records(http, key_file)
    with pytest.raises(OutpostError) as caught:
        open_record(other, record)
    assert caught.value.code == "record_unreadable"


async def test_fetch_record_by_seq(home: Path, stack: Stack, http: httpx.AsyncClient) -> None:
    key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
    for token in ("f1", "f2", "f3"):
        await lookup(stack, f"{token}-{key_file.channel_id}.{ZONE}")
    assert (await fetch_record(http, key_file, 2)).token == "f2"
    with pytest.raises(OutpostError) as caught:
        await fetch_record(http, key_file, 9)
    assert caught.value.code == "record_not_found"


async def test_a_wrong_secret_is_refused_with_the_server_code(home: Path, http: httpx.AsyncClient) -> None:
    key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
    with pytest.raises(OutpostError) as caught:
        await channel_state(http, key_file.model_copy(update={"secret": "wrong"}))
    assert (caught.value.code, caught.value.server_code) == ("outpost_refused", "unauthorized")


async def test_a_wrong_api_key_is_refused(home: Path, http: httpx.AsyncClient) -> None:
    with pytest.raises(OutpostError) as caught:
        await register(http, API, "not-the-key", key_file_path("default"))
    assert (caught.value.code, caught.value.server_code) == ("outpost_refused", "unauthorized")


async def test_an_unreachable_api_is_reported(home: Path) -> None:
    async with httpx.AsyncClient() as http:
        with pytest.raises(OutpostError) as caught:
            await register(http, "http://127.0.0.1:9", API_KEY, key_file_path("default"))
    assert caught.value.code == "outpost_unreachable"


# The API additions: retention_days at registration, rates in the answers, channel deletion, quota_exceeded.

REGISTRATION = {
    "channel_id": "k3v7x2mq6c4a",
    "zone": "oob.example",
    "listeners": ["dns", "http", "https", "smtp"],
    "retention_days": 7,
    "source_rate": 60,
    "channel_rate": 600,
}


def additions_api(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST":
            return httpx.Response(201, json=REGISTRATION)
        if request.method == "DELETE":
            return httpx.Response(204)
        if request.url.path.endswith("/records"):
            body = {"error": {"code": "quota_exceeded", "message": "too many records"}}
            return httpx.Response(429, json=body, headers={"Retry-After": "30"})
        return httpx.Response(200, json=REGISTRATION | {"last_seq": 0, "held_records": 0, "dropped_total": 0})

    return httpx.MockTransport(handle)


async def test_registration_sends_retention_days_and_reads_rates(home: Path) -> None:
    seen: list[httpx.Request] = []
    async with httpx.AsyncClient(transport=additions_api(seen)) as http:
        key_file, answer = await register(http, API, API_KEY, key_file_path("default"), retention_days=7)
        state = await channel_state(http, key_file)
    assert json.loads(seen[0].content)["retention_days"] == 7
    assert (answer.retention_days, answer.source_rate, answer.channel_rate) == (7, 60, 600)
    assert answer.listeners == ["dns", "http", "https", "smtp"]
    assert (state.source_rate, state.channel_rate) == (60, 600)


async def test_registration_without_retention_days_leaves_it_out(home: Path) -> None:
    seen: list[httpx.Request] = []
    async with httpx.AsyncClient(transport=additions_api(seen)) as http:
        await register(http, API, API_KEY, key_file_path("default"))
    assert "retention_days" not in json.loads(seen[0].content)


async def test_delete_channel_sends_the_channel_secret(home: Path) -> None:
    seen: list[httpx.Request] = []
    async with httpx.AsyncClient(transport=additions_api(seen)) as http:
        key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
        await delete_channel(http, key_file)
    assert seen[-1].method == "DELETE"
    assert seen[-1].url.path == "/v1/channels/k3v7x2mq6c4a"
    assert seen[-1].headers["Authorization"] == f"Bearer {key_file.secret}"


async def test_quota_exceeded_is_refused_with_its_code(home: Path) -> None:
    async with httpx.AsyncClient(transport=additions_api([])) as http:
        key_file, _ = await register(http, API, API_KEY, key_file_path("default"))
        with pytest.raises(OutpostError) as caught:
            await all_records(http, key_file)
    assert (caught.value.code, caught.value.server_code) == ("outpost_refused", "quota_exceeded")
    assert "30" in caught.value.message
