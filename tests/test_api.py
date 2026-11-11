"""CONTRACT sections 4 and 5: authentication, errors, registration, the channel answer and pulls."""

import asyncio
import base64
import hashlib
import sqlite3
from pathlib import Path

import httpx
import pytest
from conftest import API_KEY, ZONE, Stack, capture_for, open_stack, put

from outpost.config import Limits
from outpost.models import ErrorBody, HealthAnswer
from outpost.sealing import new_key_pair

API_AUTH = {"Authorization": f"Bearer {API_KEY}"}


def registration_body(public_key: bytes, secret: str) -> dict[str, str]:
    return {
        "public_key": base64.b64encode(public_key).decode(),
        "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
    }


def assert_error(response: httpx.Response, status: int, code: str) -> ErrorBody:
    assert response.status_code == status, response.text
    body = ErrorBody.model_validate_json(response.content)
    assert body.error.code == code
    return body


async def test_health_needs_no_authentication(stack: Stack) -> None:
    response = await stack.client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "contract": 1, "store_full": False}
    HealthAnswer.model_validate_json(response.content)


async def test_registration_needs_the_api_key(stack: Stack) -> None:
    body = registration_body(new_key_pair().public_key, "s")
    assert_error(await stack.client.post("/v1/channels", json=body), 401, "unauthorized")
    wrong = {"Authorization": "Bearer not-the-key"}
    assert_error(await stack.client.post("/v1/channels", json=body, headers=wrong), 401, "unauthorized")
    basic = {"Authorization": f"Basic {API_KEY}"}
    assert_error(await stack.client.post("/v1/channels", json=body, headers=basic), 401, "unauthorized")


async def test_registration_answer_and_idempotent_repeat(stack: Stack) -> None:
    keys = new_key_pair()
    body = registration_body(keys.public_key, "secret-1")
    first = await stack.client.post("/v1/channels", json=body, headers=API_AUTH)
    assert first.status_code == 201
    answer = first.json()
    assert answer["zone"] == ZONE
    assert answer["listeners"] == ["dns", "http"]
    assert answer["retention_days"] == 90
    assert len(answer["channel_id"]) == 12 and set(answer["channel_id"]) <= set("abcdefghijklmnopqrstuvwxyz234567")
    repeat = await stack.client.post("/v1/channels", json=body, headers=API_AUTH)
    assert repeat.status_code == 200
    assert repeat.json() == answer


async def test_registration_with_another_secret_conflicts(stack: Stack) -> None:
    keys = new_key_pair()
    first = await stack.client.post("/v1/channels", json=registration_body(keys.public_key, "a"), headers=API_AUTH)
    assert first.status_code == 201
    response = await stack.client.post("/v1/channels", json=registration_body(keys.public_key, "b"), headers=API_AUTH)
    assert_error(response, 409, "channel_conflict")


async def test_each_key_gets_its_own_channel(stack: Stack) -> None:
    first, second = await stack.register(), await stack.register()
    assert first.channel_id != second.channel_id


async def test_malformed_registration_names_the_field(stack: Stack) -> None:
    good = registration_body(new_key_pair().public_key, "s")
    cases = {
        "public_key": {**good, "public_key": base64.b64encode(b"short").decode()},
        "secret_sha256": {**good, "secret_sha256": "zz"},
    }
    for field, body in cases.items():
        response = await stack.client.post("/v1/channels", json=body, headers=API_AUTH)
        assert field in assert_error(response, 422, "invalid_request").error.message
    missing = assert_error(
        await stack.client.post("/v1/channels", json={"public_key": good["public_key"]}, headers=API_AUTH),
        422,
        "invalid_request",
    )
    assert "secret_sha256" in missing.error.message


async def test_channel_answer(stack: Stack) -> None:
    channel = await stack.register()
    await put(stack, channel, 2)
    response = await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)
    assert response.status_code == 200
    assert response.json() == {
        "channel_id": channel.channel_id,
        "zone": ZONE,
        "listeners": ["dns", "http"],
        "retention_days": 90,
        "last_seq": 2,
        "held_records": 2,
        "dropped_total": 0,
    }


async def test_channel_routes_need_the_channel_secret(stack: Stack) -> None:
    channel, other = await stack.register(), await stack.register()
    for path in (f"/v1/channels/{channel.channel_id}", f"/v1/channels/{channel.channel_id}/records"):
        assert_error(await stack.client.get(path), 401, "unauthorized")
        assert_error(await stack.client.get(path, headers=other.auth), 401, "unauthorized")
        assert_error(await stack.client.get(path, headers=API_AUTH), 401, "unauthorized")
        assert (await stack.client.get(path, headers=channel.auth)).status_code == 200


async def test_unknown_channel_is_not_found(stack: Stack) -> None:
    channel = await stack.register()
    for channel_id in ("aaaaaaaaaaaa", "not-an-id"):
        for path in (f"/v1/channels/{channel_id}", f"/v1/channels/{channel_id}/records"):
            assert_error(await stack.client.get(path, headers=channel.auth), 404, "channel_not_found")


async def test_auth_fail_rate_answers_429_with_retry_after(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(auth_fail_rate=3)) as stack:
        channel = await stack.register()
        wrong = {"Authorization": "Bearer wrong"}
        for _ in range(3):
            response = await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=wrong)
            assert_error(response, 401, "unauthorized")
        blocked = await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)
        assert_error(blocked, 429, "rate_limited")
        assert 1 <= int(blocked.headers["retry-after"]) <= 60
        body = registration_body(new_key_pair().public_key, "s")
        assert_error(await stack.client.post("/v1/channels", json=body, headers=API_AUTH), 429, "rate_limited")
        assert (await stack.client.get("/v1/health")).status_code == 200


async def test_records_cursor_and_more(stack: Stack) -> None:
    channel = await stack.register()
    await put(stack, channel, 5)
    page = await stack.records(channel, limit=2)
    assert [r["seq"] for r in page["records"]] == [1, 2]
    assert page["more"] is True
    page = await stack.records(channel, after=2, limit=2)
    assert [r["seq"] for r in page["records"]] == [3, 4]
    assert page["more"] is True
    page = await stack.records(channel, after=4)
    assert [r["seq"] for r in page["records"]] == [5]
    assert page["more"] is False
    assert (await stack.records(channel, after=5))["records"] == []
    tokens = [channel.open(r["sealed"]).token for r in (await stack.records(channel))["records"]]
    assert tokens == ["t0", "t1", "t2", "t3", "t4"]


async def test_pulling_does_not_delete(stack: Stack) -> None:
    channel = await stack.register()
    await put(stack, channel, 1)
    assert (await stack.records(channel))["records"] == (await stack.records(channel))["records"]


async def test_limit_defaults_to_100_and_is_lowered_to_200(tmp_path: Path) -> None:
    # SOURCE_RATE would store only 60 of these from one source; the page limits are what is under test.
    async with open_stack(tmp_path, Limits(source_rate=1000, channel_rate=1000)) as stack:
        channel = await stack.register()
        await put(stack, channel, 205)
        default = await stack.records(channel)
        assert len(default["records"]) == 100 and default["more"] is True
        capped = await stack.records(channel, limit=1000)
        assert len(capped["records"]) == 200 and capped["more"] is True


async def test_pull_max_bytes_caps_a_page_but_returns_at_least_one(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(pull_max_bytes=1500)) as stack:
        channel = await stack.register()
        await put(stack, channel, 4, raw=b"x" * 600)
        page = await stack.records(channel)
        sizes = [len(base64.b64decode(r["sealed"])) for r in page["records"]]
        assert 1 <= len(sizes) < 4 and sum(sizes) <= 1500
        assert page["more"] is True
    async with open_stack(tmp_path / "small", Limits(pull_max_bytes=10)) as stack:
        channel = await stack.register()
        await put(stack, channel, 2)
        page = await stack.records(channel)
        assert [r["seq"] for r in page["records"]] == [1]
        assert page["more"] is True


async def test_invalid_query_values(stack: Stack) -> None:
    channel = await stack.register()
    path = f"/v1/channels/{channel.channel_id}/records"
    for params in ({"after": -1}, {"limit": 0}, {"wait": -1}, {"after": "x"}):
        response = await stack.client.get(path, params=params, headers=channel.auth)
        assert next(iter(params)) in assert_error(response, 422, "invalid_request").error.message


async def test_wait_returns_when_a_record_is_stored(stack: Stack) -> None:
    channel = await stack.register()
    loop = asyncio.get_running_loop()
    started = loop.time()
    pull = asyncio.create_task(stack.records(channel, wait=10))
    await asyncio.sleep(0.3)
    assert not pull.done()
    stack.recorder.submit(capture_for(channel))
    page = await asyncio.wait_for(pull, timeout=5)
    assert [r["seq"] for r in page["records"]] == [1]
    assert loop.time() - started < 5


async def test_wait_ends_after_its_seconds_and_is_lowered_to_the_limit(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(pull_max_wait_seconds=1)) as stack:
        channel = await stack.register()
        loop = asyncio.get_running_loop()
        started = loop.time()
        page = await stack.records(channel, wait=60)
        elapsed = loop.time() - started
        assert page["records"] == []
        assert 0.9 <= elapsed < 5


async def test_dropped_total_in_pages(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(channel_max_records=1)) as stack:
        channel = await stack.register()
        await put(stack, channel, 3)
        page = await stack.records(channel)
        assert len(page["records"]) == 1
        assert page["dropped_total"] == 2


async def test_storage_failure_is_503(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    channel = await stack.register()

    async def failing_page(*_: object) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(stack.db, "page", failing_page)
    response = await stack.client.get(f"/v1/channels/{channel.channel_id}/records", headers=channel.auth)
    assert_error(response, 503, "storage_unavailable")
