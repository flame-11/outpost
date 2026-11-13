"""CONTRACT section 10: `GET /v1/key` reports what the operator's API key allows and changes nothing."""

import sqlite3
from pathlib import Path

import httpx
import pytest
from client_support import API, StackTransport
from conftest import API_KEY, ZONE, Stack, open_stack
from test_api import assert_error
from test_keys import add_key, admin

from outpost.client import key_info, register
from outpost.config import Limits
from outpost.models import KeyAnswer


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def snapshot(stack: Stack) -> list[tuple[str, list[tuple[object, ...]]]]:
    connection = sqlite3.connect(stack.settings.data_dir / "outpost.sqlite3")
    try:
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        return [(name, connection.execute(f'SELECT * FROM "{name}"').fetchall()) for name in sorted(tables)]
    finally:
        connection.close()


async def test_bootstrap_key_answer(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(channel_rate=40)) as stack:
        empty = await stack.client.get("/v1/key", headers=bearer(API_KEY))
        assert empty.status_code == 200
        assert empty.json() == {
            "name": "default",
            "zone": ZONE,
            "listeners": ["dns", "http"],
            "responses": False,
            "max_channels": None,
            "channels": 0,
            "channel_rate": 40,
        }
        for _ in range(3):
            await stack.register()
        answer = KeyAnswer.model_validate_json((await stack.client.get("/v1/key", headers=bearer(API_KEY))).content)
        assert answer.channels == 3 and answer.name == "default"


async def test_named_key_with_quota_counts_only_its_own_channels(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = add_key(tmp_path, "alice", capsys, "--max-channels", "5", "--channel-rate", "7")
    async with open_stack(tmp_path, Limits(channel_rate=40), responses=True) as stack:
        await stack.register(api_key=key)
        await stack.register(api_key=key)
        await stack.register(api_key=API_KEY)
        response = await stack.client.get("/v1/key", headers=bearer(key))
        assert response.status_code == 200
        assert response.json() == {
            "name": "alice",
            "zone": ZONE,
            "listeners": ["dns", "http"],
            "responses": True,
            "max_channels": 5,
            "channels": 2,
            "channel_rate": 7,
        }
        assert (await stack.client.get("/v1/key", headers=bearer(API_KEY))).json()["channels"] == 1


async def test_unauthorized_keys_get_401(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = add_key(tmp_path, "alice", capsys)
    async with open_stack(tmp_path) as stack:
        assert_error(await stack.client.get("/v1/key"), 401, "unauthorized")
        assert_error(await stack.client.get("/v1/key", headers=bearer("wrong")), 401, "unauthorized")
        assert (await stack.client.get("/v1/key", headers=bearer(key))).status_code == 200
        status, _, _ = admin(tmp_path, "key", "revoke", "alice", capsys=capsys)
        assert status == 0
        assert_error(await stack.client.get("/v1/key", headers=bearer(key)), 401, "unauthorized")


async def test_failed_authentications_are_rate_limited(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(auth_fail_rate=2)) as stack:
        for _ in range(2):
            assert_error(await stack.client.get("/v1/key", headers=bearer("wrong")), 401, "unauthorized")
        blocked = await stack.client.get("/v1/key", headers=bearer(API_KEY))
        assert_error(blocked, 429, "rate_limited")
        assert int(blocked.headers["retry-after"]) >= 1


async def test_storage_failure_is_503(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing(*_: object) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(stack.db, "key_channel_count", failing)
    assert_error(await stack.client.get("/v1/key", headers=bearer(API_KEY)), 503, "storage_unavailable")


async def test_the_call_changes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = add_key(tmp_path, "alice", capsys)
    async with open_stack(tmp_path) as stack:
        await stack.register(api_key=key)
        before = snapshot(stack)
        for token in (API_KEY, key, "wrong"):
            await stack.client.get("/v1/key", headers=bearer(token))
        assert snapshot(stack) == before


async def test_client_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = add_key(tmp_path, "alice", capsys, "--max-channels", "2")
    async with open_stack(tmp_path) as stack, httpx.AsyncClient(transport=StackTransport(stack)) as http:
        await register(http, API, key, tmp_path / "home" / "a.json")
        info = await key_info(http, API + "/", key)
        assert (info.name, info.zone, info.max_channels, info.channels) == ("alice", ZONE, 2, 1)
        assert info.listeners == ["dns", "http"] and info.responses is False and info.channel_rate >= 1
