"""Several clients: named API keys made by `outpost-admin`, their quotas and revocation, and the
bootstrap key OUTPOST_API_KEY_SHA256 named `default`."""

import asyncio
import base64
import hashlib
import sqlite3
from pathlib import Path

import pytest
from conftest import API_KEY, capture_for, make_settings, open_stack, put

from outpost.admin import run_admin
from outpost.config import ConfigError, Limits
from outpost.server import run


def admin(data_dir: Path, *argv: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    status = run_admin(list(argv), {"OUTPOST_DATA_DIR": str(data_dir)})
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def add_key(data_dir: Path, name: str, capsys: pytest.CaptureFixture[str], *options: str) -> str:
    status, out, _ = admin(data_dir, "key", "add", name, *options, capsys=capsys)
    assert status == 0
    (key,) = out.split()
    return key


def listing(data_dir: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, list[str]]:
    status, out, _ = admin(data_dir, "key", "list", capsys=capsys)
    assert status == 0
    rows = [line.split("\t") for line in out.splitlines()]
    assert rows[0] == ["name", "status", "created_at", "max_channels", "channel_rate", "channels"]
    return {row[0]: row[1:] for row in rows[1:]}


async def test_a_named_key_registers_and_is_stored_as_sha256_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = add_key(tmp_path, "alice", capsys)
    connection = sqlite3.connect(tmp_path / "outpost.sqlite3")
    stored = connection.execute("SELECT * FROM api_keys").fetchall()
    connection.close()
    assert key not in repr(stored)
    assert hashlib.sha256(key.encode()).hexdigest() in repr(stored)
    async with open_stack(tmp_path) as stack:
        await stack.register(api_key=key)
        await stack.register(api_key=API_KEY)  # the bootstrap key works beside it
        response, _ = await stack.try_register(api_key=key + "x")
        assert response.status_code == 401
    rows = listing(tmp_path, capsys)
    assert list(rows) == ["alice"]
    assert rows["alice"][0] == "active" and rows["alice"][2:] == ["-", "-", "1"]


async def test_key_add_refusals(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    add_key(tmp_path, "alice", capsys)
    for argv in (("alice",), ("default",), ("Bad Name",), ("bob", "--max-channels", "0")):
        status, out, err = admin(tmp_path, "key", "add", *argv, capsys=capsys)
        assert (status, out) == (1, "")
        assert err.startswith("outpost-admin: ")


async def test_max_channels_quota(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = add_key(tmp_path, "alice", capsys, "--max-channels", "2")
    async with open_stack(tmp_path) as stack:
        first = await stack.register(api_key=key)
        await stack.register(api_key=key)
        response, _ = await stack.try_register(api_key=key)
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "quota_exceeded"
        assert "retry-after" not in response.headers
        repeat = await stack.client.post(
            "/v1/channels",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "public_key": base64.b64encode(first.keys.public_key).decode(),
                "secret_sha256": hashlib.sha256(first.secret.encode()).hexdigest(),
            },
        )
        assert repeat.status_code == 200  # registering an existing channel again is not a new one
        await stack.register(api_key=API_KEY)  # another key's quota is its own
        assert (await stack.client.delete(f"/v1/channels/{first.channel_id}", headers=first.auth)).status_code == 204
        await stack.register(api_key=key)  # a deleted channel frees its place


async def test_channel_rate_quota(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = add_key(tmp_path, "slow", capsys, "--channel-rate", "2")
    async with open_stack(tmp_path, Limits(source_rate=100)) as stack:
        response, channel = await stack.try_register(api_key=key)
        assert response.json()["channel_rate"] == 2
        unlimited = await stack.register(api_key=API_KEY)
        for index in range(4):
            stack.recorder.submit(capture_for(channel, source_ip=f"198.51.100.{index}"))
        await put(stack, unlimited, 4)
        status = (await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)).json()
        assert (status["channel_rate"], status["held_records"], status["dropped_total"]) == (2, 2, 2)
        other = (await stack.client.get(f"/v1/channels/{unlimited.channel_id}", headers=unlimited.auth)).json()
        assert (other["channel_rate"], other["held_records"]) == (600, 4)
    key = add_key(tmp_path, "fast", capsys, "--channel-rate", "5000")
    async with open_stack(tmp_path) as stack:
        response, _ = await stack.try_register(api_key=key)
        assert response.json()["channel_rate"] == 600  # a quota never raises the instance's rate


async def test_revoked_key_cannot_register_and_its_channels_stay(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = add_key(tmp_path, "alice", capsys)
    async with open_stack(tmp_path) as stack:
        channel = await stack.register(api_key=key)
        await put(stack, channel, 2)
        status, out, _ = admin(tmp_path, "key", "revoke", "alice", capsys=capsys)
        assert (status, out) == (0, "revoked alice; 0 channels deleted\n")
        response, _ = await stack.try_register(api_key=key)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthorized"
        assert len((await stack.records(channel))["records"]) == 2
    assert listing(tmp_path, capsys)["alice"][0].startswith("revoked ")


async def test_revoke_with_delete_channels(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    alice, bob = add_key(tmp_path, "alice", capsys), add_key(tmp_path, "bob", capsys)
    async with open_stack(tmp_path) as stack:
        gone = [await stack.register(api_key=alice), await stack.register(api_key=alice)]
        kept = await stack.register(api_key=bob)
        for channel in (*gone, kept):
            await put(stack, channel, 2)
        status, out, _ = admin(tmp_path, "key", "revoke", "alice", "--delete-channels", capsys=capsys)
        assert (status, out) == (0, "revoked alice; 2 channels deleted\n")
        for channel in gone:
            response = await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)
            assert response.json()["error"]["code"] == "channel_not_found"
        await stack.db.refresh_known()
        assert not any(stack.recorder.knows(channel.channel_id) for channel in gone)
        assert len((await stack.records(kept))["records"]) == 2
    connection = sqlite3.connect(tmp_path / "outpost.sqlite3")
    (held,) = connection.execute("SELECT COUNT(*) FROM records").fetchone()
    connection.close()
    assert held == 2
    assert listing(tmp_path, capsys)["alice"][4] == "0"


async def test_revoke_refusals(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for name in ("nobody", "default"):
        status, _, err = admin(tmp_path, "key", "revoke", name, capsys=capsys)
        assert status == 1 and err.startswith("outpost-admin: ")


async def test_server_needs_a_key_from_env_or_store(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    settings = make_settings(tmp_path, api_key_sha256=None)
    with pytest.raises(ConfigError, match="OUTPOST_API_KEY_SHA256"):
        await run(settings, Limits(), asyncio.Event())
    key = add_key(tmp_path, "alice", capsys)
    stop = asyncio.Event()
    ready: asyncio.Future[object] = asyncio.get_running_loop().create_future()
    server = asyncio.create_task(run(settings, Limits(), stop, on_ready=ready.set_result))
    try:
        await asyncio.wait_for(ready, timeout=10)
    finally:
        stop.set()
        await asyncio.wait_for(server, timeout=10)
    async with open_stack(tmp_path, api_key_sha256=None) as stack:
        await stack.register(api_key=key)
        response, _ = await stack.try_register(api_key=API_KEY)
        assert response.status_code == 401  # without OUTPOST_API_KEY_SHA256 there is no bootstrap key
