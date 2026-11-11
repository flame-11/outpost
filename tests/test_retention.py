"""CONTRACT section 3, retention: records go `retention_days` after they arrive; a channel goes
once its last authenticated call and its newest record are both older than that."""

import base64
import hashlib
from datetime import timedelta
from pathlib import Path

from conftest import API_KEY, Stack, capture_for, open_stack, put

from outpost.recorder import Capture
from outpost.records import format_time, utc_now
from outpost.store import run_retention_once


def aged(capture: Capture, days: float) -> Capture:
    """The same interaction, received `days` ago."""
    received_at = format_time(utc_now() - timedelta(days=days))
    plaintext = capture.plaintext.replace(capture.received_at.encode(), received_at.encode())
    return Capture(
        channel_id=capture.channel_id, source_ip=capture.source_ip, received_at=received_at, plaintext=plaintext
    )


async def test_zero_days_keeps_nothing(tmp_path: Path) -> None:
    async with open_stack(tmp_path, retention_days=0) as stack:
        channel = await stack.register()
        await put(stack, channel, 3)
        result = await run_retention_once(stack.db, 0)
        assert result.records_deleted == 3
        assert result.channels_deleted == (channel.channel_id,)
        response = await stack.client.get(f"/v1/channels/{channel.channel_id}/records", headers=channel.auth)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "channel_not_found"


async def test_records_older_than_retention_go_and_seq_is_not_reused(stack: Stack) -> None:
    channel = await stack.register()
    stack.recorder.submit(aged(capture_for(channel, token="old"), 91))
    stack.recorder.submit(capture_for(channel, token="new"))
    await stack.recorder.idle()
    result = await run_retention_once(stack.db, 90)
    assert (result.records_deleted, result.channels_deleted) == (1, ())
    page = await stack.records(channel)
    assert [r["seq"] for r in page["records"]] == [2]
    assert channel.open(page["records"][0]["sealed"]).token == "new"
    await put(stack, channel, 1)
    assert [r["seq"] for r in (await stack.records(channel, after=2))["records"]] == [3]


async def test_channel_with_a_recent_call_stays_without_records(stack: Stack) -> None:
    channel = await stack.register()
    stack.recorder.submit(aged(capture_for(channel), 100))
    await stack.recorder.idle()
    result = await run_retention_once(stack.db, 90)
    assert result.channels_deleted == ()
    assert (await stack.records(channel))["records"] == []


async def test_channel_with_a_recent_record_stays_after_its_last_call_ages(stack: Stack) -> None:
    channel = await stack.register()
    future = utc_now() + timedelta(days=95)
    stack.recorder.submit(aged(capture_for(channel), -10))  # received 85 days before `future`
    await stack.recorder.idle()
    result = await run_retention_once(stack.db, 90, now=future)
    assert (result.records_deleted, result.channels_deleted) == (0, ())
    result = await run_retention_once(stack.db, 90, now=future + timedelta(days=6))
    assert (result.records_deleted, result.channels_deleted) == (1, (channel.channel_id,))


async def test_deleted_channel_registers_again_with_a_new_id(stack: Stack) -> None:
    channel = await stack.register()
    await run_retention_once(stack.db, 90, now=utc_now() + timedelta(days=91))
    response = await stack.client.post(
        "/v1/channels",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={
            "public_key": base64.b64encode(channel.keys.public_key).decode(),
            "secret_sha256": hashlib.sha256(channel.secret.encode()).hexdigest(),
        },
    )
    assert response.status_code == 201
    assert response.json()["channel_id"] != channel.channel_id
