"""CONTRACT section 3: storage limits; a dropped interaction still gets the fixed answer and is counted."""

from pathlib import Path

import dns.message
from conftest import ZONE, Stack, capture_for, open_stack, put

from outpost.config import Limits


async def channel_status(stack: Stack, channel_id: str, auth: dict[str, str]) -> dict[str, int]:
    response = await stack.client.get(f"/v1/channels/{channel_id}", headers=auth)
    assert response.status_code == 200
    return response.json()


async def test_source_rate_per_source_and_channel(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(source_rate=2)) as stack:
        channel, other = await stack.register(), await stack.register()
        await put(stack, channel, 3, source_ip="198.51.100.1")
        await put(stack, channel, 1, source_ip="198.51.100.2")  # another source
        await put(stack, other, 1, source_ip="198.51.100.1")  # another channel
        status = await channel_status(stack, channel.channel_id, channel.auth)
        assert (status["held_records"], status["dropped_total"]) == (3, 1)
        assert (await channel_status(stack, other.channel_id, other.auth))["held_records"] == 1


async def test_channel_rate(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(channel_rate=3)) as stack:
        channel = await stack.register()
        for index in range(5):
            stack.recorder.submit(capture_for(channel, source_ip=f"198.51.100.{index}"))
        await stack.recorder.idle()
        status = await channel_status(stack, channel.channel_id, channel.auth)
        assert (status["held_records"], status["dropped_total"]) == (3, 2)


async def test_channel_max_records(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(channel_max_records=2)) as stack:
        channel = await stack.register()
        await put(stack, channel, 4)
        status = await channel_status(stack, channel.channel_id, channel.auth)
        assert (status["held_records"], status["last_seq"], status["dropped_total"]) == (2, 2, 2)


async def test_channel_max_bytes(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(channel_max_bytes=3000)) as stack:
        channel = await stack.register()
        await put(stack, channel, 5, raw=b"x" * 600)  # each sealed record is over 1000 bytes
        page = await stack.records(channel)
        assert 1 <= len(page["records"]) < 5
        assert page["dropped_total"] == 5 - len(page["records"])


async def test_store_max_bytes_drops_and_health_shows_store_full(tmp_path: Path) -> None:
    async with open_stack(tmp_path, store_max_bytes=1) as stack:
        channel = await stack.register()
        await put(stack, channel, 2)
        status = await channel_status(stack, channel.channel_id, channel.auth)
        assert (status["held_records"], status["dropped_total"]) == (0, 2)
        assert (await stack.client.get("/v1/health")).json()["store_full"] is True


async def test_dropped_lookup_still_gets_its_answer(tmp_path: Path) -> None:
    async with open_stack(tmp_path, Limits(channel_max_records=0)) as stack:
        channel = await stack.register()
        query = dns.message.make_query(f"t1-{channel.channel_id}.{ZONE}", "A").to_wire()
        answer = stack.responder.respond(query, "198.51.100.1", 1, "udp")
        assert answer is not None and dns.message.from_wire(answer).answer
        await stack.recorder.idle()
        status = await channel_status(stack, channel.channel_id, channel.auth)
        assert (status["held_records"], status["dropped_total"]) == (0, 1)
