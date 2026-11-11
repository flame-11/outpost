"""The `outpost` commands against the whole app on loopback ephemeral ports."""

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import dns.asyncquery
import dns.message
import httpx
import pytest
from conftest import API_KEY, ZONE, make_settings

from outpost.cli import run_cli
from outpost.config import Limits
from outpost.server import BoundPorts, run


@dataclass(frozen=True, slots=True)
class Running:
    api: str
    ports: BoundPorts
    home: Path


@pytest.fixture
async def running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Running]:
    home = tmp_path / "home"
    monkeypatch.setenv("OUTPOST_HOME", str(home))
    limits = Limits(source_rate=100_000, channel_rate=100_000, dns_source_rate=100_000)
    stop = asyncio.Event()
    ready: asyncio.Future[BoundPorts] = asyncio.get_running_loop().create_future()
    server = asyncio.create_task(run(make_settings(tmp_path / "data"), limits, stop, on_ready=ready.set_result))
    try:
        ports = await asyncio.wait_for(ready, timeout=10)
        api = f"http://127.0.0.1:{ports.api}"
        monkeypatch.setenv("OUTPOST_API_URL", api)
        monkeypatch.setenv("OUTPOST_API_KEY", API_KEY)
        yield Running(api=api, ports=ports, home=home)
    finally:
        stop.set()
        await asyncio.wait_for(server, timeout=10)


async def cli(*argv: str) -> int:
    return await asyncio.to_thread(run_cli, list(argv))


def output(capsys: pytest.CaptureFixture[str]) -> dict[str, str]:
    return dict(line.split("\t", 1) for line in capsys.readouterr().out.splitlines())


async def lookup(running: Running, name: str) -> None:
    await dns.asyncquery.udp(dns.message.make_query(name, "A"), "127.0.0.1", port=running.ports.dns, timeout=5)


async def create(capsys: pytest.CaptureFixture[str], *options: str) -> str:
    assert await cli("channel", "create", *options) == 0
    return output(capsys)["channel_id"]


async def settle(running: Running, channel_id: str, held: int) -> None:
    secret = json.loads(next((running.home / "channels").glob("*.json")).read_text())["secret"]
    async with httpx.AsyncClient(base_url=running.api, headers={"Authorization": f"Bearer {secret}"}) as client:
        for _ in range(50):
            if (await client.get(f"/v1/channels/{channel_id}")).json()["held_records"] >= held:
                return
            await asyncio.sleep(0.1)


async def test_create_uses_the_environment_and_a_label_under_outpost_home(
    running: Running, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await cli("channel", "create", "--channel", "probe1") == 0
    shown = output(capsys)
    path = running.home / "channels" / "probe1.json"
    assert shown["key_file"] == str(path)
    assert shown["address"] == f"{{token}}-{shown['channel_id']}.{ZONE}"
    assert shown["listeners"] == "dns,http"
    assert (path.stat().st_mode & 0o777) == 0o600
    assert await cli("channel", "create", "--channel", "probe1") == 0
    assert output(capsys)["channel_id"] == shown["channel_id"]


async def test_create_without_an_api_fails(
    running: Running, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OUTPOST_API_URL")
    assert await asyncio.to_thread(run_cli, ["channel", "create"]) == 1
    assert "invalid_request" in capsys.readouterr().err


async def test_status_list_and_read(running: Running, capsys: pytest.CaptureFixture[str]) -> None:
    channel_id = await create(capsys)
    await lookup(running, f"s1-{channel_id}.{ZONE}")
    await lookup(running, f"s2-{channel_id}.{ZONE}")
    await settle(running, channel_id, 2)

    assert await cli("channel", "status") == 0
    status = output(capsys)
    assert (status["channel_id"], status["held_records"], status["last_seq"]) == (channel_id, "2", "2")

    assert await cli("list") == 0
    lines = [line.split("\t") for line in capsys.readouterr().out.splitlines()]
    assert [(line[0], line[1], line[2]) for line in lines] == [("1", "dns", "s1"), ("2", "dns", "s2")]
    assert await cli("list", "--after", "1") == 0
    assert capsys.readouterr().out.startswith("2\tdns\ts2\t")

    assert await cli("read", "2") == 0
    record = json.loads(capsys.readouterr().out)
    assert (record["seq"], record["protocol"], record["token"], record["qtype"]) == (2, "dns", "s2", "A")
    assert await cli("read", "7") == 1
    assert "record_not_found" in capsys.readouterr().err


async def test_read_shows_a_web_request_decoded(running: Running, capsys: pytest.CaptureFixture[str]) -> None:
    channel_id = await create(capsys)
    reader, writer = await asyncio.open_connection("127.0.0.1", running.ports.http)
    writer.write(f"POST /in HTTP/1.1\r\nHost: r1-{channel_id}.{ZONE}\r\nContent-Length: 4\r\n\r\nk=v1".encode())
    await writer.drain()
    await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    await settle(running, channel_id, 1)
    assert await cli("read", "1") == 0
    record = json.loads(capsys.readouterr().out)
    assert record["request_line"] == "POST /in HTTP/1.1"
    assert record["body"]["content"] == "k=v1"


async def test_watch_prints_records_that_arrive_after_it_starts(
    running: Running, capsys: pytest.CaptureFixture[str]
) -> None:
    channel_id = await create(capsys)
    await lookup(running, f"old-{channel_id}.{ZONE}")
    await settle(running, channel_id, 1)
    watching = asyncio.create_task(cli("watch", "--count", "1"))
    await asyncio.sleep(1.0)
    await lookup(running, f"new-{channel_id}.{ZONE}")
    assert await asyncio.wait_for(watching, timeout=15) == 0
    lines = [line.split("\t") for line in capsys.readouterr().out.splitlines()]
    assert [(line[0], line[2]) for line in lines] == [("2", "new")]


async def test_assemble_writes_the_data(running: Running, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    channel_id = await create(capsys)
    data = bytes(range(256)) * 4
    chunks = [data[i : i + 31] for i in range(0, len(data), 31)]
    for index, chunk in reversed(list(enumerate(chunks))):
        await lookup(running, f"{chunk.hex()}.{index}.as1-{channel_id}.{ZONE}")
    await settle(running, channel_id, len(chunks))
    out = tmp_path / "data.bin"
    assert await cli("assemble", "as1", "--encoding", "hex", "--out", str(out)) == 0
    assert out.read_bytes() == data
    report = dict(line.split("\t", 1) for line in capsys.readouterr().err.splitlines())
    assert (report["bytes"], report["chunks"], report["missing"]) == (str(len(data)), str(len(chunks)), "")


async def test_an_explicit_key_file_works_for_every_command(
    running: Running, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    key_file = str(tmp_path / "channel.json")
    channel_id = await create(capsys, "--key-file", key_file)
    await lookup(running, f"k1-{channel_id}.{ZONE}")
    await asyncio.sleep(0.3)
    assert await cli("list", "--key-file", key_file, "--wait", "5") == 0
    assert "\tk1\t" in capsys.readouterr().out
    assert not (running.home / "channels").exists()


async def test_delete_removes_the_channel_and_its_key_file(
    running: Running, capsys: pytest.CaptureFixture[str]
) -> None:
    channel_id = await create(capsys, "--channel", "gone")
    assert await cli("channel", "delete", "--channel", "gone") == 0
    assert output(capsys)["deleted"] == channel_id
    assert not (running.home / "channels" / "gone.json").exists()
    assert await cli("channel", "status", "--channel", "gone") == 1
    assert "key_file_unreadable" in capsys.readouterr().err
