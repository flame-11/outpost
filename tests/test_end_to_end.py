"""The whole app on loopback ephemeral ports: a lookup (UDP and TCP) and a web request reach it,
and the CLI registers, lists and reads them (PLAN stage 2, proof 1)."""

import asyncio
import json
from pathlib import Path

import dns.asyncquery
import dns.message
import httpx
import pytest
from conftest import API_KEY, PUBLIC_IPV4, ZONE, make_settings

from outpost.cli import run_cli
from outpost.config import Limits
from outpost.server import BoundPorts, run


async def test_lookup_and_request_read_back_through_the_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    settings = make_settings(tmp_path / "data")
    stop = asyncio.Event()
    ready: asyncio.Future[BoundPorts] = asyncio.get_running_loop().create_future()
    server = asyncio.create_task(run(settings, Limits(), stop, on_ready=ready.set_result))
    try:
        ports = await asyncio.wait_for(ready, timeout=10)
        api = f"http://127.0.0.1:{ports.api}"
        key_file = tmp_path / "channel.json"

        health = await asyncio.to_thread(httpx.get, f"{api}/v1/health")
        assert health.json() == {"status": "ok", "contract": 1, "store_full": False}

        argv = ["channel", "create", "--api", api, "--api-key", API_KEY, "--key-file", str(key_file)]
        assert await asyncio.to_thread(run_cli, argv) == 0
        saved = json.loads(key_file.read_text())
        channel_id = saved["channel_id"]
        assert (key_file.stat().st_mode & 0o777) == 0o600
        assert await asyncio.to_thread(run_cli, argv) == 0  # a repeat keeps the channel
        assert json.loads(key_file.read_text())["channel_id"] == channel_id
        capsys.readouterr()

        udp = await dns.asyncquery.udp(
            dns.message.make_query(f"c1-{channel_id}.{ZONE}", "A"), "127.0.0.1", port=ports.dns, timeout=5
        )
        assert [rdata.to_text() for rdata in udp.answer[0]] == [PUBLIC_IPV4]
        tcp = await dns.asyncquery.tcp(
            dns.message.make_query(f"c3-{channel_id}.{ZONE}", "MX"), "127.0.0.1", port=ports.dns, timeout=5
        )
        assert tcp.answer
        reader, writer = await asyncio.open_connection("127.0.0.1", ports.http)
        writer.write(f"POST /c HTTP/1.1\r\nHost: c2-{channel_id}.{ZONE}\r\nContent-Length: 3\r\n\r\nx=1".encode())
        await writer.drain()
        assert (await asyncio.wait_for(reader.read(), timeout=5)).startswith(b"HTTP/1.1 200 OK\r\n")
        writer.close()

        auth = {"Authorization": f"Bearer {saved['secret']}"}
        async with httpx.AsyncClient(base_url=api, headers=auth) as client:
            for _ in range(50):
                if (await client.get(f"/v1/channels/{channel_id}")).json()["held_records"] == 3:
                    break
                await asyncio.sleep(0.1)

        assert await asyncio.to_thread(run_cli, ["list", "--key-file", str(key_file), "--wait", "5"]) == 0
        lines = [line.split("\t") for line in capsys.readouterr().out.splitlines()]
        assert sorted((line[1], line[2]) for line in lines) == [("dns", "c1"), ("dns", "c3"), ("http", "c2")]
        assert all(line[4] == "127.0.0.1" for line in lines)

        http_seq = next(line[0] for line in lines if line[1] == "http")
        assert await asyncio.to_thread(run_cli, ["read", "--key-file", str(key_file), http_seq]) == 0
        record = json.loads(capsys.readouterr().out)
        assert (record["method"], record["target"], record["host"]) == ("POST", "/c", f"c2-{channel_id}.{ZONE}")

        assert await asyncio.to_thread(run_cli, ["read", "--key-file", str(key_file), "99"]) == 1
    finally:
        stop.set()
        await asyncio.wait_for(server, timeout=10)
