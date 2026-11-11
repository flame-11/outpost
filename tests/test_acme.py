"""The ACME component: certbot's arguments, the manual hooks writing and removing the
`_acme-challenge` values the name server answers, and a server obtaining its certificate at start
and renewing it (certbot itself is a stand-in, tests/fakes/certbot.py)."""

import asyncio
import contextlib
import json
import ssl
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import dns.asyncquery
import dns.message
import pytest
from conftest import ZONE, certificate_serial, client_tls_context, make_settings

from outpost import acme, schema
from outpost.acme import AcmePlan, hook
from outpost.config import Limits, Settings
from outpost.server import BoundPorts, run

FAKE_CERTBOT = Path(__file__).resolve().parent / "fakes" / "certbot.py"
CHALLENGE = f"_acme-challenge.{ZONE}"


def plan(tmp_path: Path, *, email: str | None = None, staging: bool = False) -> AcmePlan:
    return AcmePlan(zone=ZONE, email=email, staging=staging, certs_dir=tmp_path / "certs")


def test_obtain_asks_for_the_zone_and_its_wildcard_by_dns(tmp_path: Path) -> None:
    args = plan(tmp_path).obtain_args()
    assert args[0] == "certonly"
    assert [args[i + 1] for i, arg in enumerate(args) if arg == "-d"] == [ZONE, f"*.{ZONE}"]
    assert {"--manual", "--non-interactive", "--agree-tos"} <= set(args)
    assert args[args.index("--preferred-challenges") + 1] == "dns"
    assert args[args.index("--manual-auth-hook") + 1].endswith("-m outpost.acme hook auth")
    assert args[args.index("--manual-cleanup-hook") + 1].endswith("-m outpost.acme hook cleanup")
    for option, directory in (("--config-dir", "config"), ("--work-dir", "work"), ("--logs-dir", "logs")):
        assert args[args.index(option) + 1] == str(tmp_path / "certs" / directory)
    assert "--staging" not in args


def test_account_email_is_optional(tmp_path: Path) -> None:
    without = plan(tmp_path).obtain_args()
    assert "--register-unsafely-without-email" in without and "-m" not in without
    with_email = plan(tmp_path, email="ops@oob.example").obtain_args()
    assert with_email[with_email.index("-m") + 1] == "ops@oob.example"
    assert "--register-unsafely-without-email" not in with_email


def test_staging_uses_the_staging_server_and_its_own_certificate(tmp_path: Path) -> None:
    staged, real = plan(tmp_path, staging=True), plan(tmp_path)
    assert "--staging" in staged.obtain_args()
    assert staged.cert_name != real.cert_name
    assert staged.paths.cert != real.paths.cert
    assert str(staged.paths.cert).startswith(str(tmp_path / "certs"))
    renew = real.renew_args()
    assert renew[0] == "renew" and renew[renew.index("--cert-name") + 1] == real.cert_name


@contextlib.asynccontextmanager
async def serving(settings: Settings) -> AsyncIterator[BoundPorts]:
    stop = asyncio.Event()
    ready: asyncio.Future[BoundPorts] = asyncio.get_running_loop().create_future()
    server = asyncio.create_task(run(settings, Limits(), stop, on_ready=ready.set_result))
    try:
        yield await asyncio.wait_for(ready, timeout=20)
    finally:
        stop.set()
        await asyncio.wait_for(server, timeout=10)


async def txt_values(port: int) -> list[bytes]:
    answer = await dns.asyncquery.udp(dns.message.make_query(CHALLENGE, "TXT"), "127.0.0.1", port=port, timeout=5)
    return sorted(b"".join(rdata.strings) for rrset in answer.answer for rdata in rrset)


async def test_hooks_write_and_remove_values_the_name_server_answers(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    async with serving(settings) as ports:
        env = {"OUTPOST_ZONE": ZONE, "OUTPOST_DATA_DIR": str(tmp_path), "OUTPOST_BIND_IP": "127.0.0.1"}
        env["OUTPOST_DNS_PORT"] = str(ports.dns)
        for value in ("first", "second"):
            # the auth hook returns once the name server serves its value
            assert (
                await asyncio.to_thread(hook, "auth", {**env, "CERTBOT_DOMAIN": ZONE, "CERTBOT_VALIDATION": value}) == 0
            )
        assert await txt_values(ports.dns) == [b"first", b"second"]
        wildcard = {**env, "CERTBOT_DOMAIN": f"*.{ZONE}", "CERTBOT_VALIDATION": "first"}
        assert await asyncio.to_thread(hook, "cleanup", wildcard) == 0
        await asyncio.sleep(1.5)
        assert await txt_values(ports.dns) == [b"second"]
        assert (
            await asyncio.to_thread(hook, "cleanup", {**env, "CERTBOT_DOMAIN": ZONE, "CERTBOT_VALIDATION": "second"})
            == 0
        )
        await asyncio.sleep(1.5)
        assert await txt_values(ports.dns) == []


def test_hook_refuses_another_domain(tmp_path: Path) -> None:
    env = {"OUTPOST_ZONE": ZONE, "OUTPOST_DATA_DIR": str(tmp_path), "CERTBOT_VALIDATION": "v"}
    assert hook("auth", {**env, "CERTBOT_DOMAIN": "oob.example"}) == 1
    assert hook("auth", {**env, "CERTBOT_DOMAIN": ZONE, "CERTBOT_VALIDATION": ""}) == 1
    connection = schema.connect(tmp_path)
    assert schema.challenge_values(connection) == {}
    connection.close()


def test_auth_hook_fails_when_the_name_server_does_not_serve_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acme, "HOOK_WAIT_SECONDS", 0.5)
    env = {
        "OUTPOST_ZONE": ZONE,
        "OUTPOST_DATA_DIR": str(tmp_path),
        "OUTPOST_BIND_IP": "127.0.0.1",
        "OUTPOST_DNS_PORT": "9",  # nothing answers there
        "CERTBOT_DOMAIN": ZONE,
        "CERTBOT_VALIDATION": "v",
    }
    assert hook("auth", env) == 1


async def test_server_obtains_its_certificate_at_start_and_renews(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "certbot.log"
    monkeypatch.setenv("FAKE_CERTBOT_LOG", str(log))
    monkeypatch.setattr(acme, "certbot_command", lambda: [sys.executable, str(FAKE_CERTBOT)])
    monkeypatch.setattr(acme, "RENEW_INTERVAL_SECONDS", 0.2)
    settings = make_settings(tmp_path / "data", tls="acme", https_port=0)
    async with serving(settings) as ports:
        assert ports.https is not None
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", ports.https, ssl=client_tls_context(), server_hostname=f"x.{ZONE}"
        )
        assert certificate_serial(writer.get_extra_info("ssl_object").getpeercert(binary_form=True)) == 7
        writer.write(b"GET / HTTP/1.0\r\n\r\n")
        assert (await asyncio.wait_for(reader.read(), timeout=5)).startswith(b"HTTP/1.1 200 OK")
        writer.close()
        context = client_tls_context()
        _, api = await asyncio.open_connection("127.0.0.1", ports.api, ssl=context, server_hostname=f"api.{ZONE}")
        assert isinstance(api.get_extra_info("ssl_object"), ssl.SSLObject)
        api.close()
        await asyncio.sleep(1.5)
        assert await txt_values(ports.dns) == []  # cleaned up after validation
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls[0][0] == "certonly"
    assert calls[1] == {"served_while_validating": ["validation-one", "validation-two"]}
    assert [call[0] for call in calls[2:]] and all(call[0] == "renew" for call in calls[2:])
    assert (tmp_path / "data" / "certs" / "config" / "live" / "outpost" / "fullchain.pem").exists()


async def test_a_certbot_that_cannot_start_leaves_the_server_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acme, "certbot_command", lambda: [str(tmp_path / "no-certbot")])
    settings = make_settings(tmp_path / "data", tls="acme", https_port=0)
    stop = asyncio.Event()
    server = asyncio.create_task(run(settings, Limits(), stop))
    await asyncio.sleep(1.0)
    assert not server.done()  # still waiting for a certificate, serving the name server meanwhile
    stop.set()
    await asyncio.wait_for(server, timeout=10)
