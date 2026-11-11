"""Runs every component in one event loop: `python -m outpost.server`."""

import asyncio
import contextlib
import logging
import os
import signal
import socket
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import uvicorn

from outpost.acme import AcmePlan, acme_loop, hook_environment
from outpost.api import ApiContext, create_app
from outpost.config import ConfigError, Limits, Settings
from outpost.dns import ChallengeValues, DnsResponder, DnsUdpProtocol, challenge_loop, dns_tcp_handler
from outpost.http import HttpListener
from outpost.recorder import Notifier, Recorder
from outpost.smtp import mail_session_factory
from outpost.store import Database, retention_loop
from outpost.tls import CertificatePaths, Certificates, watch_certificates

log = logging.getLogger("outpost")

API_SHUTDOWN_SECONDS = 2  # a pull waiting on `wait` is cut short at shutdown
KNOWN_REFRESH_SECONDS = 60


@dataclass(frozen=True, slots=True)
class BoundPorts:
    dns: int
    http: int
    api: int
    https: int | None = None
    smtp: int | None = None


class _ApiServer(uvicorn.Server):
    """uvicorn inside our loop: signals belong to the process, not to uvicorn."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield

    def install_signal_handlers(self) -> None:
        return None


def _bound_port(server: asyncio.Server) -> int:
    return int(server.sockets[0].getsockname()[1])


async def _certificates(settings: Settings) -> Certificates | None:
    """The certificate component of OUTPOST_TLS; `files` must load at start, `acme` may come later."""
    if settings.tls == "off":
        return None
    if settings.tls == "files":
        assert settings.tls_cert is not None and settings.tls_key is not None
        certificates = Certificates(CertificatePaths(cert=settings.tls_cert, key=settings.tls_key))
        if not await certificates.reload_if_changed():
            raise ConfigError("OUTPOST_TLS_CERT, OUTPOST_TLS_KEY: the files are missing or do not load")
        return certificates
    certificates = Certificates(AcmePlan.from_settings(settings).paths)
    await certificates.reload_if_changed()
    return certificates


def _responses(settings: Settings, db: Database) -> Database | None:
    return db if settings.responses else None


async def _known_loop(db: Database) -> None:
    while True:
        await asyncio.sleep(KNOWN_REFRESH_SECONDS)
        await db.refresh_known()


async def _wait_either(first: asyncio.Event, second: asyncio.Event) -> None:
    async with asyncio.TaskGroup() as group:
        waits = [group.create_task(first.wait()), group.create_task(second.wait())]
        await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
        for wait in waits:
            wait.cancel()


def _api_server(ctx: ApiContext, certificates: Certificates | None) -> _ApiServer:
    tls: dict[str, Any] = {}
    if certificates is not None:
        tls["ssl_context_factory"] = lambda _config, _default: certificates.server_context()
    return _ApiServer(
        uvicorn.Config(
            create_app(ctx),
            lifespan="off",
            access_log=False,
            log_config=None,
            log_level="warning",
            proxy_headers=False,
            server_header=False,
            timeout_graceful_shutdown=API_SHUTDOWN_SECONDS,
            **tls,
        )
    )


async def run(
    settings: Settings,
    limits: Limits,
    stop: asyncio.Event,
    on_ready: Callable[[BoundPorts], None] | None = None,
) -> None:
    """Serve until `stop` is set. Every task is owned by one TaskGroup. With TLS on, the HTTPS
    listener and the API start once a certificate is loaded."""
    db = await Database.open(settings.data_dir, limits, settings.store_max_bytes)
    loop = asyncio.get_running_loop()
    udp_transport: asyncio.DatagramTransport | None = None
    try:
        if settings.api_key_sha256 is None and not await db.has_active_keys():
            raise ConfigError("OUTPOST_API_KEY_SHA256: required while the store holds no API key")
        certificates = await _certificates(settings)
        notifier = Notifier()
        recorder = Recorder(db, limits, notifier)
        challenges = ChallengeValues()
        challenges.set(await db.challenge_values())
        responder = DnsResponder(settings, limits, recorder, challenges)
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: DnsUdpProtocol(responder), local_addr=(settings.bind_ip, settings.dns_port)
        )
        dns_port = int(udp_transport.get_extra_info("sockname")[1])
        dns_tcp = await asyncio.start_server(dns_tcp_handler(responder), settings.bind_ip, dns_port)
        web = await asyncio.start_server(
            HttpListener(settings, limits, recorder, _responses(settings, db)).handler(),
            settings.bind_ip,
            settings.http_port,
        )
        mail = (
            await loop.create_server(
                mail_session_factory(settings, limits, recorder, certificates), settings.bind_ip, settings.smtp_port
            )
            if settings.smtp
            else None
        )
        family = socket.AF_INET6 if ":" in settings.bind_ip else socket.AF_INET
        api_socket = socket.create_server((settings.bind_ip, settings.api_port), family=family)
        api = _api_server(ApiContext(settings=settings, limits=limits, db=db, notifier=notifier), certificates)
        async with asyncio.TaskGroup() as group:
            background = [
                group.create_task(recorder.run(), name="recorder"),
                group.create_task(retention_loop(db, settings.retention_days), name="retention"),
                group.create_task(challenge_loop(db, challenges), name="challenges"),
                group.create_task(_known_loop(db), name="known-channels"),
                group.create_task(dns_tcp.serve_forever(), name="dns-tcp"),
                group.create_task(web.serve_forever(), name="http"),
            ]
            if mail is not None:
                background.append(group.create_task(mail.serve_forever(), name="smtp"))
            if certificates is not None:
                background.append(group.create_task(watch_certificates(certificates), name="certificate-watch"))
                if settings.tls == "acme":
                    plan, env = AcmePlan.from_settings(settings), hook_environment(settings, dns_port)
                    background.append(group.create_task(acme_loop(plan, certificates, env), name="acme"))
                await _wait_either(stop, certificates.loaded_event)
            https_port: int | None = None
            if certificates is not None and certificates.loaded:
                https = await asyncio.start_server(
                    HttpListener(settings, limits, recorder, _responses(settings, db), tls=True).handler(),
                    settings.bind_ip,
                    settings.https_port,
                    ssl=certificates.server_context(),
                    ssl_handshake_timeout=limits.http_read_seconds,
                )
                https_port = _bound_port(https)
                background.append(group.create_task(https.serve_forever(), name="https"))
            api_task = group.create_task(api.serve(sockets=[api_socket]), name="api") if not stop.is_set() else None
            ports = BoundPorts(
                dns=dns_port,
                http=_bound_port(web),
                api=int(api_socket.getsockname()[1]),
                https=https_port,
                smtp=_bound_port(mail) if mail is not None else None,
            )
            if api_task is not None:
                log.info(
                    "serving: dns %d udp+tcp, http %d, https %s, smtp %s, api %d%s, retention %d days, responses %s",
                    ports.dns,
                    ports.http,
                    ports.https,
                    ports.smtp,
                    ports.api,
                    " tls" if certificates is not None else "",
                    settings.retention_days,
                    "on" if settings.responses else "off",
                )
                if on_ready is not None:
                    on_ready(ports)
            await stop.wait()
            if api_task is not None:
                api.should_exit = True
                await api_task
            else:
                api_socket.close()
            for task in background:
                task.cancel()
    finally:
        if udp_transport is not None:
            udp_transport.close()
        await db.close()


async def _main(settings: Settings, limits: Limits) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    await run(settings, limits, stop)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        settings = Settings.from_env(os.environ)
        limits = Limits.from_env(os.environ)
        asyncio.run(_main(settings, limits))
    except ConfigError as exc:
        print(f"outpost: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
