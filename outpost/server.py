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

import uvicorn

from outpost.api import ApiContext, create_app
from outpost.config import ConfigError, Limits, Settings
from outpost.dns import DnsResponder, DnsUdpProtocol, dns_tcp_handler
from outpost.http import HttpListener
from outpost.recorder import Notifier, Recorder
from outpost.store import Database, retention_loop

log = logging.getLogger("outpost")

DB_FILE_NAME = "outpost.sqlite3"
API_SHUTDOWN_SECONDS = 2  # a pull waiting on `wait` is cut short at shutdown


@dataclass(frozen=True, slots=True)
class BoundPorts:
    dns: int
    http: int
    api: int


class _ApiServer(uvicorn.Server):
    """uvicorn inside our loop: signals belong to the process, not to uvicorn."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield

    def install_signal_handlers(self) -> None:
        return None


async def run(
    settings: Settings,
    limits: Limits,
    stop: asyncio.Event,
    on_ready: Callable[[BoundPorts], None] | None = None,
) -> None:
    """Serve until `stop` is set. Every task is owned by one TaskGroup."""
    db = await Database.open(settings.data_dir / DB_FILE_NAME, limits, settings.store_max_bytes)
    loop = asyncio.get_running_loop()
    udp_transport: asyncio.DatagramTransport | None = None
    try:
        notifier = Notifier()
        recorder = Recorder(db, limits, notifier)
        responder = DnsResponder(settings, limits, recorder)
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: DnsUdpProtocol(responder), local_addr=(settings.bind_ip, settings.dns_port)
        )
        dns_port = int(udp_transport.get_extra_info("sockname")[1])
        dns_tcp = await asyncio.start_server(dns_tcp_handler(responder), settings.bind_ip, dns_port)
        web = await asyncio.start_server(
            HttpListener(settings, limits, recorder).handler(), settings.bind_ip, settings.http_port
        )
        http_port = int(web.sockets[0].getsockname()[1])
        family = socket.AF_INET6 if ":" in settings.bind_ip else socket.AF_INET
        api_socket = socket.create_server((settings.bind_ip, settings.api_port), family=family)
        api_port = int(api_socket.getsockname()[1])
        api = _ApiServer(
            uvicorn.Config(
                create_app(ApiContext(settings=settings, limits=limits, db=db, notifier=notifier)),
                lifespan="off",
                access_log=False,
                log_config=None,
                log_level="warning",
                proxy_headers=False,
                server_header=False,
                timeout_graceful_shutdown=API_SHUTDOWN_SECONDS,
            )
        )
        async with asyncio.TaskGroup() as group:
            background = [
                group.create_task(recorder.run(), name="recorder"),
                group.create_task(retention_loop(db, settings.retention_days), name="retention"),
                group.create_task(dns_tcp.serve_forever(), name="dns-tcp"),
                group.create_task(web.serve_forever(), name="http"),
            ]
            api_task = group.create_task(api.serve(sockets=[api_socket]), name="api")
            log.info(
                "serving: dns %d udp+tcp, http %d, api %d, retention %d days",
                dns_port,
                http_port,
                api_port,
                settings.retention_days,
            )
            if on_ready is not None:
                on_ready(BoundPorts(dns=dns_port, http=http_port, api=api_port))
            await stop.wait()
            api.should_exit = True
            await api_task
            for task in background:
                task.cancel()
    finally:
        if udp_transport is not None:
            udp_transport.close()
        await db.close()


async def _main(settings: Settings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    await run(settings, Limits(), stop)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        settings = Settings.from_env(os.environ)
    except ConfigError as exc:
        print(f"outpost: {exc}", file=sys.stderr)
        sys.exit(2)
    asyncio.run(_main(settings))


if __name__ == "__main__":
    main()
