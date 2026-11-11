"""The certificate: loaded from two files, reloaded when they change, without restarting a listener.

Each listener gets a front context whose server-name callback switches every handshake to the
context of the certificate loaded now, and remembers the server name the client sent.
"""

import asyncio
import logging
import os
import ssl
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("outpost.tls")

WATCH_INTERVAL_SECONDS = 60.0
_SERVER_NAME_ATTRIBUTE = "outpost_server_name"
_ALPN = ["http/1.1"]

FileStamp = tuple[int, int, int, int]  # mtime_ns and size of both files


@dataclass(frozen=True, slots=True)
class CertificatePaths:
    cert: Path  # the chain, leaf first, PEM
    key: Path  # the private key, PEM


class CertificateError(Exception):
    """The certificate files are missing or do not load; the message names the file."""


def _stamp(paths: CertificatePaths) -> FileStamp | None:
    try:
        cert, key = os.stat(paths.cert), os.stat(paths.key)
    except OSError:
        return None
    return (cert.st_mtime_ns, cert.st_size, key.st_mtime_ns, key.st_size)


def _base_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(_ALPN)  # the web listener and the API speak HTTP/1.1 only
    return context


def _load(paths: CertificatePaths) -> ssl.SSLContext:
    context = _base_context()
    try:
        context.load_cert_chain(paths.cert, paths.key)
    except (OSError, ssl.SSLError) as exc:
        raise CertificateError(f"{paths.cert} with {paths.key}: {type(exc).__name__}") from exc
    return context


def server_name(ssl_object: object) -> str | None:
    """The server name (SNI) the client sent on a connection served by a front context."""
    value = getattr(ssl_object, _SERVER_NAME_ATTRIBUTE, None)
    return value if isinstance(value, str) else None


class Certificates:
    def __init__(self, paths: CertificatePaths) -> None:
        self.paths = paths
        self._current: ssl.SSLContext | None = None
        self._stamp: FileStamp | None = None
        self.loaded_event = asyncio.Event()

    @property
    def loaded(self) -> bool:
        return self._current is not None

    async def reload_if_changed(self) -> bool:
        """Load the files when they differ from what is loaded. Files that are missing or do not
        load leave the loaded certificate in place; they are tried again on the next call."""
        stamp = await asyncio.to_thread(_stamp, self.paths)
        if stamp is None or stamp == self._stamp:
            return False
        try:
            context = await asyncio.to_thread(_load, self.paths)
        except CertificateError as exc:
            log.warning("certificate not loaded: %s", exc)
            return False
        self._current, self._stamp = context, stamp
        self.loaded_event.set()
        log.info("certificate loaded")
        return True

    def server_context(self) -> ssl.SSLContext:
        """A front context for one listener; it carries no certificate of its own."""
        context = _base_context()
        context.sni_callback = self._on_server_name
        return context

    def _on_server_name(self, ssl_object: ssl.SSLObject, name: str | None, _: ssl.SSLContext) -> int | None:
        current = self._current
        if current is None:
            return ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE
        ssl_object.context = current
        setattr(ssl_object, _SERVER_NAME_ATTRIBUTE, name)
        return None


async def watch_certificates(certificates: Certificates, interval: float = WATCH_INTERVAL_SECONDS) -> None:
    while True:
        await asyncio.sleep(interval)
        await certificates.reload_if_changed()
