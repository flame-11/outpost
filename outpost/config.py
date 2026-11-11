"""Configuration from the environment, and the limits of CONTRACT section 3."""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

DEFAULT_RETENTION_DAYS = 90
DEFAULT_STORE_MAX_BYTES = 21_474_836_480

TlsMode = Literal["off", "acme", "files"]
_TLS_MODES: tuple[TlsMode, ...] = ("off", "acme", "files")
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"", "0", "false", "no", "off"}


class ConfigError(ValueError):
    """An environment variable is missing or malformed; the message names it."""


@dataclass(frozen=True, slots=True)
class Limits:
    """CONTRACT section 3. Four are set by the environment; tests build smaller values."""

    http_max_bytes: int = 65_536
    http_read_seconds: float = 10.0
    source_rate: int = 60  # stored records a minute, per source address and channel
    channel_rate: int = 600  # stored records a minute, per channel
    channel_max_records: int = 50_000
    channel_max_bytes: int = 268_435_456
    dns_source_rate: int = 50  # answers a second, per source address
    pull_max_limit: int = 200
    pull_max_bytes: int = 4_194_304
    pull_max_wait_seconds: int = 25
    auth_fail_rate: int = 10  # failed authentications a minute, per source address
    mail_max_rcpt: int = 10  # accepted recipients per message
    mail_max_bytes: int = 1_048_576  # DATA bytes per message

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Limits":
        defaults = cls()
        return cls(
            source_rate=_integer(env, "OUTPOST_SOURCE_RATE", defaults.source_rate, minimum=1),
            channel_rate=_integer(env, "OUTPOST_CHANNEL_RATE", defaults.channel_rate, minimum=1),
            channel_max_records=_integer(env, "OUTPOST_CHANNEL_MAX_RECORDS", defaults.channel_max_records, minimum=1),
            channel_max_bytes=_integer(env, "OUTPOST_CHANNEL_MAX_BYTES", defaults.channel_max_bytes, minimum=1),
        )

    def channel_rate_for(self, key_quota: int | None) -> int:
        """The channel rate of a channel whose key has `key_quota` (None: no quota of its own)."""
        return self.channel_rate if key_quota is None else min(self.channel_rate, key_quota)


@dataclass(frozen=True, slots=True)
class Settings:
    zone: str
    public_ipv4: str
    public_ipv6: str | None
    bind_ip: str
    api_key_sha256: str | None  # the bootstrap key `default`; optional once the store holds keys
    retention_days: int
    store_max_bytes: int
    dns_port: int
    http_port: int
    api_port: int
    data_dir: Path
    tls: TlsMode = "off"
    acme_email: str | None = None
    acme_staging: bool = False
    tls_cert: Path | None = None
    tls_key: Path | None = None
    https_port: int = 443
    smtp: bool = False
    smtp_port: int = 25
    responses: bool = False  # channels may set what their names answer (CONTRACT section 9)

    @property
    def listeners(self) -> tuple[str, ...]:
        """The listeners this instance runs. With TLS on, the API itself serves only once a
        certificate is loaded, so every answer it gives can report `https`."""
        return ("dns", "http") + (("https",) if self.tls != "off" else ()) + (("smtp",) if self.smtp else ())

    @property
    def mail_host(self) -> str:
        return f"mx.{self.zone}"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Settings":
        tls = _tls_mode(env)
        acme_email = env.get("OUTPOST_ACME_EMAIL", "").strip() or None
        if acme_email is not None and "@" not in acme_email:
            raise ConfigError(f"OUTPOST_ACME_EMAIL: not an e-mail address: {acme_email!r}")
        tls_cert = _path(env, "OUTPOST_TLS_CERT", required=tls == "files")
        tls_key = _path(env, "OUTPOST_TLS_KEY", required=tls == "files")
        api_key = env.get("OUTPOST_API_KEY_SHA256", "").strip()
        return cls(
            zone=_zone(_required(env, "OUTPOST_ZONE")),
            public_ipv4=_address(env, "OUTPOST_PUBLIC_IPV4", 4, required=True) or "",
            public_ipv6=_address(env, "OUTPOST_PUBLIC_IPV6", 6, required=False),
            bind_ip=_bind_ip(env.get("OUTPOST_BIND_IP", "0.0.0.0")),
            api_key_sha256=_api_key_sha256(api_key) if api_key else None,
            retention_days=_integer(env, "OUTPOST_RETENTION_DAYS", DEFAULT_RETENTION_DAYS, minimum=0),
            store_max_bytes=_integer(env, "OUTPOST_STORE_MAX_BYTES", DEFAULT_STORE_MAX_BYTES, minimum=1),
            dns_port=_port(env, "OUTPOST_DNS_PORT", 53),
            http_port=_port(env, "OUTPOST_HTTP_PORT", 80),
            api_port=_port(env, "OUTPOST_API_PORT", 9443),
            data_dir=Path(env.get("OUTPOST_DATA_DIR", "/var/lib/outpost")),
            tls=tls,
            acme_email=acme_email if tls == "acme" else None,
            acme_staging=_boolean(env, "OUTPOST_ACME_STAGING"),
            tls_cert=tls_cert if tls == "files" else None,
            tls_key=tls_key if tls == "files" else None,
            https_port=_port(env, "OUTPOST_HTTPS_PORT", 443),
            smtp=_switch(env, "OUTPOST_SMTP"),
            smtp_port=_port(env, "OUTPOST_SMTP_PORT", 25),
            responses=_switch(env, "OUTPOST_RESPONSES"),
        )


def _tls_mode(env: Mapping[str, str]) -> TlsMode:
    value = env.get("OUTPOST_TLS", "").strip().lower() or "off"
    for mode in _TLS_MODES:
        if value == mode:
            return mode
    raise ConfigError(f"OUTPOST_TLS: one of off, acme, files, got {value!r}")


def _switch(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "").strip().lower() or "off"
    if value not in ("on", "off"):
        raise ConfigError(f"{name}: on or off, got {value!r}")
    return value == "on"


def _boolean(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "").strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name}: true or false, got {value!r}")


def _path(env: Mapping[str, str], name: str, *, required: bool) -> Path | None:
    value = env.get(name, "").strip()
    if not value:
        if required:
            raise ConfigError(f"{name}: required for OUTPOST_TLS=files")
        return None
    return Path(value)


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name}: required")
    return value


def _zone(value: str) -> str:
    zone = value.lower().rstrip(".")
    labels = zone.split(".")
    if len(zone) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise ConfigError(f"OUTPOST_ZONE: not a domain name: {value!r}")
    return zone


def _address(env: Mapping[str, str], name: str, version: int, *, required: bool) -> str | None:
    value = env.get(name, "").strip()
    if not value:
        if required:
            raise ConfigError(f"{name}: required")
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{name}: not an IP address: {value!r}") from exc
    if parsed.version != version:
        raise ConfigError(f"{name}: not an IPv{version} address: {value!r}")
    return str(parsed)


def _bind_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ConfigError(f"OUTPOST_BIND_IP: not an IP address: {value!r}") from exc


def _api_key_sha256(value: str) -> str:
    digest = value.lower()
    if not _HEX64.match(digest):
        raise ConfigError("OUTPOST_API_KEY_SHA256: must be 64 hex characters")
    return digest


def _integer(env: Mapping[str, str], name: str, default: int, *, minimum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}: not an integer: {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name}: must be at least {minimum}")
    return value


def _port(env: Mapping[str, str], name: str, default: int) -> int:
    value = _integer(env, name, default, minimum=0)
    if value > 65_535:
        raise ConfigError(f"{name}: not a port: {value}")
    return value
