"""Configuration from the environment, and the fixed limits of CONTRACT section 3."""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

DEFAULT_RETENTION_DAYS = 90
DEFAULT_STORE_MAX_BYTES = 21_474_836_480


class ConfigError(ValueError):
    """An environment variable is missing or malformed; the message names it."""


@dataclass(frozen=True, slots=True)
class Limits:
    """CONTRACT section 3. Tests build smaller values; production uses the defaults."""

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


@dataclass(frozen=True, slots=True)
class Settings:
    zone: str
    public_ipv4: str
    public_ipv6: str | None
    bind_ip: str
    api_key_sha256: str
    retention_days: int
    store_max_bytes: int
    dns_port: int
    http_port: int
    api_port: int
    data_dir: Path

    @property
    def listeners(self) -> tuple[str, ...]:
        # This version runs neither the TLS listener nor the mail receiver (OUTPOST_TLS and
        # OUTPOST_SMTP accept only "off").
        return ("dns", "http")

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Settings":
        _require_off(env, "OUTPOST_TLS")
        _require_off(env, "OUTPOST_SMTP")
        return cls(
            zone=_zone(_required(env, "OUTPOST_ZONE")),
            public_ipv4=_address(env, "OUTPOST_PUBLIC_IPV4", 4, required=True) or "",
            public_ipv6=_address(env, "OUTPOST_PUBLIC_IPV6", 6, required=False),
            bind_ip=_bind_ip(env.get("OUTPOST_BIND_IP", "0.0.0.0")),
            api_key_sha256=_api_key_sha256(_required(env, "OUTPOST_API_KEY_SHA256")),
            retention_days=_integer(env, "OUTPOST_RETENTION_DAYS", DEFAULT_RETENTION_DAYS, minimum=0),
            store_max_bytes=_integer(env, "OUTPOST_STORE_MAX_BYTES", DEFAULT_STORE_MAX_BYTES, minimum=1),
            dns_port=_port(env, "OUTPOST_DNS_PORT", 53),
            http_port=_port(env, "OUTPOST_HTTP_PORT", 80),
            api_port=_port(env, "OUTPOST_API_PORT", 9443),
            data_dir=Path(env.get("OUTPOST_DATA_DIR", "/var/lib/outpost")),
        )


def _require_off(env: Mapping[str, str], name: str) -> None:
    value = env.get(name, "").strip().lower() or "off"
    if value != "off":
        raise ConfigError(f"{name}: this version accepts only 'off', got {value!r}")


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
