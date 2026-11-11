"""Configuration by environment (PLAN section 4); this version runs without TLS and mail."""

import hashlib

import pytest

from outpost.config import ConfigError, Settings

BASE = {
    "OUTPOST_ZONE": "OOB.Test.",
    "OUTPOST_PUBLIC_IPV4": "192.0.2.10",
    "OUTPOST_API_KEY_SHA256": hashlib.sha256(b"k").hexdigest(),
}


def test_defaults() -> None:
    settings = Settings.from_env(BASE)
    assert settings.zone == "oob.test"
    assert (settings.retention_days, settings.store_max_bytes) == (90, 21_474_836_480)
    assert settings.public_ipv6 is None
    assert settings.listeners == ("dns", "http")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("OUTPOST_TLS", "acme"),
        ("OUTPOST_SMTP", "on"),
        ("OUTPOST_ZONE", "not a zone"),
        ("OUTPOST_PUBLIC_IPV4", "2001:db8::1"),
        ("OUTPOST_PUBLIC_IPV6", "192.0.2.1"),
        ("OUTPOST_API_KEY_SHA256", "abc"),
        ("OUTPOST_RETENTION_DAYS", "-1"),
        ("OUTPOST_DNS_PORT", "70000"),
    ],
)
def test_rejected_values_name_the_variable(name: str, value: str) -> None:
    with pytest.raises(ConfigError, match=name):
        Settings.from_env({**BASE, name: value})


def test_switches_accept_off() -> None:
    assert Settings.from_env({**BASE, "OUTPOST_TLS": "off", "OUTPOST_SMTP": "off"}).listeners == ("dns", "http")


@pytest.mark.parametrize("name", ["OUTPOST_ZONE", "OUTPOST_PUBLIC_IPV4", "OUTPOST_API_KEY_SHA256"])
def test_required(name: str) -> None:
    env = dict(BASE)
    del env[name]
    with pytest.raises(ConfigError, match=name):
        Settings.from_env(env)
