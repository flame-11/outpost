"""Configuration by environment: the zone and listeners, the four storage limits, TLS and mail."""

import hashlib
from pathlib import Path

import pytest

from outpost.config import ConfigError, Limits, Settings

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
    assert (settings.tls, settings.smtp) == ("off", False)
    assert (settings.https_port, settings.smtp_port, settings.api_port) == (443, 25, 9443)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("OUTPOST_TLS", "on"),
        ("OUTPOST_SMTP", "yes"),
        ("OUTPOST_ZONE", "not a zone"),
        ("OUTPOST_PUBLIC_IPV4", "2001:db8::1"),
        ("OUTPOST_PUBLIC_IPV6", "192.0.2.1"),
        ("OUTPOST_API_KEY_SHA256", "abc"),
        ("OUTPOST_RETENTION_DAYS", "-1"),
        ("OUTPOST_DNS_PORT", "70000"),
        ("OUTPOST_HTTPS_PORT", "70000"),
        ("OUTPOST_SMTP_PORT", "x"),
        ("OUTPOST_ACME_STAGING", "maybe"),
        ("OUTPOST_ACME_EMAIL", "not-an-address"),
    ],
)
def test_rejected_values_name_the_variable(name: str, value: str) -> None:
    with pytest.raises(ConfigError, match=name):
        Settings.from_env({**BASE, name: value})


@pytest.mark.parametrize("name", ["OUTPOST_ZONE", "OUTPOST_PUBLIC_IPV4"])
def test_required(name: str) -> None:
    env = dict(BASE)
    del env[name]
    with pytest.raises(ConfigError, match=name):
        Settings.from_env(env)


def test_bootstrap_key_is_optional() -> None:
    env = dict(BASE)
    del env["OUTPOST_API_KEY_SHA256"]
    assert Settings.from_env(env).api_key_sha256 is None
    assert Settings.from_env(BASE).api_key_sha256 == hashlib.sha256(b"k").hexdigest()


def test_listeners_follow_tls_and_mail() -> None:
    assert Settings.from_env({**BASE, "OUTPOST_TLS": "off", "OUTPOST_SMTP": "off"}).listeners == ("dns", "http")
    assert Settings.from_env({**BASE, "OUTPOST_SMTP": "on"}).listeners == ("dns", "http", "smtp")
    both = Settings.from_env({**BASE, "OUTPOST_TLS": "acme", "OUTPOST_SMTP": "on", "OUTPOST_SMTP_PORT": "2525"})
    assert both.listeners == ("dns", "http", "https", "smtp")
    assert both.smtp_port == 2525
    assert both.mail_host == "mx.oob.test"


def test_acme_email_is_optional_and_staging_is_a_switch() -> None:
    plain = Settings.from_env({**BASE, "OUTPOST_TLS": "acme"})
    assert (plain.tls, plain.acme_email, plain.acme_staging) == ("acme", None, False)
    staged = Settings.from_env(
        {**BASE, "OUTPOST_TLS": "ACME", "OUTPOST_ACME_EMAIL": "ops@oob.example", "OUTPOST_ACME_STAGING": "true"}
    )
    assert (staged.tls, staged.acme_email, staged.acme_staging) == ("acme", "ops@oob.example", True)


def test_files_mode_needs_both_paths() -> None:
    for missing in ("OUTPOST_TLS_CERT", "OUTPOST_TLS_KEY"):
        env = {**BASE, "OUTPOST_TLS": "files", "OUTPOST_TLS_CERT": "/c.pem", "OUTPOST_TLS_KEY": "/k.pem"}
        del env[missing]
        with pytest.raises(ConfigError, match=missing):
            Settings.from_env(env)
    settings = Settings.from_env(
        {**BASE, "OUTPOST_TLS": "files", "OUTPOST_TLS_CERT": "/c.pem", "OUTPOST_TLS_KEY": "/k.pem"}
    )
    assert (settings.tls_cert, settings.tls_key) == (Path("/c.pem"), Path("/k.pem"))


def test_limit_defaults() -> None:
    limits = Limits.from_env({})
    assert (limits.source_rate, limits.channel_rate) == (60, 600)
    assert (limits.channel_max_records, limits.channel_max_bytes) == (50_000, 268_435_456)
    assert (limits.mail_max_rcpt, limits.mail_max_bytes) == (10, 1_048_576)


def test_limits_from_env() -> None:
    limits = Limits.from_env(
        {
            "OUTPOST_SOURCE_RATE": "5",
            "OUTPOST_CHANNEL_RATE": "50",
            "OUTPOST_CHANNEL_MAX_RECORDS": "100",
            "OUTPOST_CHANNEL_MAX_BYTES": "1000000",
        }
    )
    assert (limits.source_rate, limits.channel_rate) == (5, 50)
    assert (limits.channel_max_records, limits.channel_max_bytes) == (100, 1_000_000)


@pytest.mark.parametrize(
    "name", ["OUTPOST_SOURCE_RATE", "OUTPOST_CHANNEL_RATE", "OUTPOST_CHANNEL_MAX_RECORDS", "OUTPOST_CHANNEL_MAX_BYTES"]
)
@pytest.mark.parametrize("value", ["0", "x", "-3"])
def test_rejected_limits_name_the_variable(name: str, value: str) -> None:
    with pytest.raises(ConfigError, match=name):
        Limits.from_env({name: value})
