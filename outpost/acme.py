"""The wildcard certificate for `<zone>` and `*.<zone>` through ACME DNS-01, with certbot.

certbot runs as a subprocess of the server: `certonly` when no certificate is present, `renew`
once a day. Its manual hooks run `python -m outpost.acme hook auth|cleanup`, which write and
remove the `_acme-challenge.<zone>` TXT values in the store; the name server answers them. The
auth hook returns only once the name server serves its value.
"""

import argparse
import asyncio
import contextlib
import logging
import os
import shlex
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import dns.exception
import dns.message
import dns.query
import dns.rdatatype

from outpost import schema
from outpost.config import Settings
from outpost.records import format_time, utc_now
from outpost.tls import CertificatePaths, Certificates

log = logging.getLogger("outpost.acme")

RENEW_INTERVAL_SECONDS = 86_400
RETRY_SECONDS = 3_600  # while no certificate could be obtained
CERTBOT_TIMEOUT_SECONDS = 900
HOOK_WAIT_SECONDS = 30.0
HOOK_POLL_SECONDS = 0.5


def certbot_command() -> list[str]:
    """certbot from the environment Outpost runs in (the image installs the `acme` extra)."""
    return [str(Path(sys.executable).with_name("certbot"))]


def _hook(action: str) -> str:
    return f"{shlex.quote(sys.executable)} -m outpost.acme hook {action}"


@dataclass(frozen=True, slots=True)
class AcmePlan:
    zone: str
    email: str | None
    staging: bool
    certs_dir: Path  # <data dir>/certs: certbot's config, work and logs directories

    @classmethod
    def from_settings(cls, settings: Settings) -> "AcmePlan":
        return cls(
            zone=settings.zone,
            email=settings.acme_email,
            staging=settings.acme_staging,
            certs_dir=settings.data_dir / "certs",
        )

    @property
    def cert_name(self) -> str:
        # A staging certificate has its own name, so turning staging off obtains a real one.
        return "outpost-staging" if self.staging else "outpost"

    @property
    def paths(self) -> CertificatePaths:
        live = self.certs_dir / "config" / "live" / self.cert_name
        return CertificatePaths(cert=live / "fullchain.pem", key=live / "privkey.pem")

    def _directories(self) -> list[str]:
        return [
            "--config-dir",
            str(self.certs_dir / "config"),
            "--work-dir",
            str(self.certs_dir / "work"),
            "--logs-dir",
            str(self.certs_dir / "logs"),
        ]

    def obtain_args(self) -> list[str]:
        account = ["-m", self.email] if self.email else ["--register-unsafely-without-email"]
        return [
            "certonly",
            "--non-interactive",
            "--agree-tos",
            *account,
            "--manual",
            "--preferred-challenges",
            "dns",
            "--manual-auth-hook",
            _hook("auth"),
            "--manual-cleanup-hook",
            _hook("cleanup"),
            "--cert-name",
            self.cert_name,
            "-d",
            self.zone,
            "-d",
            f"*.{self.zone}",
            *(["--staging"] if self.staging else []),
            *self._directories(),
        ]

    def renew_args(self) -> list[str]:
        return ["renew", "--non-interactive", "--cert-name", self.cert_name, *self._directories()]


async def run_certbot(args: Sequence[str], env: Mapping[str, str]) -> int:
    """certbot's exit status; its output goes to its log under `<certs>/logs`, not ours."""
    process = await asyncio.create_subprocess_exec(
        *certbot_command(),
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        env=dict(env),
    )
    try:
        async with asyncio.timeout(CERTBOT_TIMEOUT_SECONDS):
            return await process.wait()
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await asyncio.shield(process.wait())
        raise


def hook_environment(settings: Settings, dns_port: int) -> dict[str, str]:
    """What the hooks read, set to what this server runs with (the bound DNS port included)."""
    return {
        **os.environ,
        "OUTPOST_ZONE": settings.zone,
        "OUTPOST_DATA_DIR": str(settings.data_dir),
        "OUTPOST_BIND_IP": settings.bind_ip,
        "OUTPOST_DNS_PORT": str(dns_port),
    }


async def acme_loop(plan: AcmePlan, certificates: Certificates, env: Mapping[str, str]) -> None:
    """Obtain the certificate when it is missing, else renew it (certbot renews only when due);
    reload after each run."""
    while True:
        present = await asyncio.to_thread(lambda: plan.paths.cert.exists() and plan.paths.key.exists())
        action = "renew" if present else "obtain"
        try:
            status = await run_certbot(plan.renew_args() if present else plan.obtain_args(), env)
        except (TimeoutError, OSError) as exc:  # a certbot that hangs or cannot start
            log.warning("certbot %s: %s", action, type(exc).__name__)
            status = -1
        log.info("certbot %s: exit %d", action, status)
        await certificates.reload_if_changed()
        await asyncio.sleep(RENEW_INTERVAL_SECONDS if certificates.loaded else RETRY_SECONDS)


def _query_address(env: Mapping[str, str]) -> tuple[str, int]:
    bind_ip = env.get("OUTPOST_BIND_IP", "0.0.0.0").strip() or "0.0.0.0"
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(bind_ip, bind_ip)
    return host, int(env.get("OUTPOST_DNS_PORT", "53").strip() or "53")


def _served(name: str, value: str, host: str, port: int) -> bool:
    query = dns.message.make_query(name, dns.rdatatype.TXT)
    try:
        answer = dns.query.udp(query, host, port=port, timeout=2.0)
    except (dns.exception.DNSException, OSError):
        return False
    return any(value.encode() in rdata.strings for rrset in answer.answer for rdata in rrset)


def wait_until_served(name: str, value: str, host: str, port: int, timeout: float = HOOK_WAIT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if _served(name, value, host, port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(HOOK_POLL_SECONDS)


def hook(action: str, env: Mapping[str, str]) -> int:
    """certbot's manual auth or cleanup hook, configured by certbot's and Outpost's environment."""
    zone = env.get("OUTPOST_ZONE", "").strip().lower().rstrip(".")
    domain = env.get("CERTBOT_DOMAIN", "").strip().lower().rstrip(".").removeprefix("*.")
    value = env.get("CERTBOT_VALIDATION", "").strip()
    if not zone or domain != zone or not value:
        print(f"outpost acme hook: CERTBOT_DOMAIN must be the zone {zone!r}, with a value", file=sys.stderr)
        return 1
    name = schema.challenge_name(zone)
    conn = schema.connect(Path(env.get("OUTPOST_DATA_DIR", "/var/lib/outpost")))
    try:
        if action == "cleanup":
            schema.remove_challenge(conn, name, value)
            return 0
        schema.add_challenge(conn, name, value, format_time(utc_now()))
    finally:
        conn.close()
    host, port = _query_address(env)
    if wait_until_served(name, value, host, port, HOOK_WAIT_SECONDS):
        return 0
    print(f"outpost acme hook: the name server at {host}:{port} did not serve the value", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m outpost.acme")
    commands = parser.add_subparsers(dest="command", required=True)
    hook_parser = commands.add_parser("hook", help="certbot manual hook")
    hook_parser.add_argument("action", choices=["auth", "cleanup"])
    arguments = parser.parse_args(argv)
    return hook(arguments.action, os.environ)


if __name__ == "__main__":
    sys.exit(main())
