"""A stand-in for certbot (tests only): logs its arguments; `certonly` runs the manual hooks for two
validation values, as certbot does for `<zone>` and `*.<zone>`, then writes a self-signed
certificate where certbot would put it."""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from conftest import make_certificate


def option(args: list[str], name: str) -> str:
    return args[args.index(name) + 1]


def main() -> int:
    args = sys.argv[1:]
    log = Path(os.environ["FAKE_CERTBOT_LOG"])
    with log.open("a") as handle:
        handle.write(json.dumps(args) + "\n")
    if args[0] != "certonly":
        return 0
    domains = [args[i + 1] for i, arg in enumerate(args) if arg == "-d"]
    values = ["validation-one", "validation-two"]
    for domain, value in zip(domains, values, strict=True):
        env = {**os.environ, "CERTBOT_DOMAIN": domain.removeprefix("*."), "CERTBOT_VALIDATION": value}
        if subprocess.run(option(args, "--manual-auth-hook"), shell=True, env=env, check=False).returncode != 0:
            return 1
    with log.open("a") as handle:
        handle.write(json.dumps({"served_while_validating": values}) + "\n")
    live = Path(option(args, "--config-dir")) / "live" / option(args, "--cert-name")
    make_certificate(live, serial=7)
    for value in values:
        env = {**os.environ, "CERTBOT_DOMAIN": domains[0], "CERTBOT_VALIDATION": value}
        subprocess.run(option(args, "--manual-cleanup-hook"), shell=True, env=env, check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
