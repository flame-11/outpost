"""`outpost-admin`: API keys, on the host, in the store of OUTPOST_DATA_DIR.

    outpost-admin key add NAME [--max-channels N] [--channel-rate N]   prints the new key once
    outpost-admin key list
    outpost-admin key revoke NAME [--delete-channels]

A running server reads keys from the store at each registration, so changes need no restart.
"""

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from outpost import keys, schema
from outpost.records import format_time, utc_now


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="outpost-admin", description="Manage the API keys of this Outpost host.")
    groups = parser.add_subparsers(dest="group", required=True)
    key = groups.add_parser("key", help="API keys").add_subparsers(dest="command", required=True)
    add = key.add_parser("add", help="add a key and print it once")
    add.add_argument("name")
    add.add_argument("--max-channels", type=int, default=None, help="channels the key may hold")
    add.add_argument("--channel-rate", type=int, default=None, help="stored records a minute per channel")
    key.add_parser("list", help="list the keys")
    revoke = key.add_parser("revoke", help="revoke a key; it can no longer register channels")
    revoke.add_argument("name")
    revoke.add_argument("--delete-channels", action="store_true", help="also delete its channels and their records")
    return parser


def _optional(value: int | None) -> str:
    return "-" if value is None else str(value)


def run_admin(argv: Sequence[str], env: Mapping[str, str]) -> int:
    arguments = _parser().parse_args(argv)
    conn = schema.connect(Path(env.get("OUTPOST_DATA_DIR", "/var/lib/outpost")))
    now = format_time(utc_now())
    try:
        if arguments.command == "add":
            print(
                keys.add_key(
                    conn,
                    arguments.name,
                    now,
                    max_channels=arguments.max_channels,
                    channel_rate=arguments.channel_rate,
                )
            )
        elif arguments.command == "list":
            print("name\tstatus\tcreated_at\tmax_channels\tchannel_rate\tchannels")
            for listing in keys.list_keys(conn):
                status = "active" if listing.revoked_at is None else f"revoked {listing.revoked_at}"
                print(
                    f"{listing.name}\t{status}\t{listing.created_at}\t{_optional(listing.max_channels)}"
                    f"\t{_optional(listing.channel_rate)}\t{listing.channels}"
                )
        else:
            deleted = keys.revoke_key(conn, arguments.name, now, delete_channels=arguments.delete_channels)
            print(f"revoked {arguments.name}; {deleted} channels deleted")
    except keys.KeyRefused as exc:
        print(f"outpost-admin: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


def main() -> None:
    sys.exit(run_admin(sys.argv[1:], os.environ))
