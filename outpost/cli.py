"""The client CLI: `outpost channel create`, `outpost list`, `outpost read`.

The key file holds the API address, the channel id, the X25519 private key and the channel
secret. It is written (mode 0600) before registration, so a repeat after an uncertain answer
registers the same key and secret again and gets the same channel back.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

import httpx
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from pydantic import ValidationError

from outpost.models import ChannelAnswer, ErrorBody, RecordsPage, RegistrationAnswer, SealedRecord
from outpost.records import OPENED_RECORD, ChannelId, DnsRecord, HttpRecord, StrictModel
from outpost.sealing import open_sealed

HTTP_TIMEOUT_SECONDS = 10.0


class CliError(Exception):
    pass


class KeyFile(StrictModel):
    api: str
    channel_id: ChannelId | None
    zone: str | None
    private_key: str
    secret: str

    def private_key_bytes(self) -> bytes:
        return base64.b64decode(self.private_key)


def _load_key_file(path: Path) -> KeyFile:
    try:
        return KeyFile.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise CliError(f"cannot read key file {path}: {exc}") from exc


def _save_key_file(path: Path, key_file: KeyFile) -> None:
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(key_file.model_dump_json(indent=2) + "\n")
    os.replace(temporary, path)


def _raise_for_error(response: httpx.Response) -> None:
    if response.status_code < 400:
        return
    try:
        error = ErrorBody.model_validate_json(response.content).error
        detail = f"{error.code}: {error.message}"
    except ValidationError:
        detail = response.text[:200]
    raise CliError(f"HTTP {response.status_code} {detail}")


def create_channel(api: str, api_key: str, key_path: Path, client: httpx.Client) -> KeyFile:
    if key_path.exists():
        key_file = _load_key_file(key_path).model_copy(update={"api": api})
    else:
        key_file = KeyFile(
            api=api,
            channel_id=None,
            zone=None,
            private_key=base64.b64encode(bytes(PrivateKey.generate())).decode("ascii"),
            secret=secrets.token_hex(32),
        )
        _save_key_file(key_path, key_file)
    public_key = bytes(PrivateKey(key_file.private_key_bytes()).public_key)
    response = client.post(
        f"{api.rstrip('/')}/v1/channels",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "secret_sha256": hashlib.sha256(key_file.secret.encode()).hexdigest(),
        },
    )
    _raise_for_error(response)
    answer = RegistrationAnswer.model_validate_json(response.content)
    key_file = key_file.model_copy(update={"channel_id": answer.channel_id, "zone": answer.zone})
    _save_key_file(key_path, key_file)
    return key_file


def channel_status(key_file: KeyFile, client: httpx.Client) -> ChannelAnswer:
    response = client.get(_channel_url(key_file), headers=_auth(key_file))
    _raise_for_error(response)
    return ChannelAnswer.model_validate_json(response.content)


def pull(key_file: KeyFile, client: httpx.Client, *, after: int, wait: int) -> Iterator[SealedRecord]:
    """Every held record past `after`, page by page; `wait` applies to the first page."""
    while True:
        response = client.get(
            f"{_channel_url(key_file)}/records",
            params={"after": after, "wait": wait},
            headers=_auth(key_file),
            timeout=HTTP_TIMEOUT_SECONDS + wait,
        )
        _raise_for_error(response)
        page = RecordsPage.model_validate_json(response.content)
        yield from page.records
        if not page.more or not page.records:
            return
        after = page.records[-1].seq
        wait = 0


def open_record(key_file: KeyFile, record: SealedRecord) -> DnsRecord | HttpRecord:
    """Raises CryptoError or ValidationError when the record does not open or validate."""
    plaintext = open_sealed(key_file.private_key_bytes(), base64.b64decode(record.sealed))
    opened = OPENED_RECORD.validate_json(plaintext)
    if opened.received_at != record.received_at:
        raise ValueError("received_at inside the box differs from the one outside")
    return opened


def _channel_url(key_file: KeyFile) -> str:
    if key_file.channel_id is None:
        raise CliError("the key file holds no channel id; run `outpost channel create` again")
    return f"{key_file.api.rstrip('/')}/v1/channels/{key_file.channel_id}"


def _auth(key_file: KeyFile) -> dict[str, str]:
    return {"Authorization": f"Bearer {key_file.secret}"}


def _cmd_create(args: argparse.Namespace, client: httpx.Client) -> None:
    key_file = create_channel(args.api, args.api_key, Path(args.key_file), client)
    print(f"channel_id\t{key_file.channel_id}")
    print(f"zone\t{key_file.zone}")
    print(f"address\t{{token}}-{key_file.channel_id}.{key_file.zone}")
    print(f"key_file\t{args.key_file}")


def _cmd_list(args: argparse.Namespace, client: httpx.Client) -> None:
    key_file = _load_key_file(Path(args.key_file))
    for record in pull(key_file, client, after=args.after, wait=args.wait):
        try:
            opened = open_record(key_file, record)
        except (CryptoError, ValueError):
            print(f"{record.seq}\tunreadable\t\t\t\t{record.received_at}")
            continue
        print(
            f"{record.seq}\t{opened.protocol}\t{opened.token}\t{opened.name}\t{opened.source_ip}\t{opened.received_at}"
        )


def _cmd_read(args: argparse.Namespace, client: httpx.Client) -> None:
    key_file = _load_key_file(Path(args.key_file))
    records = pull(key_file, client, after=args.seq - 1, wait=0)
    record = next(records, None)
    if record is None or record.seq != args.seq:
        raise CliError(f"record {args.seq} is not held")
    try:
        opened = open_record(key_file, record)
    except (CryptoError, ValueError) as exc:
        raise CliError(f"record {args.seq} does not open or validate: {exc}") from exc
    print(json.dumps(opened.model_dump(), indent=2))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="outpost", description="Outpost client")
    commands = parser.add_subparsers(dest="command", required=True)
    channel = commands.add_parser("channel", help="channel commands")
    channel_commands = channel.add_subparsers(dest="channel_command", required=True)
    create = channel_commands.add_parser("create", help="register a channel, keeping its keys in a key file")
    create.add_argument("--api", required=True, help="API base address, e.g. http://172.17.0.1:9080")
    create.add_argument("--api-key", required=True, help="the operator's API key")
    create.add_argument("--key-file", required=True)
    create.set_defaults(handler=_cmd_create)
    listing = commands.add_parser("list", help="pull and print the channel's records, one line each")
    listing.add_argument("--key-file", required=True)
    listing.add_argument("--after", type=int, default=0)
    listing.add_argument("--wait", type=int, default=0, help="seconds to wait for a first record")
    listing.set_defaults(handler=_cmd_list)
    read = commands.add_parser("read", help="print one opened record in full")
    read.add_argument("--key-file", required=True)
    read.add_argument("seq", type=int)
    read.set_defaults(handler=_cmd_read)
    return parser


def run_cli(argv: Sequence[str], client: httpx.Client | None = None) -> int:
    args = _parser().parse_args(list(argv))
    own_client = client is None
    http_client = client or httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, trust_env=False)
    try:
        args.handler(args, http_client)
    except CliError as exc:
        print(f"outpost: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"outpost: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        if own_client:
            http_client.close()
    return 0


def main() -> None:
    sys.exit(run_cli(sys.argv[1:]))
