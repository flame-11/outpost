"""The `outpost` command: channel create|status|delete, list, read, watch, assemble,
response set|list|delete, and `mcp`.

A channel's key file is named by `--channel LABEL` (`$OUTPOST_HOME/channels/LABEL.json`, label
`default` when neither option is given) or given as a path with `--key-file`.
"""

import argparse
import asyncio
import base64
import json
import os
import sys
from collections.abc import Callable, Coroutine, Sequence
from contextlib import aclosing
from pathlib import Path
from typing import Any, TextIO

import httpx
from pydantic import ValidationError

from outpost.assemble import assemble
from outpost.client import (
    KeyFile,
    OutpostError,
    ResponseInfo,
    SealedRecord,
    channel_state,
    check_token,
    delete_channel,
    delete_response,
    fetch_record,
    key_file_path,
    list_responses,
    load_key_file,
    new_http_client,
    open_record,
    pull,
    register,
    set_response,
)
from outpost.records import DnsRecord
from outpost.responses import ANY_PATH, RESPONSE_DEFAULT_TTL_SECONDS, ResponseRequest
from outpost.views import detail

Handler = Callable[[argparse.Namespace, httpx.AsyncClient], Coroutine[Any, Any, None]]


def _path(args: argparse.Namespace) -> Path:
    return Path(args.key_file) if args.key_file else key_file_path(args.channel)


def _key_file(args: argparse.Namespace) -> KeyFile:
    return load_key_file(_path(args))


async def _create(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    if not args.api or not args.api_key:
        raise OutpostError("invalid_request", "give --api and --api-key, or set OUTPOST_API_URL and OUTPOST_API_KEY")
    path = _path(args)
    key_file, answer = await register(http, args.api, args.api_key, path, retention_days=args.retention_days)
    print(f"channel_id\t{key_file.channel_id}")
    print(f"zone\t{answer.zone}")
    print(f"address\t{{token}}-{key_file.channel_id}.{answer.zone}")
    print(f"listeners\t{','.join(answer.listeners)}")
    print(f"retention_days\t{answer.retention_days}")
    for name in ("source_rate", "channel_rate"):
        if (value := getattr(answer, name)) is not None:
            print(f"{name}\t{value}")
    print(f"key_file\t{path}")


async def _status(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    state = await channel_state(http, _key_file(args))
    for name, value in state.model_dump().items():
        if value is not None:
            print(f"{name}\t{','.join(value) if isinstance(value, list) else value}")


async def _delete(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    path = _path(args)
    key_file = load_key_file(path)
    try:
        await delete_channel(http, key_file)
    except OutpostError as exc:
        if exc.server_code != "channel_not_found":
            raise
    path.unlink()
    print(f"deleted\t{key_file.channel_id}")


def _line(seq: int, key_file: KeyFile, record: SealedRecord, out: TextIO) -> None:
    try:
        opened = open_record(key_file, record)
    except OutpostError:
        print(f"{seq}\tunreadable\t\t\t\t{record.received_at}", file=out)
        return
    fields = (seq, opened.protocol, opened.token, opened.name, opened.source_ip, opened.received_at)
    print("\t".join(map(str, fields)), file=out)


async def _list(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    key_file = _key_file(args)
    async for record in pull(http, key_file, after=args.after, wait=args.wait):
        _line(record.seq, key_file, record, sys.stdout)


async def _watch(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    key_file = _key_file(args)
    after = args.after if args.after is not None else (await channel_state(http, key_file)).last_seq
    shown = 0
    while args.count is None or shown < args.count:
        async with aclosing(pull(http, key_file, after=after, wait=25)) as records:
            async for record in records:
                _line(record.seq, key_file, record, sys.stdout)
                sys.stdout.flush()
                after, shown = record.seq, shown + 1
                if args.count is not None and shown >= args.count:
                    break


async def _read(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    record = await fetch_record(http, _key_file(args), args.seq)
    try:
        shown = detail(args.seq, record, part=args.part)
    except IndexError as exc:
        raise OutpostError("invalid_request", str(exc)) from exc
    print(json.dumps(shown, indent=2, ensure_ascii=False))


async def _assemble(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    key_file = _key_file(args)
    token = check_token(args.token)
    records: list[DnsRecord] = []
    async for sealed in pull(http, key_file, limit=200):
        try:
            opened = open_record(key_file, sealed)
        except OutpostError:
            continue
        if isinstance(opened, DnsRecord) and opened.token == token:
            records.append(opened)
    result = assemble(records, token, args.encoding)
    if args.out:
        Path(args.out).write_bytes(result.data)
    else:
        sys.stdout.buffer.write(result.data)
        sys.stdout.flush()
    print(
        f"bytes\t{len(result.data)}\nchunks\t{len(result.present)}\n"
        f"missing\t{','.join(map(str, result.missing))}\nundecodable\t{','.join(map(str, result.undecodable))}",
        file=sys.stderr,
    )


def _response_request(args: argparse.Namespace) -> ResponseRequest:
    headers = []
    for header in args.header:
        name, sep, value = header.partition(":")
        if not sep:
            raise OutpostError("invalid_request", f"--header {header!r} is not `Name: value`")
        headers.append([name.strip(), value.strip()])
    body = Path(args.body_file).read_bytes() if args.body_file else (args.body or "").encode()
    cors: dict[str, object] | None = None
    if args.cors_origin:
        cors = {
            "allow_origins": args.cors_origin,
            "allow_credentials": args.cors_credentials,
            "allow_methods": args.cors_method or None,
            "allow_headers": args.cors_header or None,
            "expose_headers": args.cors_expose,
            "max_age": args.cors_max_age,
            "allow_private_network": args.cors_private_network,
        }
    try:
        return ResponseRequest.model_validate(
            {
                "token": args.token,
                "path": args.path,
                "status": args.status,
                "headers": headers,
                "body_b64": base64.b64encode(body).decode("ascii"),
                "cors": cors,
                "ttl_seconds": args.ttl,
            },
            strict=False,
        )
    except ValidationError as exc:
        raise OutpostError("invalid_request", str(exc)) from exc


def _response_line(info: ResponseInfo, key_file: KeyFile) -> str:
    path = "/" if info.path == ANY_PATH else info.path
    url = f"http://{info.token}-{key_file.channel_id}.{key_file.zone}{path}"
    return "\t".join(
        map(str, (info.response_id, info.token, info.path, info.status, info.body_size, info.expires_at, url))
    )


async def _response_set(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    key_file = _key_file(args)
    print(_response_line(await set_response(http, key_file, _response_request(args)), key_file))


async def _response_list(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    key_file = _key_file(args)
    for info in await list_responses(http, key_file):
        print(_response_line(info, key_file))


async def _response_delete(args: argparse.Namespace, http: httpx.AsyncClient) -> None:
    await delete_response(http, _key_file(args), args.response_id)
    print(f"deleted\t{args.response_id}")


def _response_parser(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    response = commands.add_parser("response", help="set, list or delete what the channel's names answer")
    response_commands = response.add_subparsers(dest="response_command", required=True)
    setting = response_commands.add_parser("set", help="set the answer of one token and path")
    _channel_options(setting)
    setting.add_argument("token")
    setting.add_argument("--path", default=ANY_PATH, help="exact path, or * for any (default)")
    setting.add_argument("--status", type=int, default=200)
    setting.add_argument("--header", action="append", default=[], help="`Name: value`; repeat for more")
    body = setting.add_mutually_exclusive_group()
    body.add_argument("--body", help="body text (UTF-8)")
    body.add_argument("--body-file", help="body bytes from this file")
    setting.add_argument("--ttl", type=int, default=RESPONSE_DEFAULT_TTL_SECONDS, help="seconds it answers")
    setting.add_argument("--cors-origin", action="append", default=[], help="allowed origin; turns on cors")
    setting.add_argument("--cors-credentials", action="store_true")
    setting.add_argument("--cors-method", action="append", default=[], help="preflight method (default: as asked)")
    setting.add_argument("--cors-header", action="append", default=[], help="preflight header (default: as asked)")
    setting.add_argument("--cors-expose", action="append", default=[], help="exposed response header")
    setting.add_argument("--cors-max-age", type=int)
    setting.add_argument("--cors-private-network", action="store_true")
    setting.set_defaults(handler=_response_set)
    listing = response_commands.add_parser("list", help="print the unexpired responses, one line each")
    _channel_options(listing)
    listing.set_defaults(handler=_response_list)
    delete = response_commands.add_parser("delete", help="stop one response")
    _channel_options(delete)
    delete.add_argument("response_id")
    delete.set_defaults(handler=_response_delete)


def _channel_options(parser: argparse.ArgumentParser) -> None:
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--channel", default="default", help="channel label (default: default)")
    choice.add_argument("--key-file", help="key file path, instead of a label")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="outpost", description="Outpost client")
    commands = parser.add_subparsers(dest="command", required=True)

    channel = commands.add_parser("channel", help="create, show or delete a channel")
    channel_commands = channel.add_subparsers(dest="channel_command", required=True)
    create = channel_commands.add_parser("create", help="register a channel, keeping its keys in a key file")
    create.add_argument("--api", default=os.environ.get("OUTPOST_API_URL"), help="API base address (OUTPOST_API_URL)")
    create.add_argument("--api-key", default=os.environ.get("OUTPOST_API_KEY"), help="API key (OUTPOST_API_KEY)")
    create.add_argument("--retention-days", type=int, help="days records are kept, up to the instance's limit")
    _channel_options(create)
    create.set_defaults(handler=_create)
    status = channel_commands.add_parser("status", help="show the channel's state")
    _channel_options(status)
    status.set_defaults(handler=_status)
    delete = channel_commands.add_parser("delete", help="delete the channel, its records and its key file")
    _channel_options(delete)
    delete.set_defaults(handler=_delete)

    listing = commands.add_parser("list", help="print the channel's records, one line each")
    _channel_options(listing)
    listing.add_argument("--after", type=int, default=0, help="only records with a higher seq")
    listing.add_argument("--wait", type=int, default=0, help="seconds to wait for a first record (at most 25)")
    listing.set_defaults(handler=_list)

    read = commands.add_parser("read", help="print one record in full, as JSON")
    _channel_options(read)
    read.add_argument("seq", type=int)
    read.add_argument("--part", type=int, help="mail part to show (default: the first text part)")
    read.set_defaults(handler=_read)

    watch = commands.add_parser("watch", help="print records as they arrive, until interrupted")
    _channel_options(watch)
    watch.add_argument("--after", type=int, help="start past this seq (default: the newest record)")
    watch.add_argument("--count", type=int, help="stop after this many records")
    watch.set_defaults(handler=_watch)

    assembled = commands.add_parser("assemble", help="reassemble data sent as indexed lookups of one token")
    _channel_options(assembled)
    assembled.add_argument("token")
    assembled.add_argument("--encoding", choices=["hex", "base32"], required=True)
    assembled.add_argument("--out", help="write the data to this file instead of standard output")
    assembled.set_defaults(handler=_assemble)

    _response_parser(commands)

    mcp = commands.add_parser("mcp", help="run the MCP server on standard input and output")
    mcp.set_defaults(handler=None)
    return parser


async def _run(handler: Handler, args: argparse.Namespace) -> None:
    async with new_http_client() as http:
        await handler(args, http)


def run_cli(argv: Sequence[str]) -> int:
    args = _parser().parse_args(list(argv))
    if args.handler is None:
        from outpost.mcp_server import main as mcp_main

        mcp_main()
        return 0
    try:
        asyncio.run(_run(args.handler, args))
    except OutpostError as exc:
        print(f"outpost: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


def main() -> None:
    sys.exit(run_cli(sys.argv[1:]))
