"""The client library: key files, registration, channel state, pulls, opening records, deletion,
and the responses a channel serves.

A key file holds the API address, the channel id, the X25519 private key and the channel secret.
It is written (mode 0600) before registration, so a repeat after an uncertain answer registers
the same key and secret again and gets the same channel back. Named key files live in
`$OUTPOST_HOME/channels/<label>.json`; `OUTPOST_HOME` defaults to `~/.config/outpost`.

Every failure is an `OutpostError` with a stable `code`.
"""

import base64
import binascii
import hashlib
import os
import re
import secrets
from collections.abc import AsyncIterator
from contextlib import aclosing
from pathlib import Path
from typing import Annotated, Any

import httpx
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from outpost.records import OPENED_RECORD, ChannelId, DnsRecord, HttpRecord, SmtpRecord, StrictModel, Timestamp
from outpost.responses import ResponseRequest
from outpost.sealing import open_sealed

HTTP_TIMEOUT_SECONDS = 10.0
PULL_MAX_WAIT_SECONDS = 25
LABEL_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
TOKEN_PATTERN = re.compile(r"[a-z0-9]{1,20}")

OpenedRecord = DnsRecord | HttpRecord | SmtpRecord


class OutpostError(Exception):
    """`code` is one of `outpost_unreachable`, `outpost_refused`, `record_not_found`, `record_unreadable`,
    `key_file_unreadable`, `invalid_request`."""

    def __init__(self, code: str, message: str, *, server_code: str | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.server_code = server_code  # the API's error code, for `outpost_refused`


class KeyFile(StrictModel):
    api: str
    channel_id: ChannelId | None
    zone: str | None
    private_key: str
    secret: str

    def private_key_bytes(self) -> bytes:
        return base64.b64decode(self.private_key)

    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(PrivateKey(self.private_key_bytes()).public_key)).decode("ascii")


class Answer(BaseModel):
    """API answers are read strictly by type; fields this client does not know are ignored."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)


Count = Annotated[int, Field(ge=0)]


class Registration(Answer):
    channel_id: ChannelId
    zone: str
    listeners: list[str]
    retention_days: Count
    source_rate: Count | None = None
    channel_rate: Count | None = None
    responses: bool = False  # absent before Outpost 1.1


class ChannelState(Registration):
    last_seq: Count
    held_records: Count
    dropped_total: Count


class SealedRecord(Answer):
    seq: Annotated[int, Field(ge=1)]
    received_at: Timestamp
    sealed: str


class RecordsPage(Answer):
    records: list[SealedRecord]
    more: bool
    dropped_total: Count


class ResponseInfo(Answer):
    """A response the channel serves (CONTRACT section 9), without its body."""

    response_id: str
    token: str
    path: str
    status: int
    headers: list[list[str]]
    cors: dict[str, Any] | None
    body_size: Count
    body_sha256: str
    created_at: Timestamp
    expires_at: Timestamp


class _ResponseList(Answer):
    responses: list[ResponseInfo]


class _ErrorDetail(Answer):
    code: str
    message: str


class _ErrorBody(Answer):
    error: _ErrorDetail


def outpost_home() -> Path:
    configured = os.environ.get("OUTPOST_HOME")
    return Path(configured) if configured else Path.home() / ".config" / "outpost"


def key_file_path(label: str) -> Path:
    if not LABEL_PATTERN.fullmatch(label):
        raise OutpostError("invalid_request", f"channel label {label!r} is not 1 to 40 of a-z0-9_- starting a-z0-9")
    return outpost_home() / "channels" / f"{label}.json"


def check_token(token: str) -> str:
    if not TOKEN_PATTERN.fullmatch(token):
        raise OutpostError("invalid_request", f"token {token!r} is not 1 to 20 of a-z0-9")
    return token


def load_key_file(path: Path) -> KeyFile:
    try:
        return KeyFile.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise OutpostError("key_file_unreadable", f"cannot read key file {path}: {exc}") from exc


def save_key_file(path: Path, key_file: KeyFile) -> None:
    """Replace the key file atomically, mode 0600."""
    temporary = _write_temporary(path, key_file)
    os.replace(temporary, path)


def new_key_file(path: Path, api: str) -> KeyFile:
    """Write a fresh key pair and secret to `path`, unless a key file is already there (then keep that one)."""
    key_file = KeyFile(
        api=api,
        channel_id=None,
        zone=None,
        private_key=base64.b64encode(bytes(PrivateKey.generate())).decode("ascii"),
        secret=secrets.token_hex(32),
    )
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = _write_temporary(path, key_file)
    try:
        os.link(temporary, path)
    except FileExistsError:
        return load_key_file(path)
    finally:
        temporary.unlink()
    return key_file


def _write_temporary(path: Path, key_file: KeyFile) -> Path:
    temporary = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(key_file.model_dump_json(indent=2) + "\n")
    return temporary


def new_http_client(transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, trust_env=False, transport=transport)


async def register(
    http: httpx.AsyncClient, api: str, api_key: str, path: Path, *, retention_days: int | None = None
) -> tuple[KeyFile, Registration]:
    """Register the key in `path` (creating it first when absent) at `api`; a repeat answers the same channel."""
    key_file = load_key_file(path) if path.exists() else new_key_file(path, api)
    key_file = key_file.model_copy(update={"api": api})
    body: dict[str, object] = {
        "public_key": key_file.public_key_b64(),
        "secret_sha256": hashlib.sha256(key_file.secret.encode()).hexdigest(),
    }
    if retention_days is not None:
        body["retention_days"] = retention_days
    response = await _call(http, "POST", f"{api.rstrip('/')}/v1/channels", api_key, json=body)
    answer = _parse(Registration, response)
    key_file = key_file.model_copy(update={"channel_id": answer.channel_id, "zone": answer.zone})
    save_key_file(path, key_file)
    return key_file, answer


async def channel_state(http: httpx.AsyncClient, key_file: KeyFile) -> ChannelState:
    response = await _call(http, "GET", _channel_url(key_file), key_file.secret)
    return _parse(ChannelState, response)


async def delete_channel(http: httpx.AsyncClient, key_file: KeyFile) -> None:
    """Delete the channel and its records on the server; the key file is left to the caller."""
    await _call(http, "DELETE", _channel_url(key_file), key_file.secret)


async def pull(
    http: httpx.AsyncClient, key_file: KeyFile, *, after: int = 0, limit: int = 100, wait: int = 0
) -> AsyncIterator[SealedRecord]:
    """Every held record past `after`, ascending, `limit` a page, following `more`.

    `wait` (at most 25 seconds) applies to the first page: the server holds it until a record arrives.
    """
    wait = min(wait, PULL_MAX_WAIT_SECONDS)
    while True:
        response = await _call(
            http,
            "GET",
            f"{_channel_url(key_file)}/records",
            key_file.secret,
            params={"after": after, "limit": limit, "wait": wait},
            timeout=HTTP_TIMEOUT_SECONDS + wait,
        )
        page = _parse(RecordsPage, response)
        for record in page.records:
            yield record
        if not page.more or not page.records:
            return
        after = page.records[-1].seq
        wait = 0


def open_record(key_file: KeyFile, record: SealedRecord) -> OpenedRecord:
    try:
        plaintext = open_sealed(key_file.private_key_bytes(), base64.b64decode(record.sealed, validate=True))
        opened = OPENED_RECORD.validate_json(plaintext)
    except (CryptoError, binascii.Error, ValidationError) as exc:
        raise OutpostError("record_unreadable", f"record {record.seq} does not open or validate: {exc}") from exc
    if opened.received_at != record.received_at:
        raise OutpostError("record_unreadable", f"record {record.seq}: received_at differs inside and outside the box")
    return opened


async def fetch_record(http: httpx.AsyncClient, key_file: KeyFile, seq: int) -> OpenedRecord:
    async with aclosing(pull(http, key_file, after=seq - 1, limit=1)) as records:
        async for record in records:
            if record.seq == seq:
                return open_record(key_file, record)
            break
    raise OutpostError("record_not_found", f"record {seq} is not held")


async def set_response(http: httpx.AsyncClient, key_file: KeyFile, request: ResponseRequest) -> ResponseInfo:
    """Set what the channel's token answers on `request.path`, replacing what it answered there before."""
    body = request.model_dump(mode="json")
    response = await _call(http, "POST", f"{_channel_url(key_file)}/responses", key_file.secret, json=body)
    return _parse(ResponseInfo, response)


async def list_responses(http: httpx.AsyncClient, key_file: KeyFile) -> list[ResponseInfo]:
    response = await _call(http, "GET", f"{_channel_url(key_file)}/responses", key_file.secret)
    return _parse(_ResponseList, response).responses


async def delete_response(http: httpx.AsyncClient, key_file: KeyFile, response_id: str) -> None:
    await _call(http, "DELETE", f"{_channel_url(key_file)}/responses/{response_id}", key_file.secret)


def _channel_url(key_file: KeyFile) -> str:
    if key_file.channel_id is None:
        raise OutpostError("invalid_request", "the key file holds no channel id; create the channel again")
    return f"{key_file.api.rstrip('/')}/v1/channels/{key_file.channel_id}"


async def _call(
    http: httpx.AsyncClient,
    method: str,
    url: str,
    bearer: str,
    *,
    json: dict[str, object] | None = None,
    params: dict[str, int] | None = None,
    timeout: float = HTTP_TIMEOUT_SECONDS,
) -> httpx.Response:
    try:
        response = await http.request(
            method, url, json=json, params=params, headers={"Authorization": f"Bearer {bearer}"}, timeout=timeout
        )
    except httpx.HTTPError as exc:
        raise OutpostError("outpost_unreachable", f"{method} {url}: {type(exc).__name__}: {exc}") from exc
    if response.status_code >= 400:
        server_code = None
        try:
            error = _ErrorBody.model_validate_json(response.content).error
            server_code, detail = error.code, f"{error.code}: {error.message}"
        except ValidationError:
            detail = response.text[:200]
        retry = response.headers.get("Retry-After")
        suffix = f" (retry after {retry} s)" if retry else ""
        raise OutpostError("outpost_refused", f"HTTP {response.status_code} {detail}{suffix}", server_code=server_code)
    return response


def _parse[M: Answer](model: type[M], response: httpx.Response) -> M:
    try:
        return model.model_validate_json(response.content)
    except ValidationError as exc:
        raise OutpostError("outpost_refused", f"unexpected answer: {exc}") from exc
