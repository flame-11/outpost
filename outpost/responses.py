"""Responses a channel sets for its own names (CONTRACT section 9): their request and answer
shapes, the header and cross-origin rules, and the bytes a matching web request is answered with."""

import base64
import binascii
import hashlib
import re
import secrets
from dataclasses import dataclass
from http import HTTPStatus
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from outpost.records import StrictModel, Timestamp, Token

RESPONSE_MAX_BODY_BYTES = 65_536
RESPONSE_MAX_HEADERS = 32
RESPONSE_MAX_HEADER_BYTES = 8_192
RESPONSE_MAX_TTL_SECONDS = 86_400
RESPONSE_DEFAULT_TTL_SECONDS = 3_600
CHANNEL_MAX_RESPONSES = 64
ANY_PATH = "*"

_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$")
_HEADER_VALUE = re.compile(r"^[\t\x20-\x7e]{0,4096}$")
_VISIBLE = re.compile(r"^[\x21-\x7e]+$")
_OWNED_HEADERS = frozenset(
    {"content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"}
)
_CORS_PREFIX = "access-control-"
_ORIGIN_ENTRY = re.compile(r"^([a-z][a-z0-9+.\-]*)://(\*\.)?([a-z0-9\-._~%!$&'()*+,;=]+|\[[0-9a-f:.]+\])(:\d{1,5})?$")
_RESPONSE_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

ResponseId = Annotated[str, StringConstraints(pattern=r"^r[a-z0-9]{15}$")]
Path = Annotated[str, StringConstraints(pattern=r"^(\*|/[\x21\x22\x24-\x3e\x40-\x7e]{0,1023})$")]
HeaderToken = Annotated[str, StringConstraints(pattern=_HEADER_NAME.pattern)]
HeaderPair = Annotated[list[str], Field(min_length=2, max_length=2)]


def new_response_id() -> str:
    return "r" + "".join(secrets.choice(_RESPONSE_ID_ALPHABET) for _ in range(15))


def request_path(target: str | None) -> str | None:
    """The path a response's `path` is compared with: the target up to `?`, or an absolute-form
    target's URL path. None when the target is unreadable or has no path."""
    if target is None:
        return None
    if target.startswith("/"):
        return target.split("?", 1)[0]
    if "://" in target:
        return urlsplit(target).path or "/"
    return None


@dataclass(frozen=True, slots=True)
class _Origin:
    scheme: str
    host: str
    port: str


def _parse_origin(value: str) -> _Origin | None:
    match = _ORIGIN_ENTRY.fullmatch(value.lower())
    if match is None or match.group(2):
        return None
    return _Origin(scheme=match.group(1), host=match.group(3), port=match.group(4) or "")


def _origin_entry(value: str) -> str:
    if value in ("*", "null") or _ORIGIN_ENTRY.fullmatch(value.lower()):
        return value
    raise ValueError(f"not an origin, `*`, `null` or `scheme://*.suffix`: {value!r}")


OriginEntry = Annotated[str, StringConstraints(max_length=256), AfterValidator(_origin_entry)]


def origin_matches(entry: str, origin: str) -> bool:
    """CONTRACT section 9, `allow_origins`."""
    if entry == "*":
        return True
    if entry == "null":
        return origin == "null"
    parsed = _parse_origin(origin)
    match = _ORIGIN_ENTRY.fullmatch(entry.lower())
    if parsed is None or match is None:
        return False
    scheme, wildcard, host, port = match.group(1), match.group(2), match.group(3), match.group(4) or ""
    if parsed.scheme != scheme or parsed.port != port:
        return False
    if wildcard:
        return parsed.host.endswith("." + host) and len(parsed.host) > len(host) + 1
    return parsed.host == host


class CorsRules(StrictModel):
    allow_origins: Annotated[list[OriginEntry], Field(min_length=1, max_length=32)]
    allow_credentials: bool = False
    allow_methods: Annotated[list[HeaderToken], Field(min_length=1, max_length=32)] | None = None
    allow_headers: Annotated[list[HeaderToken], Field(min_length=1, max_length=32)] | None = None
    expose_headers: Annotated[list[HeaderToken], Field(max_length=32, default_factory=list)]
    max_age: Annotated[int, Field(ge=0, le=86_400)] | None = None
    allow_private_network: bool = False

    def matching_entry(self, origin: str | None) -> str | None:
        if origin is None or not _VISIBLE.fullmatch(origin):
            return None
        return next((entry for entry in self.allow_origins if origin_matches(entry, origin)), None)


def _check_headers(headers: list[list[str]], cors: CorsRules | None) -> None:
    if len(headers) > RESPONSE_MAX_HEADERS:
        raise ValueError(f"headers: at most {RESPONSE_MAX_HEADERS}")
    total = 0
    for name, value in headers:
        if not _HEADER_NAME.fullmatch(name):
            raise ValueError(f"headers: not a header name: {name!r}")
        if not _HEADER_VALUE.fullmatch(value):
            raise ValueError(f"headers: {name}: at most 4,096 characters of visible ASCII, space and tab")
        lowered = name.lower()
        if lowered in _OWNED_HEADERS:
            raise ValueError(f"headers: {name} is written by Outpost")
        if cors is not None and lowered.startswith(_CORS_PREFIX):
            raise ValueError(f"headers: {name} is written by `cors`; set it there or leave `cors` null")
        total += len(name) + len(value)
    if total > RESPONSE_MAX_HEADER_BYTES:
        raise ValueError(f"headers: names and values together at most {RESPONSE_MAX_HEADER_BYTES} bytes")


def _decode_body(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("body_b64: must be standard base64") from exc


class ResponseRequest(StrictModel):
    token: Token
    path: Path = ANY_PATH
    status: Annotated[int, Field(ge=200, le=599)] = 200
    headers: Annotated[list[HeaderPair], Field(default_factory=list)]
    body_b64: str = ""
    cors: CorsRules | None = None
    ttl_seconds: Annotated[int, Field(ge=1, le=RESPONSE_MAX_TTL_SECONDS)] = RESPONSE_DEFAULT_TTL_SECONDS

    @model_validator(mode="after")
    def _rules(self) -> Self:
        _check_headers(self.headers, self.cors)
        body = _decode_body(self.body_b64)
        if len(body) > RESPONSE_MAX_BODY_BYTES:
            raise ValueError(f"body_b64: the body is at most {RESPONSE_MAX_BODY_BYTES} bytes")
        if body and self.status in (204, 304):
            raise ValueError(f"body_b64: status {self.status} has no body")
        return self

    def body(self) -> bytes:
        return _decode_body(self.body_b64)


class ResponseAnswer(StrictModel):
    response_id: ResponseId
    token: Token
    path: Path
    status: int
    headers: list[HeaderPair]
    cors: CorsRules | None
    body_size: Annotated[int, Field(ge=0)]
    body_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    created_at: Timestamp
    expires_at: Timestamp


class ResponseList(StrictModel):
    responses: list[ResponseAnswer]


class ResponseSpec(StrictModel):
    """What the store keeps beside the body, as JSON."""

    status: int
    headers: list[HeaderPair]
    cors: CorsRules | None


@dataclass(frozen=True, slots=True)
class RequestFacts:
    """What of a web request decides its answer."""

    method: str | None
    origin: str | None
    preflight_method: str | None  # Access-Control-Request-Method
    preflight_headers: str | None  # Access-Control-Request-Headers
    private_network: bool  # Access-Control-Request-Private-Network: true


@dataclass(frozen=True, slots=True)
class ServedResponse:
    response_id: str
    channel_id: str
    token: str
    path: str
    spec: ResponseSpec
    body: bytes
    created_at: str
    expires_at: str

    def answer(self) -> ResponseAnswer:
        return ResponseAnswer(
            response_id=self.response_id,
            token=self.token,
            path=self.path,
            status=self.spec.status,
            headers=self.spec.headers,
            cors=self.spec.cors,
            body_size=len(self.body),
            body_sha256=hashlib.sha256(self.body).hexdigest(),
            created_at=self.created_at,
            expires_at=self.expires_at,
        )

    def render(self, request: RequestFacts) -> bytes:
        """The whole answer to one request (CONTRACT section 9)."""
        cors = self.spec.cors
        entry = cors.matching_entry(request.origin) if cors is not None else None
        if cors is not None and entry is not None and request.origin is not None:
            allow = _allow_origin(cors, entry, request.origin)
            if request.method == "OPTIONS" and request.preflight_method is not None:
                return _message(204, allow + _preflight_headers(cors, request), b"", send_body=False)
            exposed = [["Access-Control-Expose-Headers", ", ".join(cors.expose_headers)]] if cors.expose_headers else []
            headers = self.spec.headers + allow + exposed
        else:
            headers = self.spec.headers
        return _message(self.spec.status, headers, self.body, send_body=request.method != "HEAD")


def _allow_origin(cors: CorsRules, entry: str, origin: str) -> list[list[str]]:
    headers = (
        [["Access-Control-Allow-Origin", "*"]]
        if entry == "*" and not cors.allow_credentials
        else [["Access-Control-Allow-Origin", origin], ["Vary", "Origin"]]
    )
    if cors.allow_credentials:
        headers.append(["Access-Control-Allow-Credentials", "true"])
    return headers


def _preflight_headers(cors: CorsRules, request: RequestFacts) -> list[list[str]]:
    headers: list[list[str]] = []
    methods = ", ".join(cors.allow_methods) if cors.allow_methods else _token_or_none(request.preflight_method)
    if methods:
        headers.append(["Access-Control-Allow-Methods", methods])
    allowed = ", ".join(cors.allow_headers) if cors.allow_headers else _list_or_none(request.preflight_headers)
    if allowed:
        headers.append(["Access-Control-Allow-Headers", allowed])
    if cors.max_age is not None:
        headers.append(["Access-Control-Max-Age", str(cors.max_age)])
    if cors.allow_private_network and request.private_network:
        headers.append(["Access-Control-Allow-Private-Network", "true"])
    return headers


def _token_or_none(value: str | None) -> str | None:
    return value if value is not None and _HEADER_NAME.fullmatch(value) else None


def _list_or_none(value: str | None) -> str | None:
    return value if value is not None and value.strip() and _HEADER_VALUE.fullmatch(value) else None


def _reason(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Unknown"


def _message(status: int, headers: list[list[str]], body: bytes, *, send_body: bool) -> bytes:
    lines = [f"HTTP/1.1 {status} {_reason(status)}"]
    lines += [f"{name}: {value}" for name, value in headers]
    lines += [f"Content-Length: {len(body)}", "Connection: close"]
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    return head + body if send_body else head
