"""The pull API (CONTRACT section 5)."""

import asyncio
import base64
import hashlib
import hmac
import logging
import math
import sqlite3
from dataclasses import dataclass
from typing import Annotated, NoReturn

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from outpost.addresses import CHANNEL_ID
from outpost.config import Limits, Settings
from outpost.keys import ApiKey, bootstrap_key
from outpost.models import (
    ChannelAnswer,
    ErrorBody,
    ErrorCode,
    ErrorDetail,
    HealthAnswer,
    RecordsPage,
    RegistrationAnswer,
    RegistrationRequest,
    SealedRecord,
    decode_public_key,
)
from outpost.rates import RateWindow
from outpost.recorder import Notifier
from outpost.records import utc_now
from outpost.store import ChannelConflict, Database, Page, QuotaExceeded

log = logging.getLogger("outpost.api")


class ApiError(Exception):
    def __init__(self, status: int, code: ErrorCode, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


@dataclass(frozen=True, slots=True)
class ApiContext:
    settings: Settings
    limits: Limits
    db: Database
    notifier: Notifier


def _error_response(status: int, code: ErrorCode, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    body = ErrorBody(error=ErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status, content=body.model_dump(), headers=headers)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _bearer(request: Request) -> str | None:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    value = value.strip()
    return value if scheme.lower() == "bearer" and value else None


def create_app(ctx: ApiContext) -> FastAPI:
    settings, limits, db = ctx.settings, ctx.limits, ctx.db
    auth_failures = RateWindow(limits.auth_fail_rate, 60.0)
    app = FastAPI(title="Outpost", version="1", docs_url=None, redoc_url=None)

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return _error_response(exc.status, exc.code, exc.message, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = exc.errors()
        first = errors[0] if errors else {}
        location = [str(part) for part in first.get("loc", ()) if part not in ("body", "query", "path")]
        field = ".".join(location) or "body"
        return _error_response(422, "invalid_request", f"{field}: {first.get('msg', 'invalid')}")

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error_response(exc.status_code, "invalid_request", str(exc.detail))

    @app.exception_handler(sqlite3.Error)
    async def _storage(_: Request, exc: sqlite3.Error) -> JSONResponse:
        log.error("storage error: %s", type(exc).__name__)
        return _error_response(503, "storage_unavailable", "the store could not be read or written")

    def _authenticate(request: Request, stored_sha256: str | None) -> None:
        """Constant-time check of the bearer value against a stored SHA-256; counts failures."""
        value = _bearer(request)
        if value is not None and stored_sha256 is not None and hmac.compare_digest(_sha256_hex(value), stored_sha256):
            return
        _refuse(request)

    def _refuse(request: Request) -> NoReturn:
        auth_failures.add(request.client.host if request.client else "")
        raise ApiError(401, "unauthorized", "missing or wrong bearer value")

    def _rate_gate(request: Request) -> None:
        source = request.client.host if request.client else ""
        if not auth_failures.allows(source):
            retry = max(1, math.ceil(auth_failures.seconds_until_allowed(source)))
            raise ApiError(429, "rate_limited", "too many failed authentications", {"Retry-After": str(retry)})

    async def api_key(request: Request) -> ApiKey:
        """The bootstrap key (OUTPOST_API_KEY_SHA256) or an unrevoked named key from the store."""
        _rate_gate(request)
        value = _bearer(request)
        if value is None:
            _refuse(request)
        digest = _sha256_hex(value or "")
        if settings.api_key_sha256 is not None and hmac.compare_digest(digest, settings.api_key_sha256):
            return bootstrap_key()
        key = await db.api_key(digest)
        if key is None or key.revoked:
            _refuse(request)
        return key

    async def channel(request: Request, channel_id: str) -> str:
        _rate_gate(request)
        if _bearer(request) is None:
            _authenticate(request, None)
        stored = await db.channel_secret_sha256(channel_id) if CHANNEL_ID.fullmatch(channel_id) else None
        if stored is None:
            raise ApiError(404, "channel_not_found", f"no channel {channel_id}")
        _authenticate(request, stored)
        await db.touch(channel_id, utc_now())
        return channel_id

    def _retention(asked: int | None) -> int:
        return settings.retention_days if asked is None else min(asked, settings.retention_days)

    @app.get("/v1/health")
    async def health() -> HealthAnswer:
        return HealthAnswer(status="ok", contract=1, store_full=await db.store_full())

    @app.post(
        "/v1/channels",
        status_code=201,
        response_model=RegistrationAnswer,
        responses={200: {"model": RegistrationAnswer, "description": "already registered with this secret"}},
    )
    async def register(body: RegistrationRequest, key: Annotated[ApiKey, Depends(api_key)]) -> JSONResponse:
        if body.retention_days is not None and body.retention_days > settings.retention_days:
            raise ApiError(
                422, "invalid_request", f"retention_days: must be at most {settings.retention_days} on this instance"
            )
        try:
            registration = await db.register(
                decode_public_key(body.public_key), body.secret_sha256.lower(), utc_now(), key, body.retention_days
            )
        except ChannelConflict as exc:
            raise ApiError(409, "channel_conflict", "this public_key is registered with another secret") from exc
        except QuotaExceeded as exc:
            raise ApiError(429, "quota_exceeded", "this API key holds its maximum number of channels") from exc
        if registration.created:
            log.info("channel registered: %s", registration.channel_id)
        answer = RegistrationAnswer(
            channel_id=registration.channel_id,
            zone=settings.zone,
            listeners=list(settings.listeners),
            retention_days=_retention(registration.retention_days),
            source_rate=limits.source_rate,
            channel_rate=limits.channel_rate_for(registration.key_channel_rate),
        )
        return JSONResponse(status_code=201 if registration.created else 200, content=answer.model_dump())

    @app.get("/v1/channels/{channel_id}")
    async def channel_answer(channel_id: Annotated[str, Depends(channel)]) -> ChannelAnswer:
        status = await db.channel_status(channel_id)
        if status is None:
            raise ApiError(404, "channel_not_found", f"no channel {channel_id}")
        return ChannelAnswer(
            channel_id=channel_id,
            zone=settings.zone,
            listeners=list(settings.listeners),
            retention_days=_retention(status.retention_days),
            source_rate=limits.source_rate,
            channel_rate=limits.channel_rate_for(status.key_channel_rate),
            last_seq=status.last_seq,
            held_records=status.held_records,
            dropped_total=status.dropped_total,
        )

    @app.delete("/v1/channels/{channel_id}", status_code=204, response_class=Response)
    async def delete_channel(channel_id: Annotated[str, Depends(channel)]) -> Response:
        if not await db.delete_channel(channel_id):
            raise ApiError(404, "channel_not_found", f"no channel {channel_id}")
        ctx.notifier.stored(channel_id)  # a pull waiting on it answers channel_not_found
        log.info("channel deleted: %s", channel_id)
        return Response(status_code=204)

    @app.get("/v1/channels/{channel_id}/records")
    async def records(
        channel_id: Annotated[str, Depends(channel)],
        after: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1)] = 100,
        wait: Annotated[int, Query(ge=0)] = 0,
    ) -> RecordsPage:
        page = await _wait_for_page(
            ctx,
            channel_id,
            after=after,
            limit=min(limit, limits.pull_max_limit),
            wait=min(wait, limits.pull_max_wait_seconds),
        )
        return RecordsPage(
            records=[
                SealedRecord(seq=r.seq, received_at=r.received_at, sealed=base64.b64encode(r.sealed).decode("ascii"))
                for r in page.records
            ],
            more=page.more,
            dropped_total=page.dropped_total,
        )

    return app


async def _wait_for_page(ctx: ApiContext, channel_id: str, *, after: int, limit: int, wait: int) -> Page:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    while True:
        stored = ctx.notifier.event(channel_id)
        page = await ctx.db.page(channel_id, after, limit, ctx.limits.pull_max_bytes)
        if page is None:
            raise ApiError(404, "channel_not_found", f"no channel {channel_id}")
        remaining = deadline - loop.time()
        if page.records or remaining <= 0:
            return page
        try:
            async with asyncio.timeout(remaining):
                await stored.wait()
        except TimeoutError:
            deadline = loop.time()  # one last read, then answer
