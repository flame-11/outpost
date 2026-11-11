"""Request and answer bodies of the API (CONTRACT section 5)."""

import base64
import binascii
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator

from outpost.records import ChannelId, StrictModel, Timestamp

Listener = Literal["dns", "http", "https", "smtp"]
ErrorCode = Literal[
    "unauthorized",
    "channel_not_found",
    "channel_conflict",
    "invalid_request",
    "rate_limited",
    "storage_unavailable",
]
Count = Annotated[int, Field(ge=0)]


def decode_public_key(value: str) -> bytes:
    """Standard base64 of exactly 32 bytes; raises ValueError otherwise."""
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("must be standard base64") from exc
    if len(raw) != 32:
        raise ValueError("must decode to 32 bytes")
    return raw


class HealthAnswer(StrictModel):
    status: Literal["ok"]
    contract: Literal[1]
    store_full: bool


class RegistrationRequest(StrictModel):
    public_key: str
    secret_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]

    @field_validator("public_key")
    @classmethod
    def _public_key(cls, value: str) -> str:
        decode_public_key(value)
        return value


class RegistrationAnswer(StrictModel):
    channel_id: ChannelId
    zone: str
    listeners: list[Listener]
    retention_days: Count


class ChannelAnswer(StrictModel):
    channel_id: ChannelId
    zone: str
    listeners: list[Listener]
    retention_days: Count
    last_seq: Count
    held_records: Count
    dropped_total: Count


class SealedRecord(StrictModel):
    seq: Annotated[int, Field(ge=1)]
    received_at: Timestamp
    sealed: str


class RecordsPage(StrictModel):
    records: list[SealedRecord]
    more: bool
    dropped_total: Count


class ErrorDetail(StrictModel):
    code: ErrorCode
    message: str


class ErrorBody(StrictModel):
    error: ErrorDetail
