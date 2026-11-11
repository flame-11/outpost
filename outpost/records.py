"""The opened record of CONTRACT section 6 (the JSON inside `sealed`), and the time format."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter

TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
Timestamp = Annotated[str, StringConstraints(pattern=TIMESTAMP_PATTERN)]
ChannelId = Annotated[str, StringConstraints(pattern=r"^[a-z2-7]{12}$")]
Token = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{1,20}$")]
Port = Annotated[int, Field(ge=0, le=65_535)]


def format_time(moment: datetime) -> str:
    """RFC 3339 UTC with milliseconds: `2026-11-11T08:15:30.123Z`."""
    moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def utc_now() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class DnsRecord(StrictModel):
    v: Literal[1]
    protocol: Literal["dns"]
    channel_id: ChannelId
    token: Token
    prefix: str
    name: str
    source_ip: str
    source_port: Port
    received_at: Timestamp
    qname: str
    qtype: str
    transport: Literal["udp", "tcp"]


class HttpRecord(StrictModel):
    v: Literal[1]
    protocol: Literal["http"]
    channel_id: ChannelId
    token: Token
    prefix: str
    name: str
    source_ip: str
    source_port: Port
    received_at: Timestamp
    port: Port
    tls: bool
    sni: str | None
    method: str | None
    target: str | None
    host: str | None
    raw_b64: str
    truncated: bool


class SmtpRecord(StrictModel):
    """One accepted recipient of one message received in `DATA`."""

    v: Literal[1]
    protocol: Literal["smtp"]
    channel_id: ChannelId
    token: Token
    prefix: str
    name: str
    source_ip: str
    source_port: Port
    received_at: Timestamp
    helo: str
    mail_from: str
    rcpt_to: str
    tls: bool
    raw_b64: str


OpenedRecord = Annotated[DnsRecord | HttpRecord | SmtpRecord, Field(discriminator="protocol")]
OPENED_RECORD: TypeAdapter[DnsRecord | HttpRecord | SmtpRecord] = TypeAdapter(OpenedRecord)
