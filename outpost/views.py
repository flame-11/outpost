"""What the CLI and the MCP tools show of an opened record: a compact row and the full reading."""

import base64
from typing import Any

from outpost.client import OpenedRecord
from outpost.mailview import part_content, view_mail
from outpost.records import DnsRecord, HttpRecord, SmtpRecord

COMMON_FIELDS = ("protocol", "token", "received_at", "source_ip", "name", "prefix")


def row(seq: int, record: OpenedRecord) -> dict[str, Any]:
    shown: dict[str, Any] = {"seq": seq} | {field: getattr(record, field) for field in COMMON_FIELDS}
    match record:
        case DnsRecord():
            shown["qtype"] = record.qtype
        case HttpRecord():
            shown |= {"method": record.method, "target": record.target, "tls": record.tls}
        case SmtpRecord():
            raw = base64.b64decode(record.raw_b64)
            shown |= {
                "mail_from": record.mail_from,
                "rcpt_to": record.rcpt_to,
                "subject": view_mail(raw).header("Subject"),
                "size": len(raw),
            }
    return shown


def detail(
    seq: int, record: OpenedRecord, *, part: int | None = None, offset: int = 0, max_chars: int | None = None
) -> dict[str, Any]:
    """Every field but `raw_b64`, plus the decoded request or message.

    The one long text (a web request's body, a mail part's content) is cut to `max_chars` from `offset`;
    `next_offset` names where the rest starts, or is None at the end. Raises IndexError for a missing part.
    """
    shown: dict[str, Any] = {"seq": seq} | record.model_dump(exclude={"raw_b64", "v"})
    match record:
        case DnsRecord():
            pass
        case HttpRecord():
            shown |= _http(base64.b64decode(record.raw_b64), offset, max_chars)
        case SmtpRecord():
            shown |= _mail(base64.b64decode(record.raw_b64), part, offset, max_chars)
    return shown


def _http(raw: bytes, offset: int, max_chars: int | None) -> dict[str, Any]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body = raw.partition(b"\n\n")
    lines = [line.rstrip(b"\r") for line in head.split(b"\n")]
    headers = [[_text(name).strip(), _text(value).strip()] for name, _, value in (h.partition(b":") for h in lines[1:])]
    return {"request_line": _text(lines[0]), "headers": headers, "body": content_page(body, None, offset, max_chars)}


def _mail(raw: bytes, part: int | None, offset: int, max_chars: int | None) -> dict[str, Any]:
    view = view_mail(raw)
    chosen = part_content(raw, part)
    return {
        "size": len(raw),
        "headers": [list(header) for header in view.headers],
        "parts": [
            {"index": p.index, "content_type": p.content_type, "filename": p.filename, "size": p.size}
            for p in view.parts
        ],
        "part": None
        if chosen is None
        else {"index": chosen.index, "content_type": chosen.content_type}
        | content_page(chosen.data, chosen.text, offset, max_chars),
    }


def content_page(data: bytes, text: str | None, offset: int, max_chars: int | None) -> dict[str, Any]:
    """`text` when given or when `data` is UTF-8, else base64 of `data`; cut from `offset`."""
    if text is None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
    encoding = "text" if text is not None else "base64"
    whole = text if text is not None else base64.b64encode(data).decode("ascii")
    end = len(whole) if max_chars is None else min(len(whole), offset + max_chars)
    return {
        "size": len(data),
        "encoding": encoding,
        "total_chars": len(whole),
        "offset": offset,
        "content": whole[offset:end],
        "next_offset": end if end < len(whole) else None,
    }


def _text(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1")
