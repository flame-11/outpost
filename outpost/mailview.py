"""Reading a received message: headers, leaf parts and the text of one part (standard library `email`)."""

import email
import email.policy
from dataclasses import dataclass
from email.message import Message


@dataclass(frozen=True, slots=True)
class MailPart:
    """A leaf part; `size` is its length after transfer decoding."""

    index: int
    content_type: str
    filename: str | None
    size: int


@dataclass(frozen=True, slots=True)
class MailView:
    """`headers` are the top-level headers in order, encoded words decoded."""

    headers: tuple[tuple[str, str], ...]
    parts: tuple[MailPart, ...]

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        return next((value for key, value in self.headers if key.lower() == wanted), None)


@dataclass(frozen=True, slots=True)
class PartContent:
    """`data` is transfer-decoded; `text` is `data` decoded by the part's charset for `text/*` parts (UTF-8
    when none is declared), or as UTF-8 for other parts when that succeeds, else None."""

    index: int
    content_type: str
    data: bytes
    text: str | None


def view_mail(raw: bytes) -> MailView:
    message = _parse(raw)
    headers = tuple((name, _header_text(message, name, value)) for name, value in message.raw_items())
    parts = tuple(
        MailPart(index=index, content_type=part.get_content_type(), filename=_filename(part), size=len(_payload(part)))
        for index, part in enumerate(_leaves(message))
    )
    return MailView(headers=headers, parts=parts)


def part_content(raw: bytes, index: int | None = None) -> PartContent | None:
    """Part `index`, or by default the first text/plain part, else the first text/* part.

    Returns None when no part is chosen by default; raises IndexError for an index out of range.
    """
    leaves = _leaves(_parse(raw))
    if index is None:
        types = [part.get_content_type() for part in leaves]
        index = next((i for i, kind in enumerate(types) if kind == "text/plain"), None)
        if index is None:
            index = next((i for i, kind in enumerate(types) if kind.startswith("text/")), None)
        if index is None:
            return None
    if not 0 <= index < len(leaves):
        raise IndexError(f"part {index} does not exist; the message has {len(leaves)} parts")
    part = leaves[index]
    data = _payload(part)
    return PartContent(index=index, content_type=part.get_content_type(), data=data, text=_text(part, data))


def _parse(raw: bytes) -> Message:
    return email.message_from_bytes(raw, policy=email.policy.default)


def _leaves(message: Message) -> list[Message]:
    return [part for part in message.walk() if not part.is_multipart()]


def _payload(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


def _text(part: Message, data: bytes) -> str | None:
    if part.get_content_maintype() == "text":
        charset = part.get_content_charset() or "utf-8"
        try:
            return data.decode(charset, errors="replace")
        except LookupError:
            return data.decode("utf-8", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _header_text(message: Message, name: str, raw_value: str) -> str:
    try:
        return str(message.policy.header_fetch_parse(name, raw_value))
    except Exception:  # a malformed header is shown as received
        return raw_value


def _filename(part: Message) -> str | None:
    try:
        return part.get_filename()
    except Exception:  # a malformed parameter is shown as absent
        return None
