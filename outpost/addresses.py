"""The address grammar of CONTRACT section 1: which channel and token a name carries."""

import re
from dataclasses import dataclass

import dns.name

PAIR_LABEL = re.compile(r"([a-z0-9]{1,20})-([a-z2-7]{12})")
CHANNEL_ID = re.compile(r"[a-z2-7]{12}")
MAX_LABEL_BYTES = 63
MAX_NAME_BYTES = 253


@dataclass(frozen=True, slots=True)
class Address:
    """What an in-zone name names: a channel, a token, the free prefix and the whole name."""

    channel_id: str
    token: str
    prefix: str
    name: str


def address_from_text(text: str, zone: str) -> Address | None:
    """Read the pair from a host name in text form (a web request's `Host`, without its port).

    `zone` is lowercase without a trailing dot. Letters are lowercased (ASCII only); one
    trailing dot is ignored.
    """
    name = _ascii_lower(text)
    if name.endswith("."):
        name = name[:-1]
    if len(name.encode()) > MAX_NAME_BYTES or not name.endswith("." + zone):
        return None
    labels = name[: -len(zone) - 1].split(".")
    if any(not label or len(label.encode()) > MAX_LABEL_BYTES for label in labels):
        return None
    return _address(labels[-1], ".".join(labels[:-1]), name)


def address_from_dns(qname: dns.name.Name, zone: dns.name.Name) -> Address | None:
    """Read the pair from a queried name, label by label (a label may hold any byte)."""
    if not qname.is_subdomain(zone) or qname == zone:
        return None
    labels = qname.relativize(zone).labels
    try:
        pair_label = labels[-1].lower().decode("ascii")
    except UnicodeDecodeError:
        return None
    prefix = dns.name.Name(labels[:-1]).to_text().lower() if len(labels) > 1 else ""
    return _address(pair_label, prefix, qname.to_text(omit_final_dot=True).lower())


def _address(pair_label: str, prefix: str, name: str) -> Address | None:
    match = PAIR_LABEL.fullmatch(pair_label)
    if match is None:
        return None
    return Address(channel_id=match.group(2), token=match.group(1), prefix=prefix, name=name)


def _ascii_lower(text: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in text)
