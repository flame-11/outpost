"""CONTRACT section 1: the address grammar and where the pair is read."""

import dns.name
import pytest

from outpost.addresses import address_from_dns, address_from_text
from outpost.http import host_without_port

ZONE = "oob.example"
CHANNEL = "k3v7x2mq6c4a"


@pytest.mark.parametrize(
    ("name", "token", "prefix"),
    [
        (f"t1-{CHANNEL}.{ZONE}", "t1", ""),
        (f"uid0.t1-{CHANNEL}.{ZONE}", "t1", "uid0"),
        (f"a.b.c.q7ab12cd9z-{CHANNEL}.{ZONE}", "q7ab12cd9z", "a.b.c"),
        (f"{'9' * 20}-{CHANNEL}.{ZONE}", "9" * 20, ""),
        ("T1-K3V7X2MQ6C4A.OOB.EXAMPLE", "t1", ""),
        (f"UID0.t1-{CHANNEL}.{ZONE}.", "t1", "uid0"),
    ],
)
def test_valid_names_name_a_channel(name: str, token: str, prefix: str) -> None:
    address = address_from_text(name, ZONE)
    assert address is not None
    assert (address.channel_id, address.token, address.prefix) == (CHANNEL, token, prefix)
    assert address.name == name.lower().rstrip(".")


@pytest.mark.parametrize(
    "name",
    [
        ZONE,
        f"ns1.{ZONE}",
        f"ns2.{ZONE}",
        f"mx.{ZONE}",
        f"api.{ZONE}",
        f"_acme-challenge.{ZONE}",
        f"{'a' * 21}-{CHANNEL}.{ZONE}",  # token longer than 20
        f"-{CHANNEL}.{ZONE}",  # empty token
        f"t1-k3v9x2mq7c4.{ZONE}",  # channel id of 11
        f"t1-k3v7x2mq6c4ab.{ZONE}",  # channel id of 13
        f"t1-k3v9x2mq7c41.{ZONE}",  # 1 is not in a-z2-7
        f"t_1-{CHANNEL}.{ZONE}",
        f"t1-{CHANNEL}.x.{ZONE}",  # the pair is not the label left of the zone
        f"t1-{CHANNEL}.other.example",  # outside the zone
        f"t1-{CHANNEL}.x{ZONE}",  # suffix match is by label
        f"a..t1-{CHANNEL}.{ZONE}",  # empty label
        f"{'a' * 64}.t1-{CHANNEL}.{ZONE}",  # label over 63 bytes
        ".".join(["a" * 60] * 4) + f".t1-{CHANNEL}.{ZONE}",  # name over 253 bytes
    ],
)
def test_other_names_name_no_channel(name: str) -> None:
    assert address_from_text(name, ZONE) is None


def test_longest_allowed_name_names_a_channel() -> None:
    tail = f".t1-{CHANNEL}.{ZONE}"
    prefix = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * (253 - len(tail) - 3 * 64)])
    assert len(prefix + tail) == 253
    assert address_from_text(prefix + tail, ZONE) is not None


def test_dns_name_keeps_prefix_and_lowercases() -> None:
    qname = dns.name.from_text("Data.UID0.T1-K3V7X2MQ6C4A.Oob.Example.")
    address = address_from_dns(qname, dns.name.from_text(ZONE))
    assert address is not None
    assert (address.token, address.channel_id, address.prefix) == ("t1", CHANNEL, "data.uid0")
    assert address.name == f"data.uid0.t1-{CHANNEL}.{ZONE}"


@pytest.mark.parametrize("name", [ZONE, f"ns1.{ZONE}", f"_acme-challenge.{ZONE}", f"t1-{CHANNEL}.other.example"])
def test_dns_reserved_and_outside_names_name_no_channel(name: str) -> None:
    assert address_from_dns(dns.name.from_text(name), dns.name.from_text(ZONE)) is None


def test_dns_pair_label_with_a_dot_inside_names_no_channel() -> None:
    qname = dns.name.Name([b"x.t1-" + CHANNEL.encode(), *dns.name.from_text(ZONE).labels])
    assert address_from_dns(qname, dns.name.from_text(ZONE)) is None


@pytest.mark.parametrize(
    ("host", "name"),
    [
        (f"t1-{CHANNEL}.{ZONE}:8080", f"t1-{CHANNEL}.{ZONE}"),
        (f"t1-{CHANNEL}.{ZONE}", f"t1-{CHANNEL}.{ZONE}"),
        ("[::1]:80", "[::1]:80"),
    ],
)
def test_host_port_is_removed(host: str, name: str) -> None:
    assert host_without_port(host) == name
