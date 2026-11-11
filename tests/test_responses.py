"""CONTRACT section 9 (responses), and the `response_id` of section 6."""

import asyncio
import base64
import hashlib
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import ZONE, Channel, Stack, open_stack
from test_api import assert_error
from test_http import FIXED, listening, send

from outpost.records import HttpRecord


@pytest.fixture
async def serving(tmp_path: Path) -> AsyncIterator[Stack]:
    async with open_stack(tmp_path, responses=True) as opened:
        yield opened


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def set_response(stack: Stack, channel: Channel, **fields: object) -> httpx.Response:
    return await stack.client.post(f"/v1/channels/{channel.channel_id}/responses", json=fields, headers=channel.auth)


async def answer_to(stack: Stack, request: bytes) -> bytes:
    async with listening(stack) as port:
        return await send(port, request)


def get(channel: Channel, target: str = "/", token: str = "x1", method: str = "GET", headers: str = "") -> bytes:
    return f"{method} {target} HTTP/1.1\r\nHost: {token}-{channel.channel_id}.{ZONE}\r\n{headers}\r\n".encode()


def split(answer: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    head, _, body = answer.partition(b"\r\n\r\n")
    status, *lines = head.decode().split("\r\n")
    return status, [(name, value) for name, _, value in (line.partition(": ") for line in lines)], body


async def opened_records(stack: Stack, channel: Channel) -> list[HttpRecord]:
    await stack.recorder.idle()
    records = [channel.open(item["sealed"]) for item in (await stack.records(channel))["records"]]
    return [record for record in records if isinstance(record, HttpRecord)]


# --- the routes ---------------------------------------------------------------------------


async def test_instance_without_responses_refuses_every_route(stack: Stack) -> None:
    channel = await stack.register()
    base = f"/v1/channels/{channel.channel_id}/responses"
    assert_error(await set_response(stack, channel, token="x1"), 403, "responses_off")
    assert_error(await stack.client.get(base, headers=channel.auth), 403, "responses_off")
    assert_error(await stack.client.delete(f"{base}/r000000000000000", headers=channel.auth), 403, "responses_off")
    status = await stack.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)
    assert status.json()["responses"] is False


async def test_answers_say_the_instance_serves_responses(serving: Stack) -> None:
    response, channel = await serving.try_register()
    assert response.json()["responses"] is True
    status = await serving.client.get(f"/v1/channels/{channel.channel_id}", headers=channel.auth)
    assert status.json()["responses"] is True


async def test_routes_need_the_channel_secret(serving: Stack) -> None:
    channel = await serving.register()
    stranger = Channel(channel_id=channel.channel_id, keys=channel.keys, secret="wrong")
    assert_error(await set_response(serving, stranger, token="x1"), 401, "unauthorized")


async def test_set_answers_the_response_with_defaults(serving: Stack) -> None:
    channel = await serving.register()
    response = await set_response(serving, channel, token="x1", body_b64=b64(b"hello"))
    assert response.status_code == 201
    answer = response.json()
    assert set(answer) == {
        "response_id",
        "token",
        "path",
        "status",
        "headers",
        "cors",
        "body_size",
        "body_sha256",
        "created_at",
        "expires_at",
    }
    assert (answer["token"], answer["path"], answer["status"], answer["headers"], answer["cors"]) == (
        "x1",
        "*",
        200,
        [],
        None,
    )
    assert (answer["body_size"], answer["body_sha256"]) == (5, hashlib.sha256(b"hello").hexdigest())
    created = datetime.fromisoformat(answer["created_at"])
    assert datetime.fromisoformat(answer["expires_at"]) - created == timedelta(seconds=3600)


async def test_same_token_and_path_replaces_with_a_new_id(serving: Stack) -> None:
    channel = await serving.register()
    first = (await set_response(serving, channel, token="x1", path="/a", body_b64=b64(b"one"))).json()
    other_path = await set_response(serving, channel, token="x1", path="/b")
    assert other_path.status_code == 201
    again = await set_response(serving, channel, token="x1", path="/a", body_b64=b64(b"two"))
    assert again.status_code == 200
    assert again.json()["response_id"] != first["response_id"]
    listed = (await serving.client.get(f"/v1/channels/{channel.channel_id}/responses", headers=channel.auth)).json()
    assert [item["path"] for item in listed["responses"]] == ["/b", "/a"]  # oldest first
    assert "body_b64" not in listed["responses"][0]
    gone = await serving.client.delete(
        f"/v1/channels/{channel.channel_id}/responses/{first['response_id']}", headers=channel.auth
    )
    assert_error(gone, 404, "response_not_found")
    assert (await answer_to(serving, get(channel, "/a"))).endswith(b"\r\n\r\ntwo")


@pytest.mark.parametrize(
    ("fields", "named"),
    [
        ({"token": "X1"}, "token"),
        ({"token": "x1", "path": "/a?b"}, "path"),
        ({"token": "x1", "path": "/a#b"}, "path"),
        ({"token": "x1", "path": "a"}, "path"),
        ({"token": "x1", "path": "/" + "a" * 1024}, "path"),
        ({"token": "x1", "status": 199}, "status"),
        ({"token": "x1", "status": 600}, "status"),
        ({"token": "x1", "status": 204, "body_b64": b64(b"x")}, "body_b64"),
        ({"token": "x1", "status": 304, "body_b64": b64(b"x")}, "body_b64"),
        ({"token": "x1", "body_b64": "not base64!"}, "body_b64"),
        ({"token": "x1", "body_b64": b64(b"x" * 65_537)}, "body_b64"),
        ({"token": "x1", "headers": [["Content-Length", "1"]]}, "Content-Length"),
        ({"token": "x1", "headers": [["transfer-encoding", "chunked"]]}, "transfer-encoding"),
        ({"token": "x1", "headers": [["Connection", "keep-alive"]]}, "Connection"),
        ({"token": "x1", "headers": [["Keep-Alive", "1"]]}, "Keep-Alive"),
        ({"token": "x1", "headers": [["Proxy-Connection", "x"]]}, "Proxy-Connection"),
        ({"token": "x1", "headers": [["TE", "x"]]}, "TE"),
        ({"token": "x1", "headers": [["Trailer", "x"]]}, "Trailer"),
        ({"token": "x1", "headers": [["Upgrade", "x"]]}, "Upgrade"),
        ({"token": "x1", "headers": [["Bad Name", "x"]]}, "headers"),
        ({"token": "x1", "headers": [["X-A", "a\r\nX-B: b"]]}, "headers"),
        ({"token": "x1", "headers": [["X-A", "é"]]}, "headers"),
        ({"token": "x1", "headers": [["X-A", "a" * 4097]]}, "headers"),
        ({"token": "x1", "headers": [["X-A", "b", "c"]]}, "headers"),
        ({"token": "x1", "headers": [["X-A", "b"]] * 33}, "headers"),
        ({"token": "x1", "headers": [[f"X-{i}", "a" * 4000] for i in range(3)]}, "headers"),
        (
            {"token": "x1", "cors": {"allow_origins": ["*"]}, "headers": [["Access-Control-Allow-Origin", "*"]]},
            "Access-Control-Allow-Origin",
        ),
        ({"token": "x1", "cors": {"allow_origins": []}}, "allow_origins"),
        ({"token": "x1", "cors": {"allow_origins": ["example.com"]}}, "allow_origins"),
        ({"token": "x1", "cors": {"allow_origins": ["https://a.example/path"]}}, "allow_origins"),
        ({"token": "x1", "cors": {"allow_origins": ["*"], "max_age": 86_401}}, "max_age"),
        ({"token": "x1", "ttl_seconds": 0}, "ttl_seconds"),
        ({"token": "x1", "ttl_seconds": 86_401}, "ttl_seconds"),
    ],
)
async def test_malformed_response_is_refused_naming_the_field(
    serving: Stack, fields: dict[str, object], named: str
) -> None:
    channel = await serving.register()
    refused = assert_error(await set_response(serving, channel, **fields), 422, "invalid_request")
    assert named in refused.error.message


async def test_access_control_headers_are_free_without_cors(serving: Stack) -> None:
    channel = await serving.register()
    response = await set_response(serving, channel, token="x1", headers=[["Access-Control-Allow-Origin", "*"]])
    assert response.status_code == 201


async def test_channel_holds_at_most_64_responses(serving: Stack) -> None:
    channel = await serving.register()
    for index in range(64):
        assert (await set_response(serving, channel, token="x1", path=f"/{index}")).status_code == 201
    assert_error(await set_response(serving, channel, token="x1", path="/64"), 429, "quota_exceeded")
    assert (await set_response(serving, channel, token="x1", path="/0")).status_code == 200


async def test_delete_stops_the_answer_at_once(serving: Stack) -> None:
    channel = await serving.register()
    answer = (await set_response(serving, channel, token="x1", body_b64=b64(b"hi"))).json()
    deleted = await serving.client.delete(
        f"/v1/channels/{channel.channel_id}/responses/{answer['response_id']}", headers=channel.auth
    )
    assert deleted.status_code == 204
    assert await answer_to(serving, get(channel)) == FIXED
    again = await serving.client.delete(
        f"/v1/channels/{channel.channel_id}/responses/{answer['response_id']}", headers=channel.auth
    )
    assert_error(again, 404, "response_not_found")


async def test_expired_response_answers_nothing_and_leaves_the_list(serving: Stack) -> None:
    channel = await serving.register()
    await set_response(serving, channel, token="x1", body_b64=b64(b"hi"), ttl_seconds=1)
    await asyncio.sleep(1.1)
    assert await answer_to(serving, get(channel)) == FIXED
    listed = await serving.client.get(f"/v1/channels/{channel.channel_id}/responses", headers=channel.auth)
    assert listed.json() == {"responses": []}


# --- the answer ---------------------------------------------------------------------------


async def test_matching_request_gets_the_response_in_order(serving: Stack) -> None:
    channel = await serving.register()
    headers = [["Content-Type", "text/plain"], ["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"], ["Location", "/x"]]
    answer = (
        await set_response(serving, channel, token="x1", status=302, headers=headers, body_b64=b64(b"moved"))
    ).json()
    raw = await answer_to(serving, get(channel, "/anything?q=1", method="POST"))
    assert raw == (
        b"HTTP/1.1 302 Found\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nLocation: /x\r\n"
        b"Content-Length: 5\r\nConnection: close\r\n\r\nmoved"
    )
    (record,) = await opened_records(serving, channel)
    assert record.response_id == answer["response_id"]


async def test_other_tokens_and_unmatched_paths_get_the_empty_200(serving: Stack) -> None:
    channel = await serving.register()
    await set_response(serving, channel, token="x1", path="/only", body_b64=b64(b"hi"))
    assert await answer_to(serving, get(channel, "/only", token="x2")) == FIXED
    assert await answer_to(serving, get(channel, "/other")) == FIXED
    records = await opened_records(serving, channel)
    assert [record.response_id for record in records] == [None, None]


async def test_a_name_with_a_prefix_is_the_token_s_name(serving: Stack) -> None:
    channel = await serving.register()
    await set_response(serving, channel, token="x1", body_b64=b64(b"hi"))
    request = f"GET / HTTP/1.1\r\nHost: data.x1-{channel.channel_id}.{ZONE}\r\n\r\n".encode()
    assert (await answer_to(serving, request)).endswith(b"\r\n\r\nhi")


async def test_exact_path_wins_over_any_path_and_compares_bytes(serving: Stack) -> None:
    channel = await serving.register()
    await set_response(serving, channel, token="x1", body_b64=b64(b"any"))
    await set_response(serving, channel, token="x1", path="/d.dtd", body_b64=b64(b"exact"))
    assert (await answer_to(serving, get(channel, "/d.dtd?x=1"))).endswith(b"exact")
    assert (await answer_to(serving, get(channel, "/D.dtd"))).endswith(b"any")
    assert (await answer_to(serving, get(channel, "/d%2Edtd"))).endswith(b"any")
    absolute = f"http://x1-{channel.channel_id}.{ZONE}/d.dtd?y"
    assert (await answer_to(serving, get(channel, absolute))).endswith(b"exact")


async def test_head_gets_the_headers_and_no_body(serving: Stack) -> None:
    channel = await serving.register()
    await set_response(serving, channel, token="x1", body_b64=b64(b"hello"))
    raw = await answer_to(serving, get(channel, method="HEAD"))
    assert raw == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"


async def test_deleting_the_channel_deletes_its_responses(serving: Stack) -> None:
    channel = await serving.register()
    await set_response(serving, channel, token="x1", body_b64=b64(b"hi"))
    await serving.client.delete(f"/v1/channels/{channel.channel_id}", headers=channel.auth)
    assert await answer_to(serving, get(channel)) == FIXED


# --- cors ---------------------------------------------------------------------------------


async def cors_answer(stack: Stack, cors: dict[str, object], headers: str, method: str = "GET") -> bytes:
    channel = await stack.register()
    response = await set_response(
        stack, channel, token="x1", cors=cors, headers=[["X-Mine", "1"]], body_b64=b64(b"body")
    )
    assert response.status_code == 201, response.text
    return await answer_to(stack, get(channel, method=method, headers=headers))


async def test_any_origin_without_credentials_is_a_star(serving: Stack) -> None:
    _, headers, body = split(await cors_answer(serving, {"allow_origins": ["*"]}, "Origin: https://a.example\r\n"))
    assert headers[:2] == [("X-Mine", "1"), ("Access-Control-Allow-Origin", "*")]
    assert ("Vary", "Origin") not in headers
    assert body == b"body"


async def test_credentials_echo_the_origin(serving: Stack) -> None:
    cors = {"allow_origins": ["*"], "allow_credentials": True}
    _, headers, _ = split(await cors_answer(serving, cors, "Origin: https://a.example\r\n"))
    assert headers[1:4] == [
        ("Access-Control-Allow-Origin", "https://a.example"),
        ("Vary", "Origin"),
        ("Access-Control-Allow-Credentials", "true"),
    ]


@pytest.mark.parametrize(
    ("entry", "origin", "matches"),
    [
        ("https://app.example", "https://app.example", True),
        ("https://app.example", "HTTPS://APP.EXAMPLE", True),
        ("https://app.example", "http://app.example", False),
        ("https://app.example", "https://app.example:8443", False),
        ("https://app.example:8443", "https://app.example:8443", True),
        ("https://*.example.com", "https://a.b.example.com", True),
        ("https://*.example.com", "https://example.com", False),
        ("https://*.example.com", "https://badexample.com", False),
        ("https://*.example.com", "https://a.example.com:444", False),
        ("null", "null", True),
        ("https://app.example", "null", False),
        ("*", "null", True),
    ],
)
async def test_origin_entries(serving: Stack, entry: str, origin: str, matches: bool) -> None:
    _, headers, _ = split(await cors_answer(serving, {"allow_origins": [entry]}, f"Origin: {origin}\r\n"))
    allow = [value for name, value in headers if name == "Access-Control-Allow-Origin"]
    assert allow == ([origin] if matches and entry != "*" else ["*"] if matches else [])


async def test_no_origin_gets_no_cors_headers(serving: Stack) -> None:
    _, headers, _ = split(await cors_answer(serving, {"allow_origins": ["*"], "allow_credentials": True}, ""))
    assert not [name for name, _ in headers if name.startswith("Access-Control-")]


async def test_actual_response_exposes_headers(serving: Stack) -> None:
    cors = {"allow_origins": ["https://a.example"], "expose_headers": ["X-Mine", "X-Two"]}
    _, headers, _ = split(await cors_answer(serving, cors, "Origin: https://a.example\r\n"))
    assert ("Access-Control-Expose-Headers", "X-Mine, X-Two") in headers


async def test_preflight_answers_204_with_what_it_asked_for(serving: Stack) -> None:
    asked = (
        "Origin: https://a.example\r\nAccess-Control-Request-Method: PUT\r\n"
        "Access-Control-Request-Headers: x-a, content-type\r\nAccess-Control-Request-Private-Network: true\r\n"
    )
    status, headers, body = split(await cors_answer(serving, {"allow_origins": ["*"]}, asked, method="OPTIONS"))
    assert status == "HTTP/1.1 204 No Content"
    assert headers == [
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "PUT"),
        ("Access-Control-Allow-Headers", "x-a, content-type"),
        ("Content-Length", "0"),
        ("Connection", "close"),
    ]
    assert body == b""


async def test_preflight_with_configured_lists(serving: Stack) -> None:
    cors = {
        "allow_origins": ["https://a.example"],
        "allow_credentials": True,
        "allow_methods": ["GET", "DELETE"],
        "allow_headers": ["X-A"],
        "max_age": 600,
        "allow_private_network": True,
    }
    asked = (
        "Origin: https://a.example\r\nAccess-Control-Request-Method: PUT\r\n"
        "Access-Control-Request-Headers: x-b\r\nAccess-Control-Request-Private-Network: true\r\n"
    )
    _, headers, _ = split(await cors_answer(serving, cors, asked, method="OPTIONS"))
    assert headers[:-2] == [
        ("Access-Control-Allow-Origin", "https://a.example"),
        ("Vary", "Origin"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Access-Control-Allow-Methods", "GET, DELETE"),
        ("Access-Control-Allow-Headers", "X-A"),
        ("Access-Control-Max-Age", "600"),
        ("Access-Control-Allow-Private-Network", "true"),
    ]


async def test_private_network_only_when_asked(serving: Stack) -> None:
    cors = {"allow_origins": ["*"], "allow_private_network": True}
    asked = "Origin: https://a.example\r\nAccess-Control-Request-Method: GET\r\n"
    _, headers, _ = split(await cors_answer(serving, cors, asked, method="OPTIONS"))
    assert "Access-Control-Allow-Private-Network" not in dict(headers)


async def test_options_without_a_request_method_is_not_a_preflight(serving: Stack) -> None:
    status, headers, body = split(
        await cors_answer(serving, {"allow_origins": ["*"]}, "Origin: https://a.example\r\n", method="OPTIONS")
    )
    assert status == "HTTP/1.1 200 OK"
    assert ("X-Mine", "1") in headers and ("Access-Control-Allow-Origin", "*") in headers
    assert body == b"body"


async def test_preflight_from_an_unmatched_origin_gets_the_response(serving: Stack) -> None:
    asked = "Origin: https://evil.example\r\nAccess-Control-Request-Method: PUT\r\n"
    status, headers, _ = split(
        await cors_answer(serving, {"allow_origins": ["https://a.example"]}, asked, method="OPTIONS")
    )
    assert status == "HTTP/1.1 200 OK"
    assert not [name for name, _ in headers if name.startswith("Access-Control-")]
