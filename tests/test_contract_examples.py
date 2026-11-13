"""CONTRACT section 6 and the published examples: every example validates against the server's
models, the server's answers have the examples' shape, and the sealed example opens to the
opened one."""

import base64
import hashlib
import json

import pytest
from conftest import EXAMPLES, Stack, example
from nacl.exceptions import CryptoError

from outpost.models import (
    ChannelAnswer,
    ErrorBody,
    HealthAnswer,
    KeyAnswer,
    RecordsPage,
    RegistrationAnswer,
    RegistrationRequest,
    SealedRecord,
)
from outpost.records import OPENED_RECORD, DnsRecord, HttpRecord
from outpost.responses import ResponseAnswer, ResponseRequest
from outpost.sealing import new_key_pair, open_sealed, seal


@pytest.mark.parametrize(
    ("file", "model"),
    [
        ("health.json", HealthAnswer),
        ("registration_request.json", RegistrationRequest),
        ("registration_answer.json", RegistrationAnswer),
        ("key_answer.json", KeyAnswer),
        ("channel_answer.json", ChannelAnswer),
        ("records_page.json", RecordsPage),
        ("sealed_record.json", SealedRecord),
        ("record_dns.json", DnsRecord),
        ("record_http.json", HttpRecord),
        ("response_request.json", ResponseRequest),
        ("response_answer.json", ResponseAnswer),
    ],
)
def test_example_validates_and_round_trips(file: str, model: type[HealthAnswer]) -> None:
    data = example(file)
    assert model.model_validate_json(json.dumps(data)).model_dump(exclude_unset=True) == data


def test_error_examples_validate() -> None:
    for status, body in example("errors.json").items():
        assert 400 <= int(status) < 600
        ErrorBody.model_validate_json(json.dumps(body))


def test_sealed_example_opens_to_the_opened_example() -> None:
    keys = example("test_only_keypair.json")
    sealed = example("sealed_record.json")
    plaintext = open_sealed(base64.b64decode(str(keys["private_key"])), base64.b64decode(str(sealed["sealed"])))
    opened = OPENED_RECORD.validate_json(plaintext)
    assert opened.model_dump(exclude_unset=True) == example("record_http.json")
    assert isinstance(opened, HttpRecord) and opened.response_id is None  # a record from before 1.1
    assert opened.received_at == sealed["received_at"]
    assert example("records_page.json")["records"] == [sealed]


def test_registration_example_matches_the_test_key_pair() -> None:
    keys = example("test_only_keypair.json")
    request = example("registration_request.json")
    assert request["public_key"] == keys["public_key"]
    assert request["secret_sha256"] == hashlib.sha256(str(keys["channel_secret"]).encode()).hexdigest()
    assert "TEST ONLY" in str(keys["warning"])


def test_sealing_round_trip_and_only_the_private_key_opens() -> None:
    keys, stranger = new_key_pair(), new_key_pair()
    sealed = seal(keys.public_key, b'{"v":1}')
    assert b'{"v":1}' not in sealed
    assert open_sealed(keys.private_key, sealed) == b'{"v":1}'
    with pytest.raises(CryptoError):
        open_sealed(stranger.private_key, sealed)


def test_examples_directory_lists_what_the_contract_publishes() -> None:
    names = {path.name for path in EXAMPLES.iterdir()}
    assert {
        "health.json",
        "registration_request.json",
        "registration_answer.json",
        "channel_answer.json",
        "records_page.json",
        "record_dns.json",
        "record_http.json",
        "errors.json",
        "sealed_record.json",
        "test_only_keypair.json",
        "response_request.json",
        "response_answer.json",
    } <= names


async def test_server_answers_have_the_example_shapes(stack: Stack) -> None:
    channel = await stack.register()
    paths = {
        "/v1/health": ("health.json", {}),
        f"/v1/channels/{channel.channel_id}": ("channel_answer.json", channel.auth),
        f"/v1/channels/{channel.channel_id}/records": ("records_page.json", channel.auth),
    }
    for path, (file, headers) in paths.items():
        response = await stack.client.get(path, headers=headers)
        assert response.status_code == 200
        assert set(response.json()) == set(example(file))
    unknown = await stack.client.get("/v1/channels/aaaaaaaaaaaa", headers=channel.auth)
    assert set(unknown.json()["error"]) == set(example("errors.json")["404"]["error"])  # type: ignore[index]
