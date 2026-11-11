"""Reading a received message: headers with encoded words decoded, every leaf part, one part's text."""

import base64

import pytest
from client_support import sample_message

from outpost.mailview import part_content, view_mail


def test_headers_keep_their_order_and_decode_encoded_words() -> None:
    raw = (
        b"From: =?utf-8?b?w4lsb2RpZQ==?= <e@sender.example>\r\n"
        b"To: probe@oob.test\r\n"
        b"Subject: =?iso-8859-1?q?Caf=E9_cr=E8me?=\r\n"
        b"X-Note: plain\r\n"
        b"\r\n"
        b"body\r\n"
    )
    view = view_mail(raw)
    assert [name for name, _ in view.headers] == ["From", "To", "Subject", "X-Note"]
    assert view.header("subject") == "Café crème"
    assert view.header("From") == "Élodie <e@sender.example>"
    assert view.header("missing") is None


def test_every_leaf_part_is_listed_with_type_filename_and_decoded_size() -> None:
    view = view_mail(sample_message().as_bytes())
    assert [(p.index, p.content_type, p.filename) for p in view.parts] == [
        (0, "text/plain", None),
        (1, "text/html", None),
        (2, "application/octet-stream", "data.bin"),
    ]
    assert view.parts[2].size == 256
    assert view.header("Subject") == "Grüße aus Köln"


def test_default_text_is_the_first_text_plain_part_decoded_by_charset() -> None:
    chosen = part_content(sample_message().as_bytes())
    assert chosen is not None
    assert (chosen.index, chosen.content_type) == (0, "text/plain")
    assert chosen.text == "Hallo, schöne Grüße.\n"


def test_without_text_plain_the_first_text_part_is_chosen() -> None:
    raw = (
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw==\r\n"
        b"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<b>hi</b>\r\n"
        b"--b--\r\n"
    )
    chosen = part_content(raw)
    assert chosen is not None
    assert (chosen.index, chosen.content_type) == (1, "text/html")
    assert chosen.text is not None and chosen.text.startswith("<b>hi</b>")


def test_a_message_without_text_parts_has_no_default() -> None:
    raw = b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC\r\n"
    assert part_content(raw) is None
    assert view_mail(raw).parts[0].size == 3


def test_base64_utf8_part_is_decoded() -> None:
    text = "Привет, мир"
    raw = (
        b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(text.encode())
        + b"\r\n"
    )
    chosen = part_content(raw)
    assert chosen is not None and chosen.text == text


def test_an_explicit_binary_part_gives_its_bytes_and_no_text() -> None:
    chosen = part_content(sample_message().as_bytes(), 2)
    assert chosen is not None
    assert chosen.data == bytes(range(256))
    assert chosen.text is None


def test_an_unknown_charset_still_gives_text() -> None:
    raw = b"Content-Type: text/plain; charset=x-unknown-charset\r\n\r\nplain words\r\n"
    chosen = part_content(raw)
    assert chosen is not None and chosen.text is not None and "plain words" in chosen.text


def test_a_part_index_out_of_range_raises() -> None:
    with pytest.raises(IndexError):
        part_content(sample_message().as_bytes(), 3)
