# Contributing

## Setup

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
```

Python 3.12, line length 120. Tests run on loopback ports; none needs network access or root.

## Ground rules

- `docs/API.md` is the contract. Version 1 only grows: add fields and endpoints, never remove
  or change one. A change a client would notice needs a test against `contract/v1/examples/`.
- The public host never holds anything readable: a feature that has to read a record belongs
  in the client.
- Outpost records; it does not serve content, relay or send mail, or connect out (except to
  the certificate authority).
- Logs carry counts and channel ids only, never names, addresses or content.
- Keep examples on reserved names (`oob.example`, `oob.test`, `192.0.2.0/24`).

## Changes

Open an issue first for anything larger than a fix. Each pull request: tests for the
behaviour it changes, lint clean, and the README or `docs/API.md` updated when users see the
change.
