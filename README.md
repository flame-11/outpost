# Outpost

Outpost is a public callback catcher. It is the authoritative name server for one DNS zone
and runs a plain web listener. Lookups and web requests that reach a channel's addresses are
recorded. Each record is sealed to the channel's public key before it is written, and clients
pull the records through an HTTP API. Outpost serves no content, sends no mail and does no
recursion.

This version runs the name server (UDP and TCP) and the web listener on port 80. It has no
TLS listener, no certificate component and no mail receiver, so `OUTPOST_TLS` and
`OUTPOST_SMTP` accept only `off`.

## Addresses

```
[prefix.]<token>-<channel_id>.<zone>
```

`token` is 1 to 20 of `a-z0-9`. `channel_id` is 12 of `a-z2-7`, drawn by Outpost. The pair is
read from the label immediately left of the zone. A web request's pair comes from its `Host`
header. An interaction is stored only when its pair names an existing channel. Every other
interaction gets the same answer and is not stored.

## Run on a public host

1. Delegate a zone to the host. For a subdomain of a domain you control, add to that domain:
   `A ns1.<zone> → <host address>` and `NS <zone> → ns1.<zone>`. For a whole domain, set glue
   records and name servers at the registrar.
2. Open 53/udp, 53/tcp and 80/tcp to everyone. Open the API port only to the addresses your
   clients call from, or keep it private and reach it through a tunnel.
3. Next to `compose.yml`, write a `.env` with `OUTPOST_ZONE`, `OUTPOST_PUBLIC_IPV4` (the
   address the zone's names should resolve to), `OUTPOST_BIND_IP` (the host's own interface
   address), `OUTPOST_API_KEY_SHA256` and, if wanted, `OUTPOST_API_PORT`.
4. `sudo install -d -m 700 /var/lib/outpost && sudo docker compose up -d --build`

`compose.yml` uses host networking, so records carry the real source addresses. The container
keeps only the capability to bind ports below 1024 and runs on a read-only filesystem.

## Run on the dev host

```bash
uv sync
uv run pytest -q
docker compose -f compose.dev.yml up -d --build
```

`compose.dev.yml` publishes on one address only, `OUTPOST_DEV_BIND` (default `127.0.0.1`): name
server `5353` (UDP and TCP), web `8080`, API `9080`, zone `oob.test`. It reads
`OUTPOST_API_KEY_SHA256` and `OUTPOST_DEV_BIND` from a `.env` file next to it (ignored by git);
the hash is the SHA-256 (hex) of the API key string:

```bash
KEY=$(openssl rand -hex 32); printf %s "$KEY" | sha256sum
```

Then:

```bash
uv run outpost channel create --api http://127.0.0.1:9080 --api-key "$KEY" --key-file channel.json
uv run outpost list --key-file channel.json [--after N] [--wait S]
uv run outpost read --key-file channel.json SEQ
```

The key file holds the API address, the channel id, the X25519 private key and the channel
secret, and is written with mode 0600. Running `channel create` again with an existing key
file registers the same key and secret again.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OUTPOST_ZONE` | required | the zone |
| `OUTPOST_PUBLIC_IPV4` | required | the address `A` queries answer |
| `OUTPOST_PUBLIC_IPV6` | none | the address `AAAA` queries answer |
| `OUTPOST_BIND_IP` | `0.0.0.0` | address every listener binds |
| `OUTPOST_API_KEY_SHA256` | required | SHA-256 (hex) of the operator's API key |
| `OUTPOST_RETENTION_DAYS` | `90` | days a record is kept |
| `OUTPOST_STORE_MAX_BYTES` | `21474836480` | store size past which interactions are dropped |
| `OUTPOST_TLS`, `OUTPOST_SMTP` | `off` | only `off` in this version |
| `OUTPOST_DNS_PORT`, `OUTPOST_HTTP_PORT`, `OUTPOST_API_PORT` | `53`, `80`, `9443` | listener ports |
| `OUTPOST_DATA_DIR` | `/var/lib/outpost` | directory of `outpost.sqlite3` |

Logs carry counts and channel ids only.

## API (version 1)

The examples in `contract/v1/examples/` are the API's test vectors. FastAPI serves the
OpenAPI document at `/openapi.json`. `test_only_keypair.json` opens `sealed_record.json` and is for tests only.

Authentication is `Authorization: Bearer <value>`. Registration takes the API key and channel
routes take the channel secret. Outpost compares the SHA-256 of the value as sent, in
constant time.

- `GET /v1/health` returns `{"status": "ok", "contract": 1, "store_full": false}` and needs no authentication.
- `POST /v1/channels` takes `{"public_key": "<base64 32 bytes>", "secret_sha256": "<64 hex>"}`.
  It returns `201` for a new channel and `200` with the same body on a repeat. The body is
  `channel_id`, `zone`, `listeners`, `retention_days`.
- `GET /v1/channels/{id}` returns the registration body plus `last_seq`, `held_records`,
  `dropped_total`.
- `GET /v1/channels/{id}/records?after=0&limit=100&wait=0` returns held records with
  `seq > after`, ascending, as `{"records": [{"seq", "received_at", "sealed"}], "more",
  "dropped_total"}`. The limit is at most 200 records and 4 MiB of sealed data, but a page
  always holds at least one record when one exists. `wait` is at most 25 seconds.

Errors have the shape `{"error": {"code", "message"}}`. The codes are `unauthorized` (401),
`channel_not_found` (404), `channel_conflict` (409), `invalid_request` (422), `rate_limited`
(429, with `Retry-After`) and `storage_unavailable` (503).

`sealed` is a libsodium sealed box over the record JSON. A record is deleted
`OUTPOST_RETENTION_DAYS` after it arrives. A channel is deleted when its last authenticated
call and its newest record are both older than that.
