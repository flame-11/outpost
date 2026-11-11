# Outpost

Outpost is a public callback catcher for out-of-band testing. It is the authoritative name
server for one DNS zone and runs web (HTTP and HTTPS) and mail listeners. Lookups, web
requests and mail that reach a channel's addresses are recorded. Each record is sealed to the
channel's public key before it is written, so the public host holds nothing readable; clients
pull the records through an HTTP API and open them locally. Outpost sends or relays no mail
and does no recursion. Its web addresses answer an empty `200`, unless the operator turns on
responses and a channel sets what one of its tokens answers: status, headers, body and
cross-origin rules, for a limited time.

The `outpost` client is a command line tool, a Python library and a local MCP server, so
agents such as Claude Code, Codex CLI and Claude Desktop can hand out addresses and read what
arrived.

## Addresses

```
[prefix.]<token>-<channel_id>.<zone>
```

`token` is 1 to 20 of `a-z0-9`. `channel_id` is 12 of `a-z2-7`, drawn by Outpost. The pair is
read from the label immediately left of the zone. A web request's pair comes from its `Host`
header (for HTTPS, else from the TLS server name); a mail recipient's from the domain after
`@`. An interaction is stored only when its pair names an existing channel. Every other
interaction gets the same answer and is not stored.

Data longer than one name can be sent over many lookups and joined by the client
(`outpost assemble`, `outpost_assemble`); `docs/API.md` section 8 gives the name layout.

## Use it

Install the client with [uv](https://docs.astral.sh/uv/) (`uv tool install outpost-oob`) or
run it with `uvx --from outpost-oob outpost`. It reads `OUTPOST_API_URL` and `OUTPOST_API_KEY`,
and keeps one key file per channel under `OUTPOST_HOME` (default `~/.config/outpost`,
`channels/<label>.json`, mode 0600). The key file holds the API address, the channel id, the
X25519 private key and the channel secret.

```bash
outpost channel create [--channel LABEL] [--retention-days N]
outpost channel status
outpost list [--after N] [--wait S]
outpost read SEQ [--part N]
outpost watch
outpost assemble TOKEN --encoding hex|base32 [--out FILE]
outpost response set TOKEN [--path P] [--status N] [--header 'Name: value']... [--body TEXT | --body-file FILE]
    [--cors-origin ORIGIN]... [--cors-credentials] [--cors-method M]... [--cors-header H]...
    [--cors-expose H]... [--cors-max-age S] [--cors-private-network] [--ttl S]
outpost response list
outpost response delete RESPONSE_ID
outpost channel delete
```

`--channel LABEL` (default `default`) or `--key-file PATH` picks the channel.

### Agents

`outpost mcp` runs a stdio MCP server with six tools: `outpost_addresses` (creates the channel
on first use and shows its names, URLs, mail address and rates), `outpost_list`,
`outpost_read`, `outpost_assemble`, and `outpost_serve` and `outpost_responses` (set, list and
delete what a token's web address answers). Records are opened by this local process.
`integrations/README.md` has ready configuration for Claude Code (command or plugin), Codex CLI
and Claude Desktop, and `skills/outpost/SKILL.md` is the skill that goes with it.

## Run on a public host

1. Delegate a zone to the host. For a subdomain of a domain you control, add to that domain:
   `A ns1.<zone> → <host address>` and `NS <zone> → ns1.<zone>`. For a whole domain, set glue
   records and name servers at the registrar. Outpost answers `MX` for every name in the zone
   with `mx.<zone>`, and `TXT` with `v=spf1 -all` (and `v=DMARC1; p=reject` at `_dmarc.<name>`),
   since nothing in the zone sends mail.
2. Open 53/udp, 53/tcp and 80/tcp to everyone, plus 443/tcp with TLS on and 25/tcp with mail
   on. Open the API port only to the addresses your clients call from, or keep it private and
   reach it through a tunnel.
3. Next to `compose.yml`, write a `.env` with `OUTPOST_ZONE`, `OUTPOST_PUBLIC_IPV4` (the
   address the zone's names resolve to), `OUTPOST_BIND_IP` (the host's own interface address)
   and the settings below you want.
4. `sudo install -d -m 700 /var/lib/outpost && sudo docker compose up -d --build`

`compose.yml` uses host networking, so records carry the real source addresses. The container
keeps only the capability to bind ports below 1024 and runs on a read-only filesystem.

**API keys.** `OUTPOST_API_KEY_SHA256` is the SHA-256 (hex) of a bootstrap key named
`default` (`KEY=$(openssl rand -hex 32); printf %s "$KEY" | sha256sum`). More keys, each with an
optional channel count and channel rate, are made on the host and printed once:

```bash
docker exec outpost outpost-admin key add NAME [--max-channels N] [--channel-rate N]
docker exec outpost outpost-admin key list
docker exec outpost outpost-admin key revoke NAME [--delete-channels]
```

The server refuses to start when the bootstrap hash is unset and the store holds no active key.

**TLS.** `OUTPOST_TLS=acme` obtains a certificate for `<zone>` and `*.<zone>` from Let's
Encrypt through DNS-01, answered by Outpost's own name server, and renews it; certbot runs
inside the container and keeps its files under `/var/lib/outpost/certs`. Set
`OUTPOST_ACME_STAGING=true` for a first try against the staging authority. `OUTPOST_ACME_EMAIL`
is optional. `OUTPOST_TLS=files` uses a certificate pair you place under `/var/lib/outpost`
(`OUTPOST_TLS_CERT`, `OUTPOST_TLS_KEY`, as `/data/...` paths). With TLS on, the certificate
serves HTTPS on 443, the API and mail STARTTLS, and is reloaded when its files change. The API
then serves only TLS, and starts once a certificate is loaded.

**Responses.** `OUTPOST_RESPONSES=on` lets each channel set what its own names answer to web
requests, per token and path (`docs/API.md` section 9): a status, free headers, a body of up to
64 KiB and cross-origin rules that match origins exactly, by `*.suffix`, `null` or `*`. A
response lasts at most a day and is stored unsealed, since it is public. With it off, every
web request gets the empty `200`. Hosting chosen content on a zone with a valid certificate
invites abuse reports, so give API keys only to people you trust with that.

**Mail.** `OUTPOST_SMTP=on` receives mail on 25 for any address at a channel's names, one
record per recipient. It offers STARTTLS when TLS is on, refuses unknown recipients, never
offers AUTH and never relays.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OUTPOST_ZONE` | required | the zone |
| `OUTPOST_PUBLIC_IPV4` | required | the address `A` queries answer |
| `OUTPOST_PUBLIC_IPV6` | none | the address `AAAA` queries answer |
| `OUTPOST_BIND_IP` | `0.0.0.0` | address every listener binds |
| `OUTPOST_API_KEY_SHA256` | none | SHA-256 (hex) of the bootstrap API key `default` |
| `OUTPOST_RETENTION_DAYS` | `90` | days a record is kept; a channel may ask for fewer |
| `OUTPOST_STORE_MAX_BYTES` | `21474836480` | store size past which interactions are dropped |
| `OUTPOST_SOURCE_RATE` | `60` | stored records a minute per source address and channel |
| `OUTPOST_CHANNEL_RATE` | `600` | stored records a minute per channel |
| `OUTPOST_CHANNEL_MAX_RECORDS` | `50000` | records a channel holds |
| `OUTPOST_CHANNEL_MAX_BYTES` | `268435456` | bytes a channel holds |
| `OUTPOST_TLS` | `off` | `off`, `acme` or `files` |
| `OUTPOST_ACME_EMAIL` | none | account e-mail at the certificate authority |
| `OUTPOST_ACME_STAGING` | `false` | use the staging authority |
| `OUTPOST_TLS_CERT`, `OUTPOST_TLS_KEY` | none | certificate and key paths for `files` |
| `OUTPOST_SMTP` | `off` | `on` runs the mail receiver |
| `OUTPOST_RESPONSES` | `off` | `on` lets channels set what their names answer |
| `OUTPOST_DNS_PORT`, `OUTPOST_HTTP_PORT`, `OUTPOST_HTTPS_PORT`, `OUTPOST_SMTP_PORT`, `OUTPOST_API_PORT` | `53`, `80`, `443`, `25`, `9443` | listener ports |
| `OUTPOST_DATA_DIR` | `/var/lib/outpost` | directory of `outpost.sqlite3` and the certificates |

Logs carry counts and channel ids only.

## Develop

```bash
uv sync --all-extras
uv run pytest -q
docker compose -f compose.dev.yml up -d --build
```

`compose.dev.yml` publishes on one address only, `OUTPOST_DEV_BIND` (default `127.0.0.1`): name
server `5353` (UDP and TCP), web `8080`, mail `2525`, API `9080`, zone `oob.test`, no TLS. It
reads `OUTPOST_API_KEY_SHA256` and `OUTPOST_DEV_BIND` from a `.env` file next to it (ignored by
git). Then `OUTPOST_API_URL=http://127.0.0.1:9080 OUTPOST_API_KEY=$KEY uv run outpost channel create`.

## API

`docs/API.md` is the contract (version 1): addresses, listeners, limits, channels, the pull
API, the record format and the reassembly convention. The examples in
`contract/v1/examples/` are its test vectors; FastAPI serves the OpenAPI document at
`/openapi.json`. `SECURITY.md` says what a host holds and what a compromise exposes.

## License

MIT. See [LICENSE](LICENSE).
