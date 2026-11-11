# Outpost API, version 1

This is the contract between an Outpost instance and its clients: the addresses, what each
listener answers, the limits, the HTTP API and the record shapes. The JSON examples in
`contract/v1/examples/` are its test vectors; `test_only_keypair.json` opens
`sealed_record.json`. Examples use the zone `oob.example` and the channel `k3v7x2mq6c4a`.

Version 1 only ever grows: a field or endpoint may be added, none is removed or changed in
meaning. A change that breaks a client gets `/v2`.


## 1. Addresses

```
name       = [ prefix "." ] pair "." zone
pair       = token "-" channel_id
token      = 1*20( a-z / 0-9 )
channel_id = 12( a-z / 2-7 )            ; 60 random bits, drawn by Outpost
prefix     = one or more DNS labels, free content
```

- Outpost lowercases a name, then reads the pair from **the label immediately left of
  the zone**. The pair label matches `^([a-z0-9]{1,20})-([a-z2-7]{12})$`; any other shape
  names no channel.
- `prefix` is free and recorded: `uid0.t1-k3v7x2mq6c4a.oob.example` is token `t1`, prefix
  `uid0`. Each label is at most 63 bytes and the whole name at most 253.
- Web requests: the pair is read from the `Host` header (port removed). When `Host` is
  missing or outside the zone, it is read from the TLS server name. Otherwise the request
  names no channel.
- Mail: the recipient is `local@name`. `local` is free (1 to 64 bytes) and recorded; the
  pair is read from the recipient's domain by the rule above.
- The certificate covers `<zone>` and `*.<zone>`: a name without a prefix. A name with a
  prefix works for name lookups and plain web requests only.
- Reserved names, never a channel: `<zone>`, `ns1.<zone>`, `ns2.<zone>`, `mx.<zone>`,
  `api.<zone>`, `_acme-challenge.<zone>`.

An interaction is **stored** only when its pair names an existing channel. Everything else
gets the same fixed answer and is dropped.

## 2. What Outpost answers

Name server (UDP and TCP, authoritative, no recursion):

| Query | Answer |
|---|---|
| `A`, any name in the zone | Outpost's IPv4 address, TTL 60 |
| `AAAA`, any name in the zone | Outpost's IPv6 address when one is configured, else no data |
| `MX`, any name in the zone | `10 mx.<zone>`, TTL 60 |
| `NS`, `SOA` at the zone | `ns1.<zone>`, `ns2.<zone>` and the zone's SOA |
| `TXT` at `_acme-challenge.<zone>` | the current certificate challenge values |
| any other type in the zone | no data, with the SOA |
| a name outside the zone | `REFUSED` |

Web listener (80, and 443 with TLS, HTTP/1.1 only): reads at most `HTTP_MAX_BYTES`, for at
most `HTTP_READ_SECONDS`, then sends `HTTP/1.1 200 OK`, `Content-Length: 0`,
`Connection: close` and closes. Same answer for every method, path and host.

Mail receiver (25, STARTTLS offered when a certificate is loaded):

| Event | Answer |
|---|---|
| connect | `220 mx.<zone> ESMTP` |
| `RCPT TO` whose domain names an existing channel | `250 2.1.5` |
| any other `RCPT TO` | `550 5.1.1` |
| a recipient past `MAIL_MAX_RCPT` | `452 4.5.3` |
| `DATA` larger than `MAIL_MAX_BYTES` | `552 5.3.4` |
| `DATA` accepted | `250 2.0.0 OK` |
| `AUTH`, `VRFY`, `EXPN` | `502 5.5.1` |

Outpost never sends, relays or forwards mail, never serves content, and opens no
outbound connection except to the certificate authority.

## 3. Limits and retention

| Name | Value | Effect past the limit |
|---|---|---|
| `HTTP_MAX_BYTES` | 65,536 | rest of the request is not read; record has `truncated: true` |
| `HTTP_READ_SECONDS` | 10 | what arrived is recorded if it named a channel |
| `MAIL_MAX_BYTES` | 1,048,576 | `552`, not stored, counted as dropped |
| `MAIL_MAX_RCPT` | 10 | further recipients refused |
| `SOURCE_RATE` | 60 stored records a minute, per source address and channel | dropped, counted |
| `CHANNEL_RATE` | 600 stored records a minute, per channel, or the API key's lower rate | dropped, counted |
| `CHANNEL_MAX_RECORDS` | 50,000 records held | dropped, counted |
| `CHANNEL_MAX_BYTES` | 268,435,456 bytes held | dropped, counted |
| `OUTPOST_STORE_MAX_BYTES` | operator setting, default 21,474,836,480 | dropped, counted; health shows `store_full: true` |
| `DNS_SOURCE_RATE` | 50 answers a second per source address | query not answered |
| `PULL_MAX_LIMIT` / `PULL_MAX_BYTES` / `PULL_MAX_WAIT_SECONDS` | 200 / 4,194,304 / 25 | request value is lowered to the limit |
| `AUTH_FAIL_RATE` | 10 failed authentications a minute per source address | `429 rate_limited` |

The operator sets these four with `OUTPOST_SOURCE_RATE`, `OUTPOST_CHANNEL_RATE`,
`OUTPOST_CHANNEL_MAX_RECORDS` and `OUTPOST_CHANNEL_MAX_BYTES`; the values above are the
defaults. A dropped interaction still gets the fixed answer. Each channel counts its drops in
`dropped_total`.

**Retention** is an operator setting, `OUTPOST_RETENTION_DAYS` (default 90), which a
channel may lower for itself at registration (section 7):

- A record is deleted `retention_days` after its `received_at`. Pulling a record does not
  delete it, so Outpost holds the history of every channel for that long.
- A channel keeps recording until it is deleted. It is deleted, with its records, once its
  last authenticated call and its newest record are both older than `retention_days`.
- The registration and channel answers carry `retention_days`, so a client knows what the
  Outpost keeps.

## 4. Channels

1. The client draws an X25519 key pair and a secret of at least 32 random bytes written as
   text (the `outpost` client uses hex), and keeps both.
2. It registers the public key and the SHA-256 of the secret's text as sent (its UTF-8
   bytes). Outpost draws the `channel_id`. API keys are hashed the same way.
3. Every later call for that channel carries the secret itself as the bearer token. The
   Outpost stores only its SHA-256.

A channel is deleted by its client (`DELETE`, section 7) or by retention (section 3). A call for a deleted
channel answers `404 channel_not_found`; the client may register again with the same key
and secret and receive a new `channel_id`.

## 5. API

The API listens on its own port (production: `https://api.<zone>:9443`), never on 80, 443
or 25. JSON in UTF-8. Times are RFC 3339 UTC with milliseconds
(`2026-11-11T08:15:30.123Z`). The path prefix `/v1` is the contract version; a change that
breaks a client gets `/v2`.

Authentication: `Authorization: Bearer <value>`. The value is the operator's API key for
registration, and the channel secret for channel routes. Comparison is constant-time against
a stored SHA-256.

Errors: a 4xx or 5xx status with `{"error": {"code": "<code>", "message": "<text>"}}`.

| Status | `code` | When |
|---|---|---|
| 401 | `unauthorized` | missing or wrong bearer value |
| 404 | `channel_not_found` | the channel id is unknown or deleted (one answer for both) |
| 409 | `channel_conflict` | registration: this public key is registered with another secret |
| 422 | `invalid_request` | a field is missing or malformed; `message` names it. Also an unknown route (404) or method (405) |
| 429 | `rate_limited` | `AUTH_FAIL_RATE` passed; carries `Retry-After` |
| 429 | `quota_exceeded` | registration: the API key's channel quota is used up (section 7) |
| 503 | `storage_unavailable` | Outpost could not read or write its store |

### `GET /v1/health`

No authentication. `200 {"status": "ok", "contract": 1, "store_full": false}`.

### `POST /v1/channels`

Bearer: the API key.

```json
{"public_key": "<base64, 32 bytes>", "secret_sha256": "<64 hex characters>"}
```

`201` for a new channel; `200` with the same body when this `public_key` and
`secret_sha256` already hold a channel, so a repeat after an uncertain delivery is safe.

```json
{
  "channel_id": "k3v7x2mq6c4a",
  "zone": "oob.example",
  "listeners": ["dns", "http", "https", "smtp"],
  "retention_days": 90
}
```

`listeners` names the listeners this Outpost instance runs: always `dns` and `http`; `https` when TLS
is on; `smtp` when the mail receiver is on.

### `GET /v1/channels/{channel_id}`

Bearer: the channel secret.

```json
{
  "channel_id": "k3v7x2mq6c4a",
  "zone": "oob.example",
  "listeners": ["dns", "http", "https", "smtp"],
  "retention_days": 90,
  "last_seq": 17,
  "held_records": 17,
  "dropped_total": 0
}
```

### `GET /v1/channels/{channel_id}/records?after=<seq>&limit=<n>&wait=<seconds>`

Bearer: the channel secret.

- `seq` starts at 1 for each channel, rises by 1 with each stored record and is never reused.
- `after` (default 0) is a cursor: the answer holds the held records with `seq > after`,
  ascending, at most `limit` (default 100) and at most `PULL_MAX_BYTES` of `sealed` data,
  but always at least one when one exists. Records past retention are gone, so the first
  `seq` returned may be above `after + 1`.
- `wait` (default 0): when there is no such record, Outpost holds the request until one
  is stored or `wait` seconds pass, then answers.

```json
{
  "records": [
    {"seq": 17, "received_at": "2026-11-11T08:15:30.123Z", "sealed": "<base64>"}
  ],
  "more": false,
  "dropped_total": 0
}
```

`more` is true when records past this page exist now.

## 6. Records

`sealed` is the base64 of a libsodium sealed box (`crypto_box_seal`: X25519,
XSalsa20-Poly1305) over the UTF-8 JSON below, made with the channel's public key. Only the
holder of the private key opens it. Outpost keeps `channel_id`, `seq`, `received_at`,
the size and `sealed` for a record and nothing else; the token, the names, the source
address and the content exist on its disk only inside `sealed`.

Fields of every record:

| Field | Type | Meaning |
|---|---|---|
| `v` | int | `1` |
| `protocol` | `"dns"`, `"http"` or `"smtp"` | which listener received it |
| `channel_id` | string | the channel the pair named |
| `token` | string | the token the pair named |
| `prefix` | string | the labels left of the pair label, joined by `.`; `""` when none |
| `name` | string | the whole in-zone name, lowercased, without a trailing dot |
| `source_ip` | string | the address that contacted Outpost |
| `source_port` | int | its port |
| `received_at` | string | same value as outside the box |

Name lookup (`protocol: "dns"`):

| Field | Type | Meaning |
|---|---|---|
| `qname` | string | the name as asked, letter case kept |
| `qtype` | string | `A`, `AAAA`, `MX`, `TXT`, …; `TYPE<n>` for a type with no mnemonic |
| `transport` | `"udp"` or `"tcp"` | |

`source_ip` of a name lookup is the resolver that asked, which is often not the target.

Web request (`protocol: "http"`):

| Field | Type | Meaning |
|---|---|---|
| `port` | int | 80 or 443 |
| `tls` | bool | |
| `sni` | string or null | TLS server name |
| `method`, `target`, `host` | string or null | read from the request line and `Host`; null when not readable |
| `raw_b64` | string | the request bytes as received, at most `HTTP_MAX_BYTES` |
| `truncated` | bool | true when the request was longer than `raw_b64` |

Mail (`protocol: "smtp"`): one record per accepted recipient.

| Field | Type | Meaning |
|---|---|---|
| `helo` | string | the sender's `HELO`/`EHLO` name |
| `mail_from` | string | envelope sender |
| `rcpt_to` | string | the recipient this record is for, as sent |
| `tls` | bool | STARTTLS was used |
| `raw_b64` | string | the message as received in `DATA`, at most `MAIL_MAX_BYTES` |

Example, opened:

```json
{
  "v": 1, "protocol": "http", "channel_id": "k3v7x2mq6c4a", "token": "q7ab12cd9z",
  "prefix": "", "name": "q7ab12cd9z-k3v7x2mq6c4a.oob.example",
  "source_ip": "203.0.113.7", "source_port": 51234,
  "received_at": "2026-11-11T08:15:30.123Z",
  "port": 80, "tls": false, "sni": null,
  "method": "GET", "target": "/c", "host": "q7ab12cd9z-k3v7x2mq6c4a.oob.example",
  "raw_b64": "R0VUIC9jIEhUVFAvMS4xDQpIb3N0OiAuLi4NCg0K", "truncated": false
}
```

The product publishes these examples, and one sealed record with its key pair, as files in
its repository (`contract/v1/examples/`). Every client tests against them.

## 7. Additions in Outpost 1.0

All additive to version 1.

- **Rates.** The registration and channel answers carry `source_rate` and `channel_rate`:
  how many records a minute the instance stores per source address and channel, and per
  channel (the instance rate, or the owning API key's rate when that is lower).
- **Retention per channel.** `POST /v1/channels` takes an optional `retention_days`
  (integer, at least 1, at most the instance's `retention_days`; more is `422
  invalid_request`). Answers carry the channel's effective `retention_days`.
- **Delete.** `DELETE /v1/channels/{channel_id}` with the channel secret answers `204`; the
  channel and all its records are deleted, later calls answer `404 channel_not_found`, and a
  pull waiting on the channel ends with that `404`.
- **Named API keys.** An instance may hold several API keys, each with an optional
  maximum number of channels and an optional channel rate. A channel belongs to the key that
  registered it. Registration past the maximum answers `429 quota_exceeded`, without
  `Retry-After`. A revoked key answers `401` at registration; its channels keep working
  until deleted. Keys are managed on the host with `outpost-admin`.
- **Listeners.** `listeners` lists `https` when TLS is on and `smtp` when the mail
  receiver is on. With TLS on, the API itself starts only once a certificate is loaded, and
  never serves plain HTTP.

## 8. Reassembling data spread over many lookups

Outpost records each lookup separately; joining them is the client's job, since only the
client can open the records. The convention the `outpost` client follows:

```
<data>[.<data>…].<index>.<token>-<channel_id>.<zone>
```

- `<data>` labels hold one chunk, encoded on its own as lowercase hex or unpadded lowercase
  base32; the client decodes each chunk alone and joins the bytes in index order. Both
  encodings survive the letter-case changes many resolvers make; base64 does not.
- `<index>` is the chunk's position, decimal from 0, and makes every name unique so
  resolver caches do not hide a chunk.
- Resolvers retry, so a chunk may arrive more than once; one copy per index is kept.
- About 130 bytes fit in one lookup as base32, about 105 as hex, depending on the length of
  the zone name. Mind the instance's `source_rate` when sending many chunks.
