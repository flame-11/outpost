# Outpost 1.0 plan

Status: built in 1.0. `README.md` and `docs/API.md` describe what was built; this file is the
plan as reviewed. Before it, Outpost ran the authoritative name server (UDP and TCP), the
plain web listener, sealed storage, the pull API v1, limits, retention and the `outpost` CLI.
This plan takes it to a 1.0 that a person or an agent can use directly, without any other
product in between.

## Goals

1. Every interaction channel the API v1 contract names works: DNS, HTTP, HTTPS, mail.
2. Agents use Outpost natively: a local MCP server for Claude Code, Codex CLI, Claude Desktop
   and other MCP clients, with a skill that says when and how to use it.
3. Data that arrives spread over many lookups is reassembled on the client.
4. One instance serves several independent clients safely.
5. It is publishable: full API document, security notes, CI, released images and packages.

The design rule stays: the public host never holds anything readable. Every feature that has
to read a record (reassembly, mail parsing, display) runs on the client, where the key is.

## Phase 1: client library, MCP server, reassembly

**Goal.** One client library behind the CLI and the MCP server; agents can use Outpost from
Claude Code and Codex; multi-lookup data comes back whole.

**Changes.**

- `outpost/client.py`: the client library, moved out of `cli.py`: `register`, `channel`,
  `pull`, `open_record`, `assemble`. Key files live in `~/.config/outpost/channels/<label>.json`
  (mode 0600) unless a path is given. The CLI becomes a thin layer over it.
- Reassembly (`assemble`), client side. A sender splits data into chunks, encodes each chunk as
  lowercase hex or unpadded base32 (both survive the letter-case changes resolvers make), and
  puts it in the labels left of the pair label, followed by one label holding the chunk index:
  `<data>[.<data>…].<index>.<token>-<channel>.<zone>`. `assemble(token, encoding)` collects the
  token's records, keeps one record per index (resolvers retry), orders them, decodes them, and
  returns the bytes plus the list of missing indices. Data in a web request's path, query or
  body needs no reassembly.
- Configurable limits: `OUTPOST_SOURCE_RATE`, `OUTPOST_CHANNEL_RATE`,
  `OUTPOST_CHANNEL_MAX_RECORDS`, `OUTPOST_CHANNEL_MAX_BYTES` (today constants). The channel
  answer reports `source_rate` and `channel_rate` so a client knows what one source may send.
- `outpost mcp`: a stdio MCP server (official `mcp` Python SDK) configured by
  `OUTPOST_API_URL` and `OUTPOST_API_KEY`. Four tools:
  - `outpost_addresses(channel?)`: creates the channel on first use; host name, web URLs,
    mail address (when the instance runs mail), the token rule, the instance's rate limits.
  - `outpost_list(channel?, tokens?, protocol?, after?, wait_seconds?, limit?)`.
  - `outpost_read(channel?, seq, offset?)`: one interaction in full.
  - `outpost_assemble(channel?, token, encoding)`: reassembled data and missing indices.
- `skills/outpost/SKILL.md`: when to use callback addresses, one token per probe, reading
  results, reassembly. How-to only.
- `integrations/`: ready configuration for Claude Code (`claude mcp add`), Codex CLI
  (`~/.codex/config.toml` `[mcp_servers.outpost]`) and Claude Desktop (plain config entry).

**Proof.** Unit tests for the client, reassembly (order, duplicates, gaps, both encodings) and
the MCP tools against an in-process server. Live, against the public instance: from Claude Code
and from Codex CLI, an agent gets addresses and sees a lookup made through a public resolver; a
4 KB test file sent as indexed lookups through a public resolver reassembles byte for byte.

**Proceed when** both agent clients list and use the four tools and reassembly is exact.

## Phase 2: certificate and HTTPS

**Goal.** `https://` addresses and the API over TLS.

**Changes.** Wildcard certificate for `<zone>` and `*.<zone>` through ACME DNS-01, answered by
Outpost's own name server (`_acme-challenge` TXT values from a table the ACME hook writes);
daily renewal and certificate reload without restart. Web listener on 443 (pair from `Host`,
else from the TLS server name; records carry `tls` and `sni`). API on 9443 over TLS with the
same certificate. `listeners` reports `https`.

**Proof.** `certbot renew --dry-run` succeeds; an outside checker gets `200` from an `https://`
channel URL and the record shows `tls: true`; the API answers over TLS from an allowed address.

**Proceed when** issuance, renewal and reload work on the public instance.

## Phase 3: mail

**Goal.** Mail addresses that record what is delivered to them.

**Changes.** SMTP receiver on 25 (`aiosmtpd`): recipients whose domain names an existing
channel are accepted, others refused `550`; size cap `552`; STARTTLS with the phase 2
certificate; one record per accepted recipient; never relays or sends. Client side: mail
parsing in `read` (headers, parts, text) and in the MCP tool. Operator notes: inbound port 25,
reverse DNS of the host to `mx.<zone>`.

**Proof.** A message sent from an ordinary mail provider to a channel address is recorded and
readable through `outpost_read`; an unknown recipient is refused; an oversized message is refused.

**Proceed when** mail from at least two outside providers arrives and parses.

## Phase 4: several clients and channel lifecycle

**Goal.** One instance shared by independent clients.

**Changes.** Named API keys with per-key quotas (channels, records a minute) managed by an
`outpost-admin` command on the host; channels belong to the key that created them. Channel
delete call (records go with it). Retention per channel at registration, capped by the
instance's `OUTPOST_RETENTION_DAYS`.

**Proof.** Two keys see only their own channels; a revoked key is refused; a deleted channel
answers `channel_not_found` and its records are gone from the store.

## Phase 5: publishing

**Goal.** Ready for an open repository.

**Changes.** `docs/API.md` (the full v1 contract: address grammar, answers, limits, endpoints,
record fields), `SECURITY.md` (what the host stores and exposes, reporting), `CONTRIBUTING.md`;
CI (lint, tests, image build); tagged releases with container images; PyPI distribution
`outpost-oob` (the name `outpost` is taken), import package and command stay `outpost`;
Claude Code plugin (MCP server plus skill) and a Claude Desktop extension bundle.

**Proof.** A fresh machine installs from the published package and image, follows the README,
and passes the phase 1 live check.

## Not planned

- A hosted remote MCP connector. It would need the host to open records, which ends the rule
  above. If wanted later, only as an explicit trusted mode for self-hosted instances.
- Pushing notifications from the host. Clients pull; the host never connects out.

## Decisions

1. PyPI distribution `outpost-oob` (owner, 2026-11-11).
2. Configured responses (a fixed status, headers or body per channel) are not in 1.0; decided
   later with concrete use cases, since they turn a recorder into a host of content.
3. The public host needs inbound 443/tcp and 25/tcp, the API port open only to client
   addresses, and reverse DNS of its address to `mx.<zone>` for phases 2 and 3.
