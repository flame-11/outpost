# Security

## What an Outpost host holds

Outpost is built so that the public host never holds anything readable about what it
recorded.

- Every record is sealed (libsodium sealed box: X25519, XSalsa20-Poly1305) to the public key
  of the channel it names, before it is written. Only the holder of the channel's private key,
  the client, can open it.
- Outside the sealed box the host keeps a record's channel id, sequence number, arrival time
  and size. Token, names, source address and content exist on disk only inside the box.
- For each channel: its id, public key, the SHA-256 of its secret, its owning API key,
  timestamps and drop counters. For each API key: its name, the SHA-256 of the key, quotas.
- The TLS private key of the zone's certificate, when TLS is on.
- With responses on: each unexpired response a channel set, as sent (token, path, status,
  headers, body). Responses are public by nature, so they are not sealed; each is deleted
  when it expires (at most a day after it was set), is replaced, or its channel is deleted.

## What a compromise exposes

- **Read access to the disk** exposes the items above. Sealed records cannot be opened.
- **Control of the running process** additionally sees interactions as they arrive, API keys
  at registration and channel secrets on each call, and can invent or withhold records. It
  still cannot open records already stored, and it holds no credential of any client system:
  clients connect to Outpost, never the other way round.

## Exposure of a running instance

- Name server: authoritative for one zone only; every other name is refused. No recursion.
  Answers are small and rate-limited per source address.
- Web listener: answers an empty `200`, except a request to a token whose channel set a
  response (responses on). Such a response is served only on that channel's own names, at
  most 64 KiB, for at most a day, and its headers cannot replace the framing Outpost writes
  (`Content-Length`, `Connection`, `Transfer-Encoding` and the other hop-by-hop headers).
  Anyone holding an API key can therefore host content and redirects on the zone for a day:
  hand out keys accordingly. Logs carry the channel id, response id, size and SHA-256 of
  every body set.
- Mail receiver: accepts mail only for recipients that name an existing channel, never relays
  or sends.
- API: should be reachable only from client addresses (firewall) or through a tunnel; failed
  authentications are rate-limited per source address.
- Channel ids are not secret: they appear in every address handed out. Anyone who learns an
  address can add records to that channel, within the limits; nobody can read them.
- Name lookups cross public resolvers in clear text, so data placed in labels is visible on
  the way.

## Use

Outpost is meant for testing systems you are authorized to test.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's security advisory feature
("Report a vulnerability") rather than in a public issue. Include the version, the
configuration involved and steps to reproduce.
