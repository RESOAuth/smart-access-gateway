# Changelog

All notable changes to SAG are recorded here. Releases use semantic versions.

## Unreleased

### Fixed

- Peered deployments no longer intermittently publish a `/jwks.json` missing an
  instance's keys. A peer is now asked for its own keys only rather than for
  its merged view of the mesh, which stops one peer fetch fanning out into a
  fetch of every peer; concurrent requests on a cold instance share one fetch
  per peer; a peer answering with an empty key set is treated as unreachable
  instead of having that emptiness cached and federated; and a document that is
  missing a configured peer's keys is served with a short `max-age` so it
  cannot be pinned in a relying party's or a CDN's cache for five minutes. A
  peer URL on this instance's own issuer origin is refused at start-up with an
  explanation, rather than fetching whichever instance happens to answer there.
- `/healthz` reports `peer_jwks.peers[].key_count`, so an operator can see
  which peer is not contributing a key.
- The "signing key leaked" runbook now covers a peered deployment, where
  taking the compromised instance offline is the one action that keeps its
  leaked key published by every peer for the whole grace period.

### Added

- `REQUIRE_PEER_JWKS_CACHE`, which refuses to start unless peers are
  configured and `PEER_JWKS_CACHE_BACKEND` is durable. A peered deployment
  left on the `memory` backend is now warned about it in the log regardless,
  because it makes every cold start refetch every peer on its first
  `/jwks.json` and so defeats `PEER_JWKS_STALE_TTL` entirely.

### Security

None.

## 0.1.0 - 2026-08-24

Initial pre-release of the stateless OpenID Connect identity proxy, with Node,
AWS Lambda, Cloudflare Worker, and container adapters.

### Security

None.
