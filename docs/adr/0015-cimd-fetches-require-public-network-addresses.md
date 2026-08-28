# 0015. CIMD fetches require public network addresses

Date: 2026-08-27
Status: Accepted

## Context

An enabled Client ID Metadata Document is fetched from an unauthenticated
`client_id`. Restricting the scheme, redirects, credentials, and response size
does not stop a hostname from resolving to loopback, a private network, or a
cloud metadata service.

## Decision

Before a CIMD fetch, resolve both A and AAAA records and refuse the request when
there is no address or any answer is not public. Apply the same classification
to IP literals. `SAG_DEV=true` permits localhost and loopback so the worked
local flow remains usable, but does not permit arbitrary private addresses.

Keep `CLIENTS_CIMD_ALLOWED_DOMAINS` as an optional, additional trust boundary.
An empty list permits public hosts rather than making an allow-list compulsory.

## Consequences

DNS resolution is now on an uncached CIMD fetch's critical path and fails
closed. Node uses its platform resolver; runtimes without one use the configured
DNS-over-HTTPS resolver. A DNS answer can still change between validation and
fetch, so an egress policy that blocks private destinations remains worthwhile
defence in depth for deployments exposed to hostile client identifiers.
