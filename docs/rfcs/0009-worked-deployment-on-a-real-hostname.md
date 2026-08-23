# 0009. A worked deployment on a real hostname

Status: Proposed

## Context

The local stack ([test/local-stack/](../../test/local-stack/README.md)) now
covers everything up to the hostname - real workerd, real Durable Objects,
real KMS - so what is left is TLS, a domain, and the upstream registrations
that need one.

## Proposal

Put an instance behind a real domain on Cloudflare and run the worked
example relying party against it end to end, then fold whatever it takes -
DNS, TLS, upstream redirect URI registration - back into
`docs/deployment.md`.

## Cost

Needs a real domain and Cloudflare account to run against; no code changes
are expected, only documentation of what a live hostname takes that the
local stack cannot exercise.
