# 0004. Per-relying-party OTP policy

Status: Proposed

## Context

Send limits and code length are per instance today. An enterprise
deployment with one high-security relying party and several ordinary ones
might want them per client, in the way `acr` demands already are.

## Proposal

Let OTP send limits and code length be overridden per relying party,
following the existing pattern for per-client `acr` demands, rather than
only ever configurable instance-wide.

## Cost

Mainly design cost: deciding where a per-client override lives (static env
var, CIMD, or the client store, matching whichever mechanism describes that
client already) and what it falls back to when unset. Implementation itself
is a small extension of `src/otp.js`.
