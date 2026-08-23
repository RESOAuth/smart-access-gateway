# 0001. Stateless by default, with one optional, pluggable state store

Date: 2026-08-23
Status: Accepted

## Context

SAG's core bet is to run as a FaaS identity proxy with no database: sessions,
in-flight requests and authorisation codes are all encrypted values the
browser or the upstream carries back, sealed with a shared secret. That
works for almost everything, but two questions cannot be answered without
something outside the request: has this authorisation code already been
redeemed, and how many codes has this address asked for. Both need state
that changes over time, held by a party other than the one being guarded
against.

## Decision

Keep the store optional and off by default (`STATE_STORE_BACKEND=none`),
rather than making SAG depend on one. Without it, correctness rests on a
60 second code lifetime, mandatory PKCE, and binding a code to its client
and redirect URI - a real mitigation, not a placeholder. With it, one store
serves both jobs (claim-once for codes, increment for OTP send limits)
through two primitives, backed by whichever platform-native primitive is
genuinely atomic: an in-memory map for a single process, a Cloudflare
Durable Object, or DynamoDB with a conditional write. Cloudflare KV was
considered and rejected outright: no compare-and-set and eventually
consistent, so the check would be a race and the control would fail
silently under load - worse than an honest absence.

A store failure is treated differently depending on what it protects. A
claim (single-use codes) refuses the request rather than serving without
the control, because letting it through would disable the control exactly
when an attacker wants it disabled. A send-limit check fails open, because
it protects the operator's mail bill rather than an account, and an outage
must not lock everybody out of signing in.

An operator who wants certainty that the store really is configured, rather
than silently absent because a template or a refactor dropped a variable,
can set `REQUIRE_STATE_STORE=true` - see
[0007](0007-require-prefix-for-fail-fast-flags.md) for why that flag has the
shape it does.

## Consequences

A deployment with no store is a deployment with two known-weaker controls,
and it says so out loud: in the start-up warnings and in `/healthz`. That is
a legitimate choice for a low-stakes deployment sitting behind edge rate
limiting, and the wrong one for anything else - see
[state-and-limits.md](../state-and-limits.md) for which backend to pick per
platform, and [limitations.md](../limitations.md) for exactly what "weaker"
means.
