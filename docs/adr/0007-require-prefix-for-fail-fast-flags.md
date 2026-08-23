# 0007. `REQUIRE_*` is the one naming pattern for a flag that turns a silent fallback into a startup error

Date: 2026-08-23
Status: Accepted

## Context

Two configuration flags exist purely to change what happens when a control
an operator wanted turns out not to be configured: refuse to start rather
than run in a quietly weaker mode. The first, requiring a post-quantum
signing algorithm, was named `SIGNING_REQUIRE_POST_QUANTUM` - "require"
embedded inside a subsystem-specific name. When a second flag of the same
shape was proposed, for requiring a state store backend, naming it to match
its own subsystem instead (`STATE_STORE_REQUIRED`, or similar) would have
produced two flags that do the same *kind* of thing with no naming
relationship between them at all.

## Decision

Every flag whose only job is "turn a silent fallback into a startup error"
gets a `REQUIRE_*` prefix, full stop, regardless of which subsystem it
belongs to: `REQUIRE_STATE_STORE`, `REQUIRE_POST_QUANTUM_SIGNING`. The
existing flag was renamed to fit, with the old name kept working as an
alias rather than broken outright - the same treatment already given to
`REPLAY_STORE_BACKEND` when it became `STATE_STORE_BACKEND`.

This is deliberately a narrower category than "any flag that makes
something mandatory": `CLIENT_<SLUG>_REQUIRE_PKCE`, for example, changes
SAG's actual behaviour (whether PKCE is enforced for that client) rather
than promoting a silent fallback into an error, so it does not need to
follow this pattern and was left alone.

## Consequences

An operator learns the pattern once - "a `REQUIRE_*` flag means I want a
startup error if this was not really configured" - rather than once per
subsystem. Any future flag of this shape (a required email sender, a
required upstream, whatever comes up) should be named the same way rather
than invented fresh each time. See [configuration.md](../configuration.md)
for the full list of environment variables.
