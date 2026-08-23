# Architecture decision records

A short record for each decision that shapes SAG and would otherwise only live
in commit messages or a maintainer's memory. Each one is a snapshot: it
records the reasoning at the time, not the current behaviour, so it is never
edited to match a later change. If a decision is reversed, the old record
stays and a new one supersedes it and says so.

These are about *why*. Configuration, environment variables and how to turn a
feature on live in the reference docs linked from each record and from
[docs/README.md](../README.md); an ADR does not repeat what is already written
there.

## Format

Each record is short: **Context** (the problem, and the options that were
actually on the table), **Decision** (what was chosen), **Consequences**
(what that costs, and what it does not solve). No record is expected to be
the last word - see [../rfcs/](../rfcs/README.md) for what is proposed but
not yet decided, and [../limitations.md](../limitations.md) for what a
decision here leaves open.

## Index

| # | Decision |
| --- | --- |
| [0001](0001-stateless-with-optional-state-store.md) | Stateless by default, with one optional, pluggable state store |
| [0002](0002-email-otp-code-design.md) | Email OTP: an unbiased high-entropy code, and one store for both send limits and replay prevention |
| [0003](0003-silent-enumeration-and-rate-limit-defence.md) | The sign-in surface never signals whether an address exists or a rate limit was hit |
| [0004](0004-session-scope-and-sign-out-confirmation.md) | Session scope is a deployment choice, and sign-out asks before it affects more than one relying party |
| [0005](0005-no-refresh-tokens.md) | No refresh tokens: a short-lived access token scoped to `/userinfo` only |
| [0006](0006-algorithm-agile-signing.md) | Algorithm-agile signing, with post-quantum support as an option rather than a rewrite |
| [0007](0007-require-prefix-for-fail-fast-flags.md) | `REQUIRE_*` is the one naming pattern for a flag that turns a silent fallback into a startup error |
| [0008](0008-branding-and-attribution.md) | Branded and attributed by default; whitelabelling available, attribution never removable |
| [0009](0009-peer-jwks-federation.md) | Multi-region and multi-cloud key distribution by federating public keys, not sharing private ones |
| [0010](0010-signed-outbound-requests.md) | Sign every outbound request SAG makes on its own behalf, via `Authentication-Info` |
| [0011](0011-subject-derived-from-the-verified-address.md) | The `sub` is derived from the verified address, never an upstream's, and a plus tag is not a separate person |
