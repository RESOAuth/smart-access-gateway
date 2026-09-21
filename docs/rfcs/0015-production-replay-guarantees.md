# 0015. Production replay guarantees

Status: Proposed

## Context

SAG seals an authorisation code and validates its client, redirect URI, expiry,
and PKCE verifier. That protects confidentiality and binds a code to its
intended relying party, but a sealed value cannot record that it was spent.
[`redeemCode`](../../src/oauth/code.js) calls `claim` only when an optional
state store exists. The current flow test explicitly demonstrates a second
successful redemption when it does not.

RFC 6749 section 4.1.2 says an authorisation code **MUST NOT** be used more
than once; a repeat use **MUST** be denied and prior tokens **SHOULD** be revoked where possible.
RFC 9700 treats code replay protection as a security requirement. PKCE and a
short lifetime reduce replay exposure, but do not make a second redemption
conformant.

[ADR 0001](../adr/0001-stateless-with-optional-state-store.md) deliberately
made shared state optional so the core identity path
could remain stateless. Its `claim`, `has`, and `increment` primitives do not
establish a global guarantee. Replicated backends can accept two claims unless
all code claims have one globally atomic authority. In-memory state is also
limited to one process.

The current claim happens after credential and binding validation, before token
issuance. A later signing or delivery failure consumes the code. This intentional
fail-closed retry behaviour prevents a post-claim replay window; SAG does not
currently retain a token-to-code relationship, so cannot currently revoke
tokens previously issued from a replayed code.

OTP attempt rollback and OTP send limiting are separate concerns. The sealed
OTP transaction can be replayed with an older attempt count; send limits use
`increment` and intentionally fail open during an outage. Neither answers this
requirement.

## Proposal

Adopt a production replay profile as the deliberate successor to ADR 0001. It
changes deployment policy, not the stateless representation of identity data.

1. Production deployments **MUST** set the existing `REQUIRE_STATE_STORE=true`
   and configure a shared, production-capable backend whose `claim` is atomic
   at one replay authority for every instance that can redeem the same code.
   No new redundant configuration flag is introduced.
2. The in-memory backend is permitted only for tests and local development. It
   **MUST NOT** satisfy the production profile, even if one process happens to
   be deployed today.
3. A backend **MUST** atomically create a code-identifier claim only when no
   live claim exists at that authority. The result must be visible to every
   possible concurrent redeemer before either receives success. A local atomic
   operation plus asynchronous replication is insufficient.
4. The code claim key remains a random code identifier, never an email address.
   Its retention is the minimum needed to cover code expiry and clock skew.
   Stores and operational logs **MUST NOT** add email addresses for this control.
5. A duplicate claim **MUST** return `invalid_grant`. A claim timeout, error, or
   indeterminate result **MUST** deny redemption. It **MUST NOT** fall back to
   untracked redemption, another region, or a best-effort read-then-write.
6. Claim before issuing tokens. If later signing, response construction, or
   transport fails, the code remains consumed. Do not add a release, rollback,
   or retry exception.
7. Document the current deviation from RFC 6749's token-revocation **SHOULD**:
   SAG currently cannot identify tokens issued from a replayed code. The
   compensating controls are short code lifetime, mandatory PKCE, exact client
   and redirect binding, and no refresh tokens. A future lifecycle design may
   provide revocation through token-to-code, session, or other durable links.
8. Keep the existing OTP send-limit availability choice separate. It may remain
   fail open and is not evidence of code replay safety. A later OTP proposal
   may require globally atomic per-transaction attempt counting and one-use
   success, but that is outside this RFC.

### Backend qualification and deployment

For DynamoDB, every redeemer must conditionally write to the same table in the
same account, region, and endpoint. Multi-region active writers with eventual
replication do not qualify. For Durable Objects, every redeemer must route a
given replay key to the same namespace and object identity. Document that
fleet-wide routing tuple and prove concurrent claims through separate runtime
instances. Backend type alone does not establish a shared authority.

Production startup **MUST** reject absent or in-memory storage and require
`REQUIRE_STATE_STORE=true` with a supported shared backend. SAG is pre-release:
apply this in one release without a warning-only migration stage. Test and
development retain an explicitly non-conformant evaluation mode. Startup can
validate local configuration and backend access; it cannot prove remote
instances use the same authority, so deployment verification is also required.

Provision the shared authority before upgrading the fleet. If replay state is
lost, restored from an older backup, or moved, do not resume claims against an
empty replacement while old codes or assertions can still pass validation.
Fence the old authority, stop issuance and exchanges, and wait out the maximum
remaining code and accepted assertion lifetimes plus skew before reopening.
An indeterminate failover must deny exchanges, not create a second writer.

Operational monitoring is private: record aggregate claim success, duplicate,
failure, and latency outcomes without codes, addresses, tokens, or client
secrets. Do not expose replay posture, backend details, or counters through a
public health endpoint.

### Decision boundaries

This RFC covers authorisation-code single use and private-key JWT assertion
replay only where the same qualifying store is used. RFC 6749 is normative for
authorisation codes. Assertion replay protection is a separate security-profile
control, not evidence that this RFC changes RFC 6749's scope.

This RFC does not add a database to the identity model, refresh tokens, token
revocation, global OTP limiting, or cross-region session revocation semantics.
It requires a small shared security-control authority, not persistence of
identity records.

## Cost

Estimate one to two weeks. The implementation is small to medium in scope,
with high security and interoperability risk.

Operators need a reachable shared atomic backend and tested failure policy. An
outage denies token exchanges, including a code claimed before a later failure.
This avoids silently issuing tokens after a replay control fails.

Multi-region deployments must choose one replay authority or prove equivalent
global atomicity. This can add latency and creates an operational dependency.
Migration may stop a previously working production deployment at startup. The
alternative is a known protocol violation in the replay path.

## Acceptance tests

1. Across every supported adapter, two concurrent valid redemptions of one
   code against the qualifying shared backend produce exactly one success and
   one `invalid_grant`.
2. A second sequential redemption returns `invalid_grant`; expired codes return
   `invalid_grant` without creating a reusable live claim.
3. Wrong client, redirect URI, or PKCE verifier does not consume a code; a
   subsequent valid redemption succeeds once.
4. A claim outage, timeout, full store, or indeterminate response denies the
   exchange and issues no token. A signing failure after a successful claim
   leaves a retry denied.
5. Production configuration rejects absent, non-qualifying, and in-memory
   state stores immediately. Development and test configuration
   retain the documented evaluation mode.
6. Separate runtime instances use the documented authority tuple. Failover,
   backup restoration, and lost state cannot reopen a live replay window;
   qualification and recovery procedures have integration-test evidence.
7. OTP send-limit failures retain their documented fail-open behaviour and are
   not reported as replay protection.
8. Concurrent private-key JWT assertions with the same namespaced `jti` produce
   one success and one replay refusal. Assertion-store outage and indeterminate
   claim results refuse authentication without accepting an assertion.

## Dated evidence

Evidence checked: 2026-09-08.

- [`src/oauth/code.js`](../../src/oauth/code.js) seals a random `jti` and only
  claims it when `replayStore` is present.
- [`test/flow.test.js`](../../test/flow.test.js) currently expects two successful
  redemptions with no replay store.
- [`src/store/index.js`](../../src/store/index.js) supplies `claim`, `has`, and
  `increment`; it documents one-process limits and fails claim errors closed.
- [`src/config.js`](../../src/config.js) already provides
  `REQUIRE_STATE_STORE` and warns about absent or in-memory state in
  non-development mode.
- [ADR 0001](../adr/0001-stateless-with-optional-state-store.md) and
  [ADR 0007](../adr/0007-require-prefix-for-fail-fast-flags.md) establish the
  optional-store and fail-fast naming decisions this RFC deliberately narrows.
- [RFC 6749 section 4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2)
  and [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) were checked on
  the research date.
