# 0019. Conditional back-channel logout

Status: Proposed

## Context

Back-channel logout is an optional OpenID Connect extension, not a correction to
SAG's RP-initiated `/logout`. The primary specification is [OpenID Connect
Back-Channel Logout 1.0, errata set 1](https://openid.net/specs/openid-connect-backchannel-1_0.html),
final, 15 December 2023. Checked: 2026-09-08.

Current-code evidence is [`session.js`](../../src/session.js),
[`tokens.js`](../../src/oauth/tokens.js),
[`userinfo.js`](../../src/endpoints/userinfo.js),
[`discovery.js`](../../src/endpoints/discovery.js),
[`request.js`](../../src/oauth/request.js), and
[`code.js`](../../src/oauth/code.js).

Today, `/logout` clears relevant browser cookies and, with a state store, claims
a `session-revoked:<sid>` marker through the absolute session lifetime. It
confirms a shared-session logout where appropriate, while a per-RP session can
end without affecting another relying party. This is local RP-initiated logout,
not upstream, front-channel, or back-channel logout. Discovery advertises both
front-channel and back-channel logout as unsupported.

SAG is an upstream relying party and a downstream OpenID Provider. A logout
notification can arrive from an upstream and, independently, need delivery
downstream. These roles have different registrations, trust roots, failure
handling, and advertisements. Implementing either must not imply the other.

The current session holds a local random `sid`, verified email address, configured
upstream id, and upstream display label. It does not retain the upstream issuer,
upstream subject, or upstream session identifier required for safe Logout Token
correlation. SAG's downstream `sub` is derived from verified email and can be
pairwise per relying party; it is not the upstream `sub`.

The optional state store supplies atomic, expiring `claim`, `has`, and
`increment` operations. It supports per-session revocation and one-time claims,
but it is not a reverse index, participant registry, durable queue, or delivery
log. A back-channel implementation needs bounded durable state beyond it.

Access tokens are opaque, sealed bearer tokens accepted only at `/userinfo`.
That endpoint does not consult session revocation. Back-channel logout therefore
cannot promise invalidation before expiry, nor invalidate offline ID Tokens held
by relying parties. [ADR 0012](../adr/0012-store-backed-session-revocation.md)
only defines local per-`sid` revocation.

## Proposal

Make this an optional standards extension.
Enable it only where durable facilities and explicit operator policy exist.

Implement two separately switchable phases.

Phase one makes SAG an upstream relying-party receiver. Each opt-in upstream
registers SAG's fixed receiver URI. This registration is upstream-specific and
never makes SAG advertise `backchannel_logout_supported`: that OpenID Provider
metadata describes the separate downstream-sender role. Receiver-only deployment
has no corresponding SAG OpenID Provider advertisement.

The receiver accepts only form-encoded POST requests with exactly one
`logout_token`. Reject duplicate `logout_token` values and ignore other
unrecognised form parameters. It returns `Cache-Control: no-store`, and returns
HTTP 200 only after local revocation and required event enqueue are durable.
Invalid input returns HTTP 400 without exposing correlation state.

Validate each Logout Token against the selected configured upstream registration:
signature against discovered keys, expected issuer, client audience, allowed
algorithm, and key-rotation grace. Reject unsecured tokens, unexpected `typ`,
and tokens whose purpose can be confused with an ID Token or another JWT.

For a new SAG profile, issued tokens use `typ: logout+jwt`; accepting an untyped
token is a deliberate compatibility policy, never a parser default. Validate
`iss`, `aud`, `iat`, `exp`, `jti`, bounded freshness, and the required logout-event
member as an object, normally `{}`. Reject `nonce`, require at least one of `sid`
or `sub`, and reject an unsupported token class. Other event members and unknown
claims remain acceptable as the specification permits. An explicitly configured
strict SAG profile may require the expected type and exact event object.

Both `iat` and `exp` are required finite NumericDate values. Check expiry,
future issuance, and the maximum accepted token age with explicit clock skew;
require `exp` after `iat`. A recent `iat` does not rescue an expired or missing
`exp`. These expiry checks are part of the receiver contract, not only rules
for tokens SAG sends.

Although replay checking is optional in the base specification, SAG requires a
strict shared authority. Add a durable event-transaction primitive keyed by the
trusted upstream registration, issuer, and `jti`, with `processing` and
`completed` states plus a stable delivery-operation id. It atomically creates or
resumes processing, records each local revocation and enqueue idempotently, then
marks completion. A completed duplicate returns success without repeating effects;
a partial durable attempt resumes instead of being stranded behind a bare `jti`
claim. A missing, unavailable, or merely local authority prevents enabling the
receiver and fails closed.

Use a durable worker to resume abandoned `processing` records with bounded
leases and retry scheduling. Recovery must not depend on the upstream sending
the same token again. Resume only work already admitted by full token
validation; an expired duplicate cannot create a new event transaction.

Create trusted upstream correlation at successful upstream authentication. Map
`(issuer, upstream registration client_id, token audience, upstream sub, upstream sid)`
to local `sid` values and downstream participation identifiers. The registration
dimension is required because an issuer can provide pairwise subjects per client.
Do not key it by email, SAG subject, or display claim.

An upstream `sid`-only token matches trusted issuer, audience registration, and
upstream `sid`. When both `sid` and `sub` occur, both must match. A `sub`-only
token targets all matching local sessions, including per-RP sessions, for that
upstream registration; it is not wrongly narrowed to one local RP session and
never becomes an email-wide logout.

Serialise session registration, issuance participation, and logout at the same
correlation authority. Keep a tombstone for a revoked upstream `sid` even when
there is no matching local session yet. A callback that finishes after logout
must not create a fresh local session for that revoked upstream session.

For `sub`-only events, keep the highest validated logout `iat` as a cutoff for
the issuer and upstream registration's subject. Revoke matching sessions with
authentication at or before that cutoff, and reject late registration of that
evidence. A new sign-in must prove an upstream authentication time after the
cutoff, allowing for the configured clock uncertainty; missing or ambiguous
time requires a fresh authentication with usable evidence. This preserves a
provably newer sign-in when an older logout arrives late. An upstream without
the evidence needed for this rule cannot enable subject-only correlation.

On upstream reauthentication, create a new local `sid` and supersede the old
correlation for further issuance; never carry the old local `sid` into a new
upstream session. Retain old participants long enough to finish their logout.
Delayed events must not revoke a new local session through a reused identifier.

Add a bounded reverse-index interface with expiry, trusted-tuple lookup,
idempotent removal, and a participant registry per local session. Retain opaque
identifiers where possible, no email or profile claims, and remove session
records at absolute expiry. Bound tombstone retention by the maximum lifetime
of sessions and in-flight authentication that can still reference them, plus
clock skew; an individual session's deletion must not remove that protection.

Record each downstream participant atomically before code or token issuance,
including a new relying party reached through shared-session reuse. Check
revocation again at code redemption. If logout wins that transition, deny
issuance; if issuance wins, its participant is included in the durable logout
work. A valid browser cookie cannot recreate a revoked participant. Delivery
can still race a relying party consuming a previously issued ID Token, so
this does not promise instant termination of every downstream session.

Revoke only matching local sessions. With `SESSION_SCOPE=rp`, a matching upstream
logout can affect every matching per-RP local session; with shared scope, it
affects that shared session and recorded participants. Do not revoke another
upstream, local `sid`, or person sharing an address. Local RP-initiated logout
keeps the selected local-`sid` scope from [ADR 0004](../adr/0004-session-scope-and-sign-out-confirmation.md)
and never calls upstream logout.

Phase two makes SAG a downstream OpenID Provider sender. A relying party opts
in through trusted registration metadata with an absolute, fragment-free
`backchannel_logout_uri` and, where needed, its session requirement. Static
configuration, a trusted client store, and validated client metadata may supply
it, but an authorisation request may not. Production requires HTTPS, explicit
client permission, and an operator allow-list for metadata-derived registrations;
metadata is not unlimited fan-out or an arbitrary notification trigger.

Apply an explicit delivery network policy: allowed schemes and ports, redirect
handling, DNS resolution, public-address checks, size and time limits, and egress
controls against private-network access. Follow the repository's public-address
approach at registration, but define delivery separately as an operator POST.

For every participant, sign a distinct Logout Token. Its `aud` is the client,
its `sub` is the public or pairwise value already issued to that client, and its
`sid` is the local value issued in that client's ID Tokens. Include the event,
`iat`, `jti`, short freshness, `exp`, and `typ: logout+jwt`. Configure the
maximum age and clock skew; do not assume historic deployments share one bound.

Retain verification keys through the Logout Token acceptance and delivery-retry
window. A queued record holds the recipient-specific token, stable delivery-
operation id, and signing-key grace, so rotation cannot change its audience or
strand it. Retry only until the signed token's freshness cutoff, dead-letter at
or before that cutoff, and never send an expired token. This proposal chooses no
token regeneration; a future alternative must retain the stable operation id.

Use a bounded, durable, idempotent queue with retry schedule, attempt cap,
metrics, and dead-letter outcome. It is not fire-and-forget. A short-lived
runtime acknowledges upstream only after revocation and enqueue are durable; it
cannot rely on background work surviving the response. A relying-party HTTP
acknowledgement confirms receipt, not global instant invalidation. Sender support
alone advertises `backchannel_logout_supported`, and advertises
`backchannel_logout_session_supported` only when it can issue the required `sid`.

Shared Signals Framework claims, SIEM delivery, and front-channel logout are
outside this proposal. `/userinfo` access tokens remain valid until expiry:
immediate invalidation would require a revocation lookup on each request,
a store-outage policy, and corresponding tests. Neither receiving nor sending
a Logout Token adds that guarantee.

## Cost

Estimate three to five weeks for the receiver and sender phases.

This adds durable correlation, participation, replay, and delivery state. The
existing state store is not a queue and cannot safely emulate one. New interfaces
need bounded capacity, expiry, encryption at rest where required, migration,
observability, and outage and dead-letter runbooks.

Cross-region deployments require one shared replay and correlation authority, or
a routing guarantee that makes it effectively singular. Separate regional stores
would accept the same `jti` or miss mappings elsewhere. This is independent of
peer JWKS federation.

Downstream delivery is eventual. A relying party can be unavailable, reject a
request, or process it after a new sign-in. Idempotency and session-specific
identifiers reduce the impact but cannot promise global instant invalidation.

The receiver and sender add denial-of-service, SSRF, key-rotation, replay, and
privacy exposure. Minimal retention, strict expiry, bounded queues, rate limits,
and fail-closed validation reduce risk at the cost of operational dependencies.
SAG issues no refresh tokens under
[ADR 0005](../adr/0005-no-refresh-tokens.md); this proposal adds none and
therefore has no refresh-token revocation flow.

## Acceptance evidence

- Tests reject invalid signatures, issuer, audience registration, algorithm,
  unsupported token class, malformed required event object, nonce, missing
  `sid` and `sub`, stale times, and malformed forms, while accepting permitted
  unrelated event members in the interoperable profile.
- Tests reject missing, malformed, non-finite, and expired `exp`, including
  tokens with a recent `iat`, and cover both time boundaries and clock skew.
- Tests accept unknown form parameters while ignoring them, and reject duplicate
  `logout_token` values.
- Tests prove issuer-qualified correlation, upstream-sub separation from SAG
  subjects, pairwise downstream subjects, and no email-derived global logout.
- Tests cover `sid`-only, `sub`-only, and both-claim correlation; shared and
  per-RP scope; completed duplicates without repeat effects; partial processing
  resumption; queue and receiver outages; expired records and tokens; registration
  SSRF; permission and allow-list checks; and key-rotation grace.
- Tests race logout with callback registration, shared-session participation,
  and code redemption. Cover tombstones without existing sessions, old
  subject-only events after a newer sign-in, missing authentication time,
  changed upstream sessions, and recovery without another upstream delivery.
- Integration tests prove upstream acknowledgement waits for durable local
  revocation and enqueue, and is never reported as universal token invalidation.
- Discovery tests advertise downstream sender support only when its registrations,
  durable dependencies, and policy are satisfied, and never advertise receiver-
  only support.
