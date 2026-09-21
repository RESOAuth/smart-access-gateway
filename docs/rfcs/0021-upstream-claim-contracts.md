# 0021. Upstream claim contracts

Status: Proposed

## Context

SAG currently establishes identity from a verified email address. [ADR
0011](../adr/0011-subject-derived-from-the-verified-address.md) derives either a public or pairwise `sub` from that address, rather than from
an upstream subject. This remains the identity contract for every upstream and
the email-code path.

The current profile path relays a sanitised, bounded allow-list of presentation
claims. Upstream verification also checks the configured issuer, the address,
and the deployment's upstream trust boundary. These controls are sufficient
for a display profile, but not for a relying party that needs an authorisation
attribute such as an entitlement, department, role, or group.

Current-code evidence, accessed 2026-09-08:
[`relayedClaims`](../../src/profile.js#L56-L90) admits only configured profile
values and bounds them; [`completeUpstream`](../../src/upstream/index.js#L246-L281)
validates an upstream token and address before returning identity evidence; and
[`newSession`](../../src/session.js#L53-L68) carries the resulting claims in the
sealed session.

There is no general contract for such attributes today. In particular, SAG has
no typed mapping policy, no per-relying-party release policy, and no rule for
distinguishing a missing required attribute from a harmless absent profile
field. Passing arbitrary upstream claims through would turn an upstream's
private schema into SAG's public API, and could grant privileges unexpectedly.

The proposal should be considered only for a
confirmed deployment that cannot meet its use case with the existing identity,
email, profile, and assurance claims.

Published [OpenID Connect Core 1.0, incorporating errata set 2, December 2023](https://openid.net/specs/openid-connect-core-1_0.html), accessed 2026-09-08, defines standard claims, but no universally interoperable `groups` claim.
Published [SCIM RFC 7643, September 2015](https://www.rfc-editor.org/rfc/rfc7643.html) and [SCIM RFC 7644, September 2015](https://www.rfc-editor.org/rfc/rfc7644.html), accessed 2026-09-08, concern provisioning. They
do not make a directory's group membership a fresh run-time authorisation
answer, and do not require SAG to become a directory or provisioning service.

## Proposal

Enable this feature only when a deployment declares a small, static contract
for a particular upstream issuer. The configuration must name the exact issuer
already trusted for that upstream and the verified claims that may be read.

Each mapping must declare all of the following:

- an input claim name and expected JSON type;
- a bounded output claim name in a SAG-owned namespace;
- whether the input is required for that contract;
- an optional explicit input-value-to-output-value table; and
- the relying parties and scopes permitted to receive the output claim.

`maxAttributeAge` is optional per contract. When configured, it bounds the age
of SAG's observation of each released mapped attribute. Once required evidence
is stale, start a new upstream authorisation to obtain an ID token and, if
configured, callback-time UserInfo. If freshness cannot be obtained, deny the
affected contract. `observed_at` is when SAG observed the assertion, not when
the directory last changed it, which SAG cannot know. Without a configured
bound, evidence can be reused for the normal session and token lifetimes; no
current-entitlement guarantee is implied.

Mappings are declarative only. Do not add executable hooks, expressions,
templates, plugins, network lookups, or another policy language. A mapping
must be reviewable from configuration and must have a fixed worst-case cost.

Treat three classes of value separately:

- The identity key is the verified address used by [ADR
  0011](../adr/0011-subject-derived-from-the-verified-address.md). No mapped group,
  role, tenant, upstream subject, or other authorisation attribute can change
  it or contribute to `sub`.
- Address-verification evidence proves the boundary at which SAG may use an
  address. It remains governed by upstream issuer, address, and verification
  checks, rather than by a mapping.
- Mutable authorisation attributes are statements for a particular issuer and
  time. They may be released only under this feature's explicit contract.

Never infer a cross-issuer link solely because two upstreams report the same
role or group. The existing verified-address identity rule is unchanged; an
attribute is not identity evidence.

Namespace every mapped attribute by the configured issuer contract. Where a
deployment needs a stable external vocabulary, require an explicit value table
rather than forwarding raw tenant-specific values. This prevents two tenants
whose `admin` or `staff` values mean different things from colliding.

Reserved protocol and identity fields must never be mapping targets. At a
minimum, reject `iss`, `sub`, `aud`, `exp`, `email_verified`, `acr`, and `amr`,
along with any SAG-managed identity or protocol claim. A mapper must not
overwrite a value SAG derived or signed itself.

Required input claims that are absent, malformed, over-size, over-count, or
not matched by a required value table must deny the request under the affected
client policy. They must not silently omit the claim, fall back to another
issuer, or turn a required authorisation condition into a presentation-only
field. A claim required by one contract must not become required for an
unrelated relying party or scope that has not enabled that contract.

Optional presentation claims retain their present bounded truncation behaviour
where it is safe to show less information. Authorisation claims are different:
groups and other collection values must have strict per-value, count, and
total-byte limits, and an excessive value must fail closed rather than be
silently truncated into a partial privilege decision.

Source claims come from an upstream ID token by default. An upstream UserInfo
request is permitted only during a fresh upstream code exchange, using the
access token held in memory by that callback. This requires changing
`completeUpstream`, which currently discards that credential before returning.
Do not retain an upstream token in a session, cookie, code, or new credential
store. A later stale session starts upstream authorisation again; it cannot
fetch UserInfo using a credential SAG no longer holds.

UserInfo is an explicit opt-in to the configured issuer's trusted endpoint,
using secure transport and response-size limits. Require returned `sub` to
equal the validated ID-token `sub`. Timeout, transport failure, malformed
response, and subject mismatch refuse any contract requiring that source.

Record an `observed_at` time when SAG accepted the upstream response. Preserve
an upstream `auth_time` only as upstream evidence. Neither a shared session,
nor a reused cookie, may manufacture a fresher authentication or attribute
observation time. SAG has no upstream refresh-token flow under
[ADR 0005](../adr/0005-no-refresh-tokens.md); this proposal obtains fresh
evidence only through a new upstream authorisation and its optional callback
UserInfo request. A silent upstream flow can refresh an attribute observation
without proving a new authentication event.

Release must be a second, independent policy step. A mapped claim is issued
only when its configured relying party permits it and the request has an
explicit configured scope for that claim. Being available to one relying party
or scope must not make it available to another. Discovery must advertise only
the scopes that an enabled deployment can honour. Claims are not output until
these scope and relying-party gates have passed.

The approval and release policy must document the data minimisation purpose,
claim audience, retention of any stored audit data, and removal path. These
are deployment conditions, not a blanket legal compliance claim for every SAG
deployment.

Do not advertise or implement OIDC distributed claims for this feature. SAG
does not use them, and an issuer-bound declarative contract does not need a
second claims endpoint.

Authentication assurance remains independent of mapped attributes. A group or
role must never imply MFA, alter `acr`, or add `amr`. This mapper does not
interpret upstream authentication-method evidence or change SAG's assurance
policy. Its input and output remain separate from authentication-context
processing.

Sealed sessions, browser cookies, and authorisation codes have finite byte
budgets. Enabling a contract whose required claims cannot fit must fail closed.
The implementation may not place giant group lists in browser-carried values.
A separately designed future store may be considered for such data, but it is
not part of this proposal.

Sessions carrying mapped evidence must persist the exact upstream issuer and
mapping version that produced it. Release remains evaluated per current relying
party and scope, so a shared session cannot leak an extra claim released to an
earlier relying party. A changed or removed mapping version must not be treated
as current evidence without a new upstream authorisation and, where configured,
its callback-time UserInfo request.

### Enforcement at issuance and use

Carry issuer, mapping version, and `observed_at` per contract through sessions,
codes, and access tokens. For a contract with `maxAttributeAge`, derive
`evidenceExpiresAt = observed_at + maxAttributeAge`. Check current mapping and
release policy at code redemption, token issuance, and `/userinfo`. Missing or
stale required evidence cannot be rescued by resetting its observation time.

Cap the `exp` of an ID Token or access token by the earliest evidence deadline
of the mapped claims it releases or authorises UserInfo to release. Report the
shortened access-token lifetime. An optional stale claim may be omitted under
its contract; a required one denies issuance. Never issue an already expired
token, even if the code was valid when created.

`/userinfo` cannot interactively refresh evidence. Expired required evidence,
or a removed or incompatible mapping, returns `invalid_token` and requires
new authorisation. Recheck per-client and per-scope release gates there. Offline
ID Token consumers must honour `exp`; SAG cannot retract a signed assertion
or terminate an RP's independently established session. Document those limits
so `maxAttributeAge` is not presented as universal entitlement revocation.

## Cost

Estimate two to three weeks for implementation, tests, and review.

This requires configuration parsing and validation, a typed mapper, explicit
claim namespaces, release checks in token and UserInfo output, documentation,
and operator-visible configuration errors. Every mapped issuer becomes a
security-sensitive contract that must be reviewed when its upstream schema or
tenant model changes.

The implementation must preserve the current default: deployments with no
claim contract retain only the existing identity and profile behaviour. A
deployment enabling a contract accepts a new upstream availability dependency
when it opts into UserInfo, and must choose its failure and freshness policy.

Tests must cover upstream spoofing and issuer-bound mapping, namespace
collisions, attempted writes to privilege and protected fields, mapping type
errors, unknown and missing claims, required-table mismatches, and oversize
collection values. They must also cover scope and relying-party isolation,
stale attributes in a shared session, pairwise subjects, and an upstream
UserInfo subject mismatch.

Tests should drive `handleRequest` across the existing adapters. They must
demonstrate that malformed or unavailable required evidence denies issuance,
that optional display claims remain safely bounded, and that no group mapping
changes `sub`, `acr`, `amr`, or an address-verification decision.

Acceptance requires an implementation and test evidence for typed parsing,
issuer and mapping-version persistence, `maxAttributeAge`, new upstream
authorisation with callback-only UserInfo, failure when freshness cannot be
obtained, and per-scope,
per-relying-party release. It also requires documented byte limits and proof
that a claim required by one enabled contract cannot affect another client.
Test a claim becoming stale between authorisation and redemption, token expiry
capped by evidence age, stale UserInfo access, changed mapping versions, and
optional-claim omission. Verify upstream access tokens never persist beyond
the callback and silent upstream authorisation does not advance `auth_time`.
