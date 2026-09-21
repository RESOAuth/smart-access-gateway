# 0020. Resource and scope contract for `/userinfo`

Status: Proposed

## Context

This proposal defines the identity-provider contract SAG already presents.
Broader API authorisation is outside its scope. Checked: 2026-09-08.

Current-code evidence is [`request.js`](../../src/oauth/request.js),
[`code.js`](../../src/oauth/code.js), [`tokens.js`](../../src/oauth/tokens.js),
[`userinfo.js`](../../src/endpoints/userinfo.js),
[`discovery.js`](../../src/endpoints/discovery.js), and
[`session.js`](../../src/session.js).

SAG implements one protected resource: `/userinfo`. Protected-resource metadata
at `/.well-known/oauth-protected-resource` names `issuer + /userinfo`; the
authorisation-server metadata names the same URI in `urn:sag:protected_resources`;
the UserInfo challenge links to that metadata. This existing URI is canonical.

The authorisation parser accepts every repeated `resource` with
`getAll('resource')`, and sealed authorisation codes retain those values. The
token endpoint neither reads `resource` nor constrains the result with it. The
opaque access-token payload records client, scope, subject, session, and expiry,
but no audience or resource. `/userinfo` opens it only when it unseals, including
the sealed value's expiry validation.

The implementation and
[ADR 0005](../adr/0005-no-refresh-tokens.md) say the bearer access token is
for `/userinfo` only. That intent is not a complete token contract: a sealed
payload has no audience check at its recipient, and accepted resource values do not establish
an audience. This is not evidence that an arbitrary external API accepts SAG
tokens, which current code neither implements nor claims.

Accepted scopes are `openid`, `email`, `profile`, and `offline_access`.
Discovery advertises only claim-producing scopes and omits `offline_access`, but
authorisation accepts and returns it. SAG issues no refresh token. OpenID Connect
can legitimately ignore `offline_access`, but returning it as granted is an
incoherent public contract. `profile` can be accepted when no profile claim is
currently reachable, but then produces no broad or implied claim set.

[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html), Resource Indicators
for OAuth 2.0, February 2020, defines `resource` as an absolute URI without a
fragment and defines `invalid_target` for an invalid, missing, unknown, or
malformed resource. It separates resource identity from scope and requires the
token response to report the effective scope when it differs from the request.
[RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)
supplies the corresponding token-response requirement.

[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html), Protected Resource
Metadata, April 2025, makes public metadata part of this contract. Its advertised
resource must match what SAG accepts; it does not create arbitrary API support.

[RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html), OAuth 2.0 for
Browser-Based Applications, BCP 212, August 2026, is relevant guidance. A
backend-for-frontend is a relying-party pattern, not a reason for SAG to become
an application reverse proxy or issue broad API tokens.

## Proposal

Define one canonical protected resource, exactly `issuer + /userinfo`. Derive it
in one shared contract helper used by protected-resource metadata,
authorisation-server metadata, UserInfo challenges, authorisation validation,
token issue, and UserInfo validation. Preserve the configured issuer path; do
not independently reconstruct it at call sites.

At `/authorize`, absent `resource` selects canonical `/userinfo`, retaining the
current successful flow. An explicit resource is accepted only when it is exactly
the canonical parsed URI, has no fragment, and has no normalisation that changes
identifier equality. Reject malformed or unsupported resources with
`invalid_target` only after client and redirect URI validation has made an error
redirect safe.

Reject malformed, empty, unknown, or non-canonical resources with
`invalid_target`, not `invalid_scope`. Reject multiple distinct resources with
`invalid_target`, as SAG issues a token for one recipient. Treat repeated,
identical values as one deterministic value, rather than expanding the audience.

The token endpoint accepts optional `resource` only for `authorization_code`.
Validate its URI shape and allow only canonical `/userinfo` sealed in the code's
authorised resource set. Reject a changed, additional, malformed, or unsupported
resource with `invalid_target`; a token request must never expand its code grant.
Authenticate the client and reject a wrong-client code before disclosing resource
validation details.

Codes issued before this change have no explicit resource contract. Reject
their schema at redemption and require a new authorisation. SAG is pre-release;
there is no need to reinterpret old codes or introduce a compatibility window.

Seal canonical resource audience and a purpose version into new access tokens,
alongside client id, effective scope, subject, session, and expiry. The existing
encryption purpose remains distinct from other sealed values; this documents a
token schema contract, not arbitrary API protection.

`/userinfo` validates purpose version, expiry, and exact audience before claims.
It accepts only canonical `/userinfo`. A missing, mismatched, or legacy audience
returns `invalid_token`, requiring the client to authorise again. Upgrade all
token and UserInfo readers in one coordinated rollout before relying on the
new audience check. A minutes-long pre-release rollout needs no legacy-token
acceptance mode. Existing deployment and secret isolation remains in force.

Effective scope is the authorised scope after client policy and resource
filtering. The token response reports exactly it, and ID Token and UserInfo
claims are filtered by it. `email` gates email claims, `profile` gates configured
profile claims, and `openid` does not imply API authority.

Remove `offline_access` from accepted authorisation scopes and reject it with
`invalid_scope`. This deliberate contract change
matches no refresh-token issuance, and prevents a response representing it as
granted. Discovery, client policy, consent text, and tests expose the same set.

Do not introduce refresh, implicit, password, client-credentials, token-exchange,
or machine grants. Keep the no-refresh-token decision in
[ADR 0005](../adr/0005-no-refresh-tokens.md). Machine grants require a distinct
principal and authorisation model; SAG must not invent a human email subject
for a workload.

Keep public metadata narrow: authorization code is the sole grant, `/userinfo`
is the sole protected resource, and scopes describe claims available there. Do
not advertise parseable but unenforced capabilities or ignore unsupported input.

A future sponsored API-authorisation RFC may define a resource allow-list,
resource-specific scopes, an access-token format such as
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html), October 2021,
introspection, resource authentication, revocation, and human-versus-workload
principals. It must not reuse an ID Token as an API credential. Those features
are outside this proposal.

## Cost

Estimate one week, including schema validation and client-facing error tests.

Clients currently sending arbitrary resources or `offline_access` receive
deterministic errors rather than tokens lacking their implied semantics. That is
a compatibility cost, but silent acceptance creates unsafe integration assumptions.

Sealed code and access-token schemas gain fields and versions. Old values are
rejected; clients may need to sign in again after deployment.
Secret rotation provides cryptographic read compatibility, not schema validation.

The shared helper makes the issuer path a public compatibility surface. Changing
that path changes the canonical resource URI and is a protected-resource migration
for clients and metadata consumers.

Audience validation at `/userinfo` creates recipient binding, not revocation. A
logout marker is not consulted there, so a valid opaque token remains usable to
its expiry. Immediate UserInfo invalidation would require a revocation lookup
on every request and a defined store-outage policy. That is outside this
proposal; [ADR 0012](../adr/0012-store-backed-session-revocation.md) governs
the existing browser-session revocation behaviour.

Broad API access remains unavailable. Operators needing resource permissions,
service identities, delegated workload access, or long-lived credentials must
sponsor the separate design, not rely on undocumented token behaviour.

## Acceptance evidence

- Tests cover absent, exact, repeated equal, multiple distinct, malformed,
  fragment-bearing, and unknown resources, with `invalid_target` where applicable.
- Tests prove a token request cannot expand or substitute a code's sealed grant.
- Tests verify resource audience and expiry at `/userinfo`, including mismatched
  audience, missing audience, unsupported schema, and legacy-token rejection.
- Tests prove ID Token and UserInfo scope filtering and accurate effective scope
  in token responses.
- Tests reject `offline_access` consistently at authorisation, client-policy,
  discovery, and consent boundaries, and prove no refresh token is emitted.
- Metadata tests prove protected-resource metadata, authorisation-server metadata,
  and the UserInfo challenge name the same canonical URI.
- Regression tests reject old code and access-token schemas and prove a fresh
  authorisation succeeds under the new contract, including an issuer path.
