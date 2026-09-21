# 0017. Client trust and assertion audiences

Status: Proposed

## Context

Checked: 2026-09-08.
Primary sources: [CIMD -02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)
and [JWT client authentication updates -11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11).
Both were drafts on the checked date. This proposal targets those revisions;
their requirements are not presented as published RFC obligations.

SAG accepts operator-configured clients, stored clients, and Client ID Metadata
Documents (CIMD). This RFC concerns CIMD and JWT client authentication only.

The current resolver permits HTTPS, subject to a broad development exception.
It rejects user information and fragments, applies a domain allow-list,
public-address checks, document bounds, bounded caching, redirect URI validation,
and same-origin `jwks_uri`.

Redirects are already refused by
[`fetchWithTimeout`](../../src/util/http.js#L201-L222),
which requests manual handling and rejects redirect responses. This is not a
missing control.

The resolver accepts any `res.ok` response, so it accepts 201 where CIMD
requires 200. It does not require document `client_id` equality.

It infers `private_key_jwt` from `jwks` or `jwks_uri`, instead of processing
`token_endpoint_auth_method`, and does not reject secret or private JWK data.

CIMD requires HTTPS, no user information or fragment, a path component, and
no single-dot or double-dot path components. A root path is valid, though not
recommended. URL equality is simple string comparison, not canonicalisation.
CIMD prohibits shared-secret methods, secret properties, and private key
material. An explicitly declared `private_key_jwt` requires corresponding usable
public keys. `token_endpoint_auth_method: none` identifies a public client; an
absent method has the draft-defined `none` default. An unknown or unsupported
explicit method must not fall back to public-client treatment.

The current development exception permits local metadata more broadly than the
draft's development-and-testing loopback exception. The draft permits loopback
only when the server is loopback-bound and the resolved address is that same
loopback interface. This is a known SAG boundary, not draft conformance.

JWT client authentication currently verifies algorithm, key, issuer, subject,
time, `iat`, `jti`, and lifetime. When configured, the optional state store
claims a namespaced hash of client id and `jti` through assertion expiry and
clock skew; duplicate claims and store failures refuse authentication. That
policy follows [ADR 0001](../adr/0001-stateless-with-optional-state-store.md).

Generic JWT validation accepts an audience array containing this issuer and
other values. That is appropriate for some token types, but not client
assertions.

The -11 draft requires the issuer as the sole assertion audience, as a string
or a single-value array. It recommends `typ: client-authentication+jwt` and
does not recommend rejection solely because `typ` is absent.

## Proposal

Apply the corrected metadata and assertion rules in one pre-release release.
Clients relying on inferred authentication methods or endpoint-only audiences
must update their registrations or assertions; no compatibility flag is needed.

For CIMD, require the raw client ID URL to be HTTPS, have no user information
or fragment, contain a path component, have no dot-path component, and exactly
equal the document `client_id` by simple string comparison.

Do not introduce a non-root-path requirement: root is a valid draft form. SAG
may later prohibit it as an explicitly labelled local policy if justified.

Fetch the raw URL, use existing redirect refusal, request JSON, and accept only
HTTP 200 with syntactically valid JSON.

Retain document byte bounds, bounded positive caching, and expiry sweeping.
Do not cache an error, malformed document, or rejected policy.

Reject shared-secret methods, `client_secret`, `client_secret_expires_at`, and
private or symmetric JWK material rather than silently discarding them.

Process `token_endpoint_auth_method` explicitly. Accept `none` as public and
`private_key_jwt` only with usable public keys. Treat an absent value as `none`.
Reject every other declared method, including unknown and unsupported values.
Do not infer a method from key presence.

Retain same-origin `jwks_uri` as a stricter SAG local policy, not a claimed
universal CIMD requirement. Revalidate it as a public target before each fetch.
This cannot DNS-pin validation to connection establishment. Egress controls and
resolver behaviour contain the remaining DNS time-of-check to time-of-use risk.

Snapshot the normalised effective client policy in each transaction and bind
its hash into the authorisation code. Include redirect URIs, authentication
method and usable public-key fingerprints, scopes, assurance floor, subject
policy, signing requirements, and operator trust restrictions. Hash canonical
JSON with sorted object keys and normalised sets, preserving semantically
ordered arrays. Exclude fetch timestamps and presentation-only metadata.

At code redemption, resolve policy again and require the same effective hash.
Removal or any material change requires a new authorisation; do not merge old
and new policy or retain old authentication keys under an implicit grace rule.
A current-policy check precedes code consumption. Pre-release clients can
restart when registration or key changes invalidate an in-flight request.

For CIMD and referenced keys, bound positive cache age by the lesser of the
HTTP freshness lifetime and SAG's configured maximum. Honour revalidation
directives and `no-store`; use SAG's maximum when no explicit freshness
lifetime is supplied. Do not serve stale data after failed refresh or reset age
because a browser transaction reused a cached entry. Policy changes are
enforced once observed, with that documented cache bound; this is not instant
revocation. Operator emergency removal must also invalidate local caches or
roll out the changed allow-list to all instances. A per-process cache purge
does not revoke a registration elsewhere.

When CIMD is enabled, discovery publishes the standard
`client_id_metadata_document_supported: true`. The current discovery exposes
only its legacy `cimd_supported` field, which is not the standard metadata
name. When CIMD is disabled, do not advertise the standard capability.

Add a dedicated client-assertion audience check after signature verification and
before replay claiming. Require exactly the issuer string or its single-value
array. Reject token-endpoint-only and mixed audiences.

Preserve existing assertion signature, issuer, subject, time, lifetime, and
replay checks. This proposal does not change which deployments require a
state store; audience validation must work with or without one.

Do not change generic ID token or upstream-token audience semantics.

Accept absent `typ`. When supplied, accept `client-authentication+jwt` and
reject conflicting values. This profile deliberately tightens type handling.

Do not add an absence warning by default: high-volume clients could turn it into
an audit-log flood. A deployment policy may add a bounded, redacted signal later.

Do not log assertions, key material, secrets, sensitive query values, or user
identifiers. No environment flag is proposed. Any future fail-fast flag follows
the `REQUIRE_*` convention.

## Cost

Estimate 1-2 weeks for implementation, test coverage, policy snapshots, and
review. The principal design cost is transaction snapshots across refresh, key
rotation, browser flow, and redemption. The operational cost is safe policy
change and revocation handling.

## Tests and evidence

Repository evidence: [`src/clients/index.js`](../../src/clients/index.js#L204-L275)
contains CIMD resolution and caching.

Repository evidence: [`src/oauth/clientauth.js`](../../src/oauth/clientauth.js#L125-L187)
verifies `private_key_jwt` assertions and claims `jti`.

Repository evidence: [`src/crypto/jose.js`](../../src/crypto/jose.js#L157-L176)
currently accepts a containing audience array.

Test exact `client_id` mismatch, path and dot-path rules, valid root path, user
information, fragments, 200-only handling, and existing redirect refusal.
Test absent and explicit `none`, `private_key_jwt` without usable public keys,
unknown methods, shared-secret fields, private JWKs, and no key-based inference.
Test the narrower draft loopback condition separately from SAG's current broad
development exception, and record the deliberate boundary.
Test malformed, failed, and rejected metadata never enters cache; test `jwks_uri`
SSRF checks, cached refresh, key rotation, and the documented DNS residual risk.
Test canonical snapshot hashes, policy changes and revocation at redemption,
current-key enforcement, cache expiry and revalidation, failed refresh without
stale acceptance, and restart after authentication-method or key changes.
Test issuer-only string and array audiences, mixed arrays, old token-endpoint
audiences, absent `typ`, recommended `typ`, and replay behaviour.
Test standard CIMD discovery metadata when enabled and its absence when disabled.
