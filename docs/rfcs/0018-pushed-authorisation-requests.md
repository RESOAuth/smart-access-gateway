# 0018. Pushed authorisation requests

Status: Proposed

## Context

Checked: 2026-09-08.
Primary sources: [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html),
[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html), and
[JWT client authentication updates -11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11).
RFC 9126 was published in September 2021. RFC 9101 was published in August
2021. The -11 update was in the RFC Editor queue on the checked date; this
proposal targets that draft revision.

SAG has no `/par` endpoint. Discovery declares request URIs unsupported and
pushed requests not required. It does not support JAR.

The authorisation parser resolves the client, exactly validates its redirect
URI, then validates the remaining request before browser effects. It requires
the authorisation-code flow and S256 PKCE by default.

The browser transaction is sealed and browser-carried. The optional store in
[ADR 0001](../adr/0001-stateless-with-optional-state-store.md) supplies atomic
`claim`, `has`, and `increment`, but no bounded payload lookup and consume.

RFC 9126 requires a client to use a request URI once. It says the server should
treat it as one-time, while permitting reload tolerance. SAG's selected profile
will require atomic one-use consumption and use a safe restart on reload.

RFC 9126 section 2 requires an implementation to accept issuer, token-endpoint,
or PAR-endpoint values as JWT client-assertion audiences. The later -11 draft
updates that rule to issuer-only. The intended new SAG PAR profile deliberately
uses issuer-only; it cannot claim unqualified RFC 9126 conformance for
`private_key_jwt` PAR until it adopts a published specification update. While
that update is unpublished, describe this as a draft-aligned local profile
with the divergence documented. Apply issuer-only validation from the first
pre-release implementation, without a transitional audience mode.
Public clients are identified by `client_id`; they are not authenticated.
PAR alone does not establish certification or support for a broader profile.

## Proposal

Add a form-encoded POST `/par` endpoint. It reuses client resolution, token
endpoint authentication methods, and their existing credential validation.
For confidential clients, authenticate before storing any request. For public
clients, resolve and identify the submitted `client_id`, without calling that
authentication.

For `private_key_jwt`, verify the signature against the client's registered
public keys, the allowed algorithm, issuer and subject equal to the client id,
expiry, `iat`, `jti`, and the existing maximum five-minute lifetime. After
signature validation, require `aud` to be exactly SAG's issuer string or a
single-value array containing it. Reject endpoint-only and mixed audiences;
do not change generic ID-token audience validation. Accept absent `typ` or
`client-authentication+jwt`, and reject another explicit type for this profile.

Before storing a pushed request, atomically claim the assertion's namespaced
client-id and `jti` hash until expiry plus clock skew. Use the same namespace
as token-endpoint client authentication, so a consumed assertion cannot be
reused there. Every accepting instance must use one shared claim authority;
asynchronous regional replication and process-local maps are insufficient.
Duplicate claims, errors, and indeterminate results refuse authentication.

Reject `request_uri` submitted to `/par`. Reject `request`, as JAR is not
implemented. Reject duplicates for `client_id`, `request_uri`, and every
single-valued parameter; reject malformed form data.

Remove authentication credentials before storage. Token-endpoint parameters not
used for authentication have no meaning at `/par` and are rejected.

Validate the complete submitted request, including exact registered redirect URI
and mandatory S256 PKCE for every client, before record creation or browser,
consent, session, email, or upstream effects. PAR does not relax redirects.

Store the complete normalised parser result and an immutable effective
client-policy snapshot. Preserve client ID, redirect URI, `state`, nonce,
scope, response type and mode, PKCE challenge and method, `prompt`, `max_age`,
requested ACR preferences and mandatory client floor, `login_hint`, resource,
requested signing algorithm, `ui_locales`, and every supported extension.
Keep requested preferences distinct from the mandatory floor; an optional
weaker preference must not bypass it. Do not reconstruct a hand-picked subset
that drops a supported parameter. Reject unsupported security parameters.
Never store authentication credentials or tokens. A login hint can contain an
address: protect the stored request, restrict access, and delete it at expiry.

Return HTTP 201, JSON, and `Cache-Control: no-store` with an opaque,
cryptographically random `request_uri` beginning
`urn:ietf:params:oauth:request_uri:` and positive `expires_in`.
Initial lifetime is at most 60 seconds and no longer than code lifetime. Do not
add a lifetime setting in this phase.

The handle uses a new bounded state payload operation with atomic read-and-
consume. Do not encode it into a browser-carried sealed value or repurpose
`claim`, `has`, or `increment`. Selected PAR deployments require an available
atomic production store.

Its read-and-consume operation must have one shared authority across all
instances that can accept the handle. Expiry and capacity bounds apply at that
authority; regional replicas must not consume the same handle independently.

At `/authorize`, require exactly one `client_id` and `request_uri`, then confirm
they match the stored client before consuming the handle.

After that check, consume once, load the stored normalised request, and ignore
all outer OAuth authorisation parameters for processing. This is the concrete
assembly rule from RFC 9101 section 6.3: only trusted stored parameters apply.
There is no outer `response_type` comparison because it is ignored, not required.
Reject duplicate or malformed outer `client_id` and `request_uri`. Never fetch a
request URI remotely and never permit override, injection, or parameter merging.

Before using the snapshot, resolve current client policy again. Compare a hash
of canonical normalised security fields, including keys and operator trust
restrictions; removal or a material change requires a new pushed request.
Apply the same check at code redemption. Positive metadata and key caches must
honour HTTP freshness and SAG's maximum age, with no stale acceptance after a
failed refresh. Document that bound on policy-change detection.

An outage, capacity failure, unknown or expired handle, or failed atomic consume
fails closed with no redirect. A browser reload after consumption gets the safe
restart outcome and needs a new pushed request.

Return JSON errors with `Cache-Control: no-store`. Use 400 for invalid requests,
405 for a non-POST method, 413 for an oversized body, and 429 for per-client
rate-limit refusal. Apply deployment and network admission limits before client
resolution, plus per-client quotas after resolution, so rotating public client
ids cannot evade payload, lookup, or global store-capacity bounds. Do not
redirect PAR errors.

Advertise `pushed_authorization_request_endpoint` when enabled. Its availability
is independent of OIDC `request_uri_parameter_supported`, which remains false
because SAG does not accept client-hosted request URIs.

Advertise `require_pushed_authorization_requests: true` only when all applicable
clients must use PAR. Represent client-specific requirements in registration,
not a standalone global strictness flag. Enforce that requirement at every
`/authorize` entry path before session reuse, interaction, or upstream effects;
a direct request returns `invalid_request` through a validated redirect only.
A future fail-fast store flag uses `REQUIRE_*`.

JAR is outside this proposal and must not be advertised. Supporting it would
require decisions on signature algorithms, issuer, audience, expiry, `jti`,
cross-JWT confusion, client binding, and remote-object policy.

## Cost

Estimate two to three weeks. The endpoint is small; a bounded, expiring,
atomic payload store across supported adapters is not.
The user-experience cost is reload requiring a new request. The operational cost
is making state storage mandatory only for deployments selecting PAR.

## Tests and evidence

Repository evidence: [`src/router.js`](../../src/router.js#L37-L66)
contains no `/par` route.

Repository evidence: [`src/endpoints/discovery.js`](../../src/endpoints/discovery.js#L149-L170)
disables request URI and PAR metadata.

Repository evidence: [`src/oauth/request.js`](../../src/oauth/request.js#L35-L173)
implements trust-order request validation and S256 PKCE.

Repository evidence: [`src/store/index.js`](../../src/store/index.js#L15-L17)
defines only claim, has, and increment operations.

Test authenticated and public-client requests, mandatory S256 PKCE, unknown
clients, invalid authentication, and issuer-only assertion audiences.
Test that published RFC 9126 alternative audiences are rejected under the
documented issuer-only local profile.
Test assertion signature, issuer, subject, lifetime, type, and replay checks,
including concurrent reuse across PAR and token endpoints, shared-authority
qualification, and store errors or indeterminate results.

Test submitted `request_uri` and `request` rejection, duplicates, malformed
forms, exact redirects, credential stripping, no record on invalid input, and
no browser or upstream effect.

Test 201 and no-store responses, 400, 405, 413, and 429 errors, opaque URN
entropy shape, expiry, bounded capacity, store outage, and no secret output.

Test concurrency, one-use consumption, reload restart, mismatched client, outer
parameter ignoring, remote URI refusal, snapshot immutability, and policy
tightening or revocation before use.
Round-trip every supported request field, including `state`, prompt, freshness,
assurance, login hint, resource, and signing choice, without an outer override.
Test direct-request refusal for PAR-required clients across all browser paths,
and admission limits before client lookup as well as per-client quotas.

Test disabled, optional, universal, and client-specific discovery policies,
including OIDC request URI support remaining false and JAR unadvertised.
