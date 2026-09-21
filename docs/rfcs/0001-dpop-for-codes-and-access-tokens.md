# 0001. DPoP for authorisation codes and access tokens

Status: Proposed

Checked: 2026-09-08

## Context

SAG currently issues bearer access tokens. They are opaque, sealed values, and
`/userinfo` accepts them without a proof of possession. They carry no resource
audience, but a disclosed token can be replayed at its intended `/userinfo`
resource until it expires, even when it is audience-bound.

PKCE and the optional shared store reduce authorisation-code theft: a thief
needs the verifier, and an atomic spend marker prevents a second code
redemption when the shared store is configured. They do not bind a code or
access token to a key.

[RFC 9449, September 2023](https://www.rfc-editor.org/rfc/rfc9449.html)
specifies DPoP as an application-level sender constraint. Its optional
`dpop_jkt` authorisation parameter is a JWK SHA-256 thumbprint, defined by
[RFC 7638, September 2015](https://www.rfc-editor.org/rfc/rfc7638.html), not a
signed proof. The client proves its key at the token endpoint and when using a
bound access token.

DPoP is defence in depth against token disclosure without the private key. It
does not defeat an attacker holding both key and token, an attacker able to
make requests from the client's origin, or XSS that can use the key. PKCE stays
required. DPoP is neither a replacement for secure transport nor itself full
FAPI or certification.

The optional store in [ADR
0001](../adr/0001-stateless-with-optional-state-store.md) supplies expiring
claims. This proposal requires a shared, globally atomic claim authority for
DPoP proofs and defines that requirement below. It leaves the store optional
for deployments that do not enable DPoP.

[ADR 0005](../adr/0005-no-refresh-tokens.md) limits access tokens to
`/userinfo`. This proposal binds DPoP tokens to that resource explicitly;
DPoP alone does not supply a resource audience. [RFC 10017, August
2026](https://www.rfc-editor.org/rfc/rfc10017.html) remains relevant to browser
client handling.

## Proposal

### Availability and policy

Implement DPoP as a per-client opt-in policy. A client with
`dpop_bound_access_tokens` required must send a valid DPoP proof to `/token`;
a request without one is rejected. A client without that policy remains on the
current bearer behaviour unless it elects to send a DPoP proof.

When DPoP is enabled, discovery publishes
`dpop_signing_alg_values_supported`, containing only proof algorithms enabled
by SAG. No new environment variable is needed: client metadata is the policy
surface.

Enable DPoP only with a qualifying shared replay store. Refuse DPoP requests
when that capability is absent, and reject client policy requiring DPoP when
the deployment cannot provide it.

### Authorisation-code binding

A client that wants to bind an authorisation code sends `dpop_jkt` on its
authorisation request. SAG validates it as an RFC 7638 SHA-256 thumbprint and
seals it into the transaction and authorisation-code payload.

The authorisation request does not carry, accept, or validate a DPoP proof, and
never receives a private key. If the code contains a `dpop_jkt`, `/token`
requires a valid proof whose public JWK has exactly that thumbprint.

Existing client, redirect URI, expiry, PKCE verifier, and single-use checks
remain in force. A proof never redeems a code alone. A client may request a
DPoP-bound access token without `dpop_jkt`; that token binds to the valid
`/token` proof key only.

### DPoP proof validation

For every DPoP-protected request, accept at most one `DPoP` header. Its value
must be one well-formed signed JWT with `typ` exactly `dpop+jwt`, an allowlisted
registered asymmetric `alg`, and a public `jwk` header parameter. Reject
`none`, symmetric algorithms, private JWK members, remote key references such
as `jku`, unsupported key types, and keys incompatible with the algorithm.

Verify the signature using only that embedded public JWK. Require a unique
`jti`, `htm` equal to the actual HTTP method, and a numeric `iat` within the
bounded local clock-skew and proof-age window. Clients should generate `jti`
values with at least 96 bits of unpredictability.

Compare `htu` with SAG's canonical external request URL: normalise scheme,
host, port, and path under syntax and scheme normalisation, excluding query and
fragment. Derive the external issuer/base URL from explicit SAG configuration,
not an untrusted forwarded-host header.

Atomically record each accepted proof before the protected operation. The
replay key is namespaced by proof-key thumbprint, endpoint, and proof
identifier, and expires after the proof acceptance window. The store operation
must be atomic across every instance that can accept the proof and have a TTL.
Route each replay key to one shared authority; asynchronously replicated
regional claims and local process caches cannot provide this guarantee.

This is a SAG profile requirement, not a claim that `jti` makes replay
prevention stateless or foolproof. If a DPoP client needs the replay store and
it is unavailable, fail the protected operation rather than accept replay risk.

### Token endpoint and response

`/token` validates its proof against `POST` and the canonical token URL. A
valid proof binds the issued opaque access-token payload to `cnf.jkt`, the proof
JWK thumbprint. This is sealed payload data, not a requirement to make the
access token a JWT. Also seal its audience as exactly the configured issuer's
canonical `/userinfo` URL, preserving any issuer path. This proposal issues no
DPoP token for another resource and grants no additional scope. The successful
response sets `token_type` to `DPoP`, never `Bearer`; for a code-bound request,
the proof key also matches `dpop_jkt`.

An invalid token-endpoint proof returns OAuth `invalid_dpop_proof`. If SAG has
chosen to require a nonce, it returns `use_dpop_nonce` and a fresh
`DPoP-Nonce` header; the next proof must include that nonce claim. Nonces are
optional extra freshness protection, not a substitute for `jti` replay storage,
and SAG must not silently downgrade a nonce requirement.

Complete proof validation, nonce checking, and proof replay claiming before
consuming the authorisation code. A nonce challenge or invalid proof must leave
the code usable with a fresh valid proof. Once the code is consumed, a signing
or response failure does not release it. A corrected proof uses a new `jti`;
JWT-authenticated clients also send a fresh client assertion if the earlier
assertion was consumed while authenticating the challenged request.

Browser clients need `DPoP` in the allowed CORS request headers and
`DPoP-Nonce` in exposed response headers, including error responses. Retain
the existing origin policy and `WWW-Authenticate` exposure.

SAG issues no refresh tokens, so this RFC adds no refresh-token binding flow.
It does not claim device protection or add unrelated API protection work.

### Userinfo resource access

For an access token carrying `cnf.jkt`, `/userinfo` requires both
`Authorization: DPoP <access-token>` and a `DPoP` proof. It validates the proof
for the actual `/userinfo` method and canonical URL, requires `ath` to equal
base64url(SHA-256(ASCII(access-token))), and requires the proof-key thumbprint
to equal sealed `cnf.jkt`.

Check token expiry and require the sealed audience to equal the canonical
`/userinfo` URL. Return claims only under the token's granted scopes and
existing claim-release policy.

A bound token presented as `Bearer`, in a request body, without the proof, with
a mismatched key, or at an inappropriate resource is rejected. There is no
bearer fallback or body-parameter bypass.

An unbound token retains bearer behaviour for clients not opted in. At a
protected resource, invalid token authentication or proof uses the DPoP scheme
and the appropriate `invalid_token` or `invalid_dpop_proof` error. A nonce
challenge uses `use_dpop_nonce` with `DPoP-Nonce`, as specified by RFC 9449.

### Deployment

Deploy proof enforcement to every token and UserInfo reader before clients
enable DPoP. SAG is pre-release: a coordinated rollout taking minutes is
sufficient; no separate envelope or extended compatibility period is required.
During that brief rollout, an old reader can still treat a bound token as a
bearer token, so the sender constraint is effective once the fleet is updated.

## Cost

Estimate one to two weeks, including shared replay-store qualification,
audience binding for DPoP tokens, all supported runtime adapters, documentation,
interoperability checks, and failure-path testing. Correctness depends on URL
handling, atomic replay storage, browser interoperability, and downgrade
prevention.

## Tests and evidence

Current-code evidence: [`tokens.js`](../../src/oauth/tokens.js),
[`userinfo.js`](../../src/endpoints/userinfo.js), and
[`code.js`](../../src/oauth/code.js).

Test the shared core through every supported runtime. Use ES256 positive proof
fixtures with public JWKs and explicit asymmetric public-key compatibility
checks. Use negative fixtures containing private JWK members and reject them.

Cover valid unbound and code-bound issuance, matching and mismatching
`dpop_jkt`, intact PKCE enforcement, and issuance of a DPoP access token from
a valid `/token` proof when `dpop_jkt` was omitted.

Cover duplicate headers, malformed JWTs, disallowed algorithms, remote keys,
private JWK members, signature failure, `typ`, `htm`, `htu`, `iat`, `jti`, and
nonce errors. Verify forwarded-host headers cannot influence the issuer URL.
Test that a nonce challenge and an invalid proof do not consume the code, and
that the corrected request succeeds once. Exercise browser preflight and nonce
header visibility on both successful and error responses.

Prove atomic rejection of concurrent proof replays, replay-key partitioning,
expiry, clock boundaries, store outage behaviour, and access-token lifetimes.
Reject DPoP requests and required-client policy when no qualifying store is
available.

Test `/userinfo` `ath`, key matching, scope and resource checks, bearer
downgrade and body-token rejection, and backwards-compatible bearer access for
a client that did not opt in.
