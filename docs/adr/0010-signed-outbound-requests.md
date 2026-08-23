# 0010. Sign every outbound request SAG makes on its own behalf, via `Authentication-Info`

Date: 2026-08-23
Status: Accepted

## Context

SAG makes outbound requests to servers it does not control, on its own
behalf rather than a relying party's or a signed-in user's: fetching a
relying party's Client ID Metadata Document (`resolveCimd` in
`src/clients/index.js`), fetching an upstream identity provider's
discovery document and `jwks_uri` (`fetchJwks` in `src/crypto/jose.js`),
and, later, a domain or email allow-list check against a relying party's
own endpoint. None of these carry any signal of who is asking -
`resolveCimd` authenticates the *response* (HTTPS only, a size cap, the
document has to self-claim its own URL as `client_id`), not the request,
and a plain GET to an upstream's discovery document carries nothing at
all. Standard OAuth client authentication (`client_secret` or
`private_key_jwt`) already covers the upstream token endpoint, but not
these other calls.

That matters more once a relying party's own domain or email allow-list
endpoint exists: SAG would be asking a question with a potentially
sensitive answer ("is this domain accepted"), and the relying party will
reasonably want confidence the caller really is the authorisation server
handling its `client_id` before answering, or before applying a looser
rate limit than it gives an anonymous caller. The full design discussion,
including alternatives that were set aside, lives in
[signed-relying-party-requests.md](../signed-relying-party-requests.md);
this record is what was actually decided.

## Decision

Add a new auth-param, `signedrequest`, to the existing
`Authentication-Info` header (RFC 7615), carrying a compact JWS, on every
outbound request SAG makes on its own behalf - relying-party-controlled
endpoints (CIMD today, a domain/email check endpoint later) and upstream
identity providers alike. `Authentication-Info` is registered for the
response direction only; using it on a request SAG itself sends is new
territory, accepted deliberately rather than treated as a misuse of the
registration, and worth proposing as its own individual Internet-Draft
once it has run in the real world for a while, alongside this record.

The JWS takes a DPoP-like shape (RFC 9449) rather than a literal DPoP
proof: `alg` and `kid` in the JOSE header as usual, plus `jku` set to
SAG's own `jwks_uri` - never `jwk`, so no key material is embedded in
every request. Claims: `iss` (this instance's issuer, matching `id_token`
`iss`); `htm`/`htu` - DPoP's HTTP-method and HTTP-URI binding claims - in
place of a plain `aud`, pinning the assertion to the verb as well as the
exact URL; `iat`/`exp`, short-lived (60 seconds or less); `jti`, 16
random bytes from the existing `randomToken` helper (`src/util/bytes.js`),
base64url-encoded, purely for the recipient's own optional use - SAG
issues it and never checks it again, holding no state to check one
against by default; and optional `sub` of the client_id naming the
client being resolved, for an endpoint that might serve more than one.

Verification stays entirely the recipient's choice: one that ignores the
header gets exactly today's behaviour, and one that checks it resolves
the signing key exactly as it already does for `id_token` verification.

Configuration: `SIGN_OUTBOUND_REQUESTS` (bool) turns on sending the
header, and, per
[ADR 0007](0007-require-prefix-for-fail-fast-flags.md),
`REQUIRE_SIGNED_OUTBOUND_REQUESTS` is the fail-fast flag for a deployment
that wants a startup error rather than a silently unsigned request when
no signer key is configured. Both are standalone, not nested under
`CLIENTS_CIMD_*`, because the scope is every outbound request, not one
endpoint type.

## Consequences

This is not
[RFC 0001, "DPoP for authorisation codes and access tokens"](../rfcs/0001-dpop-for-codes-and-access-tokens.md):
that is a relying party proving possession of a key to SAG; this is SAG
proving its own identity to whatever it calls. The two share a claim
shape, not a direction.

This decision is not yet built - `SIGN_OUTBOUND_REQUESTS` does not exist
in `src/config.js` yet.

A real-world upstream such as Microsoft or Google will not recognise or
act on this header - the practical benefit is limited to relying parties,
SAG peers, and any future upstream that chooses to look, not a change in
how today's actual upstreams behave. `jku` is a convenience, not a new
trust root: a recipient that already has SAG's `jwks_uri` from its own
discovery-document fetch should confirm the in-band value matches what it
already expects rather than fetch whatever `jku` says, the same caution
any JOSE consumer of an untrusted `jku` needs. And reusing
`Authentication-Info` outside its registered direction remains a
deliberate, documented divergence rather than a solved problem - if this
becomes an Internet-Draft, that divergence is exactly what it has to
justify.
