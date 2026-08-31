# Security review, September 2026

A full-tree review of `src/` and `adapters/`, run against the OWASP Top Ten and
API Security Top Ten, the OWASP session management guidance, the MITRE ATT&CK
techniques an internet-facing identity provider is actually exposed to, and the
OpenSSF Best Practices passing criteria. Every finding below was reached by
reading the code and, where the note says so, reproduced against a running
deployment.

Evidence base: `npm test` (358 tests, all passing) and the full local stack -
Node in a container, workerd, and a Lambda on KMS, DynamoDB, and S3 - brought up
and driven end to end with `./test/local-stack/stack.sh verify`. All four
instances signed somebody in and refused a replayed code; the peer mesh check
failed, which is finding 1.

This is a point-in-time record, not a standing document. It is not an audit and
it is not a claim that nothing else is there.

## Findings

Ordered by what an operator should look at first, not by CVSS.

### 1. `/jwks.json` pays the full peer timeout on every request while a peer is down

`src/keys/peers.js`, `keysFor`.

A successful peer fetch is cached for `PEER_JWKS_CACHE_TTL`, and a peer that has
answered before but is now unreachable is served from cache for
`PEER_JWKS_STALE_TTL`. A peer that has *never* answered has neither, so it is
re-fetched on every single inbound request. There is no negative cache and no
circuit breaker, so the cost of a peer being unreachable is
`PEER_JWKS_TIMEOUT_MS` per request, paid on the request path of the one endpoint
every relying party polls to verify a token.

Measured on the local stack, with one instance unreachable to the others:

```text
sag-node    /.well-known/jwks.json   4.000673s   (one unreachable peer)
sag-workers /.well-known/jwks.json   0.011023s   (both peers cached)
```

Exactly `PEER_JWKS_TIMEOUT_MS`, on every request, repeatably. On Workers each
attempt also spends a subrequest from the isolate's budget; on Lambda it is
billed wall-clock. Concurrency multiplies it: *n* concurrent requests hold *n ×
unreachable peers* outbound connections open for the whole timeout.

This is OWASP API4 (unrestricted resource consumption) and ATT&CK T1499. It does
not need an attacker - a peer outage or a misconfigured `PEER_JWKS_URLS` entry
is enough, and the failure mode is that the outage of one region degrades every
region's token verification rather than only its own.

**Suggested fix**: cache failures as well as successes, for a short interval, so
a dead peer costs one timeout per interval rather than one per request. The
existing cache entry shape already carries `fetchedAt`; a `failedAt` beside it is
enough. Nothing about the stale-serving behaviour needs to change.

### 2. The session idle timeout does not roll forward

`src/session.js`.

`touch()` implements the rolling idle timeout, and the module header describes it
- "`exp` is the idle timeout and is pushed forward each time the session is
used". `docs/configuration.md` says the same: `SESSION_TTL` is the "Idle
timeout", `SESSION_MAX_LIFETIME` the "Absolute lifetime, regardless of activity".

`touch()` is never called. Nothing in `src/`, `adapters/`, or `test/` references
it. `exp` is set once by `newSession`, reset only by `reauthenticate`, and
carried unchanged through every `sessionCookie` refresh, so `SESSION_TTL` is in
practice a second absolute cap and `SESSION_MAX_LIFETIME` is unreachable at its
default (7 days against a 12 hour `SESSION_TTL`).

The effect is shorter sessions than documented, which is the safe direction. The
risk is the operator who reads the table, lengthens `SESSION_TTL` believing it
governs inactivity, and gets a longer window with no re-check instead. This is
OWASP session management guidance and ATT&CK T1550.004 (web session cookie): an
idle timeout that does not exist is exactly the control that limits how long a
stolen cookie stays useful after the person stops using it.

**Suggested fix**: call `touch()` where the session is re-used and the cookie
refreshed - `complete()` in `src/endpoints/authorize.js` is the single place - or
delete `touch()` and correct both the header comment and the configuration table.
Either is defensible; the current state is neither.

### 3. A multi-tenant Microsoft upstream derives identity from a tenant-controlled claim

`src/upstream/index.js`, `completeUpstream`; `src/upstream/providers.js`,
`microsoft.verifyClaims`.

With `UPSTREAM_MICROSOFT_COMMON_*` configured, four checks that would otherwise
bound the returned address all decline to fire:

- `verifyClaims` returns immediately for a `common` upstream;
- the "address outside the domain it is configured for" check is skipped,
  because it is guarded by `!upstream.isCommon`;
- `email_verified` is only rejected when it is explicitly `false`, and Entra ID
  v2.0 id_tokens do not carry the claim at all;
- the address falls back from `email` to `preferred_username` to `upn`.

In Entra ID, `mail`, `preferred_username`, and the UPN are all directory
attributes a tenant administrator sets, and Microsoft does not verify that the
tenant controls the domain in them. Any administrator of any tenant in the world
can therefore present an id_token asserting an address they do not control. SAG
derives `sub` from the verified address and nothing else (ADR 0011), so that
token yields the same `sub` that the genuine holder of the address would get from
email OTP, from Google, or from their own tenant, and SAG then asserts
`email_verified: true` to every relying party. That is cross-method account
takeover, and it is the nOAuth pattern published against multi-tenant Entra
applications in 2023.

This is OWASP A07 (identification and authentication failures) and ATT&CK
T1199 (trusted relationship). It is raised as an open question in
`docs/questions.md` under "Which upstream claims prove control of an address?",
but it is not in `docs/limitations.md`, and the default is the unsafe one.

**Suggested fix**, in order of how much it costs:

1. For a `common` Microsoft upstream, use `email` only, never
   `preferred_username` or `upn`. The fallback exists for tenant-pinned
   deployments, where the domain check already bounds it.
2. Add an allow-list of tenant ids for `common`, so "any tenant" is a choice
   rather than the default.
3. Treat a missing `email_verified` as unverified for any provider whose
   `verifyClaims` is a no-op.

Whichever is chosen, it is an architectural decision and belongs in a numbered
ADR, with the outcome removing the question from `docs/questions.md`.

### 4. `PROMPT_NONE_SHARED_SESSION` is parsed and documented but never read

`src/config.js`, `session.promptNoneUsesSharedSession`.
`docs/configuration.md` row: "Whether `prompt=none` may be answered from the
shared session when sessions are per relying party".

Nothing consumes it. `grep -rn promptNoneUsesSharedSession src/` returns the
definition and nothing else, and the fallback it describes is not implemented in
`decide()` either. An operator setting it to `false` in order to stop a per-RP
deployment answering silent requests from a shared session gets no enforcement,
and one leaving it at the documented `true` default gets no fallback.

A configuration switch that appears to be a security control and is not is worse
than an absent one, because it is the kind of thing that goes in a hardening
checklist and is then believed.

**Suggested fix**: implement the fallback or remove the setting and its
documentation row. If it is removed, `alias()` is not needed - it never did
anything, so nothing can depend on it.

### 5. Sign-out is a state-changing GET with no CSRF token when the interstitial is off

`src/endpoints/logout.js`, `handleLogout`.

`confirmMode` resolves to `false` whenever sessions are per relying party
(`SESSION_SCOPE=rp` makes `affectsOthers` false), whenever `LOGOUT_CONFIRM=never`
is set, and whenever a client record sets `logout_confirm: never`. In that case
`GET /logout?client_id=...` signs the person out immediately. Session cookies are
`SameSite=Lax`, which is correct for `/authorize` and which also means a
top-level cross-site navigation carries them, so any page on the internet can
end a visitor's session by navigating them to that URL.

With no state store this is a nuisance: the cookie is cleared and the person
signs in again. With `STATE_STORE_BACKEND` set it is more than that, because
`finish()` calls `revokeSession()`, which writes a `session-revoked:<sid>` claim
lasting until the session's absolute expiry. A forced cross-site GET therefore
revokes every copy of that session across every instance, durably, at an
attacker's timing. Repeated across visitors it is also unbounded attacker-driven
writes into the shared store.

OWASP A01 via CSRF; ATT&CK T1531 (account access removal), at the mild end.
Neither ADR 0004 nor ADR 0012 mentions it. The OpenID Connect RP-Initiated
Logout specification raises this case directly and recommends confirmation.

**Suggested fix**: the machinery already exists. The sealed `lt` token in
`performLogout` is a perfectly good one-time CSRF token; the gap is only that the
non-confirming path does not require one. Either always render the interstitial
for a `GET`, and reserve the silent path for `POST` with the sealed token, or
keep the silent path and require `POST`.

### 6. `/healthz` publishes configuration values its own contract says it will not

`src/endpoints/health.js` says, in its header, "No configuration values, no
client ids, no secrets", and `src/config.js` moved the defence-mapping warnings
into `internalWarnings` for exactly that reason. But `warnings` is still
published verbatim, and several entries embed the raw value that was rejected:

- `Ignoring CORS_ALLOWED_ORIGINS entry "<raw>": ...` (three variants)
- `Ignoring PEER_JWKS_URLS entry "<raw>": ...` (two variants)

A typo in either is normally an internal hostname, so an unauthenticated
`GET /healthz` can disclose one. `ATT&CK T1590/T1592` reconnaissance; low impact,
but it is a straightforward contradiction of the endpoint's stated contract.

**Suggested fix**: push those five warnings to `internalWarnings` instead. The
start-up banner and the log already print both lists, so nothing is lost.

### 7. `verifyCompact` will accept any algorithm when its caller forgets the allow-list

`src/crypto/jose.js`, `verifyCompact`.

`algs` is optional. When it is omitted, any entry in `ALGS` is accepted from the
token's own header, including `HS256`. Both current call sites - the upstream
id_token check and `private_key_jwt` - pass an explicit list that excludes it, and
a genuine confusion attack is additionally blocked by Web Crypto refusing to
import an `EC` or `RSA` JWK under `{name: 'HMAC'}`. So this is latent rather than
live.

It is worth closing anyway, because it is the single classic JOSE mistake and the
cost is one line: make `algs` required, or default it to the classical and
post-quantum signature algorithms and require `HS256` to be asked for by name.
`signHs256` is the only caller that needs it, and it signs rather than verifies.

## Verified, and correct as documented

Checked because a reviewer would, and found to be as `docs/limitations.md`
describes them. No action.

- **Authorisation code replay.** Codes are sealed, bound to `client_id`,
  `redirect_uri`, and a PKCE challenge, live 60 seconds, and are made single-use
  by the state store. The local stack confirms an in-process map, a Durable
  Object, and a DynamoDB conditional write all refuse the second redemption.
- **OTP attempt counters can be rolled back.** Confirmed: `withOtpAttempt`
  writes to the sealed transaction, which the browser holds, so an older copy
  resets the count. The mitigation is real - `codeLength()` enforces a floor of
  nine characters over a thirty-symbol alphabet even when `OTP_DIGITS` asks for
  fewer, which is about 2 x 10^13 combinations against a ten minute window. The
  documented position holds. `OTP_MAX_ATTEMPTS` should be read as a deterrent,
  which is what `limitations.md` says.
- **CIMD DNS rebinding.** `assertPublicCimdTarget` resolves and validates, then
  `fetch` resolves again, so a short-TTL name can answer public once and private
  once. ADR 0015 states this ("a DNS answer can still change between validation
  and ..."). `redirect: 'error'`, the size cap, and
  `CLIENTS_CIMD_ALLOWED_DOMAINS` bound it.
- **Redirect URI matching.** Exact `href` comparison, with the RFC 8252 loopback
  port exemption and nothing else. No prefix or wildcard path.
- **Open redirect at `/authorize`.** The two-stage ordering in
  `src/oauth/request.js` holds: nothing is redirected until the client and the
  redirect URI are both validated, and `UnredirectableError` is a distinct type
  so the boundary cannot be crossed by accident.
- **XSS on the sign-in pages.** Every interpolation goes through `escapeHtml`,
  every href and image src through `safeHttpUrl`, and the policy is
  `default-src 'none'` with no inline script or style, so it needs no nonce. The
  absent `form-action` is explained at length in `src/ui/csp.js` and is the
  right call.
- **Private network access.** `src/util/ip.js` is stricter than RFC 1918:
  loopback, link-local, carrier-grade NAT, documentation, benchmarking,
  multicast, and reserved ranges are all refused, IPv4-mapped IPv6 is unwrapped
  before classification, and unique-local and link-local IPv6 fall outside
  `2000::/3`.
- **Cryptography.** HKDF-SHA-256 to purpose-bound keys, AES-256-GCM with the
  purpose as additional authenticated data so a token minted for one context
  cannot be replayed into another, rejection sampling for OTP codes, constant
  time comparison wherever a secret is compared, and RSA below 2048 bits refused
  on import. No `Math.random` in production code.
- **Logging.** No address is ever logged; `emailTag()` writes a truncated digest
  of the untagged mailbox instead, which still correlates across lines.

## OpenSSF Best Practices

`docs/best-practices.md` maps the passing criteria to evidence, and the mapping
is accurate as written. This review adds one thing to it: `dynamic_analysis_fixed`
may only be answered `N/A` while no confirmed exploitable medium-or-higher
finding exists. Finding 3 is the one that would have to be assessed before that
answer is given, and findings 1 and 5 before `vulnerabilities_fixed_60_days`.

The `no_leaked_credentials` attestation was re-checked: the committed master
secrets, the signing key in `workers/wrangler.hsm.dev.toml`, and the `rp-lambda`
client secret are all local-stack fixtures that grant access to nothing, and
`test/local-stack/README.md` says so where somebody would find it.

## What this review did not cover

- **Real upstream providers.** Federation was read, not driven. Microsoft and
  Google were not exercised against live tenants, which is what finding 3 needs
  before its fix can be validated. See
  [RFC 0006](rfcs/0006-live-upstream-testing.md).
- **Dependencies.** There are no runtime dependencies to review; the
  development ones were not audited here.
- **The published documentation site** and anything outside this repository.
- **Load.** The local stack runs one container of each. Finding 1 was measured
  with a stopwatch, not a load generator.
