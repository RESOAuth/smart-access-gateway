# 0023. Domain discovery and CIMD federation

Status: Proposed
Checked: 2026-09-29
Repository baseline: `1ed6fb2cd37eade4ba0b73c0c543e434526a324b`

## Context

A domain owner should be able to run a small SAG instance, authenticate only
addresses at that domain with email OTP, and publish where it lives. Another
SAG should discover that issuer and use it without a bilateral client
registration or shared client secret.

For example, `example.org` delegates to `https://idp.example.org`. The hosted
gateway at `https://auth.resoauth.cloud` remains the application's issuer, but
authenticates `jamie@example.org` through the domain's SAG.

There are four separate decisions: locate an issuer, establish its authority
over the requested address, introduce the gateway as a client, and decide what
authentication assurance to accept. CIMD solves the client introduction. It
does not discover the user's issuer, prove software provenance, or establish
authority over an email domain.

### Standards position

| Specification | Status on the checked date | Role here |
| --- | --- | --- |
| [WebFinger, RFC 7033](https://www.rfc-editor.org/rfc/rfc7033.html), and [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Published RFC and final OpenID specification | Existing identifier-to-issuer discovery, then provider metadata. |
| [OAuth server metadata, RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html) | Published RFC | Endpoints and capabilities once the issuer is known; not domain delegation. |
| [CIMD -02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html) | Active OAuth WG Internet-Draft, 6 July 2026; not an RFC | URL client identifiers and fetched client metadata without prior registration. |
| [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html) and [Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html) | Final, 5 May 2026; 1.0 was final on 17 February 2026 | Signed trust chains, metadata policy, and automatic client registration for governed federations. Automatic registration uses asymmetric authentication. |
| [DNS-based OIDC Discovery -01](https://datatracker.ietf.org/doc/draft-sanz-openid-dns-discovery/) | Individual draft, last revised April 2018; expired and archived | Close precedent: `_openid` TXT records. Not an adopted DNS discovery standard. |
| [Dynamic Client Registration, RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) | Published RFC | Alternative onboarding with a registration request and server-issued client identifier. |
| [Protected Resource Metadata, RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) | Published RFC | An API can advertise its `authorization_servers`; it does not identify the home IdP for an email address. |

The research found no current standard that combines DNS-only email-domain
delegation with CIMD onboarding. This RFC proposes a small SAG profile over
existing protocols. The DNS label and `urn:sag:*` fields below are experimental
SAG conventions, not IETF or OpenID registrations. They make no claim to
compatibility with the expired DNS draft.

[URI records, RFC 7553](https://www.rfc-editor.org/rfc/rfc7553.html), can carry
an issuer URL; [SVCB/HTTPS, RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html),
describe service bindings. Neither supplies this email-domain delegation
contract. TXT is proposed for operational convenience, not stronger security.
Any standards submission should settle the record type and pursue the
appropriate [underscore-name registration](https://www.rfc-editor.org/rfc/rfc8552.html)
and metadata registrations; this repository RFC performs none of them.

### Existing SAG behaviour

The relevant implementation is [upstream routing](../../src/upstream/index.js),
[mail hints](../../src/upstream/dns.js), [client resolution](../../src/clients/index.js),
[discovery](../../src/endpoints/discovery.js), and [OTP policy](../../src/otp.js).

- Static domain and parent-domain routes precede `common` routes and OTP.
  MX/SPF hints choose between already eligible providers; they confer no trust.
- Incoming CIMD exists, but SAG does not publish its own upstream client
  document. Discovery currently uses `urn:sag:client_registration.cimd`, not
  the standard draft capability name.
- Upstream code flow already uses PKCE and permits an absent client secret.
  It does not yet send upstream `private_key_jwt` assertions.
- `OTP_ALLOWED_DOMAINS=example.org` also accepts subdomains. It is not an
  instance-wide exact-domain restriction.
- [ADR 0011](../adr/0011-subject-derived-from-the-verified-address.md) derives
  ordinary subjects from verified email. [ADR 0019](../adr/0019-a-common-upstream-must-bound-what-it-may-assert.md)
  therefore requires bounds on what an upstream may assert.
- The current [assurance mapper](../../src/acr.js) treats `otp` or multiple
  AMR entries as MFA. A second SAG's email OTP would be over-promoted.

## Proposal

### 1. Scope and trust model

Add opt-in domain discovery and a terminal SAG federation profile. A terminal
issuer authenticates locally and does not forward these logins to another
upstream. Version 1 targets the OTP-only example. Arbitrary broker chains,
automatic DCR, and federation trust-anchor management are outside this version.

The broker trusts a domain-authenticated delegation only for that exact domain.
It does not add the discovered issuer as `common`, import its signing keys into
`PEER_JWKS_URLS`, share salts or sealing secrets, or change the downstream issuer.
Peer JWKS federation serves one issuer across deployments; this proposal joins
separate issuers through OIDC.

Domain authority is a deliberate identity policy: the domain operator can
assert addresses within its domain. Domain compromise, reassignment, and
mailbox recycling can consequently affect existing email-derived accounts.
Neither DNSSEC nor CIMD proves a person's legal identity or an assurance level.

### 2. Domain-to-issuer discovery

Offer this experimental DNS record:

```dns
_sag-issuer.example.org. 300 IN TXT "v=SAG1; issuer=https://idp.example.org"
```

Query the exact email domain after validated IDNA A-label conversion and
lowercasing of the domain only. Do not query parent domains, infer a route from
MX/SPF, or place an email local part in DNS.

Version 1 requires one TXT RR, joining only that RR's character strings in
order. Reject multiple records, duplicate or unknown tags, unsupported
versions, empty values, and records over 2 KiB. Tag names are case-sensitive;
trim surrounding ASCII whitespace and preserve the issuer value exactly.
Require `v=SAG1` and one `issuer` tag. A literal semicolon inside the issuer
must be percent-encoded. The issuer is an absolute HTTPS URL without
credentials, query, fragment, or dot path segments. Paths are allowed; this
profile permits only the default HTTPS port. Reject CNAME/DNAME and wildcard
synthesis for this record in version 1.

Automatic trust requires either:

1. **DNSSEC-validated delegation.** A validating resolver reports the answer
   as secure, including its chain and exact owner-name semantics. Only this
   route fulfils the DNS-record-only deployment goal.
2. **HTTPS WebFinger delegation.** Obtain the issuer from the email domain's
   own WebFinger endpoint. An unsigned TXT candidate is usable only if this
   independently authenticated response agrees exactly. WebFinger can also
   work without a TXT record.

For `jamie@example.org`, use the standard request:

```http
GET /.well-known/webfinger?resource=acct%3Ajamie%40example.org&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer HTTP/1.1
Host: example.org
```

Require HTTP 200, the requested `subject`, and exactly one issuer link with
`rel` equal to `http://openid.net/specs/connect/1.0/issuer`. For this profile,
do not follow redirects; that is stricter than general WebFinger. Reject a
conflict with a present TXT candidate. A WebFinger result is bound to the
requested account, not cached as a rule for every account at the domain.

After DNS absence, try WebFinger. An HTTPS 404, or a valid matching-subject
response without an issuer link, means no delegation only when there was no
TXT candidate. A present unsigned candidate without corroboration is an error.
Other HTTP failures, TLS failures, and invalid responses are errors. A secure
positive DNS delegation needs no WebFinger request.

DNSSEC `bogus`, a timeout, and a malformed answer are errors, not absence.
`insecure` or `indeterminate` never means secure; an ordinary TXT resolver
returning strings cannot satisfy the DNSSEC route. DoH encrypts transport but
does not itself establish signed delegation. An AD flag is usable only from
an explicitly trusted validating resolver over a protected channel.

### 3. Routing and failure behaviour

Apply these steps in order:

1. Enforce the instance's exact-domain admission policy.
2. Honour operator-configured local routing and domain/parent upstream routes.
3. If enabled, attempt authenticated domain discovery.
4. Only when discovery is absent, retain existing `common`, MX/SPF selection,
   and permitted OTP behaviour.

An authenticated delegation selects that route exclusively for this attempt.
An unavailable issuer, unsupported profile, rejected client, or failed
validation MUST NOT silently fall back to hosted OTP or a common provider.
Discovery errors also stop the attempt. The user can retry or start with a
different address. Operator configuration remains an explicit override.

An unsigned NXDOMAIN can be forged. Consequently, deployments requiring
mandatory federation for known domains must pin that requirement locally;
opportunistic discovery alone cannot guarantee its use after an attacker
suppresses all unauthenticated discovery signals. This limitation must be
visible in deployment guidance.

### 4. Provider metadata and terminal capability

Fetch OIDC configuration from the authenticated issuer using OIDC's path
rules, and require its `issuer` to equal the delegated string exactly. Do not
replace a mismatched metadata issuer with the configured value. RFC 8414 and
OIDC use different well-known placement for issuers containing paths.

For automatic version-1 routing, require code flow, `openid email`, S256 PKCE,
the selected client authentication method, RFC 9207 response issuer support,
`client_id_metadata_document_supported: true`, and this proposed extension:

```json
{
  "urn:sag:domain_federation": {
    "version": 1,
    "terminal": true,
    "domains": ["example.org"]
  }
}
```

The metadata is a capability assertion, never evidence of domain ownership or
genuine SAG software. Another implementation can support the profile. The
broker still requires delegation and enforces the exact requested domain.

SAG publishes `terminal: true` only with domain discovery off, no configured
upstreams, a finite exact-domain admission list, and an available local
authentication method. Reject self-delegation. This prevents compliant SAG
instances from creating recursive broker loops; it cannot make a malicious
external issuer behave honestly. Existing static OIDC routes need not adopt
this extension.

### 5. SAG as a CIMD client

The calling broker publishes its own metadata at this proposed ordinary path:

```text
https://auth.resoauth.cloud/federation/client-metadata.json
```

The terminal issuer fetches that document when the broker uses its URL as
`client_id`. The document belongs to the broker, not to the discovered issuer.
Its callback belongs to the broker too:

```json
{
  "client_id": "https://auth.resoauth.cloud/federation/client-metadata.json",
  "client_name": "RESOAuth hosted gateway",
  "client_uri": "https://auth.resoauth.cloud",
  "redirect_uris": ["https://auth.resoauth.cloud/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "openid email",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://auth.resoauth.cloud/federation/jwks.json"
}
```

Use CIMD -02's exact client-ID matching, HTTP 200, redirect refusal, credential
restrictions, and explicit authentication method processing. Scope this SAG
profile further to same-origin HTTPS callbacks and client JWKS, with no
wildcards. Serve the document from the configured public issuer, never an
untrusted Host header. CIMD admission remains subject to the terminal
operator's policy; enabling discovery does not enable arbitrary clients.

Recommend `private_key_jwt` plus PKCE for production gateways. It requires a
gateway-owned private key but no shared client secret or per-upstream
registration. Publish only public keys, preferably from a dedicated federation
client key set. Keep private keys out of metadata and browser-carried state.

The upstream client assertion uses the CIMD URL as both `iss` and `sub`, the
upstream issuer as its sole `aud`, a unique `jti`, and a maximum 60-second
lifetime. The receiving SAG requires atomic replay claiming for this profile.
Key rotation publishes the new public key before switching signers and accounts
for metadata cache lifetime. A material policy change invalidates in-flight
authorisation rather than combining old and new client policy.

An explicitly enabled public-client variant can publish
`token_endpoint_auth_method: none`, omit keys, and use PKCE alone. This proves
possession of the transaction verifier, not the gateway's private key. Never
silently downgrade a declared `private_key_jwt` client to `none`.

### 6. Authentication and identity checks

Start a normal OIDC code request with the broker's CIMD URL, exact callback,
`scope=openid email`, fresh `state` and `nonce`, S256 challenge, and the typed
address as `login_hint`. A login hint is not an access restriction.

Seal a bounded descriptor containing the exact domain, requested address,
issuer, endpoints, broker client ID, nonce, verifier, discovery evidence type,
evidence expiry, and policy hash. Bind it to the initiating browser as well as
the downstream transaction; sealed state alone is not browser binding.

At callback, check [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) `iss`
against the sealed issuer before exchanging the code, including error
responses. Exchange only at the selected endpoint. Validate the ID token's
signature, permitted algorithm, issuer, audience, `azp` where applicable,
expiry, nonce, and required authentication time. Require a non-empty `sub`,
an `email`, and the literal boolean `email_verified: true`.

The canonical returned email MUST equal the requested email and its domain
MUST equal the delegated domain. Do not apply client-specific plus stripping
before this comparison, accept `preferred_username`/`upn` as substitutes, or
inherit authority over subdomains. Account switching requires a new discovery
transaction for the new address.

Revalidate expired evidence and current local policy before callback acceptance,
session reuse, downstream code redemption, and UserInfo release. If the issuer
or relevant policy changed, restart; never send an existing code to a newly
discovered token endpoint. Cache snapshots cannot make expired trust fresh.

Preserve ADR 0011's subject derivation and the hosted issuer. Do not link an
operator-provisioned local account by email alone; its existing explicit
issuer/subject link rules still apply.

### 7. Preserve authentication strength

**Email OTP at the terminal MUST remain email-OTP-strength at the broker.**
Neither an extra OIDC hop, the `fed` method, an `otp` string, nor AMR array
length grants MFA or a stronger authentication context.

Version 1 caps automatically discovered identities at the local email-OTP
assurance level. Higher assurance requires a separately configured exact-issuer
mapping and is outside automatic version-1 admission. Retain the upstream
issuer and bounded original evidence separately from locally generated AMR.
Never feed synthetic method labels back into a strength inference.

The configured relying-party assurance floor is mandatory, independent of
optional requested ACR preferences. Recheck it at every result and session
reuse. Preserve validated upstream `auth_time`; callback time is not fresh
authentication. Honour `max_age`, `prompt=login`, and `prompt=none`; if their
requirements cannot be proved, return the appropriate OIDC error.

These are release gates, not optional follow-up work. They overlap with
[RFC 0016](0016-trusted-authentication-assurance.md), but this proposal requires
the stated behaviour even if that separate RFC has not been accepted.

### 8. Exact-domain local instance

Introduce `IDENTITY_ALLOWED_DOMAINS`, an optional instance-wide list of exact
normalised domains. Empty retains today's unrestricted admission. When set,
it MUST gate all authentication methods, session reuse, code redemption, and
UserInfo, not just OTP sending. No wildcard or suffix matching is permitted.

Illustrative configuration, including proposed settings:

```sh
ISSUER=https://idp.example.org
IDENTITY_ALLOWED_DOMAINS=example.org     # proposed, exact domain only
UPSTREAM_DISCOVERY=off                  # proposed; default
LOCAL_IDENTITIES_BACKEND=none            # existing password-file backend stays off
OTP_ENABLED=true
OTP_ALLOWED_DOMAINS=example.org          # existing extra restriction
CLIENTS_CIMD_ENABLED=true
CLIENTS_CIMD_ALLOWED_DOMAINS=auth.resoauth.cloud
CLIENTS_CIMD_ALLOW_SUBDOMAINS=false
```

Configure no `UPSTREAM_*` providers. Use a real email sender, production keys
and secrets, and a supported atomic state store for the recommended client
authentication profile. This is SAG acting as an OTP IdP; it does not need the
Node-only password-file identity backend. The new global admission check
excludes `sub.example.org` even though the existing OTP allow-list includes it.

The broker opts in with proposed `UPSTREAM_DISCOVERY=domain`; its default is
`off`. Federation client key configuration and the explicit public-client
opt-in must be settled during implementation review. These examples are not
deployable on the current release. Implementation must document every new
setting in the configuration reference.

### 9. Network, cache, and privacy boundaries

All discovered URLs are untrusted network input. Apply public-address checks
to WebFinger, provider metadata, token endpoints, JWKS, CIMD, and referenced
client keys. Reject credentials, IP literals, non-HTTPS schemes, and private,
loopback, link-local, reserved, or mixed public/private resolutions. Version 1
also requires provider endpoints and keys to share the issuer origin.

Reuse redirect refusal, but add deadlines covering body consumption, bounded
JSON parsing, and bounded outbound concurrency. Start with 5-second document
deadlines, 32 KiB documents, 64 KiB JWKS, and at most 500 cache entries per
document class. DNS rebinding requires connection-time destination enforcement
or an egress service providing it. A DNS preflight followed by an independent
`fetch` is insufficient. An adapter lacking this protection must not enable
automatic discovery in production.

Cache positive DNS delegation no longer than the minimum of DNS TTL, remaining
signature validity, and 300 seconds. Cache valid HTTPS evidence no longer than
HTTP freshness and 300 seconds; honour `no-store` and revalidation. If no HTTP
freshness is supplied, use a maximum of 300 seconds. Do not cache malformed
documents or HTTP errors; rate-limit failures separately. Bound DNS negative
caching by its authoritative lifetime and 60 seconds. Never use stale positive
evidence after a failed refresh.

Changing or removing a delegation stops new grants and reuse when observed,
within those cache bounds. Cap broker-issued tokens by the evidence deadline;
do not claim to revoke an application's independent session or an already
issued token instantly. Provide an operator deny rule for emergency withdrawal
that applies before caches and is deployed to every instance.

WebFinger exposes the requested account to its domain's HTTPS service. DNS
discloses the domain to the resolver. Use domain-only DNS queries and minimise
account-keyed WebFinger caching. CIMD names and logos are self-asserted; display
the client origin and apply normal consent policy. Log bounded reason codes,
issuer, and evidence type, not tokens, OTPs, raw email addresses, or sensitive
request URLs.

### 10. Delivery and acceptance

Implement in this order:

1. Exact-domain admission, truthful assurance, and CIMD -02 validation and
   capability advertisement. [RFC 0017](0017-client-trust-and-assertion-audiences.md)
   discusses related CIMD work; the requirements above stand independently.
2. Broker client metadata and dedicated public keys; upstream asymmetric
   client authentication, policy snapshots, and replay protection.
3. WebFinger discovery and the authenticated DNS resolver interface, including
   TTL, security state, authenticated absence, and owner-name information.
4. The terminal profile, strict dynamic callback validation, and a two-instance
   deployment test. Enable it only after every security gate passes.

Keep the core platform-independent. Existing Node and Workers resolver
bindings return strings without DNSSEC evidence; extend the interface rather
than interpreting successful resolution as validation. Test actual supported
adapter transports before promising DNS-only discovery on every platform.

Acceptance must demonstrate:

- An unregistered broker completes a real two-SAG code flow with CIMD and no
  shared client secret; only `example.org` succeeds, including direct endpoint
  calls and reused sessions. Subdomains and lookalike suffixes fail.
- DNSSEC secure/insecure/bogus states, absence, conflicts, multiple TXT RRs,
  chunking, IDNA, path issuers, and WebFinger account isolation behave as above.
- A validly signed out-of-domain or different-address token fails. Missing or
  false verification, wrong issuer/audience/nonce, and mix-up attempts fail.
- Email OTP remains OTP-strength through the broker; forged MFA labels and
  weaker requested alternatives cannot satisfy a client's stronger floor.
- Metadata mismatch, client key rotation, replay, expired evidence, and
  delegation changes cannot redirect code redemption or reuse stale trust.
- SSRF, redirect, rebinding, slow-body, and oversized-response cases fail on
  each enabled adapter. Self-delegation and non-terminal issuers are refused.
- Established routes remain unchanged with discovery off. A selected dynamic
  route never fails open to hosted OTP or a common upstream.

## Cost

This is more than a DNS lookup. The main work is authenticated resolution,
cross-instance identity and assurance policy, safe outbound networking, and
client key lifecycle. The current all-platform DNS abstraction cannot provide
the required DNSSEC proof, and outbound destination enforcement needs explicit
adapter work or an egress component. No implementation estimate is justified
until those two choices have been prototyped.

The proposal preserves ordinary subject derivation and the distinction between
upstream federation and peer keys. It tightens authentication for newly
discovered upstreams and adds an optional global admission boundary. New
evidence-bearing sessions and transactions may require a pre-release restart;
deploy terminal support before enabling broker discovery.

If RESOAuth needs centrally governed membership, shared assurance policy, or
trust marks, implement OpenID Federation 1.1 as a separate profile with
configured trust anchors. Do not gradually invent an equivalent trust-chain
protocol inside DNS or CIMD. For the domain-owned OTP use case, authenticated
delegation plus OIDC and CIMD is the smaller design.

Further security foundations: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html),
[PKCE, RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html),
[JWT client authentication, RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html),
[OAuth Security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), and
[DNSSEC, RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html).
