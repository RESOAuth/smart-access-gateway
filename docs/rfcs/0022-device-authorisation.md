# 0022. Device authorisation

Status: Proposed

## Context

SAG currently issues tokens through the authorisation-code flow. It can reuse
an interactive upstream or email-code sign-in, and it does not need a local
account to do so. That model normally assumes an interactive user agent on the
client path, though it can also work through loopback, remote-desktop, or other
deployment-specific arrangements.

Current-code evidence, accessed 2026-09-08:
[`issueCode`](../../src/oauth/code.js#L37-L60) seals the current token-exchange
inputs into an authorisation code, while [`redeemCode`](../../src/oauth/code.js#L70-L100)
optionally claims it once. The existing [state-store interface](../../src/store/index.js#L1-L22)
provides only `claim`, `has`, and `increment`.

A device authorisation grant serves a different, sponsor-backed use case: a client with constrained input or no useful browser asks the person to continue the interaction on another device. It is a published, adopted grant, not an experimental novelty. Its primary protocol specification is [RFC 8628, August 2019](https://www.rfc-editor.org/rfc/rfc8628.html), accessed 2026-09-08.

[RFC 10027, BCP 247, August 2026](https://www.rfc-editor.org/rfc/rfc10027.html), accessed 2026-09-08, adds current cross-device security guidance. It does not make the grant phishing-resistant. In
particular, entering a short user code alone cannot defeat a remote-phishing
attack involving a convincing link, screenshot, or relay.

The proposal should proceed only with a documented
use case, client population, threat assessment, implementation risk assessment,
operational owner, and selected RFC 10027 mitigations. Before enabling the
feature, record whether proximity evidence is feasible and, if not, why; if it
is feasible, record the selected mechanism and its justification.

## Proposal

Offer `POST /device_authorization` only in deployments that explicitly enable
it and configure a durable, shared pending-authorisation store. A
deployment without that store must not advertise or accept the grant. This is
a fail-closed feature prerequisite, rather than a best-effort use of sealed
browser values.

`POST /device_authorization` returns a `200` JSON response with `Cache-Control:
no-store` on success. It returns `device_code`, `user_code`, `verification_uri`,
`expires_in`, and `interval`. The browser verification route is `GET /device`,
with a CSRF-protected `POST /device` to confirm or deny the entered code.

The endpoint accepts a form-encoded POST containing `client_id`, `scope`, and
an optional `resource`. Resolve the client through its existing registration.
Require an operator-approved client registration that explicitly allows the
device grant. A resolvable CIMD URL alone does not grant that permission, and a
document cannot self-authorise it. For this grant, permit only `openid`,
`email`, and `profile`, further limited
by client policy; reject `offline_access` and unsupported scopes with
`invalid_scope`.

The only resource is the configured issuer's canonical `/userinfo` URL,
preserving any issuer path, as intended by
[ADR 0005](../adr/0005-no-refresh-tokens.md). Omitted `resource` selects it;
an explicit value must match exactly. Reject malformed, fragment-bearing,
duplicate, or different resource values with `invalid_target`. The stored
resource and scopes cannot expand during approval or token exchange.

This proposal does not introduce password, client-credentials, token-exchange,
implicit, or other grants.

Confidential clients authenticate as required by their registered method and
the applicable protocol rules. Public clients identify themselves with their
client id and must not be given or expected to hold a secret. The device grant
must remain bound to the client that started it.

A `verification_uri_complete` may be returned for a QR code or link, but it
does not approve the request or remove the confirmation step.
Clients still display the textual `verification_uri` and `user_code`; the
verification page displays that code and asks the person to confirm it matches
the device before approval.

The initial profile proposes a ten-minute TTL, a `device_code` with at least
256 bits from a CSPRNG, an eight-character `user_code` from a 32-character
unambiguous alphabet, and a five-second default polling interval. These are
local profile choices, not RFC 8628 mandates, and must be measured against the
sponsored client population before acceptance.

Store only a hash or similarly non-recoverable verifier of the `device_code`,
and a bounded keyed lookup value such as `HMAC(device_code)`. The lookup locates
the pending record without a scan and is distinct from the verifier. Use a keyed
HMAC lookup value for the low-entropy `user_code`, in a distinct namespace, not
an unsalted hash that enables offline guessing if the store is disclosed.
A wrong `user_code` usually matches no record, so a per-record attempt limit
cannot bound guessing. Apply shared rolling limits to the verification route
before lookup, including codes supplied by complete-URI links: initially ten
lookups per network bucket per ten minutes and an additional authenticated
account/session budget where available. Define trusted proxy handling for
network keys; user-supplied forwarding headers cannot create fresh buckets.

For the initial beta, cap live pending records globally at 1,000 and total
user-code lookups globally at 1,000 per rolling ten minutes, with additional
per-client issuance quotas. These operator-owned bounds cover rotating client
ids, addresses, and unmatched guesses. With 40-bit uniform codes, the union
bound for guessing any of N live codes in q attempts is `q * N / 2^40`, below
one in a million for these maxima during a code's lifetime. Raising either
bound requires recalculating that exposure and increasing entropy if needed.
This bounds guessing only, not phishing, and the global cap has an availability
cost under attack. Rate-store failures deny new lookups and issuance.

Only after a match may counters be attached to the trusted pending client.
Responses must not reveal whether a user code, client, or pending request
exists beyond the protocol result needed by an authorised participant.

Never render a `device_code` on the verification page or place it in URLs,
logs, analytics, referrers, browser history, or support diagnostics. Treat it
as a bearer credential until expiry or consumption. Logging may use a keyed,
non-reversible correlation value with a short retention period.

Store a bounded pending record containing a hashed device-code verifier,
device-code and user-code HMAC lookup values, client binding, validated
requested scopes and resource, creation and expiry times, polling interval,
last-poll time, and counters. The record lifecycle is `pending`, `approved`,
`denied`, `consumed`, or `expired`. Lookup and state transition are atomic for
polling and consumption. Allocate both indexes and the record atomically with
unique-key constraints. On either collision, regenerate the codes; never
overwrite another pending request. Expiry and deletion remove both indexes
with the record, and lookups reject expiry before asynchronous cleanup runs.

An `approved` record additionally holds an encrypted, short-lived, bound
authentication result: address for identity derivation, local session id,
`auth_time`, `acr`, `amr`, and scope-gated candidate claims. It needs no
durable local user id. At issuance, SAG re-checks current requirements and
applies relying-party and scope release gates again before outputting claims.

Bind the operator-approved effective client-policy version at creation.
Recheck current grant permission and security policy at approval and token
exchange; revocation or a material change requires a new device request.
Display operator-approved client identity, not an untrusted CIMD name as an
endorsement. Use the normal bounded metadata cache, document its maximum age,
and never use expired cached policy after a refresh failure.

All state transitions must use atomic compare-and-set semantics. In particular,
only one approval may win, only one token exchange may consume an approved
record, and an expired or denied record can never become approved. Consumption
occurs before token signing and is never rolled back: a signing failure consumes
the device code, so the client must begin again. The existing
state-store `claim`, `has`, and `increment` primitives are insufficient; this
needs a new store interface and backend contract.

The store must provide one shared atomic authority for every pending record
across all instances that can approve or redeem it. Separate regional writes
followed by asynchronous replication cannot satisfy this requirement. A
process-local map is acceptable only for tests and development. A timeout,
error, or indeterminate transition result must fail closed for approval and
token issuance; it must not issue tokens because a lifecycle check is
unavailable.

The token endpoint accepts the device-code grant type
`urn:ietf:params:oauth:grant-type:device_code`. It verifies the client binding,
the device-code verifier, record state, expiry, and polling controls before it
issues tokens.

Seal the stored canonical resource audience into each device-grant access
token. `/userinfo` must validate that audience and token expiry before releasing
claims under the granted scopes. Report the effective scopes in the token
response. These checks are part of implementing this grant, alongside the
existing identity and profile-release rules.

While pending, return `authorization_pending`. Per [RFC 8628 section
3.5](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5), a
`slow_down` response increases the interval by five seconds for this and every
subsequent poll of that device code. A connection timeout means the client must
reduce polling frequency; exponential back-off is recommended, but is not a
mandatory requirement. Denial returns `access_denied` and expiry returns
`expired_token`.

The verification page is a normal same-origin, accessible browser flow with no
third-party script requirement. It must authenticate the person through the
usual interactive upstream or email-code path, including any configured trusted
MFA policy. It then displays trustworthy relying-party metadata, the entered
user code, requested scopes, and resource before a CSRF-protected POST confirms
or denies approval.

There is no automatic approval, including after a `verification_uri_complete`
link. The page must make the client and requested access visible enough for a
person to notice a mismatch. Proximity evidence, channel binding, or a
sponsor-provided pairing mechanism may reduce risk only if separately specified
and tested; none makes the basic flow phishing-resistant by assertion alone.

Before final token issuance, re-check the approved record, client, expiry, and any contractually required current claims. A shared session may have been reused, an upstream authorisation attribute may have become stale, or the request may have been denied or consumed concurrently after the page rendered. The grant does not manufacture fresh authentication or claim evidence.

Do not issue refresh tokens. [ADR 0005](../adr/0005-no-refresh-tokens.md)
remains binding.
Device flow is not a reason to add a longer-lived echo of an earlier decision.

This initial device profile issues bearer access tokens. A client requiring
sender-constrained tokens cannot use it until a device-specific key-binding
flow is defined and tested. An authorisation-code `dpop_jkt` parameter does not
define how a key is carried and validated through device approval and polling.

Discovery publishes `device_authorization_endpoint` and the device grant type
only when the feature is enabled and its durable-store prerequisites pass.
Normal sign-in front ends remain available at same-origin routes. Discovery and
UI must not claim stronger phishing resistance than the configured factors and
approval ceremony provide.

Pending records have short TTLs, bounded per-client and per-network limits, and
minimal personal data. The record need not contain a durable local user id.
This proposal does not require a long-lived local identity store.

## Cost

Estimate three to five weeks for a bounded beta across the three adapters.

This adds a durable pending-authorisation subsystem, a new store interface and
production implementations, device and verification endpoints, form and CSRF
handling, discovery changes, configuration, rate limiting, expiry cleanup, and
operator metrics. A shared store becomes a hard availability dependency for
the enabled grant.

The threat model must cover attacker-created verification links, QR-code
substitution, screen sharing, screenshots, code brute force, polling floods,
client impersonation, concurrent approval and polling, denial races, expiry,
store outages, and claim changes between approval and final issuance. The
sponsor must supply evidence that the device use case and its user experience
justify these risks.

Tests must cover the complete browser and device interaction, accessible
verification UI, all three adapters, client authentication, public-client
behaviour, scope and resource validation at issuance and `/userinfo`, rejection
of clients requiring sender-constrained tokens, unapproved CIMD clients,
user-code rate limits, and no
device-code exposure in pages or logs. They must exercise `pending`,
`approved`, `denied`, `consumed`, and `expired` transitions under concurrency,
including atomic device-code lookup and transition.

They must also verify exact polling behaviour, `authorization_pending`,
`slow_down`, `access_denied`, and `expired_token` results, back-off after
failures, store failures, expired approval pages, stale shared sessions,
required-claim rechecks, and discovery suppression when the feature is off.
No implementation should be accepted without cross-device usability testing
and documented assessment against RFC 8628 and RFC 10027.

Acceptance requires demonstrated atomic consumption before signing, no rollback
after a signing failure, ten-minute expiry cleanup, HMAC user-code lookup,
authenticated approval, and a store outage denial path. It also requires tests
that prove `slow_down` persists for every later poll, timeouts reduce polling,
both lookup indexes are cleaned up with their record, concurrent polling has one
atomic outcome, and the encrypted approved result is sufficient to issue once
without a durable local identity record. Feature enablement requires the
documented risk assessment, RFC 10027 mitigation selection, and recorded
proximity decision.
Test unmatched random guesses against global and network budgets, rotated
client ids, spoofed forwarding headers, live-record capacity, forced index
collisions, and atomic allocation and cleanup. Verify the documented guessing
bound with the maximum population and rolling lookup budget, and reject
approval or polling after grant permission is removed.
