# 0016. Trusted authentication assurance

Status: Proposed

## Context

SAG currently has three local ACR values, ordered from email OTP through
federated sign-in to federated MFA. [`acrFromUpstream`](../../src/acr.js)
labels a result MFA when any raw AMR string matches a broad hint set, or when
the raw AMR array has more than one element. Duplicate, unknown, and untrusted
strings can therefore create a stronger local ACR. A single `otp` also becomes
MFA. No factor count, raw AMR value, or passwordless method automatically proves
MFA, phishing resistance, or an external assurance level.

[`parseAuthorizationRequest`](../../src/oauth/request.js) appends a client's
configured ACR floor to the requested `acr_values` list. The satisfaction check
is OR-based. A caller can therefore request a weaker known alternative and
bypass the configured floor. The same merged list directs
OTP fallback, session reuse, upstream completion, and error handling.

Upstream tokens are signature-validated and checked against an expected issuer,
[`src/upstream/index.js`](../../src/upstream/index.js). That establishes which
configured issuer signed claims; it does not establish that arbitrary AMR text
has a shared assurance meaning. Current configured upstream prompts can replace
a requested `none`, `login`, or freshness intent and therefore may weaken the
relying party's request.

OpenID Connect defines `acr_values` as non-essential requested authentication
context values, and `amr` as authentication method references. It does not
define a universal strength ordering. RFC 8176 registers AMR values, but
registration alone is not evidence of a particular factor arrangement. Email
control is not automatically a second factor, and an assurance level from
another framework must never be inferred from local labels.

The July 2025 digital-identity guidance distinguishes email authentication from
an out-of-band authenticator and does not make it phishing resistant. SAG must
not represent its email OTP, or an upstream's unverified label, as either MFA
or a higher assurance level.

## Proposal

Introduce a typed assurance requirement in the sealed transaction. It keeps two
independent fields:

- `minimumFloor`: the registered minimum local ACR policy for the client. It is
  mandatory for every result, including a fallback.
- `requestedPreferences`: the relying party's ordered `acr_values`, or the
  configured default preferences when none are supplied.

Every authentication result **MUST** meet `minimumFloor`. SAG attempts supported
`requestedPreferences` in order where possible, but an unsatisfied non-essential
preference does not make a floor-satisfying result unacceptable. Unknown
preferences are ignored: they neither hard-fail parsing, create a strength
ordering, nor bypass the floor. A missing request remains compatible with the
configured defaults. If SAG introduces a hard requirement for requested values,
it **MUST** be an explicit local policy,
not attributed to OpenID Connect `acr_values` semantics.

Essential ACR claims requested through the claims parameter are unsupported and
remain outside this RFC. SAG **MUST NOT** silently treat them as preferences,
enforce them incompletely, or advertise claims-parameter support.

The assurance mapper **MUST** be issuer-specific and allowlisted. It may assign
local federated MFA only where the exact verified issuer's policy asserts an
actual validated factor context, after signature, issuer, audience, nonce, and
freshness validation. The mapping records recognised evidence and its version
for each decision. It returns only a locally supported ACR,
never an unknown mapped ACR.

The mapper **MUST NOT** infer MFA from AMR array length, duplicate values,
unknown values, a single OTP value, a passwordless label, or a raw upstream ACR
without an explicit mapping. It **MUST NOT** infer an external assurance level,
phishing resistance, or factor count. Unrecognised AMR values may be relayed as
bounded informational claims only when current relay policy permits them; they
must not raise local assurance.

Email OTP remains only the local email-OTP ACR. It cannot satisfy a federated
or MFA floor and is a fallback only when it meets `minimumFloor`.
The discovery document exposes only local ACR values that this deployment can
actually achieve under its configured trusted mappings and enabled methods.

### Evidence lifetime

Persist the exact verified issuer and upstream registration, bounded original
authentication evidence, mapping-policy version, and actual authentication
time in sessions, transactions, and codes. Keep raw recognised evidence
separate from SAG-generated `amr`; an earlier synthetic `mfa` value cannot
become evidence for the new mapper. Re-evaluate current client floors and
mapping policy before session reuse and code redemption as well as at login.

A removed or changed mapping requires fresh upstream evidence unless the
retained original evidence is sufficient to evaluate the new policy in full.
Never retain an old stronger ACR merely because it was sealed successfully.
For this pre-release change, reject old session, transaction, and code formats
without this provenance and restart sign-in. No compatibility remapping of
legacy `amr` or multi-release migration is needed.

### Freshness and interaction

Apply the typed requirement consistently to session reuse, continue screens,
routing, upstream completion, and token issuance. `max_age` remains a freshness
constraint on `auth_time`, independent of assurance strength. `prompt=login`
requires a new authentication, and `prompt=none` must return a non-interactive
error whenever an acceptable fresh session cannot answer the request.

For upstream authentication, derive `auth_time` from validated upstream
authentication evidence. Keep token receipt time as a separate `observed_at`.
A silent upstream response, callback completion, or session renewal does not
make authentication fresh. If the upstream supplies no trustworthy
authentication time, do not fabricate one: a request needing `max_age` or
fresh authentication cannot succeed without evidence of that event. Email
OTP uses the time of successful code verification. Preserve these meanings
through session reuse, reauthentication, authorisation codes, and ID tokens.

An upstream prompt configuration may add interaction only when the original
prompt permits it. It **MUST NOT** weaken `none`, `login`, or `max_age` from the
relying party: `prompt=none` must never interact. If the upstream cannot meet
the requirement, return the appropriate OpenID Connect error. Do not silently
retry through email OTP, a weaker session, or an untrusted mapping.

### Decision boundaries

This proposal covers authentication policy. It does not add resource step-up
under RFC 9470, an assurance-to-resource model, an assurance claim from an
external framework, a credential type, or a local identity pool.

## Cost

Estimate two to three weeks, with high authentication-policy and downgrade
risk. The floor and mapper changes must cover every authentication path.

Operators must define and maintain issuer-specific mappings, and some existing
sign-ins previously labelled MFA will become federated-only. Clients with a
strong floor may receive errors until a trusted upstream path is configured.
This is a deliberate refusal of unproven assurance, not a service regression.

The typed evidence changes sealed session, transaction, and code contents;
existing browser flows may need to restart after deployment. Tests need signed
upstream fixtures with exact
issuer and claim combinations. The implementation must avoid logging raw AMR,
authentication context, or identifying claims beyond existing private security
diagnostics.

## Acceptance tests

1. A weak requested alternative cannot satisfy a stronger client floor, for
   both a new flow and session reuse.
2. Unknown or unsatisfied optional preferences do not bypass the floor and do
   not reject a result that meets it. The preference order is attempted where
   supported.
3. Duplicate, unknown, missing, overlong, and single-OTP AMR inputs never
   produce federated MFA. A true allowlisted MFA pattern from the exact verified
   issuer does.
4. A raw upstream ACR has no local strength until its issuer-specific mapping is
   configured. An untrusted issuer or invalid signature never reaches mapping.
5. An unmet floor returns an appropriate OpenID Connect error and never falls
   back to email OTP or a weaker session.
6. `max_age`, `prompt=login`, and `prompt=none` are enforced with the typed
   requirement. A stale or insufficient session yields a non-interactive error
   for `prompt=none`.
7. An upstream prompt configuration cannot suppress required freshness, or make
   `prompt=none` interactive, or turn a silent request into a weaker success.
8. Essential claims-parameter ACR requests are refused as unsupported, and
   discovery does not advertise claims-parameter support.
9. Discovery advertises only locally achievable ACR values, and all supported
   adapters exercise the same assurance decisions.
10. Legacy sessions with synthetic MFA cannot survive the provenance check.
    Mapping removal and stronger client floors affect session reuse and code
    redemption; unchanged original evidence is never confused with local AMR.
11. Silent upstream renewal and callback time do not reset `auth_time`.
    Missing authentication time cannot satisfy freshness, while fresh OTP
    records its real verification time.

## Dated evidence

Evidence checked: 2026-09-08.

- [`src/acr.js`](../../src/acr.js) derives MFA from raw hint values or AMR array
  length and evaluates requested ACR values as alternatives.
- [`src/oauth/request.js`](../../src/oauth/request.js) appends a client floor to
  the alternative list rather than retaining it as an independent requirement.
- [`src/endpoints/authorize.js`](../../src/endpoints/authorize.js) uses that
  list for session reuse, routing, fallback, and upstream completion.
- [`src/upstream/index.js`](../../src/upstream/index.js) verifies the upstream
  token and forwards freshness and prompt controls, with configured prompt
  taking precedence.
- [`src/session.js`](../../src/session.js) retains `auth_time`, ACR, and AMR
  across a session and resets them on re-authentication.
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html),
  incorporating errata set 2, dated 15 December 2023,
  [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176.html), dated June 2017,
  [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470.html), dated September
  2023, and [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html),
  dated July 2025, were checked on the research date.
