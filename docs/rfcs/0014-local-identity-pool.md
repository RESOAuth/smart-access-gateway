# 0014. Local identity pool

Status: Proposed

## Context

SAG currently authenticates an email address through a configured upstream or
an email OTP. It does not own a user record, a password verifier, or an
authenticator. That is sufficient for a stateless identity proxy, but it
cannot serve deployments that need local accounts, locally managed profile
attributes, password sign-in, or phishing-resistant and app-based MFA.

This is materially larger than adding another upstream. An upstream returns a
verified address and claims for one transaction. A local account needs durable
lookup by a normalised address, account lifecycle state, credential and MFA
enrolment records, recovery and reset policy, and concurrency controls. The
existing state store (`src/store/index.js`) only provides expiring atomic
claims and counters; it is not a suitable identity database.

The feature also changes the security boundary. A password database is a
high-value breach target, and WebAuthn requires origin-bound challenge state,
CBOR parsing, signature verification, and credential-sign-count handling.
Argon2id is not provided by the Web Crypto API, so its implementation must be
portable across the Cloudflare Worker, Lambda, and Node adapters without
silently reducing the password defence on one platform.

## Proposal

Add `local` as an authentication method selected by address routing. Keep the
existing sealed transaction, session, authorisation-code, subject, and claim
pipeline: a successful local authentication produces the same session shape,
with `amr` and `acr` describing the actual factors. Local accounts must never
be represented by password material in a transaction, cookie, authorisation
code, log, or client-visible error.

### Storage boundary

Introduce a separate identity-store interface, alongside rather than inside
the replay store. It needs at least:

- lookup and create/update by a canonical email address, with a stable opaque
  user id in an explicit identity-store tenancy namespace;
- verified-address evidence, its source and timestamp, and an account security
  version independent of the password hash version;
- conditional writes for password-version changes, account lock state, and
  authenticator sign counters;
- storage of a PHC-format Argon2id verifier, never plaintext or an application
  reversible encryption of the password;
- bounded, namespaced attributes with an explicit allow-list for outbound OIDC
  claims;
- a collection of MFA credentials, including WebAuthn credential id, public
  key, RP id, transports, sign count, backup eligibility and state, display
  name, and timestamps, plus TOTP
  secret metadata and recovery-code hashes;
- deletion, disablement, password reset, and credential revocation semantics;
- audit events or an equivalent append-only integration without recording
  passwords, OTPs, TOTP secrets, or WebAuthn assertions.

Do not implement this on the existing DynamoDB table or Durable Object used by
`STATE_STORE_BACKEND`. Those backends may be reused behind a new interface,
but identity records need different keys, retention, indexing, size, backup,
and availability guarantees. A deployment with local authentication must fail
closed at startup unless an identity store is configured. A single-process
memory implementation may exist for tests and development only.

### Authentication flow

Extend `src/endpoints/authorize.js` and the UI pages with stages for local
password and MFA. The first factor should be checked only after the address
has been normalised and the account lookup is complete. Unknown address,
disabled account, wrong password, and locked account must have the same
user-facing result and broadly equivalent work, preserving the enumeration
defence in ADR 0003. Per-address and per-network throttles must be atomic and
independent of sealed transaction counters.

An account's policy determines whether MFA is required. If more than one MFA
credential is enrolled, offer the enrolled methods without disclosing account
existence. The transaction records only an opaque user id, the selected
factor, a challenge identifier, and an expiry. It never records a password,
TOTP secret, or private key.

On success, use `newSession`/`reauthenticate` with local `amr` values such as
`pwd` and `otp`, with WebAuthn values mapped from verified ceremony evidence,
and an `acr` that distinguishes password-only from MFA and WebAuthn. Local
attributes become claims only through the existing profile allow-list and size
limits. Derive `sub` from the identity-store tenancy namespace and stable local
user id, applying the existing public or pairwise client policy. It remains
stable across email changes. This deliberately supersedes [ADR
0011](../adr/0011-subject-derived-from-the-verified-address.md) for local
accounts. Local and upstream identities sharing an email remain separate;
the initial feature has no implicit linking or subject migration. SAG is
pre-release, so define this contract before enabling local accounts.

### Address verification and account lifecycle

SAG currently emits `email_verified: true` from its verified-address pipeline.
Knowing a password for a record containing an email does not prove control of
that address. Registration, import, and email change must establish durable
address-verification evidence before local authentication can issue identity
tokens. An operator import may attest an address only under a documented
authority for that domain; merely creating a record is not verification.
Pending or unverified accounts cannot enter the existing issuance pipeline.

Choose one authenticated operator management/import surface initially. Email
changes require verification of the new address before activation, and must
not transfer an account merely because another record uses the same address.
Define canonicalisation and atomic address uniqueness within the tenancy.

Carry the local user id, tenancy, and account security version through the
session, transaction, and authorisation code. Read authoritative account state
on session reuse, credential completion, and code redemption. Disablement,
password reset, address change, MFA removal, and credential revocation increment
that version and invalidate older sessions and outstanding codes. Account
deletion has the same effect; identifiers must never be reassigned. Store
outages deny these operations, including silent session reuse.

An issuance authorised immediately before an account change can still finish;
tokens already issued remain valid until their expiry under the existing token
contract. Account changes do not terminate relying-party sessions themselves.
Document this residual lifetime instead of promising immediate token revocation.

### WebAuthn

Implement WebAuthn registration and assertion ceremonies as same-origin,
CSRF-protected POST flows. Generate high-entropy, single-use challenges and
bind them to the transaction, user, RP id, origin, and intended ceremony in
the identity store. Validate `clientDataJSON`, type, challenge, origin, RP ID
hash, user presence, and user verification before accepting an assertion.
Support the WebAuthn algorithms and authenticator data formats that the chosen
portable library can verify; do not describe U2F as a separate cryptographic
path unless legacy U2F credentials are an actual requirement.

Validate and retain backup eligibility and state as specified by
[WebAuthn](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup). A synced
passkey must not automatically be labelled `hwk` or non-exportable. Derive any
MFA or phishing-resistance claim from the verified ceremony, user-verification
policy, and supported authenticator evidence, not credential presence alone.

Update the stored sign counter conditionally. A counter regression is a
possible cloned authenticator signal, not an automatic account takeover proof;
define whether to reject, require recovery, or mark the credential suspect.
Credential deletion and replacement must be authenticated by a stronger
existing factor or an explicitly designed recovery flow.

### TOTP and recovery

Generate TOTP secrets with the platform CSPRNG, display them only during
enrolment, and store them encrypted at rest under a versioned dedicated key or
in a dedicated secret service. Include key rotation and restore procedures.
Use a constant-time comparison, a defined time step and skew, and a short
replay window keyed by user and time-step in an atomic store. Provisioning
must not log an `otpauth` URI or secret. Recovery codes should be generated
once, displayed once, and stored only as salted password-style hashes with
single-use claims.

Password change, reset, MFA enrolment, MFA removal, email change, and account
disablement need authenticated management endpoints or an external admin
interface. The first implementation should choose one supported management
surface rather than expose an unscoped public CRUD API. Reset and recovery
must be specified before password sign-in is enabled; email OTP alone is not
automatically an acceptable recovery factor.

### Configuration and discovery

Add a `REQUIRE_LOCAL_IDENTITY_STORE` fail-fast flag only if local identity
configuration can otherwise be disabled by omission, following ADR 0007.
Document every new variable in `docs/configuration.md`, including store
backend, Argon2id parameters, local routing, password policy, lockout and
throttle limits, WebAuthn RP id/origins, TOTP skew, recovery policy, and
attribute-to-claim policy. Discovery should advertise supported authentication
context only if the deployment can actually complete it; do not advertise
WebAuthn or TOTP merely because a library is installed.

### Phased delivery

1. Define the identity-store tenancy and one production backend, account schema,
   canonicalisation, verified-address gate, stable subjects, security versions,
   lifecycle, and the authenticated management/import and recovery paths.
2. Add password hashing, lockout/throttling, local attributes, and password
   authentication only after those lifecycle and recovery controls work.
3. Add TOTP enrolment, verification, replay prevention, and recovery codes.
4. Add WebAuthn ceremonies, credential lifecycle, counter policy, and browser
   compatibility coverage.
5. Add backup/restore tooling, operational documentation, audit export, and local
   stack tests for every adapter.

## Cost

This adds a database-like subsystem to a project whose central advantage is
statelessness. Operators will need backups, encryption and key rotation,
access controls, retention/deletion procedures, schema migrations, monitoring,
and an incident response plan for account and authenticator compromise. A
shared identity store becomes a hard availability dependency for local sign-in
and account management.

The implementation will touch `src/config.js`, `src/context.js`, a new
`src/identity-store/` area, `src/store/` for rate and replay primitives,
`src/endpoints/authorize.js`, new endpoint modules and routes, `src/session.js`,
`src/identity.js`, `src/profile.js`, `src/acr.js`, UI pages and CSP rules, all
three adapters where bindings are declared, and the relevant test harnesses.
It will require a reviewed Argon2id and WebAuthn dependency or a maintained
portable implementation. Native-only packages are not acceptable for the
Worker adapter; large WASM packages have cold-start, bundle-size, and memory
costs that need measurement.

Tests must cover malformed and adversarial password inputs, constant-time
failure paths, parameter upgrades, lockout races, unknown-account
enumeration, password reset abuse, TOTP drift and replay, recovery-code
single-use behaviour, WebAuthn origin/RP/challenge/signature failures,
counter races, session `acr`/`amr` and claims, subject stability, logout,
prompt and `max_age`, and store outages. The existing `test/flow.test.js`,
`test/session.test.js`, `test/identity.test.js`, `test/profile.test.js`,
`test/state-store.test.js`, and adapter/local-stack tests are the natural
starting points; new tests must drive `handleRequest` rather than mock SAG's
own code.

Before implementation is accepted, operators must decide the identity-store
backend and tenancy model, whether local accounts are opt-in per domain or
deployment-wide, password reset/recovery policy,
required MFA policy, WebAuthn RP/origin configuration, accepted algorithms,
attribute schema and claim mapping, lockout versus progressive throttling, and
the retention and audit requirements. These decisions should become ADRs when
the proposal is accepted.

Acceptance also requires tests for unverified and imported addresses, email
change, same-email upstream/local separation, tenancy isolation, deletion and
identifier reuse, disablement and reset racing code redemption, stale session
reuse, and identity-store outage. Verify passkey backup flags and assurance
mapping separately from signature success. No phase may expose password
sign-in before verification, lifecycle, and recovery controls are complete.
