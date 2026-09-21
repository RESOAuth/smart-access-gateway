# 0002. Refresh tokens, backed by the upstream token

Status: Proposed

## Context

[ADR 0005](../adr/0005-no-refresh-tokens.md) rejects a refresh token that
merely extends an old identity assertion. This proposal would supersede that
decision for explicitly enabled upstreams and clients by asking the upstream
to refresh on every SAG refresh.

Successful upstream refresh establishes that the upstream accepted a retained
credential. It does not universally prove current employment, licensing,
account status, or fresh MFA. An upstream may omit a new ID token, and any
`auth_time` in a refreshed ID token describes the original authentication.
Provider revocation rules vary: Microsoft documents cases where refresh tokens
survive password changes or single sign-out. See [OIDC Core section
12.2](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse)
and [Microsoft's refresh-token contract](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens).

SAG's replay store supplies claims and counters, not encrypted credential
records, atomic rotation, or revocation. Refresh needs a separate durable
credential-store contract and becomes an availability dependency.

## Proposal

### Eligibility and binding

Enable refresh only for operator-approved upstream registrations and clients.
Require explicit `offline_access` authorisation and the upstream's consent
requirements. Email OTP authentication has no upstream credential and cannot
produce a refresh token. Publish refresh support only where it is enabled.

Bind each grant to the exact upstream issuer, upstream registration, upstream
subject, SAG subject, downstream client, granted scopes, and resource. A
refresh cannot switch issuer, relink an account by email, expand scopes or
resources, or change the subject. Recheck current client and grant policy on
every use. Authenticate confidential clients using their registered method.

For each supported upstream, document its refresh response, rotation,
revocation, and consent behaviour. If a client requires current account or
entitlement checks beyond refresh acceptance, configure a specific supported
upstream check and deny when it is unavailable or fails. Do not advertise that
guarantee for a provider without such a contract.

### Credential storage and rotation

Return a random opaque SAG refresh handle with at least 256 bits of entropy.
Store only its hash. The record holds a grant-family id, generation, status,
client and identity bindings, scopes, resource, original authentication time
and evidence, creation and last-use times, expiry, and the encrypted upstream
refresh token. Never put the upstream credential in cookies, sealed browser
transactions, authorisation codes, logs, or downstream responses.

Encrypt credentials under a dedicated versioned key, separate from SAG's
master secret, with record identity and generation as authenticated data.
Support key rotation and deletion. Restrict store access independently from
the general replay store. Backups must not resurrect revoked grant families.

Use one atomic authority for each family. A conditional transition from
`active` to `refreshing` elects one request before contacting the upstream.
Rotate the local handle on every successful use and atomically persist the
new upstream credential, replacement handle hash, and generation before
returning any tokens. Retain consumed handle hashes through family expiry so
reuse revokes the entire family, including its latest handle. A concurrent use
is reuse, not a second successful refresh; clients must serialise refreshes.

An expired processing lease must not replay the upstream request. A timeout,
crash, indeterminate store write, or upstream success followed by local commit
failure can leave upstream rotation uncertain. Mark the family unusable, or
leave it locked until recovery does so, and require a new interactive grant.
Never restore an old credential or release the handle for another attempt.
Recheck family status and generation during the final commit so concurrent
revocation cannot be undone by a successful upstream response.

### Freshness, expiry, and revocation

Validate a renewed ID token against the bound issuer, subject, registration
audience, signature, and OIDC refresh rules. Preserve original `auth_time`;
token issuance is not new authentication or MFA. If no ID token is returned,
retain only evidence whose configured validity still permits issuance. A
requirement for newer authentication or claims needs the documented upstream
check or a new interactive flow. Refresh cannot invent fresh evidence.

Require finite idle and absolute lifetimes at enablement; use one day idle
and seven days absolute as initial maxima, further capped by known upstream
expiry and client policy. Rotation does not extend the absolute deadline.
Apply the normal access-token and claim-release limits on every issuance.
This follows [RFC 9700 section
4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14).

Provide authenticated revocation for a client to revoke its own grant and an
operator path to revoke families by account, client, or upstream registration.
Link grants to their originating SAG session: local scoped logout revokes its
affected families, and global logout revokes all families linked to that
session. Upstream refresh rejection also closes the family. Local revocation
must succeed durably before success is reported; upstream revocation, where
supported, is additional and cannot substitute for it.

Store outages deny refresh and revocation success. They must not silently
issue a token or report a completed revocation. Already issued access and ID
tokens remain valid until expiry under SAG's existing token contract; refresh
revocation does not terminate sessions already established at relying parties.

## Cost

This is a credential-management subsystem, not one extra replay record. It
requires production storage, encryption and key rotation, concurrency and
crash recovery, revocation endpoints, provider-specific integration tests,
operational recovery, and documentation across all adapters. No legacy refresh
tokens exist to migrate; the feature can introduce its complete contract at
once while SAG is pre-release.

Acceptance requires concurrent rotation and reuse tests, revocation racing a
refresh, every crash boundary around upstream rotation and local commit,
missing or changed upstream ID-token claims, unavailable entitlement checks,
idle and absolute expiry, store outages, key rotation, and proof that secrets
never enter browser state or diagnostics. Live provider tests must establish
the documented guarantees before that provider is enabled.
