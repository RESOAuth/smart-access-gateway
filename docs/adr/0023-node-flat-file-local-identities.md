# 0023. Local identities are operator-managed, Node-only flat files

Date: 2026-09-22
Status: Accepted

## Context

SAG normally proves an address through an upstream identity provider or an
email code. Some small, self-hosted deployments instead need a handful of
accounts whose credentials they manage themselves. RFC 0014 proposed a full
identity pool: portable database backends, registration, address
verification, recovery and reset flows, WebAuthn, account lifecycle APIs,
audit integration, and multi-instance concurrency. That is a new identity
management product, not a small authentication option, and is disproportionate
for this need.

A flat file holding a password verifier is much smaller, but it changes two
security contracts. First, a password for a record labelled with an email
address does not prove control of that mailbox. SAG must not convert local
credential possession into `email_verified: true`. Second, using an ordinary
digest of an address as a filename would let anybody who obtained a directory
listing test likely addresses offline. The records also contain TOTP seeds and
possibly upstream refresh tokens, which need confidentiality rather than
password hashing.

## Decision

Add one deliberately narrow local identity backend. It is available only in
the Node adapter and holds one JSON file per operator-provisioned identity.
There is no public registration, reset, recovery, email-change, or account
management API. An operator creates new records with the supplied tool; it
refuses to overwrite an address, so replacement is a deliberate offline
operation. The operator protects the directory as credential material.

The filename is a full HMAC-SHA-256 of the canonical address. Its key is
derived for this purpose from `SUBJECT_SALT`; the address is not stored in the
record or filename. `SUBJECT_SALT` is therefore both the subject key and the
local identity index key and must be supplied explicitly and never rotated.
Values shorter than 16 characters are refused when this backend is enabled;
this narrows [ADR 0017](0017-short-subject-salts-warn-without-forcing-rotation.md)
without forcing an existing deployment to rotate - it can leave local
identities disabled.

The record contains a version, a stable random local identity id, revision and
security-version counters, an optional disabled marker, bounded profile
claims, and credentials. Passwords and single-use backup codes are retained
only as bounded PHC-format Argon2id verifiers. A durable MFA-required marker
prevents exhaustion of the last backup code from silently downgrading the
account to password-only. TOTP seeds and upstream refresh
tokens are AES-256-GCM sealed under purpose-specific keys derived from
`SAG_SECRET`, bound to the local identity and credential or link id.
`SAG_SECRET_PREVIOUS` can open values during a planned rotation. Before the
previous secret is removed, an offline, idempotent rekey command conditionally
reseals every durable value under the current secret.

Local sign-in is public routing policy, configured by domain, rather than a
probe for whether a record exists. Missing, disabled, malformed, and
wrong-password records receive the same page and a real dummy Argon2id check.
Per-address and per-network attempt limits use the state store and fail closed,
so enabling local authentication requires a state-store backend. TOTP time
steps and backup-code consumption update the record conditionally, preventing
reuse within one process. Password-only and password-plus-second-factor have
their own local `acr` values; neither silently satisfies a request for a
federated authentication context.

A local credential proves only possession of that credential. The resulting
token may contain the canonical address used to locate the record, but omits
`email_verified` entirely. This is not `email_verified: false`: absence says
that this authentication supplied no address-verification evidence.

Derive `sub` for a local identity from its stable random id, the configured
public or pairwise subject policy, and `SUBJECT_SALT`, not from its address.
This supersedes
[ADR 0011](0011-subject-derived-from-the-verified-address.md) for local
identities only. Sessions and authorisation codes carry the local id and
security version, and authoritative record state is checked when a local
session is reused and when a code is redeemed. Disabling a record or changing
its security version therefore invalidates those outstanding credentials;
tokens already issued retain their normal lifetime.

An operator may explicitly link a local identity to an upstream identity by
recording the configured upstream id, its verified issuer, and its exact
subject. Matching an email address alone never links accounts. A successful
upstream sign-in converges on the local identity only when all three values and
the canonical address match. It then uses the same stable local `sub` and can
emit `email_verified: true`, because the upstream flow supplied the address
evidence. If that exact exchange returns a refresh token, SAG seals it into
the link; it never exposes the token to the browser or relying party. This does
not reverse [ADR 0005](0005-no-refresh-tokens.md): SAG still issues no refresh
token of its own.

Files are at most 64 KiB, regular files rather than symlinks, opened
non-blocking so a special file cannot occupy the filesystem worker pool,
written with mode `0600`, and replaced through a flushed temporary file and
atomic rename.
A newly created directory uses mode `0700`; on POSIX, existing directories and
records with any group or other permission bits are refused. Windows access
control remains the operator's responsibility. A revision comparison provides
compare-and-swap semantics inside one process. The in-process lock cannot make
two Node processes sharing a directory into one writer, so a local identity
directory has exactly one SAG writer. This is not a shared identity-store
backend and is not enabled on Workers or Lambda.

Version 1 records use one approved Argon2id profile - 64 MiB, three passes,
and one lane - so an existing account and the missing-account dummy perform
equivalent password work. Node's built-in `crypto.argon2` runs that work with
bounded concurrency. Local identities therefore require Node.js 24.7.0 or a
newer release that provides that API. SAG takes no native or WASM password
dependency for the other adapters.

## Consequences

Small installations get private-at-rest local credentials without deploying a
database. A stolen directory does not reveal addresses through filenames;
passwords and backup codes still have Argon2id's offline-guessing defence, and
decrypting TOTP or upstream credentials also requires `SAG_SECRET`. An
attacker who has both the files and the relevant secrets has the credential
material, so backups, file permissions, the subject salt, and current and
previous master secrets need the same protection.

The feature is intentionally operational rather than self-service. Losing a
password or factor requires an operator to replace the record. Changing the
canonical address changes its lookup filename but not its random id; doing
that safely is an offline administrative operation, not an exposed workflow.
There is no WebAuthn, enrolment UI, automatic password rehash, account
registration, public recovery, audit log, shared writer, or portable backend.
A deployment needing those things should use an upstream identity provider or
build the broader identity-store design separately.

Every local authentication depends on filesystem availability and on a state
store for attempt limits. TOTP verification, backup-code use, refresh-token
capture, disabling, and security-version changes also need successful writes
and fail closed on conflicts. Operators must back up the whole directory with
`SUBJECT_SALT`, `SAG_SECRET`, and any still-needed `SAG_SECRET_PREVIOUS`, and
must restore them as one set. See
[local-identities.md](../local-identities.md) for configuration and the record
generation workflow.
