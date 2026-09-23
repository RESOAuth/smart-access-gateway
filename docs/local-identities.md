# Local identities

The Node adapter can authenticate a small set of identities from private JSON
files. This is for operator-provisioned accounts on a single SAG process. It
is not registration, a self-service directory, or a portable identity-store
backend. The boundary and its reasons are in
[ADR 0023](adr/0023-node-flat-file-local-identities.md).

## Before enabling it

Local authentication requires:

- Node.js 24.7.0 or newer with `crypto.argon2`;
- a persistent directory with exactly one SAG process writing it;
- an explicit, high-entropy `SUBJECT_SALT` which will never rotate;
- the same `SAG_SECRET` used by the running instance, so the provisioning tool
  can seal TOTP and upstream credentials; and
- a `STATE_STORE_BACKEND`, because password and second-factor attempt limits
  fail closed when there is no atomic counter.

`memory` is an adequate state store for a single-process installation. It
resets its counters on restart and does not make a second process safe to add.
Use a rate limit in the reverse proxy as another layer; the application limits
are not a replacement for one.

The Node adapter deliberately ignores `X-Forwarded-For` for its network
counter and uses the immediate socket address. Behind a reverse proxy, every
request from that proxy therefore shares one bucket. Set
`LOCAL_AUTH_NETWORK_MAX_ATTEMPTS=0` to prevent one caller from exhausting that
shared bucket, and enforce a real client-address limit at the trusted proxy
itself. Keep the application limit enabled when clients connect directly.

Enable the backend and name its public routing scope:

```sh
LOCAL_IDENTITIES_BACKEND=file
LOCAL_IDENTITIES_DIR=/var/lib/sag/local-identities
LOCAL_IDENTITY_DOMAINS=example.com
SUBJECT_SALT=<at-least-32-random-bytes>
STATE_STORE_BACKEND=memory
```

`LOCAL_IDENTITY_DOMAINS` is public policy, not a list inferred from the files.
An exact name serves that domain. `*.example.com` serves it and its
subdomains; `*` serves every domain and should be set only deliberately. Every
address in scope gets the same password page, whether its record exists,
is disabled, or is malformed. Eligible upstreams remain available as
alternatives on that page.

For record lookup, canonical means trimmed and case-folded; a plus tag is
retained. `jamie+one@example.com` and `jamie+two@example.com` therefore name
different local records even if a relying party's `SANITISE_PLUS_EMAILS`
policy presents both without the tag. Their stable local subjects remain
different because their record ids differ.

The complete limits and defaults are in
[configuration.md](configuration.md#local-identities).

## Provision a record

Use `tools/generate-local-identity.js`; do not construct password hashes or
sealed values by hand. Run it with the exact `SAG_SECRET`, `SUBJECT_SALT`, and
identity directory used by the instance. The password is accepted only on
standard input, never as an argument:

```sh
printf '%s\n' "$LOCAL_IDENTITY_PASSWORD" |
  npm run generate-local-identity -- \
    --email jamie.taylor@example.com \
    --directory /var/lib/sag/local-identities \
    --password-stdin \
    --totp \
    --backup-codes 10
```

`LOCAL_IDENTITIES_DIR` can supply the directory instead. `--totp` is optional;
`--backup-codes` accepts zero to twenty. The password must contain 12 to 1,024
UTF-8 bytes. Run `npm run generate-local-identity -- --help` for the complete
interface.

The tool prints newly generated TOTP and backup-code material once; capture it
through the intended secure handover channel. Its output is secret and must
not enter a build log. Neither the plaintext password nor plaintext factor
secrets belong in the JSON file, shell history, logs, or a source repository.

Optional profile claims come from a JSON object passed with `--claims`. Only
the fixed OpenID Connect profile allow-list is accepted, for example:

```json
{
  "name": "Jamie Taylor",
  "preferred_username": "jamie.taylor"
}
```

The running instance applies its own `PROFILE_CLAIMS` and `PROFILE_PICTURE`
filter again, so storing a permitted claim does not force it into a token.

The generator refuses to overwrite an existing address and has no replace
mode. To change credentials, stop the SAG writer, preserve the existing stable
`id` and filename, increment `revision`, and increment `security_version` in
the replacement record. The security-version change is what invalidates old
sessions and unredeemed codes. A replacement with a new random id also gives
the person a new `sub` at every relying party.

Generated sealed values are bound to the random id created with them, so do
not copy a generated TOTP or refresh-token ciphertext onto a record whose
`id` differs. A password verifier is not identity-bound and can be generated
in a separate empty directory, then copied into a stopped writer's existing
record. Write the finished JSON through a mode `0600` temporary file and
atomic rename; do not edit a live record in place.

Restart is not needed for a newly created file: the backend reads the record
on authentication.

## What the file contains

The filename is not an ordinary hash. It is the full lower-case
HMAC-SHA-256 of the canonical email address under a key derived from
`SUBJECT_SALT`, followed by `.json`. This prevents a leaked directory listing
being tested against a list of likely addresses. The email itself is not in
the document.

The versioned JSON record contains:

- a stable, random identity id, revision, and security version;
- an optional disabled marker;
- a durable MFA-required marker when any second factor was provisioned;
- one PHC-format Argon2id password verifier;
- bounded OpenID Connect profile claims;
- up to five TOTP credentials, whose seeds are purpose-bound AES-256-GCM
  values sealed from `SAG_SECRET`;
- up to twenty single-use backup codes, each retained only as an Argon2id
  verifier; and
- up to twenty explicit upstream links, each matching a configured upstream
  id, verified issuer, and exact upstream subject. A retained refresh token is
  sealed and bound to that link.

Version 1 records require Argon2id at 64 MiB, three passes, and one lane. A
different cost profile is rejected so present and missing identities perform
equivalent password work. SAG validates the PHC parameters before allocating
work, caps parallel operations with
`LOCAL_ARGON2_CONCURRENCY`, and performs a real dummy verification for an
unknown or unusable record. Files over 64 KiB, symlinks, non-regular files,
invalid JSON, and fields outside the bounded schema are refused.

The adapter creates the directory as mode `0700` and writes replacement files
as mode `0600`. On POSIX it refuses existing directories and records with any
group or other permission bits; on Windows the operator must apply equivalent
access control. It flushes a temporary file and atomically renames it, with a
revision comparison under an in-process lock. That comparison is not a
distributed lock: never point two SAG processes or a separate live editor at
the same writable directory.

## TOTP and backup codes

A record with any TOTP credential or backup code requires a second factor
after its password. TOTP accepts the configured number of time steps either
side of the current one and records the accepted step so the same value cannot
be replayed. A backup code is selected by its public short id, verified with
Argon2id, and removed through a conditional write before authentication
completes.

Give generated backup codes to the account holder once and keep no plaintext
copy unless the recovery policy deliberately calls for an operator-held copy.
Using the last backup code does not enrol a replacement factor. The durable
MFA policy remains set, so an identity with no remaining factor is locked
rather than downgraded to password-only. This feature has no self-service
factor-management or password-reset flow; the operator must prepare an offline
replacement record.

## Link an upstream identity

An upstream link is explicit. Put an array in a JSON file and pass it with
`--upstreams`. One link has this shape:

```json
[
  {
    "id": "work",
    "upstream": "microsoft/examplecom",
    "issuer": "https://login.microsoftonline.com/tenant-id/v2.0",
    "subject": "opaque-upstream-subject",
    "refresh_token_env": "WORK_REFRESH_TOKEN"
  }
]
```

`upstream` is `<provider>/<slug>` from the corresponding
`UPSTREAM_<PROVIDER>_<SLUG>_*` configuration. `id` names this link within the
record. `refresh_token_env` is optional: it names an environment variable whose
value the tool seals. A plaintext `refresh_token` in the JSON is rejected so a
long-lived credential does not enter the source file.

Supply all of:

- the upstream id shown by SAG's configuration;
- the upstream token's verified `iss`;
- the exact upstream `sub`; and
- the same canonical email address as the local record.

At callback time SAG requires all four to match. Same-email accounts are never
linked implicitly. On a match, the upstream sign-in uses the stable local
identity id for `sub`; if the exchange supplies a refresh token, SAG seals it
into that link, whether or not one was provisioned initially. The token is
stored for that upstream relationship only and is never returned to the
browser or relying party. SAG does not issue its own refresh tokens.
The retained credential is not consumed by a background refresh flow in this
release; storing it does not extend a SAG session or token.

## What a relying party sees

When the relying party asks for the email scope, relevant claims from
password-only authentication include:

```json
{
  "acr": "urn:sag:acr:local-password",
  "amr": ["pwd"],
  "email": "jamie.taylor@example.com"
}
```

TOTP adds `otp` and `mfa` to `amr`; a backup code adds `recovery` and `mfa`.
Both use `urn:sag:acr:local-mfa`. Most importantly, local-only authentication
omits `email_verified`. Knowing the credentials for a record labelled with an
address is not proof of control of its mailbox.

An exact linked-upstream authentication can emit `email_verified: true`,
because that flow independently verified the address. Both routes use the
same public or pairwise `sub`, derived from the record's stable random id. The
upstream's `sub` is link evidence and never becomes SAG's subject.

Local authentication contexts do not silently satisfy federated contexts. A
relying party which asks for `urn:sag:acr:federated` still requires an upstream
sign-in even when the local record has TOTP.

To accept either local or federated MFA, request `urn:sag:acr:mfa`. Local
password plus TOTP or a backup code satisfies that requirement and still
returns `urn:sag:acr:local-mfa`, without `email_verified`. A password alone
cannot satisfy it.

The password page supplies the selected username and `current-password`
autocomplete hints. The MFA page gives authenticator codes a numeric keypad
and `one-time-code` autocomplete; backup codes have a separate text field
under **Use a backup code**, so their letters and hyphens remain enterable.
Both forms work without JavaScript. Codes are submitted explicitly, because
six digits may be only the prefix of a configured eight-digit TOTP.

## Disable, replace, back up, and restore

SAG checks authoritative local state when it reuses a session and when an
authorisation code is redeemed. Setting `disabled: true`, deleting the record,
or incrementing `security_version` invalidates its sealed sessions and
unredeemed codes. Tokens already issued keep their ordinary short lifetime.
Changing only `revision` coordinates a file update and does not revoke
credentials.

Back up the directory, `SUBJECT_SALT`, `SAG_SECRET`, and any still-active
`SAG_SECRET_PREVIOUS` as one set. The salt is required to find a record and to
reproduce its `sub`; the master secret is required to open TOTP and upstream
credentials. A backup missing either is not a restorable identity store.

Changing an address means creating the HMAC-named file for the new canonical
address with the same stable identity id, then removing the old file while SAG
is stopped. It does not verify the new mailbox. There is intentionally no live
rename workflow, automatic merge, or reuse of a deleted identity id.

Master-secret rotation needs extra care because local TOTP and refresh
credentials outlive a session. Keep the old secret in `SAG_SECRET_PREVIOUS`
until the offline rekey has completed:

```sh
SAG_SECRET="$NEW_SAG_SECRET" \
SAG_SECRET_PREVIOUS="$OLD_SAG_SECRET" \
SUBJECT_SALT="$UNCHANGED_SUBJECT_SALT" \
  npm run generate-local-identity -- \
    --rekey \
    --directory /var/lib/sag/local-identities
```

Stop or drain the one SAG writer first. The command conditionally replaces
every TOTP and refresh-token ciphertext still using the previous secret,
leaves `security_version` unchanged, and is safe to run again. It refuses to
continue past a malformed or undecryptable record; fix that error and rerun it
before removing `SAG_SECRET_PREVIOUS`. The full order is in
[operations.md](operations.md#rotating-the-master-secret).
