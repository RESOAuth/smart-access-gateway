# 0025: Plaintext local TOTP seeds

## Context

[ADR 0023](0023-node-flat-file-local-identities.md) sealed TOTP seeds with
`SAG_SECRET`. An independent identity-management application would therefore
need the same key that opens gateway sessions, transactions, and grants just
to enrol an authenticator. The operator prefers a private credential file
over coupling that application to gateway sealing keys.

## Decision

Supersede only the TOTP-sealing part of ADR 0023. Store each TOTP `secret` as
validated plaintext Base32 in the owner-only local identity record. Preserve
credential ids, algorithm and length controls, single-use time-step tracking,
and revision-checked writes. Passwords and backup codes remain Argon2id
verifiers; upstream refresh tokens remain purpose-bound sealed values.

Provisioning a password, TOTP seed, backup codes, or upstream links without
refresh credentials does not require `SAG_SECRET`. Filename derivation still
requires `SUBJECT_SALT`. Refresh-token provisioning and offline rekey continue
to require the gateway's sealing keys. TOTP verification and storage do not
change when those keys rotate.

The unreleased sealed-TOTP draft is not a second supported storage format.
Existing draft records need an offline conversion or a replacement seed.
Converting an existing seed preserves its replay marker; replacing one also
increments the security version to invalidate existing sessions and grants.

## Consequences

An independent manager need not hold the gateway's sealing key, but read
access to a record now reveals its TOTP seed. File permissions, encrypted
backups, and careful log handling are the protection boundary. A stolen seed
remains usable until it is replaced, regardless of master-secret rotation.

The single-writer restriction remains: this decision does not add concurrent
editing, a management API, self-service enrolment, or distributed locking.
