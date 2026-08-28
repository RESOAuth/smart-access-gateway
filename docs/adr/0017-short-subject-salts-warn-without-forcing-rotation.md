# 0017. Short subject salts warn without forcing rotation

Date: 2026-08-27
Status: Accepted

## Context

A weak `SUBJECT_SALT` makes an offline address-to-`sub` dictionary cheaper, but
changing an existing salt gives every person a new subject and orphans their
accounts at every relying party. A new hard minimum would force that migration
on upgrade.

## Decision

Emit an operator-only start-up warning when `SUBJECT_SALT` is shorter than 16
characters. Continue using the configured value unchanged. New deployments
should use at least 16 random characters, and the existing key-generation path
continues to generate more.

## Consequences

Existing subject identifiers remain stable and an upgrade is not an account
migration. A weak existing salt remains weak until the operator coordinates a
deliberate migration with every relying party.
