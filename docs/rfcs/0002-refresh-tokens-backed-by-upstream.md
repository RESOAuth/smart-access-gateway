# 0002. Refresh tokens, backed by the upstream token

Status: Proposed

## Context

See [ADR 0005](../adr/0005-no-refresh-tokens.md) for why a bare refresh
token was rejected. The feature that was asked for instead is a genuine
refresh: hold the *upstream* refresh token, and when the relying party
refreshes, refresh against Microsoft or Google as well. That turns a
refresh into a real question - is this person still employed, still
licensed, still not disabled - rather than a longer echo of an old answer.

Refresh tokens imply revocation, and revocation implies state, which is the
one thing SAG has carefully avoided. Holding an upstream refresh token is a
much bigger promise than holding a counter: it is long-lived credential
material for somebody else's identity provider, so it needs encryption at
rest under a key that is not the master secret, a revocation path, and an
answer to what happens when the store is unavailable. Realistically it is a
store-backed feature that a deployment turns on, not a default.

## Proposal

Refresh token is an opaque handle; the record holds the encrypted upstream
refresh token, the subject, the client, and a rotation counter; rotation on
every use with reuse detection, which is what catches a stolen handle. Email
OTP sessions get no refresh token at all, because there is no upstream to
ask.

## Cost

A new state-store record type, encryption under a dedicated key rather than
the master secret, and a revocation path that has to have a defined answer
for "the store is unavailable". Not a default: a deployment opts in.
