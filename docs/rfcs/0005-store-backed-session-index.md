# 0005. A store-backed session index, for sign-out everywhere

Status: Proposed

## Context

Sessions stay in the cookie, by design, so "sign this person out everywhere,
now" has no answer that does not depend on the browser cooperating.

## Proposal

Not a change to where sessions live - they stay in the cookie - but an
index in the optional state store, keyed by subject, that a global sign-out
can consult and revoke against. This is the same state question as refresh
tokens ([RFC 0002](0002-refresh-tokens-backed-by-upstream.md)) and should be
decided alongside them, since both add a state-store record that ties back
to a subject.

## Cost

A new state-store record type and a revocation check added to session
validation on every request once the store is enabled, so its read latency
becomes part of every request's critical path.
