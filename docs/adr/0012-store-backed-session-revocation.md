# 0012. A state-store marker revokes every copy of a signed-out session

Date: 2026-08-27
Status: Accepted

## Context

Clearing a session cookie signs out one browser, but a copied sealed cookie
remains valid until its idle or absolute deadline. The cookie cannot record its
own revocation because the holder controls which copy is presented.

## Decision

When a state store is configured, logout claims a marker keyed by the session's
random `sid`. The marker's TTL is the remaining absolute session lifetime, so
it disappears when the session could no longer be accepted anyway. Every
session read checks the marker, and a store failure fails closed. Without a
state store, logout retains the local cookie-only behaviour.

Use a per-session marker, not a per-subject index. Logout revokes copies of the
session being ended without creating an inventory of people or a mechanism for
an administrator to enumerate their sessions.

## Consequences

A configured state store is now on the session request path as well as the code,
client-assertion, and OTP paths. Its read latency and availability therefore
affect existing sessions. The marker consumes one TTL record per signed-out
session, and every backend removes it automatically after the absolute expiry.
There is still no subject-wide "sign out every device" operation.
