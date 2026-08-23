# 0004. Session scope is a deployment choice, and sign-out asks before it affects more than one relying party

Date: 2026-08-23
Status: Accepted

## Context

SAG can run as a single shared identity for every relying party on a
deployment, or give each relying party its own session, and different
deployments genuinely want opposite things: an enterprise wants one sign-in
across many internal apps, a multi-tenant instance wants one relying
party's session to say nothing about another. On top of that, signing out
is ambiguous whenever a session is shared: does a relying party asking to
sign out mean "just me" or "everywhere"?

## Decision

Make session scope an explicit per-instance setting, `SESSION_SCOPE=shared`
or `SESSION_SCOPE=rp`, rather than picking one and living with it. A
per-RP session gets a cookie name that is a hash rather than a derivable
client id, so the cookie jar itself does not enumerate which applications
somebody uses.

For sign-out, add an interstitial that is asked or skipped based on what is
actually true about the session: `LOGOUT_CONFIRM=auto` (the default) asks
only when the session is shared, so a person is told that one application
is signing them out of every one of them; `always` and `never` override
that for a deployment with stronger opinions either way. A relying party
can override the instance default with `CLIENT_<SLUG>_LOGOUT_CONFIRM` - the
override changes whether the question is asked, never how much is actually
cleared, so a relying party cannot make a shared sign-out look like a
narrow one just by asking a different question.

## Consequences

`prompt=none` and `prompt=consent` behaviour follows the same scope
setting - a shared session can answer `prompt=none` for a relying party
that never signed the person in itself - so the two have to be reasoned
about together rather than independently. See
[configuration.md](../configuration.md) for the session variables in full.
