# 0005. No refresh tokens: a short-lived access token scoped to `/userinfo` only

Date: 2026-08-23
Status: Accepted

## Context

A relying party that wants a longer-lived session normally re-runs the
authorisation flow, which is cheap for SAG because a session cookie lets it
answer `prompt=none` without showing anything. That stops working once the
browser is not in the loop: a background job, a mobile client closed for a
week, an API call in the middle of the night. The obvious answer is an
OAuth refresh token, and it was considered and explicitly not built as a
bare "reissue what was said before" mechanism, because that would only
re-assert a decision SAG already made without ever re-checking it.

## Decision

Issue a short-lived access token accepted only by SAG's own `/userinfo`,
and no refresh token of any kind, for now. The real feature, if it is ever
built, would hold the *upstream* refresh token and use it to ask Microsoft
or Google again whether a person is still employed, still licensed, still
not disabled, rather than echo an old answer. That is deliberately not what
a bare refresh token gets you, so building the weaker version first as a
stepping stone was rejected.

## Consequences

A relying party wanting a long-lived answer has to re-run the flow today.
The genuine feature - refresh backed by the upstream token - needs
revocation, which needs state, which is a bigger promise than anything else
SAG holds today: encryption of a long-lived third-party credential under a
key that is not the master secret, a revocation path, and a decided answer
for what happens when the backing store is unavailable. It is specified,
not built - see [RFC 0002](../rfcs/0002-refresh-tokens-backed-by-upstream.md)
for the shape it would take and what it would cost.
