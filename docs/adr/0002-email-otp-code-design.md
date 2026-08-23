# 0002. Email OTP: an unbiased high-entropy code, and one store for both send limits and replay prevention

Date: 2026-08-23
Status: Accepted

## Context

Email OTP is the fallback authentication method whenever there is no
upstream identity provider, so it has to resist two different kinds of
attack: somebody guessing a code, and somebody using the deployment to
flood an address, or many addresses, with mail. A stateless deployment
cannot rate-limit either perfectly, and the two problems have different
owners - guessing threatens an account, flooding threatens the operator's
mail bill and the recipient's inbox.

## Decision

Make guessing hopeless regardless of any rate limit: nine characters from a
thirty-symbol alphabet with every visually confusable character removed (no
0, O, 1, I, L or U), about 2×10^13 combinations rather than the million a
six-digit code offers. The attempt counter still lives in the sealed
transaction and can be rolled back by resubmitting an older form - accepted,
because with this keyspace it no longer matters either way.

For flooding, add one optional store-backed control that a deployment turns
on together with everything else the shared state store buys it (see
[0001](0001-stateless-with-optional-state-store.md)): a burst of a few codes
per short window plus a daily ceiling, keyed by an HMAC of the address so a
store dump is not a mailing list. The burst is two rather than one,
deliberately: a code lives ten minutes, so a strict one-per-window rule
leaves somebody whose first code went to spam with nothing to do but wait
out the whole window for a message that will never arrive.
`OTP_SEND_BURST=1` restores the strict version for a deployment that would
rather have it.

## Consequences

Without a store, nothing stops one address, or many, being used to send
mail all day; that is why edge rate limiting is recommended as the layer
above regardless of whether the store is configured - see
[state-and-limits.md](../state-and-limits.md). Guessing resistance does not
depend on the store at all, so it holds even in the zero-configuration
case. What a rate-limit refusal actually looks like to the person asking is
a separate decision - see
[0003](0003-silent-enumeration-and-rate-limit-defence.md).
