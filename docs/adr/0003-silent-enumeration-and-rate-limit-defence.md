# 0003. The sign-in surface never signals whether an address exists or a rate limit was hit

Date: 2026-08-23
Status: Accepted

## Context

The email address screen is the one surface anybody can reach with no
account at all, and it can answer two questions an attacker would like
answered without ever meaning to: which organisations or domains does this
deployment serve, and has a given address recently asked for a code here.
Two different mechanisms could each leak one of these - routing an
unservable address to a distinct "we don't serve you" screen, and telling
somebody plainly that a rate limit had been hit and for how long.

## Decision

Close both the same way: make the response indistinguishable from a real
one. An address no route can serve gets the ordinary code screen anyway -
same status, same wording, same resend and limit behaviour - with no mail
sent and a digest of a code nobody holds, all the way to the wrong-code
error. A send refused by the rate limiter (see
[0002](0002-email-otp-code-design.md)) gets the same treatment: exactly the
screen a successful send or resend would produce, with no title, no wording
and no wait time naming the limit. Both refusals are logged server-side
only, which is where an operator investigating abuse should look instead.

A deployment that would rather be kind than quiet can opt out of the first
with `SIGNIN_UNKNOWN_ADDRESS=explain`, which restores a clear "we do not
accept that domain" message. There is no equivalent opt-out for the rate
limit message: the decision there was to remove it entirely rather than
make it optional.

## Consequences

Two residual side channels remain, and were judged not worth closing. In
development mode the code screen prints the code, so a decoy is obviously a
decoy - that is the point of development mode. And a real send waits for
the mail provider while a decoy or a refused send answers immediately, so a
determined observer with a stopwatch can still tell them apart; closing
that would mean padding every response to a fixed time, which costs every
person's sign-in a delay to defeat somebody who already knows the address
they are testing. See [limitations.md](../limitations.md).
