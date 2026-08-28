# Known limitations

Stated plainly rather than buried. Every one of these is a consequence of a
deliberate choice, and each says what closes it.

## An authorisation code can be redeemed more than once, by default

Nothing stateless can mark a code as spent. Out of the box the mitigation is a
60 second lifetime, mandatory PKCE, and binding the code to the client and the
redirect URI, so a replay needs the code *and* the verifier *and* the same
client, inside a minute.

**Closed by** setting `STATE_STORE_BACKEND`. See
[state-and-limits.md](state-and-limits.md).

## A client assertion can be replayed, by default

A `private_key_jwt` assertion has a required issue time, a required unique
identifier, and a maximum 300 second lifetime, but a stateless instance cannot
remember that it has already seen the identifier. A captured assertion is
therefore reusable within that short window when no state store is configured.

**Closed by** setting `STATE_STORE_BACKEND`. See
[state-and-limits.md](state-and-limits.md).

## OTP attempt counters can be rolled back

The attempt and resend counters travel inside the sealed transaction, so
somebody can resubmit an older copy of the form and reset their own count. The
counter deters casual retrying; it does not prevent brute force.

**Why it no longer matters much**: a code is nine characters from a thirty
symbol alphabet, so a guess has about a one in 2 x 10^13 chance. Unlimited
guesses against that inside a ten minute window is still hopeless. A WAF rate
limiting rule is the second layer.

## OTP send limits need a store, and fail open without one

With no state store there is nothing to count with, so nothing stops somebody
requesting codes for many different addresses, which costs the operator money
and annoys the recipients. With a store, the limits apply but deliberately
fail open if the store is unreachable, and a send that fails at the mail
provider still counts against the window, so a provider outage eats an
address's allowance.

A refused send gives no hint of it: same screen, same status, same wording as
a real one. A determined observer with a stopwatch can still tell them apart,
because a real send waits for the mail provider while a refused one answers
immediately - a residual timing tell that is left in place deliberately. See
[ADR 0003](adr/0003-silent-enumeration-and-rate-limit-defence.md).

**Closed by** a state store plus edge rate limiting. See
[state-and-limits.md](state-and-limits.md).

## No refresh tokens

Revoking one needs state, and a refresh token that only re-asserts what SAG
already said is not worth the machinery. Re-run the flow instead: with a
session, SAG answers `prompt=none` without showing anything. See
[ADR 0005](adr/0005-no-refresh-tokens.md) for why, and
[RFC 0002](rfcs/0002-refresh-tokens-backed-by-upstream.md) for the real
feature this is holding out for.

## Session revocation needs a store

A session is an encrypted cookie with an idle timeout and an absolute
lifetime. Without a state store, logout only expires the current browser's
copy, and another copy remains usable. With a store, logout writes a per-`sid`
marker until the absolute expiry, so every copy of that session is refused.
There is still no subject index, so "sign this person out on every device,
now" means rotating the master secret, which signs *everybody* out. See
[ADR 0012](adr/0012-store-backed-session-revocation.md) and
[operations.md](operations.md).

## Upstream providers are tested against a stub, not the real thing

Federation is exercised against a stub provider that serves a real discovery
document and a genuinely signed `id_token`, so only the network is faked.
Microsoft and Google have not been driven for real yet, and they will have
opinions about redirect URI registration, tenant restrictions and consent
screens that a stub does not.

## Post-quantum signing depends on the runtime

ML-DSA needs a runtime that offers it. Node 24 with a recent OpenSSL does;
Workers and Lambda's Node runtime may not, and AWS KMS does not offer ML-DSA
keys in every region. SAG probes at start-up and publishes only what it can
really do, so a deployment never advertises an algorithm it cannot use. See
[post-quantum.md](post-quantum.md).

## The pages carry no `form-action` directive

Every other directive in the Content-Security-Policy on SAG's screens is as
tight as it goes - `default-src 'none'`, no inline script, no inline style, no
`connect-src` - but `form-action` is absent, and has to be.

**Why it costs little.** `form-action` only bites once somebody can already
inject markup into one of these pages; `base-uri 'none'` closes the `<base>`
route to retargeting the forms that are there; and every `action` attribute is a
server-side constant rather than anything derived from input. The `form_post`
response mode, which is the one page that legitimately posts across origins,
posts directly with no redirect in between, so it names its exact target and
nothing else.

**Closed by** a flow that does not complete through a redirected form POST, or
by browsers scoping the directive to the initial submission. Neither is
imminent.

## DNS-over-HTTPS tells a resolver which domains SAG is considering

On Workers or Lambda there is no platform resolver, so guessing the upstream
from a domain's mail records and checking a CIMD hostname's addresses use
DNS-over-HTTPS - Cloudflare's by default. That service learns the domains being
resolved. Node uses the host resolver instead.

**Closed by** `DNS_RESOLVER_URL` pointing at a resolver you run,
`SIGNIN_PROVIDER_HINT=off`, or deploying on Node, where the adapter hands the
core the host's own resolver and no query leaves the deployment. See
[upstreams.md](upstreams.md).

## Listing a peer in `PEER_JWKS_URLS` trusts it completely

There is no partial trust here: a peer's published keys are merged into this
instance's own `/jwks.json` and treated as fully able to sign for this
issuer, the same as this instance's own signer set. This is the correct
shape for genuine peers of one multi-region or multi-cloud deployment, and
the wrong one for anything else - it is not a mechanism for trusting a third
party's keys a little.

**Closed by** only ever listing infrastructure the same operator controls,
over `https` with an ordinary certificate check. See
[multi-region.md](multi-region.md) and
[ADR 0009](adr/0009-peer-jwks-federation.md).

## An email code is an assertion about an address, not about a person

The weakest sign-in SAG offers proves control of a mailbox at that moment. It
is reported honestly as `urn:sag:acr:email-otp`, and a relying party that
needs more can demand it and be refused rather than quietly satisfied.

## An identity is an email address, so changing address changes the person

A `sub` is derived from the verified address, which is what makes it survive a
domain moving between upstream providers. It is also what makes a rename a new
account at every relying party, and makes an address handed on to a new
colleague inherit the old one's accounts. Nothing is stored, so no
administrator can merge or split them here; a deployment that needs that needs
the relying party to do it.

`SUBJECT_SALT` has the same property from the other direction: rotating it
gives every person a new `sub` everywhere, with no way to re-key anybody, so it
is set once and never touched. Turning `SANITISE_PLUS_EMAILS` on or off after
people have signed in merges or splits every tagged account for the same
reason. See [ADR 0011](adr/0011-subject-derived-from-the-verified-address.md).
