# 0011. The `sub` is derived from the verified address, not the upstream's

## Context

SAG has to answer "who is this?" to a relying party. Two identifiers are
available at the end of a sign-in, and they behave very differently.

The **upstream's own `sub`** is what Microsoft, Google or another provider put
in the token SAG just validated. It is stable in that provider's world and
meaningless outside it. It is scoped to the application registration, so
re-registering SAG at the upstream changes it for everybody; it is scoped to
the tenant, so the same person at a new employer is a new person; and it does
not exist at all on the email OTP path, which is precisely the fallback a
deployment configures for the people no upstream covers. A relying party keyed
on it would lose every account the day the upstream routing changed.

The **verified email address** is the thing SAG has actually proved: either an
upstream asserted it, or a code was delivered to it. It is the same value on
every path, it survives moving a domain from one upstream to another, and it is
what a relying party asking for the `email` scope already receives.

Two further questions fall out of choosing the address. What else goes into the
derivation - the issuer? the client id? the redirect host? - decides which
routine operational changes silently orphan every account. And
`jamie@example.com` and `jamie+shop@example.com` are one mailbox with two
spellings on every mail system that implements `+`; treating them as two people
gives one person two accounts, silently, and a relying party has no way to
notice.

## Decision

**The `sub` is an HKDF of `SUBJECT_SALT` over the verified address.** An
upstream's own subject is never relayed and never derived from. `public` mixes
in the fixed string `public`, so every relying party sees the same value;
`pairwise` mixes in the relying party's sector instead, so two of them cannot
compare notes. `public` is the default, because most relying parties expect one
identity per person and pairwise is the deliberate choice.

**A sector is a declared `sector_identifier`, or the client id.** Nothing is
inferred from a relying party's redirect URIs. Sharing an account across a
group of applications is a decision somebody makes and writes down; deriving it
from a hostname would mean a relying party that changes where it redirects
silently loses every account it had.

**The issuer is not in the derivation.** A relying party stores `iss` alongside
`sub` and already treats two issuers as two identity spaces, so mixing the
issuer in buys nothing and would make renaming a deployment as destructive as
rotating the salt. The salt is the only value that must never change.

**Two spellings of one mailbox are one person, by default.**
`SANITISE_PLUS_EMAILS` strips a plus tag before the address becomes an identity,
and it is applied when the authorisation code is minted rather than when the
address is typed - the session is shared across relying parties, so a
per-client `CLIENT_<SLUG>_SANITISE_PLUS_EMAILS` could not exist otherwise. What
the person typed is still what the sign-in screens show them.

**OTP send limits always count the untagged mailbox**, whatever that policy
says. Identity is a policy; a mailbox is a fact, and keying the limit on the
tag would let one person walk past it by inventing a new tag each time. The
hashed address in the logs is keyed the same way, so a log line and a limit
describe the same person.

## Consequences

An address change is an identity change. Somebody who moves from
`jamie.taylor@` to `j.taylor@` is a new person to every relying party, and the
old address handed to a new colleague inherits the old one's accounts. That is
the trade for surviving an upstream change, and it is the same trade every
email-keyed system makes; a deployment that cannot accept it should not be
using SAG for those accounts.

`SUBJECT_SALT` is now required to start against a real hostname, where before
it was only needed for pairwise. Development falls back to a well-known salt
and says so in the start-up warnings, which means every `sub` a development
instance issues is guessable - fine for a laptop, never for anything else.

Rotating the salt orphans every account at every relying party, and there is no
migration path: nothing is stored, so no administrator can re-key anybody. The
same applies to turning `SANITISE_PLUS_EMAILS` off after people have signed in,
which splits every tagged account in two, or on, which merges them. A
per-client override has the same property for that one relying party. All of
these are migrations rather than settings to change casually.

Two SAG deployments configured with the same salt hand the same person the same
`sub`. That is deliberate - sharing a salt is sharing an identity space, which
is what a multi-region deployment answering as one issuer is doing - but it
means a salt must not be copied between deployments that are meant to be
separate.

A relying party that wants accounts merged or split needs to do it itself. That
is the price of ADR [0001](0001-stateless-with-optional-state-store.md).
