# 0019. A common upstream must bound what it may assert

Date: 2026-09-01
Status: Accepted

## Context

An upstream configured as `common` accepts any organisation its provider will
federate. That is the point of it: `UPSTREAM_MICROSOFT_COMMON_CLIENT_ID` exists
so a deployment can sign in Microsoft accounts without knowing every tenant in
advance.

A `sub` here is derived from the verified email address and nothing else
([ADR 0011](0011-subject-derived-from-the-verified-address.md)). That is what
makes somebody the same person whether they arrive through Microsoft, through
Google, or through an email code, and it is a good property. It also means the
address is the whole account: whoever can make SAG believe an address is theirs
gets that person's `sub` at every relying party, and SAG then asserts
`email_verified: true` alongside it.

Four things then have to hold for a `common` upstream, and none of them did:

- **The tenant is not checked.** `microsoft.verifyClaims` returned immediately
  for a `common` upstream, so any tenant in the world was accepted.
- **The domain is not checked.** The "address outside the domain it is
  configured for" check is guarded by `!upstream.isCommon`, because a common
  upstream has no configured domain to check against.
- **`email_verified` does not arrive.** It is only rejected when explicitly
  `false`, and Entra ID v2.0 id_tokens do not carry the claim at all, so the
  guard never fires for the provider that most needs it.
- **The address falls back to a login identifier.** `preferred_username` and
  `upn` were accepted when `email` was absent.

In Entra ID, `mail`, `preferred_username`, and the user principal name are
directory attributes a tenant administrator sets. Microsoft does not verify
that the tenant controls the domain in them, and says so: its guidance for
multi-tenant applications is not to use any of them as a unique identifier.
Any administrator of any tenant could therefore have signed in and been given
the `sub` belonging to an address they do not control. This is the pattern
published against multi-tenant Entra applications as nOAuth in 2023.

The same shape exists for a generic `oidc` upstream configured as `common`,
whose `verifyClaims` is a no-op, and for Google without an `hd`. Google is the
mildest of the three, because Google does verify the addresses it asserts and
does send `email_verified`.

The temptation is to fix this by tightening the claim rules alone - insist on
`email`, treat a missing `email_verified` as unverified. Insisting on `email`
is right and costs nothing, but it is not sufficient, because a tenant sets
`mail` as freely as it sets the UPN. Treating a missing `email_verified` as
unverified would be sufficient and would also refuse every genuine Entra
sign-in, which is not a trade a deployment can accept.

The honest reading is that this is not a claim-selection problem. It is that
"any organisation in the world" was never a bound, and a domain-specific
upstream has always had one - the domain in its own `CLIENT_ID`.

## Decision

A `common` upstream states what it is allowed to assert, in one of two ways,
and is warned about at start-up when it states neither.

**`UPSTREAM_<PROVIDER>_<SLUG>_ALLOWED_DOMAINS`** - email domains this upstream
may assert, subdomains included. This is the same check a domain-specific
upstream already gets, made explicit and allowed to name more than one domain.
It applies to every provider.

**`UPSTREAM_<PROVIDER>_<SLUG>_ALLOWED_TENANTS`** - Microsoft tenant ids this
upstream accepts, checked against `tid`. This is the stronger of the two,
because `tid` is issued by Microsoft rather than set in a directory: it bounds
*who is asserting* rather than *what they asserted*. A deployment that knows
its tenants should prefer it.

Neither is required, because a deployment that genuinely means "anybody the
provider recognises" exists and should not be refused a start. Configuring
neither raises a start-up warning naming the upstream and both variables, on
the operator's channel rather than `/healthz`.

Separately, and regardless of the above: a `common` upstream reads the address
from `email` only. The fallback to `preferred_username` and then `upn` stays
for a domain-specific upstream, where the domain check bounds whatever comes
back, and is removed where nothing does.

## Consequences

A deployment using `UPSTREAM_MICROSOFT_COMMON_*` today keeps working and gets a
start-up warning until it decides which bound it wants. That is deliberate:
refusing to start would break running deployments over a risk they may have
accepted knowingly, and silence would leave the default unsafe.

Some Microsoft accounts return `upn` but no `email` - typically where the
directory has no `mail` attribute set. Those accounts could sign in through a
`common` upstream before and cannot now. The fix for such a deployment is to
configure the tenant as a domain-specific upstream, which is what it is, and
which restores the fallback along with a real bound.

`ALLOWED_TENANTS` bounds the tenant but not the address, and `ALLOWED_DOMAINS`
the reverse. A deployment wanting both sets both; they are checked
independently and both must pass.

None of this changes what a domain-specific upstream does, which was already
bounded, and none of it touches the email OTP path, where SAG proves control of
the mailbox itself.

Two things this deliberately does not do. It does not treat a missing
`email_verified` as unverified, for the reason above. And it does not
distinguish a tenant SAG has seen before from one it has not, because that
needs state, and this deployment shape has none by design
([ADR 0001](0001-stateless-with-optional-state-store.md)).
