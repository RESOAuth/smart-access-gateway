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

Microsoft does publish a claim that answers the question directly. `xms_edov`
is a boolean saying whether the domain of the `email` claim is one the user's
own tenant has had verified, and it is the mitigation Microsoft names for
nOAuth. It is an [optional
claim](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference),
so Entra only sends it once the app registration asks for it, and it is only
sent when `email` is present.

## Decision

A `common` Microsoft upstream is bounded in one of two ways, and refuses a
sign-in that satisfies neither.

**`UPSTREAM_<PROVIDER>_<SLUG>_ALLOWED_TENANTS`** - tenant ids this upstream
accepts, checked against `tid`. This is the stronger of the two, because `tid`
is issued by Microsoft rather than set in a directory: it bounds *who is
asserting* rather than *what they asserted*. A deployment that knows its
tenants should prefer it.

**The `xms_edov` claim.** Where the tenants are not known in advance, Entra
itself says whether the tenant proved it owns the domain in the address. An
upstream with no `ALLOWED_TENANTS` requires `xms_edov: true`; an `xms_edov` of
`false` is refused either way, because a tenant being on the allow list does
not make an address it has not verified into evidence.

Configuring neither, and not asking for the claim, is a configuration mistake
rather than a deployment shape, so it draws a start-up warning naming the
upstream, `ALLOWED_TENANTS`, and `xms_edov`. It is a warning and not a refusal
to start because the app registration is not something SAG can see.

Separately, and regardless of the above: a `common` upstream reads the address
from `email` only. The fallback to `preferred_username` and then `upn` stays
for a domain-specific upstream, where the domain check bounds whatever comes
back, and is removed where nothing does.

## Consequences

A deployment using `UPSTREAM_MICROSOFT_COMMON_*` has to choose a bound. It
gets a start-up warning saying so, and until it does, sign-ins through that
upstream are refused. That is a break, and a deliberate one: the alternative is
leaving an unbounded upstream working exactly as nOAuth describes. Either
remedy is one change - a list of tenant ids, or `xms_edov` added to the app
registration's `optionalClaims.idToken`.

Some Microsoft accounts return `upn` but no `email` - typically where the
directory has no `mail` attribute set. Those accounts could sign in through a
`common` upstream before and cannot now, and `xms_edov` cannot help them,
because Entra only sends it alongside `email`. The fix for such a deployment is
to configure the tenant as a domain-specific upstream, which is what it is, and
which restores the fallback along with a real bound.

None of this changes what a domain-specific upstream does, which was already
bounded by the domain in its own `CLIENT_ID`, and none of it touches the email
OTP path, where SAG proves control of the mailbox itself. A `common` Google
upstream is bounded by `HD` where a deployment wants it and by Google's own
verification otherwise. A `common` generic `oidc` upstream is bounded by
whatever its single configured issuer chooses to assert, which is the deal a
deployment makes when it names that issuer.

Three things this deliberately does not do. It does not treat a missing
`email_verified` as unverified, because Entra never sends it and that would
refuse every genuine Microsoft sign-in - `xms_edov` is the claim that answers
the question Entra actually answers. It does not check `acct`, which
distinguishes a member of the tenant from a guest, because a guest's address is
already caught by the domain check on a domain-specific upstream and by
`xms_edov` on a common one. And it does not distinguish a tenant SAG has seen
before from one it has not, because that needs state, and this deployment shape
has none by design ([ADR 0001](0001-stateless-with-optional-state-store.md)).
