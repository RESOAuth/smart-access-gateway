# Adding upstream providers

SAG is primarily an identity proxy: it relays whoever the person already has.
The Node adapter can also hold a small set of operator-provisioned
[local identities](local-identities.md). Routing is by email domain, so there
is one sign-in screen and no deployment-wide "choose your provider" wall.

## How routing works

A person types their address. SAG takes the domain and looks for:

1. an upstream configured for that exact domain, then its parent domain;
2. a `common` upstream, if one is configured;
3. an email code.

A domain-specific entry wins over `common`, and `common` wins over an email
code. If more than one upstream serves the domain - a deployment with Microsoft,
Google and Yahoo all configured as `common`, say - SAG reads the domain's mail
records before asking. See [guessing the provider](#guessing-the-provider).

A domain in `LOCAL_IDENTITY_DOMAINS` is deliberately different: SAG offers the
local password screen without first checking whether an account file exists,
and any eligible upstream remains available as an alternative. That keeps a
missing local record from becoming an address-enumeration signal.

## Configuring one

Environment variable names cannot contain dots, so the domain a provider
serves is carried as a prefix on the client id value:

```sh
# Anyone with a Microsoft account
UPSTREAM_MICROSOFT_COMMON_CLIENT_ID=common:00000000-1111-2222-3333-444444444444
UPSTREAM_MICROSOFT_COMMON_CLIENT_SECRET=...

# But example.com goes to their own tenant
UPSTREAM_MICROSOFT_EXAMPLECOM_CLIENT_ID=example.com:22222222-3333-4444-5555-666666666666
UPSTREAM_MICROSOFT_EXAMPLECOM_CLIENT_SECRET=...
UPSTREAM_MICROSOFT_EXAMPLECOM_TENANT=example.com
```

The pattern is `UPSTREAM_<PROVIDER>_<SLUG>_<FIELD>`. The slug groups the
variables and is otherwise meaningless; the domain comes from the value.

| Field | Meaning |
| --- | --- |
| `CLIENT_ID` | `<domain>:<client id>`, or `common:<client id>` |
| `CLIENT_SECRET` | The provider's secret |
| `TENANT` | Microsoft tenant id or domain. Defaults to `common` |
| `ALLOWED_TENANTS` | Microsoft tenant ids (`tid`) this upstream accepts. Only meaningful on a `common` upstream: a domain-specific one is already bounded by its own `CLIENT_ID` |
| `HD` | Google hosted domain, sent as a hint and checked again in the claims |
| `SCOPES` | Defaults to `openid email profile` |
| `LABEL` | What the button says: "Continue with ..." |
| `ISSUER`, `AUTHORIZATION_ENDPOINT`, `TOKEN_ENDPOINT`, `JWKS_URI` | For a provider that is not Microsoft or Google, or to pin endpoints rather than discover them |
| `DISCOVERY` | `false` to skip the discovery document entirely |
| `ACR_VALUES`, `PROMPT` | Passed upstream, for step-up |
| `MAIL_PROVIDER` | Which mail fingerprint this upstream answers to, for the DNS hint below. Only needed for a provider SAG has no built-in name for |
| `ENABLED` | `false` to keep the configuration but stop using it |

## Google

```sh
UPSTREAM_GOOGLE_COMMON_CLIENT_ID=common:1234-abc.apps.googleusercontent.com
UPSTREAM_GOOGLE_COMMON_CLIENT_SECRET=...

UPSTREAM_GOOGLE_EXAMPLECOM_CLIENT_ID=example.com:5678-def.apps.googleusercontent.com
UPSTREAM_GOOGLE_EXAMPLECOM_CLIENT_SECRET=...
UPSTREAM_GOOGLE_EXAMPLECOM_HD=example.com
```

Register `https://id.example.com/callback` as the redirect URI with the
provider. One callback serves every upstream, because which one is in flight
travels in the sealed `state`.

## Linking one upstream identity to a local identity

A local record can explicitly name an upstream identity by the upstream's SAG
configuration id, the verified issuer, and its exact `sub`. The record
generation tool accepts those values; copying only an email address is not a
link. At callback time SAG also requires the upstream to return the same
canonical address.

When all four values match, upstream and local authentication produce the same
stable local `sub`. The upstream authentication can include
`email_verified: true`; password or TOTP authentication alone omits that claim.
If the upstream returns a refresh token on that exact exchange, SAG seals it
into the link rather than putting it in a cookie or returning it to the relying
party. SAG still issues no refresh token of its own.

## Guessing the provider

"Choose how to sign in" is a screen almost nobody should see. When two or more
upstreams could take an address, the answer is usually already published in DNS,
because an organisation whose identity is at Microsoft has its mail there too:

```sh
SIGNIN_PROVIDER_HINT=select   # read the records and go straight there (default)
SIGNIN_PROVIDER_HINT=order    # still ask, but put the likely one first
SIGNIN_PROVIDER_HINT=off      # do not use DNS to choose a provider
```

Two records are consulted, in order.

**MX** is the direct answer and right for the great majority of domains:
`acme-com.mail.protection.outlook.com` is Microsoft, `aspmx.l.google.com` is
Google, `mta7.am0.yahoodns.net` is Yahoo. Apple, Zoho, Proton and Fastmail are
recognised too.

**SPF** is the fallback, and it matters more than it looks. Plenty of
organisations run their mail through a security gateway - Mimecast, Proofpoint,
Barracuda - whose MX records say nothing about identity, while the SPF record
still names the provider that actually sends their mail:

```ps1
v=spf1 include:eu._netblocks.mimecast.com include:spf.protection.outlook.com -all
```

Without this, exactly the enterprise deployments SAG is for would fall through
to the chooser.

A guess is matched against `MAIL_PROVIDER`, or failing that the provider name,
so Microsoft and Google take part with nothing configured and anything else
needs one variable:

```sh
UPSTREAM_OIDC_YAHOO_CLIENT_ID=common:...
UPSTREAM_OIDC_YAHOO_ISSUER=https://api.login.yahoo.com
UPSTREAM_OIDC_YAHOO_MAIL_PROVIDER=yahoo
```

### What it is not

The provider hint is a guess, and nothing rests on it. A domain owner can publish whatever
records they like, and all that gets them is a redirect to a provider that will
refuse to authenticate them. Every guess is checked against the upstreams that
were already eligible for the address, and the upstream still validates its own
tenant or hosted domain afterwards. When the guess is wrong and the upstream
refuses, the person lands on the chooser with every option offered and nothing
suggested - not at a dead end.

Provider hints look up records only when there is a real ambiguity: one
candidate, or a domain-specific upstream the operator has already decided
about, means no query for routing. The Microsoft consumer-account check below
is separate and reads MX at callback.

### Where the query goes

The Node adapter hands the core the host's own resolver, so a container or a VM
asks whatever resolver it is already configured to trust and no query leaves the
deployment. The Cloudflare adapter hands it `node:dns`, which the Workers
runtime resolves itself. Lambda has no resolver, so it uses DNS-over-HTTPS -
Cloudflare's by default, and `DNS_RESOLVER_URL` points it anywhere that speaks
the same JSON. Provider hints are cached per instance for an hour.

On Workers the DNS-over-HTTPS fallback is not merely slower, it does not work:
a Worker's own `fetch` to a public DNS-over-HTTPS endpoint does not come back,
so a Worker without the platform resolver refuses every CIMD client with "Could
not resolve the client metadata host". Setting `DNS_RESOLVER_URL` there
overrides the resolver that does work.

That does mean a Lambda deployment on the default tells a public DNS service
which domains reach the chooser or the Microsoft consumer-account check.
`SIGNIN_PROVIDER_HINT=off` disables routing lookups, while the consumer check
still needs MX. On
Workers the query goes to the runtime's own resolver instead, which is
Cloudflare either way - it is their platform - but it is no longer a `fetch` to
a third party.

## The safety property worth knowing

A domain-specific provider cannot assert an address outside its own domain.
Configuring one for `example.com` does not let it claim to be somebody at
`gmail.com`, even if it returns that address in the token. Without that rule,
one tenant administrator could sign in as anybody.

The same check applies to Google's `hd`: it is sent as a hint, and then
verified in the returned claims rather than trusted because it was asked for.

### A common upstream has no such domain to check

That rule is what the domain in a `CLIENT_ID` buys, and a `common` upstream
does not have one. It accepts any organisation the provider will federate, and
a `sub` here is derived from the address alone, so an unbounded `common`
upstream means any of those organisations can assert any address.

That matters most on Microsoft, where `mail`, `preferred_username`, and the
user principal name are all directory attributes a tenant administrator sets
and Microsoft does not verify the domain in. A `common` upstream therefore
reads the address from `email` only - never `preferred_username` or `upn`,
which are login identifiers rather than an assertion about a mailbox - and has
to say which tenants it is for:

```sh
# Only these tenants, checked against the tid Microsoft issues
UPSTREAM_MICROSOFT_COMMON_ALLOWED_TENANTS=11111111-2222-3333-4444-555555555555
```

Where the tenants are not known in advance, let Entra answer instead. Add the
[`xms_edov` optional claim](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
to the app registration and Microsoft says, per sign-in, whether the tenant
has had the domain of that address verified:

```jsonc
// App registration -> Token configuration, or the manifest directly
"optionalClaims": {
  "idToken": [{ "name": "xms_edov", "essential": false }]
}
```

An Entra ID sign-in through a `common` Microsoft upstream needs one of the two
and is refused until it has one; SAG warns at start-up about the tenant list,
because it cannot see your app registration. `ALLOWED_TENANTS` is the stronger
of the two where you can use it - it bounds who is asserting, which a directory
administrator cannot change, rather than what they asserted. An `xms_edov` of
`false` is refused either way. See
[ADR 0019](adr/0019-a-common-upstream-must-bound-what-it-may-assert.md).

Personal Microsoft accounts, such as `jamie@outlook.com`, do not send
`xms_edov`. For these accounts, SAG accepts an absent claim only when the token
has Microsoft's consumer tenant id and every MX record for the token's email
domain ends in `.olc.protection.outlook.com`. An MX ending in
`.mail.protection.outlook.com` still needs `xms_edov` unless the tenant is on
the allow list. An absent or inconclusive MX answer also keeps the claim
requirement. This check runs even with `SIGNIN_PROVIDER_HINT=off`. See
[ADR 0026](adr/0026-microsoft-consumer-accounts-use-consumer-mx.md).

## What the relying party sees

The `acr` and `amr` claims say what actually happened - which provider, and
whether the provider reported multi-factor authentication - rather than
flattening everything into "signed in". A relying party can demand more with
`acr_values`, and a request that asks for MFA is refused rather than quietly
answered with an email code.
