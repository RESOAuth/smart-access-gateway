# Adding upstream providers

SAG is an identity proxy: it does not hold passwords, it relays whoever the
person already has. Routing is by email domain, so there is one sign-in
screen and no "choose your provider" wall.

## How routing works

A person types their address. SAG takes the domain and looks for:

1. an upstream configured for that exact domain, then its parent domain;
2. a `common` upstream, if one is configured;
3. an email code.

A domain-specific entry wins over `common`, and `common` wins over an email
code. If more than one upstream serves the domain - a deployment with Microsoft,
Google and Yahoo all configured as `common`, say - SAG reads the domain's mail
records before asking. See [guessing the provider](#guessing-the-provider).

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

## Guessing the provider

"Choose how to sign in" is a screen almost nobody should see. When two or more
upstreams could take an address, the answer is usually already published in DNS,
because an organisation whose identity is at Microsoft has its mail there too:

```sh
SIGNIN_PROVIDER_HINT=select   # read the records and go straight there (default)
SIGNIN_PROVIDER_HINT=order    # still ask, but put the likely one first
SIGNIN_PROVIDER_HINT=off      # never look
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

```
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

It is a guess, and nothing rests on it. A domain owner can publish whatever
records they like, and all that gets them is a redirect to a provider that will
refuse to authenticate them. Every guess is checked against the upstreams that
were already eligible for the address, and the upstream still validates its own
tenant or hosted domain afterwards. When the guess is wrong and the upstream
refuses, the person lands on the chooser with every option offered and nothing
suggested - not at a dead end.

Nothing is looked up unless there is a real ambiguity: one candidate, or a
domain-specific upstream the operator has already decided about, means no query
at all.

### Where the query goes

The Node adapter hands the core the host's own resolver, so a container or a VM
asks whatever resolver it is already configured to trust and no query leaves the
deployment. Workers and Lambda have no resolver, so they use DNS-over-HTTPS -
Cloudflare's by default, and `DNS_RESOLVER_URL` points it anywhere that speaks
the same JSON. Answers are cached per instance for an hour.

That does mean a Workers or Lambda deployment on the default tells a public DNS
service which domains are signing in, and only when the chooser would otherwise
have appeared. `SIGNIN_PROVIDER_HINT=off` if that is not a trade you want.

## The safety property worth knowing

A domain-specific provider cannot assert an address outside its own domain.
Configuring one for `example.com` does not let it claim to be somebody at
`gmail.com`, even if it returns that address in the token. Without that rule,
one tenant administrator could sign in as anybody.

The same check applies to Google's `hd`: it is sent as a hint, and then
verified in the returned claims rather than trusted because it was asked for.

## What the relying party sees

The `acr` and `amr` claims say what actually happened - which provider, and
whether the provider reported multi-factor authentication - rather than
flattening everything into "signed in". A relying party can demand more with
`acr_values`, and a request that asks for MFA is refused rather than quietly
answered with an email code.
