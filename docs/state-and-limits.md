# The one piece of state, and the limits it buys

SAG keeps no database. A session is an encrypted cookie, an in-flight request
is an encrypted form field, an authorisation code is an encrypted string.
There are exactly two questions that cannot be answered that way, because the
answer changes over time and the party holding the token is the party being
guarded against:

1. **Has this authorisation code already been redeemed?**
2. **How many codes has this email address asked for?**

Both reduce to two primitives - claim an identifier once, and increment a
counter - so they share one optional store rather than growing two. See
[ADR 0001](adr/0001-stateless-with-optional-state-store.md) for why the store
is optional at all, and [ADR 0002](adr/0002-email-otp-code-design.md) for why
the OTP send limits take the shape they do.

## Choosing a backend

| `STATE_STORE_BACKEND` | Use it when | Notes |
| --- | --- | --- |
| `none` (default) | Nothing is configured yet, or a WAF does the rate limiting and you accept the code trade-off | Both controls are off, and start-up says so |
| `memory` | One Node process, or one container | Genuinely atomic; per instance only. Capped by `STATE_STORE_MAX_ENTRIES`, and a full store refuses a claim rather than forgetting one |
| `cf-durable-object` | **Recommended on Cloudflare** | One object per key, single-threaded, no contention |
| `dynamodb` | **Recommended on AWS** | Conditional `PutItem` and `ADD`, with the table's own TTL sweeping records |

Cloudflare KV is deliberately **not** an option - see
[ADR 0001](adr/0001-stateless-with-optional-state-store.md) for why.

`STATE_STORE_BACKEND` being `none` is a legitimate choice, but it should be a
decision rather than a copied environment file quietly dropping a variable.
`REQUIRE_STATE_STORE=true` turns that silent fallback into a startup error -
see [ADR 0007](adr/0007-require-prefix-for-fail-fast-flags.md).

### Cloudflare

Uncomment the three blocks in `adapters/cloudflare/wrangler.toml`:

```toml
[vars]
STATE_STORE_BACKEND = "cf-durable-object"

[[durable_objects.bindings]]
name = "SAG_STATE"
class_name = "StateGuard"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["StateGuard"]
```

One object is addressed per key, so there is no shared hot object: the object
exists for as long as the record is valid, and then its alarm empties it.

### AWS

One table, one string partition key `jti`, TTL enabled on the `expires_at`
attribute. SAG checks `expires_at` itself as well as relying on the TTL,
because DynamoDB deletes expired items on its own schedule - documented as
within 48 hours - and a limit that waited for the sweeper would lock an
address out for two days rather than ten minutes:

```sh
aws dynamodb create-table --table-name sag-state \
  --attribute-definitions AttributeName=jti,AttributeType=S \
  --key-schema AttributeName=jti,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST --region eu-west-2

aws dynamodb update-time-to-live --table-name sag-state \
  --time-to-live-specification 'Enabled=true,AttributeName=expires_at' \
  --region eu-west-2
```

```sh
STATE_STORE_BACKEND=dynamodb
STATE_STORE_TABLE=sag-state
STATE_STORE_REGION=eu-west-2
```

The function's role needs `dynamodb:PutItem` and `dynamodb:UpdateItem` on that
table and nothing else.

### Containers

`STATE_STORE_BACKEND=memory` is set by the compose file and is correct for one
container. Behind a load balancer with several, each counts its own, so use
DynamoDB or accept that the limits are per instance.

## Single-use authorisation codes

Without a store, a code is single-use by convention: a 60 second lifetime,
mandatory PKCE, and binding to the client and the redirect URI. With one, a
code is claimed exactly once and the second attempt gets `invalid_grant`.

If the store is unreachable the token exchange is **refused**, not waved
through. A person can start again, whereas failing open would disable the
control exactly when somebody wants it disabled.

## OTP send limits

When a store is configured, an address may be sent:

- at most `OTP_SEND_BURST` codes (default 2) in any `OTP_SEND_WINDOW` seconds
  (default 600), and
- at most `OTP_SEND_DAILY_LIMIT` codes a day (default 5).

Set `OTP_SEND_WINDOW` or `OTP_SEND_DAILY_LIMIT` to `0` to turn that half off.

The burst is why it is a window rather than a flat "one code every ten
minutes" - see [ADR 0002](adr/0002-email-otp-code-design.md). Set
`OTP_SEND_BURST=1` for the stricter rule. The key is an HMAC of the address
under the master secret, so a store dump is not a mailing list, and the
counters are per address rather than per session, which is the point: the
counter inside the sealed transaction can be rolled back by resubmitting an
older form, and one outside it cannot.

Unlike single-use codes, **this control fails open**. If the store cannot be
reached the send goes ahead and an error is logged: this protects the
operator's mail bill rather than somebody's account, and a store outage must
not lock every person out of signing in.

A refusal is silent: the person sees the same code screen they would have
seen if the send had gone ahead, with no title, no wording and no timing
difference that would say a limit was hit. The refusal itself is logged
server-side, which is where an operator investigating abuse should look. See
[ADR 0003](adr/0003-silent-enumeration-and-rate-limit-defence.md) for why.

## The layer above: rate limiting at the edge

The send limits stop one address being used to send mail all day. They do not
stop a distributed flood of *different* addresses, and nothing inside a
stateless application can. That belongs at the edge, and it is worth
configuring even with a store:

**Cloudflare.** A rate limiting rule on `/authorize*`, something like 20
requests a minute per IP, and a stricter one on `POST /authorize/email` and
`/authorize/resend`. Turn on Bot Fight Mode for the sign-in path if the
deployment is public.

**AWS.** AWS WAF in front of API Gateway or the function URL, with a
rate-based rule on the same paths. API Gateway throttling is a blunter
instrument but better than nothing.

**Anywhere else.** nginx `limit_req`, Caddy's `rate_limit`, or whatever the
proxy offers, on `/authorize` and its sub-paths.

Guessing a code is a separate matter and is handled by the code itself: nine
characters from a thirty symbol alphabet is about 2 x 10^13 combinations, so
it is hopeless with or without a limit.

## How to tell whether it is on

Not from `/healthz`: it used to say, and no longer does. Publishing whether
codes are single-use and whether OTP sends have a ceiling is a map of which
defences this deployment has, and the audience for an unauthenticated endpoint
is not only the operator.

It is said to the operator instead. On Node it is in the start-up banner under
"Warnings:"; on every platform it is logged once per isolate as
`configuration warning`:

```sh
wrangler tail | grep 'configuration warning'
```

The behavioural test is better than either, because it checks the store is
working rather than configured: redeem an authorisation code, then redeem it
again and confirm the second attempt is refused with `invalid_grant`.
[test/local-stack/verify.js](../test/local-stack/verify.js) does exactly that
against all three platforms.
