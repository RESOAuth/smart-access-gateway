# Configuration reference

Everything is an environment variable, so the same build runs unchanged on
Cloudflare Workers, AWS Lambda, a container and a laptop. Two rules shape all
of it: local development works with no configuration at all, and the moment a
real hostname is in play every development default becomes a hard error rather
than a quiet weakness.

Relying party and upstream provider variables have their own pages:
[relying-parties.md](relying-parties.md) and [upstreams.md](upstreams.md).

## Identity of the deployment

| Variable | Default | Meaning |
| --- | --- | --- |
| `SAG_ISSUER` | derived from the request in development | The `iss` claim and the base for every URL. No trailing slash, no query |
| `SAG_SECRET` | a well-known development value | Master secret. 48 random bytes, unique to this issuer. Protects sessions, transactions and codes |
| `SAG_SECRET_PREVIOUS` | - | The secret being retired, so a rotation does not sign everybody out. See [operations.md](operations.md) |
| `SAG_DEV` | true for localhost, `.localhost`, `.local` and `.linux.test` issuers | Forces development mode on or off |
| `LOG_LEVEL` | `debug` in development, `info` otherwise | `debug`, `info`, `warn`, `error`, `silent` |

## Signing

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNING_BACKEND` | `local` | `local`, `cloudflare-hsm`, `aws-kms` |
| `SIGNING_ALG` | `ES256` | The primary `id_token` algorithm |
| `SIGNING_ADDITIONAL_ALGS` | - | Published alongside, so relying parties migrate one at a time |
| `SIGNING_PRIVATE_JWK` | - | The key, as JSON. Also `_<ALG>` suffixed, for example `SIGNING_PRIVATE_JWK_ML_DSA_44` |
| `SIGNING_PRIVATE_KEY_PEM` | - | The same thing in PEM |
| `SIGNING_KMS_KEY_ID`, `SIGNING_KMS_REGION` | - | With `aws-kms` |
| `HSM_BINDING`, `HSM_URL`, `HSM_SHARED_SECRET` | `HSM` | With `cloudflare-hsm`. See [deployment.md](deployment.md) |
| `SIGNING_PUBLIC_JWKS_EXTRA` | `[]` | Extra public keys to publish, for a migration in progress |
| `REQUIRE_POST_QUANTUM_SIGNING` | `false` | Refuse to start unless a post-quantum algorithm is configured. The older `SIGNING_REQUIRE_POST_QUANTUM` name still works |

## Peer deployments (JWKS federation)

Only relevant to more than one instance answering as the same issuer. See
[multi-region.md](multi-region.md): listing a peer here trusts its keys as
fully as this instance's own.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PEER_JWKS_URLS` | - | The full JWKS URL of every other instance of this issuer, each named by its own per-instance hostname rather than the issuer hostname. Empty means this feature is off and `/jwks.json` is exactly this instance's own keys |
| `PEER_JWKS_CACHE_TTL` | `300` | Seconds before a healthy peer is refetched |
| `PEER_JWKS_STALE_TTL` | Twice `SESSION_MAX_LIFETIME` | Seconds a peer's last known keys are still served, and still counted in `/jwks.json`, after it stops answering |
| `PEER_JWKS_RETRY_AFTER` | `30` | Seconds to leave a peer alone after a failed fetch, so an unreachable one costs one timeout per interval rather than one per request. `0` retries on every request. Also how long a `/jwks.json` that is missing a peer's keys may be cached for |
| `PEER_JWKS_TIMEOUT_MS` | `4000` | |
| `PEER_JWKS_MAX_BYTES` | `65536` | A peer's response over this size is refused rather than parsed |
| `PEER_JWKS_CACHE_BACKEND` | `memory` | `memory`, `cf-kv`, `dynamodb`. `memory` does not survive an isolate or container restart, so a peered deployment should set one of the other two and is warned in the log if it does not - see [multi-region.md](multi-region.md) |
| `REQUIRE_PEER_JWKS_CACHE` | `false` | Refuse to start unless peers are configured *and* `PEER_JWKS_CACHE_BACKEND` is durable, so a template or a Terraform refactor cannot drop either silently |
| `PEER_JWKS_CACHE_KV_BINDING` | `SAG_PEER_JWKS` | With `cf-kv` |
| `PEER_JWKS_CACHE_TABLE`, `PEER_JWKS_CACHE_REGION` | - | With `dynamodb` |

## Sessions

| Variable | Default | Meaning |
| --- | --- | --- |
| `SESSION_SCOPE` | `shared` | `shared` for one session across every relying party, `rp` for one each |
| `SESSION_COOKIE_NAME` | `sag_session` in development, `__Host-sag_session` otherwise | Production prefixes a custom name too, and uses `Secure; Path=/` as the prefix requires |
| `SESSION_TTL` | `43200` (12 hours) | Idle timeout |
| `SESSION_MAX_LIFETIME` | `604800` (7 days) | Absolute lifetime, regardless of activity |
| `PROMPT_CONSENT_MODE` | `continue` | `continue` shows "continue as ..." for `prompt=consent` and an omitted `prompt`; `off` ignores consent requests |
| `LOGOUT_CONFIRM` | `auto` | `auto` asks when the session is shared, `always`, `never` |

`prompt=none` follows `SESSION_SCOPE` with no separate setting. Under `shared`
a session can answer silently for a relying party that never signed the person
in itself; under `rp` it cannot, because the cookie a relying party's request
reads is its own. There is no fallback from one to the other in either
direction - see
[ADR 0004](adr/0004-session-scope-and-sign-out-confirmation.md).

## Tokens and codes

| Variable | Default | Meaning |
| --- | --- | --- |
| `CODE_TTL` | `60` | Authorisation code lifetime, in seconds |
| `TRANSACTION_TTL` | `900` | How long an in-flight sign-in may take |
| `ID_TOKEN_TTL` | `300` | |
| `ACCESS_TOKEN_TTL` | `600` | The access token is only accepted by SAG's own `/userinfo` |
| `CLOCK_SKEW` | `60` | Tolerance when checking times |
| `SUBJECT_TYPE` | `public` | `public` gives every relying party the same `sub`, an HKDF of `SUBJECT_SALT` over the string `public` and the address; `pairwise` gives each one a different `sub`, the same HKDF with the relying party's sector in place of `public` |
| `SUBJECT_SALT` | - | Always required; development falls back to a well-known salt and says so. Values shorter than 16 characters warn but remain unchanged. **Rotation warning**: a new salt orphans every account at every relying party |
| `SANITISE_PLUS_EMAILS` | `true` | Treat `jamie+shop@example.com` as `jamie@example.com` for identity: one mailbox, one person. Overridable per relying party with `CLIENT_<SLUG>_SANITISE_PLUS_EMAILS` |

A `sub` is derived from the verified email address, never from the upstream's
own subject, so somebody who moves between upstream providers - or falls back
to an email code - is the same person throughout. What that costs when
somebody's address changes is in
[ADR 0011](adr/0011-subject-derived-from-the-verified-address.md).

A relying party's sector is its declared `sector_identifier`, or its client id.
Nothing is inferred from its redirect URIs, so a relying party that moves where
it redirects keeps its accounts, and a group of applications that means to
share one account says so by declaring the same `sector_identifier`.

The issuer is deliberately not in the derivation: a relying party stores `iss`
alongside `sub` and already separates two deployments by it, so renaming this
one does not orphan anybody. The salt is the only thing that must never change.

`SANITISE_PLUS_EMAILS` decides identity only. OTP send limits always count the
untagged mailbox, whatever it is set to, because otherwise a new tag on every
attempt would walk straight past them.

## Cross-origin requests (CORS)

| Variable | Default | Meaning |
| --- | --- | --- |
| `CORS_ENABLED` | `true` | Whether `/token` and `/userinfo` carry CORS headers at all |
| `CORS_ALLOWED_ORIGINS` | `*` | Comma or space separated browser origins to narrow to, *in addition to* every static client's registered redirect URIs. Unset means every origin |

Neither endpoint relies on the session cookie - a `/token` request is bound to
its authorization code by PKCE, and `/userinfo` is bound to its caller by the
bearer access token - so there is nothing here for a third-party origin to
ride on. Reading either response requires a code the caller cannot obtain
without completing the flow, or a bearer token it already holds. The default
is therefore every origin, the same as the discovery documents already allow:
a browser-based relying party is the ordinary caller of these two routes, and
refusing by default produced a CORS error to debug rather than a threat
averted.

Set `CORS_ALLOWED_ORIGINS` to narrow that to a named list. Every origin among
the statically configured clients' own `CLIENT_<SLUG>_REDIRECT_URIS` (`https`,
or `http` in development) stays trusted alongside it, so narrowing to one
partner's origin does not lock out the clients this deployment was configured
with. A client that exists only in a client store or as a CIMD document is not
known at start-up, so once you narrow, its origin has to be named here too.
Each entry must be exactly an origin - scheme, host and port, no path - and
`https` outside development; `*` is accepted, and is the default said out
loud.

Set `CORS_ENABLED=false` to turn CORS off entirely. That is the only way to
say no: an empty `CORS_ALLOWED_ORIGINS` means the default, not nothing. With
it off, a relying party can still redeem a code or read a token from its own
backend, just not from JavaScript running on a page.

Every other route, including the hosted sign-in pages, never carries a CORS
header at all: they are reached by navigation and depend on the session
cookie, which is a browser-enforced, same-origin thing already.

## The state store

See [state-and-limits.md](state-and-limits.md) for what it is for and which
backend to pick.

| Variable | Default | Meaning |
| --- | --- | --- |
| `STATE_STORE_BACKEND` | `none` | `none`, `memory`, `cf-durable-object`, `dynamodb` |
| `STATE_STORE_DO_BINDING` | `SAG_STATE` | Durable Object namespace binding |
| `STATE_STORE_TABLE`, `STATE_STORE_REGION` | - | With `dynamodb` |
| `STATE_STORE_MAX_ENTRIES` | `10000` | Cap on the in-memory backend. A full store refuses a code or client assertion claim rather than forgetting one |
| `REQUIRE_STATE_STORE` | `false` | Refuse to start unless `STATE_STORE_BACKEND` names a real backend, so a template or a Terraform refactor cannot drop it silently |

The older `REPLAY_STORE_*` names still work and mean the same thing.

### Pointing AWS somewhere else

SAG signs its own requests to KMS, DynamoDB and S3 rather than carrying an SDK,
so an endpoint is only a base URL. Set one and that service is addressed there
instead of at AWS - a local stack, DynamoDB Local, MinIO, or any S3-compatible
bucket. The names are the AWS SDK's own, so an environment already configured
for an emulator needs nothing further.

| Variable | Default | Meaning |
| --- | --- | --- |
| `AWS_ENDPOINT_URL` | - | Applies to KMS, DynamoDB and S3. Not SES, which always talks to the real regional endpoint |
| `AWS_ENDPOINT_URL_KMS` | - | Overrides the above, for KMS alone |
| `AWS_ENDPOINT_URL_DYNAMODB` | - | The state store |
| `AWS_ENDPOINT_URL_S3` | - | The relying party store, which becomes path style: `<endpoint>/<bucket>/<key>` |

The region still matters when an endpoint is set, because it is part of the
signature's scope: whatever is answering has to agree about it.

A plain `http` endpoint is refused outside development. SAG's requests would
still be unforgeable, but a KMS reply travelling in clear is a signature
anybody on the path can replace, and an S3 reply is the relying party register
itself.

### Sealed environment variables

Any environment variable's value can be pasted as a reference into an AWS
secret store, instead of in plain text:

| Marker | Resolves to |
| --- | --- |
| `aws:kms:<ciphertext>` | The base64 output of `aws kms encrypt` |
| `aws:secretsmanager:<secret id>` | A Secrets Manager secret, by name or ARN |
| `aws:ssm:<name>` | An SSM parameter (`WithDecryption` is always requested, so a `SecureString` is unwrapped) |

Resolution happens once per warm instance, before configuration is parsed,
using the same signed-HTTPS call as everything else under `src/keys/`, so it
works identically on Lambda, ECS, EC2 or a plain Node process: whichever one
hands SAG ambient AWS credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
/ `AWS_SESSION_TOKEN`) and `AWS_REGION`. A deployment with nothing sealed
makes no AWS call and needs no AWS credentials at all. A failure to resolve
is a startup error, never a silent fall-back to the reference itself.

`AWS_ENDPOINT_URL_KMS`, `AWS_ENDPOINT_URL_SECRETS_MANAGER` and
`AWS_ENDPOINT_URL_SSM` (or the global `AWS_ENDPOINT_URL`) apply here too, for
a local stack.

[test/local-stack/](../test/local-stack/README.md) is a worked example: an
instance signing with KMS, counting in DynamoDB and reading its clients from a
bucket, all of it local.

## Email codes

| Variable | Default | Meaning |
| --- | --- | --- |
| `OTP_ENABLED` | `true` | |
| `OTP_CODE_LENGTH` | `9` | Minimum 9; anything lower is raised to 9 with a warning. `OTP_DIGITS` is accepted as the older name, and implies a numeric code |
| `OTP_CODE_ALPHABET` | `alphanumeric` | `alphanumeric` (30 symbols, no confusable characters) or `numeric` |
| `OTP_TTL` | `600` | |
| `OTP_MAX_ATTEMPTS` | `5` | Per transaction, and see the honesty note in [limitations.md](limitations.md) |
| `OTP_MAX_RESENDS` | `3` | Per transaction |
| `OTP_SEND_WINDOW` | `600` | The rate limit window, in seconds. Needs a state store. `OTP_SEND_MIN_INTERVAL` is the older name |
| `OTP_SEND_BURST` | `2` | Codes to one address within a window |
| `OTP_SEND_DAILY_LIMIT` | `5` | Codes a day to one address. Needs a state store |
| `OTP_ALLOWED_DOMAINS` | - | An allow list. When set, it is exclusive |
| `OTP_BLOCKED_DOMAINS` | - | Always applied |
| `SIGNIN_UNKNOWN_ADDRESS` | `silent` | `silent` shows the code screen for an address no route can serve; `explain` says so |

## Sending the mail

| Variable | Meaning |
| --- | --- |
| `EMAIL_PROVIDER` | `console`, `ses`, `notify`, `mailchannels`, `cloudflare`, `smtp` |
| `EMAIL_FROM` | `Sign in <no-reply@id.example.com>` |
| `EMAIL_REPLY_TO`, `EMAIL_OTP_SUBJECT` | Optional |
| `SES_REGION`, `SES_CONFIGURATION_SET` | AWS SES |
| `NOTIFY_API_KEY`, `NOTIFY_TEMPLATE_ID`, `NOTIFY_BASE_URL` | GOV.UK Notify, which owns the wording of the message |
| `MAILCHANNELS_ENDPOINT`, `MAILCHANNELS_API_KEY` | MailChannels, for Workers |
| `CLOUDFLARE_EMAIL_BINDING`, `CLOUDFLARE_EMAIL_DESTINATION` | Cloudflare Email Routing |
| `SMTP_URL` | `smtps://user:pass@host:465` |

`console` only prints codes to the log, so it is refused outside development.

## Relying party store

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLIENTS_STORE_BACKEND` | `none` | `none`, `file`, `cf-kv`, `s3` |
| `CLIENTS_STORE_DIR` | `<SAG_DATA_DIR>/clients` | With `file`: the directory of `<client id>.json` records |
| `CLIENTS_STORE_KV_BINDING` | `SAG_CLIENTS` | With `cf-kv` |
| `CLIENTS_STORE_S3_BUCKET`, `CLIENTS_STORE_S3_REGION` | - | With `s3` |
| `CLIENTS_STORE_PREFIX` | `clients/`, or empty with `file` | Key prefix within the store |
| `CLIENTS_STORE_CACHE_TTL` | `60` | Seconds a record is cached. "No such client" is cached too, but for at most ten seconds, so a record added a moment ago is not refused for a minute |
| `CLIENTS_OPAQUE_ENABLED` | `true` | Whether store-held clients are accepted at all |
| `CLIENTS_REDIRECT_URI_SCHEMES` | `*` | Comma or space separated schemes accepted for authorisation and post-logout redirects, without the colon, or `*` for any. Exact registered URI matching still applies |
| `CLIENTS_CIMD_ENABLED` | Development mode | Client ID Metadata Documents. Production deployments must enable it explicitly. |
| `CLIENTS_CIMD_ALLOWED_DOMAINS` | - | Optional additional allow-list. Empty accepts any public host; every listed domain may declare its own redirect URIs. |
| `CLIENTS_CIMD_ALLOW_SUBDOMAINS` | `true` | |
| `CLIENTS_CIMD_CACHE_TTL` | `300` | |
| `CLIENTS_CIMD_MAX_BYTES` | `32768` | Size cap on a fetched document |

## Appearance and legal links

See [branding.md](branding.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `UI_TITLE` | `Sign in` | |
| `UI_ORG_NAME`, `UI_LOGO_URL` | - | An operator logo at the bottom of the footer; the organisation name is its alternative text |
| `UI_BRAND_NAME`, `UI_PRODUCT_NAME`, `UI_BRAND_URL` | `RESOAuth`, `Smart Access Gateway`, `https://resoauth.dev` | |
| `UI_WHITELABEL` | `false` | Drops the product name, keeps the attribution |
| `UI_TERMS_URL`, `UI_PRIVACY_URL` | - | Instance-wide, overridden per relying party |
| `UI_SUPPORT_URL` | - | "Get help signing in" |
| `UI_LOCALE` | `en-GB` | The document language |
| `CUSTOM_CSS_SNIPPET` | - | Served from `/static/custom.css`, after the stylesheet |
| `CUSTOM_CSS_REMOTE_URL` | - | Replaces the default stylesheet. Must be `https` |

The colour theme control on the pages needs nothing configured: it is built by
`/static/sag.js` and the choice lives in the person's own browser.

## Profile claims

See [profile-claims.md](profile-claims.md) for what is relayed, what is guessed,
and why guessing is off by default.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PROFILE_CLAIMS` | `name given_name family_name preferred_username picture locale` | Which OpenID Connect profile claims may be relayed from an upstream. Anything not named is dropped |
| `PROFILE_PICTURE` | `true` | Separate from the list above, because it is the one claim that makes a relying party's page fetch from a third party |
| `PROFILE_NAME_FROM_EMAIL` | `off` | `infer` guesses a display name from the local part of the address, for the email code path where there is no upstream. Emitted alongside `urn:sag:name_inferred` |
| `PROFILE_AVATAR_FALLBACK` | `off` | `initials` draws an initials avatar as a `data:` URI when there is no upstream picture. Asks no avatar service anything |
| `PROFILE_SHOW_ON_SCREEN` | `true` | Whether SAG's own screens show the name and picture they hold |

## Routing an address to a provider

See [upstreams.md](upstreams.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNIN_PROVIDER_HINT` | `select` | What to do when more than one upstream could take an address. `select` reads the domain's mail records and goes straight there; `order` shows the chooser with that option first; `off` never looks |
| `DNS_RESOLVER_URL` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS, used only where the platform has no resolver. Lambda has none; the Node and Cloudflare adapters supply the platform's own, and on Node no query leaves the deployment. Setting this on Workers overrides the platform resolver, which is rarely what you want - a Worker's `fetch` to a DNS-over-HTTPS endpoint does not come back |
| `DNS_BINDING` | `SAG_DNS` | Where an adapter puts a platform resolver |
| `DNS_TIMEOUT_MS` | `1500` | A lookup that does not answer is simply not an answer |
| `DNS_CACHE_TTL` | `3600` | Seconds an answer is cached, per instance. A domain that matched nothing is cached for five minutes |

## Authentication context

| Variable | Default | Meaning |
| --- | --- | --- |
| `ACR_DEFAULT_REQUIRED` | - | A floor for every relying party, applied whether or not they ask |

The values SAG understands, weakest first:

``` ascii
urn:sag:acr:email-otp        a code sent to an address
urn:sag:acr:federated        an upstream identity provider
urn:sag:acr:federated-mfa    the upstream reported multi-factor
```

A request that asks for more than the sign-in achieved is refused with
`unmet_authentication_requirements` rather than quietly answered with
something weaker.
