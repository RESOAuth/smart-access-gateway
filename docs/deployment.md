# Deploying SAG

One core, thin adapters. The same configuration variables mean the same thing
everywhere. Whichever platform, two things are worth doing before you take
traffic: configure a [state store](state-and-limits.md), and put a rate
limiting rule in front of `/authorize`.

## Before any deployment

```sh
npm run keygen                          # ES256 and a master secret
npm run keygen -- --alg ES256,ML-DSA-44 # and a post-quantum key alongside
```

At minimum:

```sh
SAG_ISSUER=https://id.example.com
SAG_SECRET=<from keygen>
SIGNING_PRIVATE_JWK=<from keygen>
EMAIL_PROVIDER=ses            # or notify, mailchannels, smtp, cloudflare
EMAIL_FROM=Sign in <no-reply@id.example.com>
```

SAG refuses to start with a development default once the issuer is a real
hostname, and refuses an `http` issuer outright.

## Cloudflare Workers

Workers have no asymmetric key service, so the signing key lives in a second
Worker reached only over a service binding - a small private HSM. Deploy it
first:

```sh
wrangler deploy --config adapters/cloudflare/wrangler.hsm.toml
wrangler deploy --config adapters/cloudflare/wrangler.toml
```

Secrets go in with `wrangler secret put`, never in the TOML:

```sh
wrangler secret put SAG_SECRET
wrangler secret put HSM_SHARED_SECRET     # must match the HSM Worker's copy
wrangler secret put MAILCHANNELS_API_KEY
```

Recommended extras:

- **State store**: Durable Objects. Uncomment the three blocks in
  `wrangler.toml`; see [state-and-limits.md](state-and-limits.md).
- **Rate limiting**: a Cloudflare rate limiting rule on `/authorize*`, and a
  stricter one on `POST /authorize/email` and `/authorize/resend`.
- **Relying parties**: a KV namespace bound as `SAG_CLIENTS` when there are
  more than a handful.

## AWS Lambda

`adapters/lambda/handler.js` handles API Gateway HTTP API v2, function URLs
and the older v1 REST shape. Everything is `process.env`, so the configuration
is the same as anywhere else.

```sh
SIGNING_BACKEND=aws-kms
SIGNING_KMS_KEY_ID=arn:aws:kms:eu-west-2:123456789012:key/...
SIGNING_KMS_REGION=eu-west-2
```

With KMS the private key never exists in the function's memory. The execution
role needs `kms:Sign` and `kms:GetPublicKey` on that key and nothing else.

Recommended extras:

- **State store**: DynamoDB, one small table. See
  [state-and-limits.md](state-and-limits.md).
- **Rate limiting**: AWS WAF in front of API Gateway or the function URL, with
  a rate-based rule on `/authorize` and its sub-paths.
- **Mail**: SES in the same region, with `SES_CONFIGURATION_SET` if you want
  bounce and complaint handling.

## Containers, and anywhere else

`docker compose up`, or run `node adapters/node/server.js` behind whatever
proxy you already have. See [docker.md](docker.md).

Behind a proxy, `SAG_ISSUER` must be the public URL: SAG never derives what it
is from a `Host` header on a real deployment, because that would let a header
decide what it claims to be.

Recommended extras:

- **State store**: `memory` for a single container, DynamoDB for several.
- **Rate limiting**: nginx `limit_req`, Caddy's `rate_limit`, or the load
  balancer's own, on `/authorize` and its sub-paths.

## After deploying, check

```sh
curl -s https://id.example.com/alive
curl -s https://id.example.com/healthz | jq
curl -s https://id.example.com/.well-known/openid-configuration | jq
```

`/alive` is an unconditional `200`, there to say a process is listening at
all. `/healthz` reports the signing backend, which algorithms are really
available, whether the state store is there, and every warning the
configuration raised. [operations.md](operations.md) explains how to read it,
how to rotate secrets and keys, and what to do after a suspected compromise.

## More than one instance behind one issuer

Several regions, several clouds, or both, all answering as the same issuer,
is [multi-region.md](multi-region.md): what has to be identical everywhere,
why most of it already works, and which health endpoint a failover check
should actually use.
