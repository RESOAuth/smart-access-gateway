# The local stack

Every platform SAG runs on, at once, on one machine.

```sh
./stack.sh up          # build, start, wait, print the map
./stack.sh verify      # sign in as all four applications, headless
./stack.sh down
```

Then open <http://localhost:8801>.

## Why this exists

`npm test` drives `handleRequest` directly. That is the right way to test what
SAG decides, and it covers almost everything - but it cannot see the platform.
A Durable Object, a signature made inside KMS, the separate `cookies` array
API Gateway hands a Lambda: none of those exist in a unit test, and all of them
are load-bearing.

So this stack runs the same code three ways, with a different backend for every
replaceable part, and then signs somebody in on each:

| Instance | Runtime | Signing | State | Relying parties |
| --- | --- | --- | --- | --- |
| `sag-node` :8791 | Node, in the repository's own image | a key generated into a volume | an in-process map | a directory of JSON files |
| `sag-workers` :8792 | workerd, via `wrangler dev` | a second, private Worker | a Durable Object | environment variables |
| `sag-lambda` :8793 | AWS's Lambda base image | AWS KMS | DynamoDB | an S3 bucket |

Nothing inside SAG is stubbed. workerd and its Durable Objects are the real
implementation; the Lambda runs in AWS's own image behind its runtime interface
emulator; KMS, DynamoDB and S3 are LocalStack. What SAG sees is what it would
see deployed.

All three also set `PEER_JWKS_URLS` to the other two, a complete mesh, so each
instance's `/jwks.json` ends up describing all three signers rather than only
its own - the JWKS federation described in
[docs/multi-region.md](../../docs/multi-region.md), exercised for real rather
than only in `test/peer-jwks.test.js`'s unit tests.

## Who is signing in

Four applications, all running the same hundred lines from
[examples/relying-party](../../examples/relying-party/server.js):

| | Signs in against | As |
| --- | --- | --- |
| <http://localhost:8801> | the Node instance | `rp-node`, a public client with PKCE |
| <http://localhost:8802> | the Workers instance | `rp-workers`, a public client with PKCE |
| <http://localhost:8803> | the Lambda instance | `rp-lambda`, confidential, `client_secret_basic` |
| <http://localhost:8804> | the Node instance | a client id that is a URL, registered nowhere |

The fourth is the interesting one. Nobody registered it: its client id is
`http://localhost:8804/.well-known/client.json`, and SAG fetches that document
to find out what the client is - a Client ID Metadata Document, which is how an
application can turn up with no registration step at either end. Only somebody
controlling that origin can change what the client claims to be, which is what
makes the URL usable as an identity.

The Node instance accepts such clients from `localhost` only
(`CLIENTS_CIMD_ALLOWED_DOMAINS`). That allow list is the trust boundary: a
permitted metadata publisher chooses its redirect URIs, which can be on another
origin or be loopback URIs for a native application.

Four separate applications rather than one with a switch, because that is what
catches an issuer or an audience leaking between them. Each page links to the
other three.

Every instance guesses a display name from the address and draws an initials
avatar, because there is no Microsoft or Google registration here to relay a
real one from and the "continue signing in" screen is worth seeing with
something on it. Both are off by default; see
[docs/profile-claims.md](../../docs/profile-claims.md) for why. The applications
ask for the `profile` scope, so what arrives is visible on their own pages -
including the `urn:sag:name_inferred` flag that marks the name as a guess.

Sign-in codes are printed to the instance's log and shown on the page, because
every issuer here is a development hostname:

```sh
./stack.sh logs sag-node
```

## Addresses

Every container shares the host's network, so `http://localhost:8791` is the
same address to the browser, to an application, and to SAG itself. There are no
published ports, no service names, and nothing to rewrite between the front
channel and the back.

That is not just convenience. A client id that is a URL has to resolve
identically for the browser following a redirect and for SAG fetching the
document behind it, and one flat address space is the simplest way to be sure
it does. The alternative - a container network, published ports, and a
`EXAMPLE_BACKCHANNEL_ORIGIN` rewriting the token endpoint and the JWKS - is
what a deployment behind a load balancer looks like, and the example still
supports it, but it is not what this stack needs.

Two consequences. This wants Linux or a Linux VM: Docker Desktop on macOS and
Windows does not hand a container the host's network the same way. And it needs
a `podman-compose` from this decade - 1.0.3, which Debian still ships, passes
`--network-alias` alongside `--network host` and podman refuses the pair. If
`./stack.sh up` fails with *cannot set multiple networks*, that is why:

```sh
pip3 install --user --break-system-packages -U podman-compose
```

## What `verify` checks

```sh
./stack.sh verify              # all of them
./stack.sh verify sag-lambda   # one, by name: sag-node, sag-workers,
                               # sag-lambda or rp-cimd
```

For each instance, as a browser: discovery, the JWKS, the email screen, the
code screen, the redirect back, the token exchange, and the `id_token` verified
against the key that instance publishes. Then the three things only a real
platform can answer:

- **the code is single use** - an in-process map, a Durable Object and a
  DynamoDB conditional write have to give the same answer the second time;
- **the session survives** - sealed by one platform and opened again by it,
  which is what makes `prompt=none` silent;
- **the round trip** - on Lambda, a request that has been through an API
  Gateway event and back, cookies and base64 and all.

Once every instance has run, a final **peer mesh** check fetches
`/.well-known/jwks.json` from `sag-node`, `sag-workers` and `sag-lambda` fresh
- not the cached view `/healthz`'s `peer_jwks` field reports - and confirms
each one's document carries the signing key each of the other two just used,
proving `PEER_JWKS_URLS` is genuinely federating rather than merely configured.
Running `verify` against a single named instance skips this, since there is
nothing to cross-check with one.

For the self-describing client it also reads the metadata document and checks
that it declares redirect URIs and no secret-based authentication method.

## The AWS side

LocalStack, provisioned on start by
[localstack/init/10-provision.sh](localstack/init/10-provision.sh): an
`ECC_NIST_P256` signing key behind the alias `alias/sag-signing`, a `sag-state`
table with a TTL attribute, and a `sag-clients` bucket seeded from
[localstack/clients](localstack/clients). That script is the same three
resources [docs/deployment.md](../../docs/deployment.md) asks for on AWS, which
is what makes the Lambda instance a rehearsal rather than a demonstration.

SAG reads the AWS SDK's own endpoint variables, so nothing here is
LocalStack-specific:

```sh
AWS_ENDPOINT_URL_KMS=http://localstack:4566
AWS_ENDPOINT_URL_DYNAMODB=http://localstack:4566
AWS_ENDPOINT_URL_S3=http://localstack:4566
```

Point them at MinIO, DynamoDB Local, or a real account instead and nothing else
changes. An `http` endpoint is refused outside development, because a KMS reply
in clear is a signature anybody on the path can replace.

Poke at it directly - port 4566 is published:

```sh
podman exec sag-localstack awslocal dynamodb scan --table-name sag-state
podman exec sag-localstack awslocal s3 ls s3://sag-clients/clients/
podman exec sag-localstack awslocal kms describe-key --key-id alias/sag-signing
```

## Editing things while it runs

| What | Where | Takes effect |
| --- | --- | --- |
| Settings shared by the Node and Lambda instances | [env/sag-common.env](env/sag-common.env) | `./stack.sh restart sag-node` |
| AWS coordinates | [env/aws.env](env/aws.env) | `./stack.sh restart sag-lambda` |
| The Node instance's relying parties | [clients/](clients) | within `CLIENTS_STORE_CACHE_TTL`, 60s by default; a newly added one within ten |
| The Lambda instance's relying parties | [localstack/clients/](localstack/clients) | `podman restart sag-localstack`, which re-seeds the bucket |
| The Workers instance, all of it | [workers/wrangler.dev.toml](workers/wrangler.dev.toml) | `./stack.sh restart sag-workers` |
| The self-describing client's registration | nothing to edit - it is [the document the application serves](../../examples/relying-party/server.js) | `./stack.sh restart rp-cimd`, then within `CLIENTS_CIMD_CACHE_TTL` |
| SAG itself | `src/`, `adapters/` | `./stack.sh up`, which always rebuilds and recreates |

A Worker's environment comes from its wrangler configuration rather than from
the process, which is why the Workers instance has no `.env` file and why
`env/sag-common.env` has an equivalent in the TOML instead.

## Every port

| Port | |
| --- | --- |
| 8791, 8792, 8793 | the three SAG instances |
| 8801, 8802, 8803, 8804 | the four applications |
| 4566 | LocalStack: KMS, DynamoDB, S3 |
| 8790 | the Lambda runtime interface emulator, on loopback, for posting an event by hand |

Port 8790 is the fastest way to see what the handler is actually given:

```sh
curl -sX POST http://localhost:8790/2015-03-31/functions/function/invocations \
  -d '{"version":"2.0","rawPath":"/healthz","requestContext":{"http":{"method":"GET"}}}'
```

## Development keys, on purpose

The master secrets in `compose.yml`, the signing key in
`workers/wrangler.hsm.dev.toml`, and the client secret for `rp-lambda` are all
committed. They are here so the stack comes up the same way on every machine,
and they protect nothing. Never copy one into a deployment: generate your own
with `npm run keygen` and `npm run generate-client-secret`.

`./stack.sh down` removes the volumes with it. A test rig with a history is not
a test rig.

## What it does not cover

- **Upstream Microsoft and Google.** Both need a real client registration and
  an https redirect URI, so the stack is email codes only. Federation is tested
  in `npm test` against a stub provider that serves a real discovery document
  and a genuinely signed `id_token`. With no upstreams there is never more than
  one route for an address, so the DNS provider hint never fires either and is
  set to `off` explicitly, so a machine with no DNS behaves the same as one
  with. It has its own tests, driven through a resolver binding.
- **Cloudflare KV for relying party records.** The Workers instance keeps its
  one client in the environment. Seeding wrangler's local KV means driving
  wrangler to write it, which is more moving parts than it earns when the file
  and S3 backends already cover records held outside the environment.
- **Client metadata documents over https.** The one here is fetched over
  `http`, which SAG allows only because the issuer is a development hostname.
  Against a real name the document must be `https`, and only the origin in the
  client id is ever read - never a redirect from it.
- **TLS.** Everything is `http` on `localhost`, which SAG treats as
  development - and one consequence is worth knowing: session cookies are not
  marked `Secure` here, because a `Secure` cookie over `http` is a cookie the
  browser would refuse. Against a real hostname the flag is always set, and an
  `http` issuer is refused outright.
- **Anything about scale.** One container each. The point is that the code
  paths work, not how fast.

## When it will not start

`./stack.sh up` waits for each piece and names the one that never answered.
After that:

```sh
./stack.sh logs sag-workers      # follow one container
./stack.sh ps
curl -s http://localhost:4566/_localstack/init   # did provisioning succeed?
curl -s http://localhost:8793/healthz            # what does the Lambda think it is?
```

`/healthz` is the most useful thing here: it answers only when configuration,
keys and signing are all usable, and it says which backend each part resolved
to. If the Lambda instance reports an ephemeral key, it never reached KMS.

**`Sign-in failed: fetch failed` on a callback.** The application could not
reach its instance, and the code in brackets after it says why:
`ECONNREFUSED` or `ENOTFOUND` while the stack is being rebuilt is just that -
wait for `./stack.sh up` to finish. `ENOTFOUND` on a settled stack is the
container DNS blinking, which rootless Podman does occasionally; the
application retries a connection that never opened, and logs when it does:

```sh
./stack.sh logs rp-workers
```

**Signing in at one application appears to sign you out of another.** It
should not, and in this stack it does not - but only because every instance and
every application is given its own cookie name. A cookie is scoped to a host
and ignores the port, so `localhost:8791` and `localhost:8792` share one jar:
two instances both calling their cookie `sag_session` would overwrite each
other. `SESSION_COOKIE_NAME` and `EXAMPLE_COOKIE_NAME` in `compose.yml` are
there for that reason, and it is a localhost problem only - real deployments
have real hostnames.

The Workers instance is the slow one: workerd starts, then compiles the Worker
on the first request. Sixty seconds from cold is normal.
