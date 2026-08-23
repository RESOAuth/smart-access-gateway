# SAG - Smart Access Gateway

An identity proxy rather than an identity provider. SAG gives your application
one OpenID Connect endpoint to talk to, and behind it uses whatever the person
already has - a Microsoft or Google account, or a code emailed to them - so you
never hold a password and never run a user database.

```
your app  ──OIDC──▶  SAG  ──OIDC──▶  Microsoft / Google
                      └────email───▶  a one-time code
```

It is built to be deployed by anybody in a few minutes, and to be operated at
scale by [RESOAuth](https://resoauth.dev) on behalf of customers who would
rather not.

## Try it

```sh
npm run dev              # http://127.0.0.1:8787, no configuration, no dependencies
docker compose up        # the same, keeping its keys in a volume
```

Then point any OpenID Connect client library at
`http://127.0.0.1:8787/.well-known/openid-configuration`, or run the worked
example relying party with `npm run example` and open
`http://127.0.0.1:8788`.

[Quickstart](docs/quickstart.md) has the details, including what to do next.

## What makes it different

**No database.** Not "a database you can swap out" - none, unless you want
single-use authorisation codes and rate limits, which are the two things that
genuinely cannot be stateless. A session is an encrypted cookie, an in-flight
request is an encrypted form field, an authorisation code is an encrypted
string, all AES-256-GCM under keys derived from one master secret.

**Runs where you already are.** One core, thin adapters: Cloudflare Workers,
AWS Lambda, a container, or a plain Node process. Same code, same variables.

**Routes by email domain.** A person types their address. If a Microsoft tenant
is configured for their domain they go there, otherwise a common endpoint if
there is one, otherwise a code by email. One sign-in screen, no "choose your
provider" wall - and when two providers could both take an address, SAG reads
the domain's mail records to work out which, rather than asking.

**Honest about authentication strength.** `acr` and `amr` say what actually
happened, and a relying party can demand more. A request that asks for MFA is
refused rather than quietly answered with an email code.

**Post-quantum ready, not post-quantum theatre.** Confidentiality is already in
symmetric primitives. The signing layer is algorithm-agile and can publish an
ML-DSA key alongside ES256, so relying parties migrate one at a time.

**Multi-region and multi-cloud without a shared private key.** Each instance
keeps its own signing key and federates the public half via
`PEER_JWKS_URLS`, so several regions or clouds can serve one issuer hostname
with nothing more secret than a JWKS URL crossing between them. `/alive`
answers whether a process is listening at all, independent of configuration;
`/healthz` answers whether it can actually sign somebody in, and reports the
running `version`.

**Says only what it can do.** The discovery documents describe the running
instance, not the software: no federated `acr` without an upstream configured,
no `profile` scope when nothing could fill it, no algorithm without a key
behind it.

**Works without CSS or JavaScript.** Semantic HTML that happens to be styled.
It reflows at 400% zoom, respects reduced motion and increased contrast, and
submits fine with scripting off. Light and dark, with a toggle that only exists
when the script that builds it has run - so a page whose script was blocked
shows no dead control. There is no inline script and no inline style on any
page, which is what lets every one of them carry a policy starting at
`default-src 'none'`.

## Documentation

Everything is in [docs/](docs/README.md):

| | |
| --- | --- |
| [quickstart.md](docs/quickstart.md) | Get it running |
| [docker.md](docs/docker.md) | The container and its data directory |
| [deployment.md](docs/deployment.md) | Cloudflare, AWS, containers |
| [multi-region.md](docs/multi-region.md) | Running several instances as one issuer |
| [configuration.md](docs/configuration.md) | Every environment variable |
| [relying-parties.md](docs/relying-parties.md) | Adding applications |
| [upstreams.md](docs/upstreams.md) | Adding Microsoft and Google, and guessing which |
| [profile-claims.md](docs/profile-claims.md) | Names and pictures: relayed, and guessed |
| [branding.md](docs/branding.md) | Branding, whitelabelling, custom CSS, light and dark |
| [state-and-limits.md](docs/state-and-limits.md) | Single-use codes and rate limits |
| [operations.md](docs/operations.md) | Rotation, compromise, `/healthz` |
| [limitations.md](docs/limitations.md) | What it does not do |
| [post-quantum.md](docs/post-quantum.md) | Where the cryptography stands |
| [adr/](docs/adr/README.md) · [rfcs/](docs/rfcs/README.md) | Why, and what is next |
| [test/local-stack/](test/local-stack/README.md) | Every platform at once, locally |

## Testing

```sh
npm test
```

No mocks of SAG's own code and no server: the tests drive the same
`handleRequest` every adapter runs, as a browser and a relying party would.
Federation is tested against a stub provider that serves a real discovery
document and a genuinely signed `id_token`, so only the network is faked.

What that cannot reach is the platform: a Durable Object, a signature made
inside KMS, the way API Gateway hands a Lambda its cookies. For those there is
a local stack - the same code running three ways at once, with three
applications signing in against it.

```sh
npm run stack:up          # a container, Cloudflare Worker, and a Lambda
npm run stack:verify      # sign in against all three, headless
npm run stack:down
```

See [test/local-stack/](test/local-stack/README.md).

## Licence

AGPL-3.0. Built by [RESOAuth Ltd](https://resoauth.dev).
