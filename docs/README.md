# SAG documentation

Start here.

## Getting it running

- [quickstart.md](quickstart.md) - `npm run dev`, `docker compose up`, and the
  worked example relying party.
- [docker.md](docker.md) - the container: what is in the data directory, how
  configuration works, TLS, upgrading.
- [deployment.md](deployment.md) - Cloudflare Workers, AWS Lambda, containers,
  and what to configure before taking traffic.
- [multi-region.md](multi-region.md) - running several instances as one
  issuer: what has to be identical, and `/alive` versus `/healthz`.
- [../test/local-stack/](../test/local-stack/README.md) - every platform at
  once: a container, workerd, and a Lambda against KMS, DynamoDB and S3, with
  three applications signing in.

## Configuring it

- [configuration.md](configuration.md) - every environment variable.
- [relying-parties.md](relying-parties.md) - the four ways to describe an
  application that signs people in.
- [upstreams.md](upstreams.md) - Microsoft, Google, routing by email domain,
  and guessing the provider from a domain's mail records.
- [profile-claims.md](profile-claims.md) - names and pictures: what is relayed
  from an upstream, what is guessed from an address, and why guessing is off.
- [branding.md](branding.md) - operator branding, whitelabelling, custom CSS,
  terms and privacy links.
- [state-and-limits.md](state-and-limits.md) - single-use codes and client
  assertions, OTP send limits, and which backend to use per platform.

## Running it

- [operations.md](operations.md) - rotating secrets and keys, suspected
  compromise, reading `/healthz`.
- [limitations.md](limitations.md) - what SAG does not do, and what closes
  each gap.
- [post-quantum.md](post-quantum.md) - where the cryptography stands and how a
  migration runs.

## Where it is going

- [adr/](adr/README.md) - why SAG's decisions were made, one record each.
- [rfcs/](rfcs/README.md) - proposed but not yet decided, with the reasoning.
- [signed-relying-party-requests.md](signed-relying-party-requests.md) - the
  design discussion behind [ADR 0010](adr/0010-signed-outbound-requests.md):
  authenticating every outbound call SAG makes on its own behalf, to a
  relying party's own endpoints or an upstream identity provider.
