# AGENTS.md

## What this is

SAG (Smart Access Gateway), by RESOAuth Ltd: an open-source, stateless
identity proxy. It sits in front of Microsoft, Google and other upstream
IDPs (or falls back to an email OTP) and issues its own `id_token` to
relying parties via OAuth 2.1 / OpenID Connect. Deployable as a Cloudflare
Worker, an AWS Lambda, or a plain Node process from the same core.

## Architecture, in one pass

- **No database.** A session, an in-flight authorisation request and an
  authorisation code are all encrypted values the browser or upstream
  carries back, sealed with a shared secret (AES-256-GCM + HKDF-SHA-256).
  One optional shared store (`STATE_STORE_BACKEND`) adds single-use codes and
  client assertions, and OTP send limits when a deployment wants them - see
  [docs/adr/0001](docs/adr/0001-stateless-with-optional-state-store.md).
- **Algorithm-agile signing** (`src/keys/`): one interface over a local key,
  AWS KMS and a Cloudflare HSM Worker; a signer set can publish several
  algorithms at once (classical + post-quantum ML-DSA) so relying parties
  migrate independently - [ADR 0006](docs/adr/0006-algorithm-agile-signing.md).
- **Upstream routing**: email domain -> domain-specific upstream -> `common`
  -> email OTP. Upstream env vars follow
  `UPSTREAM_<PROVIDER>_<DOMAIN-SLUG-OR-COMMON>_<FIELD>`, e.g.
  `UPSTREAM_MICROSOFT_COMMON_CLIENT_ID`.
- **Clients/relying parties**: static env vars, CIMD (client-ID-metadata-
  document), or a store (files, Cloudflare KV, S3) keyed by client id.
- **Multi-region/multi-cloud**: each instance keeps its own signing key and
  federates the public half via `PEER_JWKS_URLS`, never a shared private key
  - [ADR 0009](docs/adr/0009-peer-jwks-federation.md).
- Other load-bearing decisions, each with its own short record: OTP code
  design ([0002](docs/adr/0002-email-otp-code-design.md)), silent
  enumeration/rate-limit handling
  ([0003](docs/adr/0003-silent-enumeration-and-rate-limit-defence.md)),
  session scope & sign-out
  ([0004](docs/adr/0004-session-scope-and-sign-out-confirmation.md)), no
  refresh tokens ([0005](docs/adr/0005-no-refresh-tokens.md)), branding
  ([0008](docs/adr/0008-branding-and-attribution.md)), and what a `sub` is
  derived from
  ([0011](docs/adr/0011-subject-derived-from-the-verified-address.md)).

## Where things are

- `src/` - platform-independent core; `src/endpoints/` is one file per
  route; `src/config.js` parses every environment variable in one place.
- `adapters/{cloudflare,lambda,node}/` - thin shims over the same
  `handleRequest(request, env)`. Put new behaviour in `src/`, not here.
- `docs/` - [docs/README.md](docs/README.md) is the index. `docs/adr/` is
  *why* (one immutable record per decision); `docs/rfcs/` is a pending ADR -
  a proposal written up in enough detail to build from, but not yet decided;
  other docs are *how* (configuration, deployment);
  `docs/questions.md` is a scratch file for open questions during autonomous
  sessions, questions are for human operators but never put decisions there
  permanently - write an RFC once there is an actual proposal, or an ADR
  directly if the decision is obvious enough not to need one. Tell the user
  to check that file if you write any questions and to answer inline.
- `test/` - `node:test`, no mocks of SAG's own code, no server: tests drive
  `handleRequest` directly. `test/local-stack/` runs all three platforms for
  real (workerd, a container, Lambda-on-KMS/DynamoDB/S3).

## Conventions to follow

- A config flag whose only job is "turn a silent fallback into a startup
  error" is named `REQUIRE_*` (e.g. `REQUIRE_STATE_STORE`), never embedded
  elsewhere - [ADR 0007](docs/adr/0007-require-prefix-for-fail-fast-flags.md).
- Renaming a public environment variable keeps the old name working via the
  `alias()` helper in `src/config.js`; do not just break it.
- Every new environment variable gets a row in
  [docs/configuration.md](docs/configuration.md) (or
  [relying-parties.md](docs/relying-parties.md) / [upstreams.md](docs/upstreams.md)
  if it is per-client or per-upstream).
- A real architectural decision gets a new numbered file in `docs/adr/`
  (Context / Decision / Consequences) and an index row in
  `docs/adr/README.md`, not prose bolted onto an unrelated doc. A proposal
  that is not yet decided goes in `docs/rfcs/` instead (Context / Proposal /
  Cost); when it is accepted, move it to `docs/adr/` and delete it from
  `docs/rfcs/`.
- Prose style throughout `docs/` and comments: British English, Oxford
  commas, hyphens instead of em-dashes, terse and direct - match what is
  already there rather than introducing a different voice.
- Comments explain the non-obvious *why* only; never restate what the code
  already says. No speculative abstractions, feature flags or
  backwards-compatibility shims beyond what was actually asked for.
- No personal names or identifying information in anything checked in -
  this is a public repository. Use a placeholder ("Jamie Taylor") in
  examples and test fixtures instead.

## Before calling anything done

Run `npm install` once to fetch the test dependencies, then run `npm test`.
There is no build step, so there is no excuse for skipping it.
