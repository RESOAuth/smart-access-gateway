# Multi-region and multi-cloud deployment

One issuer can be served by more than one running instance - several AWS
regions, several clouds, or both - provided every instance answers the same
questions the same way. This is about what "the same way" has to mean, not
about new code: almost none of this needs a code change, because SAG already
refuses to let a request decide what it claims to be. That single design
decision, made for a different reason, turns out to be exactly what
multi-region needs.

## The shape

A central hostname is the issuer identity - `auth.resoauth.cloud` in
[configuration.md](configuration.md)'s terms, `SAG_ISSUER`. It is the only
hostname a relying party is ever configured with, and the only one that
appears in `iss`, in discovery, in a cookie.

Each real deployment gets its own hostname as well -
`aws-eu-west-2.auth.resoauth.cloud`, `cf-workers.auth.resoauth.cloud` - which
exists for machines, not people:

- a health checker that has to reach one specific deployment directly,
  because checking through the central hostname would just ask whichever
  deployment DNS or a proxy currently prefers, which defeats the point;
- an operator debugging one region without wondering whether the central
  hostname just moved them somewhere else mid-investigation;
- Route 53, or any other DNS or traffic-manager failover in front of several
  regions, which needs a per-region target to check and route to.

**Never hand a regional hostname to a person's browser or configure one as a
relying party's issuer.** Nothing in SAG stops it working - a token is a
token regardless of which hostname the connection arrived on - but doing so
defeats the reason a central hostname exists: that relying party now depends
on one specific region rather than on however many the deployment has, and
gets none of the benefit of failover it presumably thinks it has. Write this
down as an operating rule, because nothing enforces it technically and there
is no reason to make it enforce something that is not a security boundary -
see "Why SAG does not check the Host header" below.

## Why this already works

`SAG_ISSUER` is read once from configuration and never re-derived from a
request. [config.js](../src/config.js) only falls back to the request's own
host when `SAG_ISSUER` is unset at all, which is refused outright once a real
hostname is in play (see [deployment.md](deployment.md)). Every other place
that matters - the `iss` claim, the discovery documents, `config.issuer` in
[context.js](../src/context.js) - reads that one fixed value. A deployment
answering on `aws-eu-west-2.auth.resoauth.cloud` with
`SAG_ISSUER=https://auth.resoauth.cloud` set already issues tokens as
`auth.resoauth.cloud`, today, with nothing added.

Session cookies follow the same logic from the other direction: SAG never
sets a `Domain` attribute (see [session.js](../src/session.js)), so a cookie
is scoped to whichever hostname the browser actually used. As long as real
traffic only ever talks to the central hostname, that is the only cookie jar
in play, and which region answered underneath is invisible to the browser.
Visiting a regional hostname directly gets an entirely separate session, by
the same mechanism - a useful accident, not something to rely on as a
security control.

### Why SAG does not check the Host header

It would be reasonable to ask whether an instance should refuse a request
whose Host is neither the central hostname nor its own. It does not, and
should not gain that check: Host is not trusted for anything today, so
nothing is guarded by adding a check for it. An arbitrary Host header reaching
SAG's application code at all means the TLS/edge layer in front of it - a
Cloudflare custom hostname, an API Gateway custom domain, an ALB listener
rule - already terminated a connection it should not have. That is where this
belongs: configure each deployment's edge to accept exactly the hostnames it
should (its own, and the central one if it is meant to receive proxied or
failed-over traffic), the same way you would refuse to provision a TLS
certificate for a hostname you do not run.

## What has to be identical everywhere

Everything below is configuration and key material, not code, but getting it
wrong is silent: SAG has no way to notice that one region disagrees with
another, because each instance only ever sees itself.

- **`SAG_ISSUER`.** Identical, and this is the only one already covered above.
- **`SAG_SECRET` (and `SAG_SECRET_PREVIOUS` during rotation).** Identical
  everywhere. This makes the rotation runbook in
  [operations.md](operations.md) stricter, not different: step 1 has to land
  in every region before anywhere moves to step 2, and step 3 cannot happen
  anywhere until step 1 and the wait have completed everywhere. A session
  sealed in one region under a secret another region does not have yet is a
  session that region cannot read - which, to the person carrying it, looks
  like being randomly signed out the moment DNS or failover moves them.
- **The signing key material.** Does not have to be identical any more - see
  "Publishing every instance's keys" below, which is a better answer than
  copying a private key between regions. What still has to be planned once,
  for the whole deployment rather than per region, is the algorithm *set*:
  `SIGNING_ALG`, `SIGNING_ADDITIONAL_ALGS`, `REQUIRE_POST_QUANTUM_SIGNING`.
  This is where [post-quantum.md](post-quantum.md) and
  [limitations.md](limitations.md) stop being hypothetical: AWS KMS does not
  offer ML-DSA keys in every region today, so a deployment spanning regions
  may only be able to sign with a post-quantum algorithm from some of them,
  and no amount of JWKS federation changes that - federation shares public
  keys, not the ability to produce new signatures with them. Either hold
  every region to the same offered algorithm set, or accept that a relying
  party who happens to be routed to a region that cannot sign with the
  algorithm it asked for gets refused there. Discovery already says so per
  instance (`id_token_signing_alg_values_supported`); it is a deployment-wide
  decision whether that difference between regions is acceptable.
- **`SUBJECT_SALT`.** Identical, and - as
  [operations.md](operations.md) already says for a single deployment - never
  rotated. Doubly true here: a region catching up with a changed salt would
  hand out different `sub` values than the others for the same person.
- **The state store, if configured.** [state-and-limits.md](state-and-limits.md)
  already warns that the `memory` backend is per-instance; multi-region is
  that warning at the scale of a whole region or cloud instead of one process.
  What actually shares cleanly:
  - **Cloudflare only.** Durable Objects are already addressed by name across
    Cloudflare's own network, so a Cloudflare-only spread gets one logical
    store for free.
  - **AWS only, several regions.** Point every region's `STATE_STORE_TABLE`
    and `STATE_STORE_REGION` at a DynamoDB **global table** - same table name
    in each region, replicated by AWS. Nothing in SAG changes; it is
    provisioning, not configuration.
  - **Genuine multi-cloud.** [store/index.js](../src/store/index.js) signs its
    own DynamoDB requests with SigV4 over plain `fetch`, rather than carrying
    the AWS SDK, specifically so it has no Node dependency - which means a
    Cloudflare Workers deployment can point `STATE_STORE_BACKEND=dynamodb` at
    the same table an AWS deployment uses. A cross-cloud deployment that wants
    one real, shared state store already can, today.
  - Otherwise, say plainly - in the start-up banner and the logs, the way
    every other absent defence is reported - that single-use codes and OTP
    send limits are enforced per region or per cloud rather than for the
    deployment as a whole, and decide whether that is acceptable rather than
    discovering it later.
- **Relying party configuration**, if held in a store rather than the
  environment. The same rule again: an S3 bucket or a KV namespace is
  regional/platform-local unless the operator replicates it, so a client
  added in one place is invisible to a region reading from a different copy
  until it catches up.

## Publishing every instance's keys: JWKS federation

Rather than copying one private key into every region's signing backend,
each instance can hold its own, generated and kept in its own KMS or HSM, and
still have every relying party treat every instance's tokens as equally
valid. `PEER_JWKS_URLS` names the other instances; `/jwks.json` becomes this
instance's own keys plus whatever it currently trusts from each of them. See
[ADR 0009](adr/0009-peer-jwks-federation.md) for why this was chosen over
sharing one private key across instances.

```sh
PEER_JWKS_URLS=https://aws-eu-west-2.auth.resoauth.cloud/.well-known/jwks.json,https://cf-workers.auth.resoauth.cloud/.well-known/jwks.json
```

List every instance's peers as a complete mesh - each one naming all the
others - or the guarantee this exists for quietly stops holding for whichever
pairs are missing. There is no discovery mechanism here beyond that list:
this is not "find other SAG instances on the network," it is "these specific,
already-known instances of my own deployment."

**Listing a URL here is a trust decision, not a convenience.** Whatever keys
a peer's JWKS returns become as fully trusted for this issuer as this
instance's own signer set, because that is exactly what letting relying
parties treat instances interchangeably requires: a token signed with any key
this instance vouches for verifies as if this instance had signed it itself.
Only ever list a deployment's own peers, reached over `https` with an
ordinary, unmodified certificate check - the same trust `SAG_ISSUER` and
`SIGNING_KMS_KEY_ID` already carry as plain configuration, extended to
"instances," not a new kind of risk.

Some defensive handling happens regardless, because a peer is still an
external HTTP response: a size cap (`PEER_JWKS_MAX_BYTES`) so a compromised or
misbehaving peer cannot be used to exhaust memory, strict parsing that refuses
anything that is not a `keys` array, and any entry carrying a private or
symmetric component (`d`, `k`) is dropped and logged rather than merged in -
a peer that ever answered with that by mistake must not have the mistake
amplified into every other instance's published JWKS.

### The cache, and why the grace period is generous

A peer's keys are fetched, merged, and cached; `PEER_JWKS_CACHE_TTL` (default
five minutes) is how often a healthy peer is asked again. The more important
number is `PEER_JWKS_STALE_TTL`: how long this instance keeps vouching for a
peer's last-known keys after that peer stops answering at all, before finally
dropping them. It defaults to **twice `SESSION_MAX_LIFETIME`**.

That default is deliberately generous rather than tightly derived. The
narrowest correct answer would chain `ID_TOKEN_TTL` or `ACCESS_TOKEN_TTL`
together with however long a relying party's own JWKS cache might run -
"a day is safe" is the figure [operations.md](operations.md) already gives
for a relying party's own cache during a key rotation - which would put the
true minimum somewhere around a day or two. The cost of going well past that
minimum is a few kilobytes of harmless, still-correct public key material
sitting in a cache; the cost of falling short of it is a token that instance
signed while perfectly healthy failing verification somewhere, for a reason
that looks nothing like what actually happened and lands exactly during an
incident. Twice the longest-lived thing this deployment already tracks is a
round number comfortably past the minimum, not a precisely computed bound -
tighten it with `PEER_JWKS_STALE_TTL` if a deployment wants to reason about it
more exactly.

Failures are held for a short interval of their own, `PEER_JWKS_RETRY_AFTER`
(default thirty seconds). Only a successful fetch is cached, so without it a
peer that has never answered - a URL with a typo in it, a region still coming
up, an outage that started before this instance did - would be attempted again
on every single request, and each attempt would hold the connection open for
`PEER_JWKS_TIMEOUT_MS` before giving up. `/jwks.json` is the endpoint every
relying party calls to verify a token, so that is the wrong place to pay a
four second timeout per request: one region being unreachable would slow token
verification everywhere rather than only there. The backoff does not shorten
the grace period - a peer inside it still contributes its last known keys -
and a success clears it immediately, so a peer that comes back is picked up on
the next attempt rather than waiting the interval out.

### Where the cache lives

`PEER_JWKS_CACHE_BACKEND` picks where a fetched entry is kept:

- **`memory`** (default). Works everywhere with no provisioning, and is
  exactly as durable as the `memory` state store backend: gone the moment the
  isolate or container recycles. Fine for trying this out; not durable enough
  to lean on the grace period for real, because the very restart that would
  make a peer's keys useful to remember is the one that empties this cache.
- **`cf-kv`**. The right Cloudflare-native answer, and notably *not* the
  choice state store made: [state-and-limits.md](state-and-limits.md) refuses
  Cloudflare KV for single-use codes because it has no compare-and-set and is
  eventually consistent, which makes it unsafe for a security control with
  one correct answer. Neither property matters here - this is a read-mostly
  resilience cache with a single writer per key, not a control deciding
  whether a code has been spent - so the same eventual consistency that
  disqualified KV there is simply irrelevant here.
- **`dynamodb`**. The same signed-`fetch` implementation the state store
  uses, so - as in "genuine multi-cloud" above - a Cloudflare Workers instance
  can use it too, not only AWS ones.

### What `/healthz` adds

`peer_jwks` reports the configured peers and, for each, how long ago its keys
were last actually fetched - read from the cache, never a live fetch, so this
stays as cheap as everything else `/healthz` reports:

```json
"peer_jwks": {
  "backend": "dynamodb",
  "peers": [
    { "url": "https://aws-eu-west-2.auth.resoauth.cloud/.well-known/jwks.json",
      "last_fetched_seconds_ago": 42, "within_cache_ttl": true, "within_grace_period": true }
  ]
}
```

`within_grace_period: false` means that peer's keys have already dropped out
of this instance's `/jwks.json` - worth alerting on, since it means that
peer has been unreachable for a very long time by design.

## Health checks: `/alive` versus `/healthz`, and where Route 53 should point

SAG now answers two different questions at two different paths, and a
multi-region deployment is exactly the situation where the difference
matters:

- **`/alive`** answers `200 ok` unconditionally, before configuration is even
  read. It answers even when this instance's configuration would refuse to
  start, because a broken configuration must not also take down the one
  signal that says "there is a process here to restart" or "there is nothing
  listening here at all." It never depends on signing, the state store, or
  anything else, and its shape is meant to stay exactly this stable forever -
  the right thing for a container orchestrator's liveness probe, or a load
  balancer deciding whether to keep a target in its pool at the network
  level, and cheap enough to hit very often from many places.
- **`/healthz`** is deliberately the harder question: can this instance
  actually sign somebody in. It fails - `500`, via the same path a broken
  configuration always takes - exactly when a region cannot do its job. See
  [operations.md](operations.md) for how to read what it reports.

**Point Route 53's (or any other DNS/traffic-manager) per-region health check
at `/healthz`, not `/alive`.** The entire purpose of a regional health check
feeding failover is to route traffic away from a region that cannot actually
do the job; `/alive` would say a region is fine right up until it is
completely unreachable, which hides precisely the failure failover exists to
catch. `/alive` earns its place lower down the stack - a load balancer's own
target-health check in front of `/healthz`, or a platform's own liveness
probe - not as the signal deciding which region gets real sign-ins.

One tuning note that is not particular to SAG: the first request to a cold
instance is also the one that builds its signer set, which for
`SIGNING_BACKEND=aws-kms` means a real `GetPublicKey` call. A health checker
that hits a cold region pays that cost once, and every request after it on
that instance is warm. Set the failure threshold - the number of consecutive
failed checks before Route 53 acts - to tolerate one slow response rather
than failing over on it.

## What this does not solve

- **How `SAG_SECRET` and `SUBJECT_SALT` actually get to every region/cloud.**
  JWKS federation answers this for signing keys specifically; the master
  secret and the pairwise salt still have to be identical everywhere and this
  document does not say how they get distributed, rotated in step, or audited
  as staying in sync. That is an operational secrets-management question - a
  parameter store replicated deliberately, not copy-pasted once and forgotten
  - worth its own decision before a second region goes live for real traffic.
- **An asymmetric peer list.** `PEER_JWKS_URLS` is plain configuration with no
  cross-check: if region A lists B but B does not list A, A's `/jwks.json`
  includes B's keys, but B's `/jwks.json` never includes A's - so a token A
  signed fails verification against whatever a relying party cached from B,
  and nothing today notices the mismatch to warn anyone. Keeping the peer
  list a complete mesh is an operator discipline, the same as keeping the
  algorithm set aligned above.
- **Automatic detection of regions disagreeing on anything else.** JWKS itself
  self-heals through federation; the algorithm set and client configuration
  do not. A worthwhile addition later would be a comparison tool - fetch
  discovery from every known regional hostname and diff what each claims to
  offer - rather than discovering a mismatch from a relying party's bug
  report.
