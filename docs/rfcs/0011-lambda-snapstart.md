# 0011. Lambda SnapStart with preloaded configuration and restore-safe credentials

Status: Proposed

## Context

SAG should start faster on Lambda and make fewer configuration reads when
traffic creates new execution environments. This proposal enables SnapStart
for a dedicated Node.js 24 Lambda image, with explicit initialisation and
restore hooks. Merging this RFC records the proposal; implementation and
production enablement follow separately.

AWS announced container-image SnapStart on 2 September 2026. Its current
[container hook guide](https://docs.aws.amazon.com/lambda/latest/dg/snapstart-runtime-hooks-custom.html)
explicitly covers the Lambda Node.js base image. Use
`FROM public.ecr.aws/lambda/nodejs:24`, pinned to a verified digest. The managed
Node.js ZIP runtime is a different deployment path. The older SnapStart
overview still excludes containers; the
[container announcement](https://aws.amazon.com/about-aws/whats-new/2026/07/aws-lambda-snapstart-container/)
and dedicated hook guide establish the newer support. These sources were
checked on 19 September 2026.

The relevant behaviour at repository commit `6d6dfe5` is:

| Component | Current behaviour | Implication |
| --- | --- | --- |
| [Lambda handler](../../adapters/lambda/handler.js) | Calls `handleRequest` with `process.env` | Importing the handler does not initialise SAG |
| [Context](../../src/context.js) | Lazily resolves configuration and services, cached by environment-object identity | Warm requests already reuse configuration; the saving is across restored environments |
| [Sealed environment](../../src/keys/sealedEnv.js) | One parallel AWS call per sealed variable; SSM uses `GetParameter` with decryption | Every fresh environment repeats these reads; duplicate references are fetched separately |
| [KMS signer](../../src/keys/awskms.js) | Lazily fetches its public key and retains a credentials object | Public keys can be preloaded; credentials must become renewable |
| [S3 client store](../../src/clients/store.js) | Captures credentials when constructed | Reusing its closure after restore can reuse expired credentials |
| [Other AWS integrations](../../src/crypto/sigv4.js) | Read credentials from an environment bag; unsealing copies that bag | Reading again from the copied bag does not guarantee current credentials |
| [Local Lambda image](../../test/local-stack/lambda/Dockerfile) | Already uses a digest-pinned Lambda Node.js 24 image | Reuse this packaging experience; it has no SnapStart hooks today |

[ADR 0018](../adr/0018-sealed-environment-variables.md) already defines
`aws:ssm:`, `aws:secretsmanager:`, and `aws:kms:` values. Preserve those forms
and fail closed on resolution errors. Neither a container alone nor a
handler-level warm-up moves this work before the snapshot.

## Proposal

### 1. Initialise the same application instance that serves requests

Extract request-independent initialisation from `createContext` into a shared
`initialiseEnvironment(env)` function in `src/context.js`. Cache its in-flight
promise by environment identity so concurrent callers share one attempt;
discard a rejected attempt rather than retain a partially initialised slot.
`createContext` then adds the request URL, route, and request-bound helpers.
Keep ordinary Worker, Node, and Lambda entry points lazy and compatible.

Add an ESM entry point at `adapters/lambda/snapstart.js`. It awaits
initialisation at module scope and exports the existing event handler.
Preparation and requests must use the same stable environment object and
cache slot. Do not initialise with `{ ...process.env }` and then serve with
`process.env`, or run a separate warm-up process: neither warms the serving
instance's cache. Keep decrypted values in SAG's private environment bag,
not in `process.env`.

Before snapshotting:

1. Resolve all sealed application variables, including dynamically named
   upstream and client variables, without a fixed secret-name allowlist.
   Deduplicate identical service, region, endpoint, and reference tuples
   within the initialisation attempt. Bound outbound concurrency and retries;
   publish fails if a required value cannot be resolved.
2. Require an explicitly configured, valid production `SAG_ISSUER`, after
   unsealing. Parse configuration and run `assertUsable` without inventing a
   request or allowing a Host header to establish the issuer.
3. Initialise configured signers, email sender, stores, CSP, and asset metadata.
   Await `signerSet.jwks()` so configured KMS public keys are actually loaded.
   Use immutable KMS key ARNs, not retargetable aliases, for this deployment:
   signing and the cached public key must continue to identify the same key.
4. Allow explicitly provisioned local signing keys, but reject ephemeral
   signing keys in this production entry point. Retain existing algorithm
   selection and `REQUIRE_*` behaviour. Cache completed capability results,
   not probe operations still in flight.
5. Finish outbound work and close application-owned connections. Do not send
   email, issue tokens, invoke authentication routes, write shared state, or
   fetch arbitrary client and upstream documents as warm-up. Do not generate
   request IDs, OTPs, nonces, or AES-GCM IVs for later use.

This deliberately preloads configuration and own public keys, not every
possible network dependency. KMS private signing keys remain in KMS;
`kms:Sign` remains a request-time operation.

### 2. Coordinate the snapshot lifecycle before the invocation loop

Use the AWS image's Runtime Interface Client (RIC) to load the ESM entry point.
Its module-level await runs the hooks in the serving Node process before the
RIC starts fetching invocations. Verify that ordering against the pinned
image in the implementation tests; do not fork the RIC or replace its normal
event, response, and error handling.

The entry point follows this contract, using the
[Runtime API](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html):

| Phase | Required action |
| --- | --- |
| Initialisation | Install the live credential provider; await application preparation |
| Before snapshot | If `AWS_LAMBDA_INITIALIZATION_TYPE` is `snap-start`, finish preparation, clear transient credential state, and call `GET /2018-06-01/runtime/restore/next` |
| Restore | After HTTP 200, reset transient state and credentials, complete restore checks, and only then finish loading the handler |
| Invocation | Let the stock RIC call `/runtime/invocation/next` and dispatch to SAG |
| SnapStart disabled | Skip the restore handshake; the same image must still initialise and serve normally |

Build the Runtime API URL from `AWS_LAMBDA_RUNTIME_API`. Use a dedicated
`node:http` transport without socket/read timeouts for its blocking calls;
SAG's ordinary `fetchWithTimeout` is inappropriate here. Do not attach AWS
SigV4 credentials. Treat unexpected statuses as fatal lifecycle failures,
including 403, 404, and 500; never silently fall through into normal serving
when SnapStart was requested.

Report preparation failures to `/runtime/init/error` and restore-hook failures
to `/runtime/restore/error`, with the documented error-type header, sanitised
message, and non-zero process exit. Do not invoke the handler after either
failure. AWS allows initialisation up to the greater of 130 seconds and the
function timeout; restore plus runtime loading has a 10-second limit.
[Lifecycle reference](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html).
Target less than one second for SAG's restore hook, with bounded credential
retrieval and no secret-store round trips.

Do not use the no-hook `com.amazonaws.lambda.feature.snapstart="Allow"`
label as a shortcut. This design needs an actual after-restore phase.

### 3. Separate application secrets from temporary AWS credentials

Introduce an asynchronous credential-provider contract shared by the AWS
callers. Each signed operation asks the provider for credentials; a provider
may reuse them until shortly before expiry, with concurrent refreshes sharing
one promise. A credentials object captured during construction is insufficient.

The Lambda adapter supplies a provider using a pinned, image-only
`@aws-sdk/credential-providers` dependency and its container credential
provider. Keep the existing lightweight signed-HTTP clients and keep this
Node dependency out of Worker imports. Prefer Lambda's container credential
endpoint explicitly in SnapStart mode instead of a default chain that might
choose stale access-key variables. AWS documents
[container credentials for SnapStart](https://docs.aws.amazon.com/lambda/latest/dg/snapstart-activate.html#snapstart-sdk).
Use the provider's endpoint validation and authorisation handling; never
derive credential URLs from HTTP requests or client configuration.

Apply the contract to sealed-env reads, KMS `GetPublicKey` and `Sign`, S3
client reads, DynamoDB state and peer-JWKS storage, and SES. Preserve explicit
credentials and environment-based behaviour on other platforms. Keep the
provider separate from the unsealed configuration copy, pass its live
reference through service construction, and resolve it before SigV4 signing.

Clear credential caches before snapshotting. On restore, recreate the
underlying container provider and refresh credentials before exposing the
handler; existing services delegate through the same provider reference.
Refresh again before expiry during warm use. Never fall back to expired
credentials on failure. Integration tests must prove both initialisation-time
access and post-restore renewal on the selected Lambda image.

### 4. Define exactly which state survives

| State | Snapshot policy | Restore/request policy |
| --- | --- | --- |
| Resolved application configuration and long-lived secrets | Retain in memory | Fixed for the deployment's configuration revision |
| Provisioned signing keys, own public JWKS, deterministic derived keys | Retain where initialised | Preserve key identity; remote signatures still call KMS |
| AWS execution-role credentials | Do not deliberately retain cached values | Recreate provider and renew before expiry |
| Sockets, connection pools, in-flight promises, retry timers | Drain or close before snapshot | Recreate transports; no pending application I/O crosses the boundary |
| Client, peer, DNS, and upstream caches | Do not populate with synthetic traffic | Clear transient caches after restore; normal TTLs still apply during warm use |
| Randomness and request-scoped state | No buffered random output or request artefacts | Obtain fresh entropy and create values when needed |
| OTP limits, consumed codes, revocations | Shared store remains authoritative | Never copy live in-memory security state across restored environments |

The RNG requirement is a release gate for an identity service. Audit the
exact Node/OpenSSL build used by the image, including WebCrypto
`getRandomValues`, signing randomness, capability probes, and any UUID entropy
cache. AWS's
[uniqueness guidance](https://docs.aws.amazon.com/lambda/latest/dg/snapstart-uniqueness.html)
distinguishes fresh kernel entropy from snapshotted userspace RNG state.
Do not assume a CSPRNG name, a Node.js 24 tag, or generating values inside the
handler proves restore safety. Record the image's reseeding mechanism and
verify it across independent restores. If this cannot be established, keep
SnapStart disabled; retain the configuration and credential improvements.

Do not enable the in-memory state store for a production Lambda fleet.
Use the existing shared DynamoDB backend where replay protection, revocation,
or OTP limits are required, as in
[ADR 0001](../adr/0001-stateless-with-optional-state-store.md).

### 5. Make secret rotation a deployment operation

Version one of this feature treats application configuration as immutable per
release. Do not reread SSM or Secrets Manager on every restore: that would
reintroduce the dependency and much of the API traffic being removed.

Use release-specific references whose contents cannot change while the
release is active. SSM references may include a numeric parameter version;
for Secrets Manager, use a release-specific secret identity and prohibit
in-place mutation through the deployment process. The current resolver has
no Secrets Manager `VersionId` field: do not invent an unsupported suffix.
Direct KMS ciphertext already identifies fixed encrypted input. Snapshot
regeneration must resolve the same configuration, not whichever secret value
happens to be current that day.

Rotate by creating the new secret revision, updating the function's sealed
references, publishing a new version, validating it, and moving the serving
alias. Preserve required old/new overlap for upstream credentials and SAG's
existing secret/key rotation rules in [operations.md](../operations.md).
Retain referenced secret revisions and decrypt permissions while their
function versions remain valid rollback targets or may be regenerated.

Changing a parameter, denying future `GetParameter`/`Decrypt` calls, or
disabling a decrypt key does not erase plaintext already in a snapshot or
warm environment. Emergency rotation removes traffic and invocation access
from affected versions, retires their snapshots/versions, and revokes the
underlying credential where possible. Never roll back to a compromised
version. Deployments requiring independently rotating configuration without
republishing remain on the ordinary path until a separate bounded-refresh
design is agreed.

Plaintext secrets in process memory are already part of SAG's model;
SnapStart extends their lifetime into an encrypted Lambda snapshot. Keep them
out of image layers, build arguments, logs, metrics, and `/tmp`. Restrict
publication, invocation, and execution-role permissions. Grant only required
secret reads and decrypt operations on configured resources, alongside
existing signing and store permissions.

### 6. Package, measure, and roll out

Add a production `adapters/lambda/Dockerfile` using the verified Node.js 24
base digest, the adapter-only dependencies, and
`CMD ["adapters/lambda/snapstart.handler"]`. The ordinary Node-server
Dockerfile keeps its current purpose. Build a single architecture per image,
reuse the production image in the local stack, and publish immutable image
digests to ECR. Rebuild and revalidate when the base digest changes.

Deploy `PackageType: Image` with `SnapStart.ApplyOn: PublishedVersions` and
512 MB ephemeral storage, without provisioned concurrency or EFS. An existing
ZIP function needs a new image-based function and an integration cutover;
do not promise an in-place package-type conversion. Add a reproducible
deployment example and update [deployment.md](../deployment.md) when the
feature exists. This RFC adds no public configuration variables.

Publish the version, wait for `State=Active` and
`SnapStart.OptimizationStatus=On`, then test the qualified version. Route
API Gateway or the function URL through a serving alias, never `$LATEST`.
Canary at 10% before moving to 100%, preserving issuer, keys, and shared state
compatibility. Roll back by moving the alias to a retained known-good version;
retain a tested non-SnapStart image version as the fallback. Remove unused
versions after the agreed rollback window.

Implementation acceptance requires:

| Test | Pass condition |
| --- | --- |
| Shared preparation | Concurrent callers initialise once; failures leave no usable partial configuration; first request reuses the prepared slot |
| Secret API accounting | One read per distinct reference per initialisation attempt; zero SSM, Secrets Manager, or direct KMS decrypt calls on restore and warm requests |
| Lifecycle contract | Fake Runtime API verifies ordering, error endpoints, no invocation on hook failure, and ordinary operation with SnapStart off |
| Real Lambda restore | Published image restores after idle time and in a scale-out burst; RIC does not request an invocation before hooks finish |
| Credentials | KMS signing, S3 reads, SES, and DynamoDB work after restore and after credential expiry without re-unsealing configuration |
| Security behaviour | No duplicated random sequences/IVs across independent restores; expired tokens stay expired; shared replay and rate-limit protections still work |
| Rotation and rollback | New alias target uses the new revision; regeneration uses pinned inputs; ordinary rollback works; compromised versions are excluded |
| Platform regression | Existing adapters and the Node 20/24 CI matrix pass; SnapStart-specific dependencies remain confined to the Lambda image |

The runtime emulator and LocalStack do not establish real snapshot safety;
the live Lambda tests are mandatory before production enablement. A
duplicate-free sample is supporting evidence, not a substitute for the RNG
audit. Use synthetic identities and non-production secrets in these tests.

Compare the same commit, image, memory, architecture, network, and workload
with SnapStart on and off. Collect at least 100 independently started or
restored environments per arm, plus warm requests, across three runs. Measure
discovery, the first authorisation page, and token exchange separately;
`/alive` bypasses the expensive path and is not a useful startup benchmark.
Report p50/p95/p99 end-to-end latency, init/restore duration, errors, secret
API counts, KMS signing calls, and estimated total cost. Proposed rollout
gates are at least 30% lower p95 first-request latency, at most 5% warm p95
regression, no new functional or hook errors in the test workload, and zero
restore-time secret reads. These are acceptance targets, not measured claims.

Emit only phase, duration, count, version, and sanitised error category in
startup metrics. Monitor Lambda `INIT_REPORT` and `RESTORE_REPORT`, hook
failures, credential refresh failures, and alias-level latency/error rates.
Abort the canary on any restore failure or sustained regression against the
baseline. Establish an operator cost ceiling from the measured workload
before enabling production.

## Cost

The implementation has three reviewable pieces: shared preparation and
renewable credentials; image and lifecycle integration; then deployment,
rotation, benchmarks, and live restore tests. The ongoing cost is maintaining
the adapter dependency, validating Node/OpenSSL and RIC changes, and treating
secret rotation and snapshot retirement as deployment responsibilities.

Let `E` be ordinary fresh environments, `V` sealed variables, `U` distinct
sealed references, `I` initialisation attempts including snapshot rebuilds,
and `P` configured KMS public keys. Ignoring retries, today's secret reads are
approximately `E * V`; the proposal's are `I * U`, with zero reads per restore.
Preloading own KMS public keys costs up to `I * P` reads. It does not reduce
request-time KMS signing, SES delivery, or shared-store operations. Initial
publication, rebuilds, failed attempts, and retries still consume API calls;
this is not a promise of one fetch per release forever.

For illustration, 1,000 fresh environments and eight distinct sealed values
would produce about 8,000 reads today. Three snapshot initialisation attempts
would produce about 24 before retries. Actual savings depend on observed
environment churn and regeneration frequency.

Budget snapshot caching and restores, billed execution and hook work, ECR,
and remaining AWS API usage using the target region's
[Lambda pricing](https://aws.amazon.com/lambda/pricing/). Fewer SSM calls do
not necessarily mean a lower bill: small or quiet deployments may save little
while retaining snapshots. Keep the ordinary deployment available when the
measured benefit does not justify the cost.

Alternatives are ordinary warm-instance caching, which SAG already has;
deduplication/batching alone, which cannot remove reads across environments;
or provisioned concurrency, which trades a standing capacity charge for more
predictable latency. Loading everything after restore defeats this proposal's
main saving. A runtime rewrite or baking decrypted secrets into the container
is unnecessary. The recommended path is the Node.js 24 image with explicit
hooks, subject to the credential and RNG release gates above.
