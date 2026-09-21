# RFC 0012: Signed releases across containers and Lambda

## Context

SAG needs verifiable release artefacts and evidence that OpenSSF Scorecard can
discover. These are related requirements, but a registry signature alone does
not satisfy the linked [Signed-Releases check][scorecard-docs].

At repository commit `65cb2c0f2cbaf55a5284b3a461cbc3887d8799c1`:

- [release.yml](../../.github/workflows/release.yml) tests a published GitHub
  release, then pushes `ghcr.io/resoauth/sag`. BuildKit provenance and an SBOM
  are enabled, but there is no explicit signing step or release-asset upload.
- [RELEASING.md](../../RELEASING.md) requires signed Git tags. These authenticate
  source references, not the resulting container or deployment ZIP.
- The three published prereleases, `v0.1.0`, `v0.2.0`, and `v0.2.1`, have no
  uploaded assets. GitHub's automatic source archives are not uploaded assets.
- Lambda has a [handler](../../adapters/lambda/handler.js), but no production
  ZIP, layer, or image release pipeline. The root Dockerfile starts the Node
  server; it is not a Lambda runtime image. This proposal covers the existing
  container and Lambda ZIP packaging; a Lambda runtime image is outside its
  release set.

At the Scorecard revision linked above, recognised signature suffixes include
`.sigstore.json`; signatures score 8, and `.intoto.jsonl` provenance scores 10
per assessed release, with the average rounded down. The check does not verify
the signatures. Its documentation mentions both five and 30 releases; the
[signature probe][signature-probe] and [provenance probe][provenance-probe]
inspect the first five releases supplied by the client and skip entries without
assets. The [evaluation code][evaluation] is the authority for the score.
Record the actual Scorecard version and findings during rollout rather than
assuming every deployed version behaves identically.

## Proposal

Use keyless Sigstore signing for the existing container, a signed release
manifest for consumers, and signed SLSA build provenance attached to each
GitHub release. Deliver those together as the baseline, targeting 10/10 for
Signed-Releases once every assessed release carries provenance. Add Lambda
ZIP packaging next; add layers only when an operator needs them. This RFC
changes no running release workflow or application behaviour.

### 1. Publish a defined release set

| Artefact | Authentication and delivery |
| --- | --- |
| `ghcr.io/resoauth/sag@sha256:...` | Cosign signature and GitHub build attestation for the exact registry digest |
| `sag-vX.Y.Z-source.tar.gz` | Explicit archive from the tagged commit, attached to the release, hashed in the manifest, and covered by file provenance |
| `release-manifest.json` | Keyless blob signature in `release-manifest.sigstore.json` |
| `files.provenance.sigstore.json` | Full verification bundle for the source archive, manifest, and any other released files |
| `container.provenance.sigstore.json` | Full verification bundle for the OCI digest, also pushed to GHCR |
| `release.intoto.jsonl` | Signed in-toto envelopes exported from those provenance bundles, one per line |
| Future Lambda ZIP or layer ZIP | Final distributed bytes hashed in the manifest and covered by file provenance; AWS Signer additionally required for native Lambda enforcement |

The manifest has a versioned schema and records the repository URL, tag,
peeled source commit, workflow run URL and attempt, named file SHA-256 hashes,
and fully qualified OCI references with digests and supported platforms. A
future AWS distribution also records region, architecture, runtime, signing
profile version, and immutable layer version ARN where relevant. Reject
duplicate names, unsafe paths, missing files, and malformed digests.

List payloads and exported SBOM files, not the manifest itself or its signature
and provenance companions, avoiding circular hashes. Retain BuildKit's
provenance/SBOM; authenticate the exported SBOM bytes if offering them as a
download. No application keys, decrypted configuration, or deployment secrets
belong in any release artefact. Release signing is independent of SAG's token
signing and KMS configuration.

### 2. Build once, then sign, verify, and publish

Change `release.yml` from `release: published` to a protected `v*` tag-push
workflow. Keep its path stable because verifiers trust that workflow identity.
Retain signed tags and the existing release checks. Update `RELEASING.md` in
the implementation PR: maintainers prepare the version/changelog and push the
signed tag; the workflow prepares and publishes the GitHub release last.

1. Validate semantic version, matching `package.json` and `src/version.js`,
   the tag signature against maintained release-key trust, and membership of
   the peeled commit in protected `main`. Check out that commit explicitly.
   A tag naming pattern alone is not authorisation. Protect tag creation and
   prevent tag updates/deletion; review workflow changes through normal PRs.
2. Run the current syntax, lint, SAST, release fuzzing, and test gates. Preserve
   the existing CodeQL and security-advisory review requirements. These jobs
   have no signing identity or publication permissions.
3. Build from that same commit and push under a unique candidate reference.
   Give the build step an ID and capture its returned digest; do not resolve
   `latest` later or rebuild during promotion. Archive source with a fixed
   prefix from the Git object, not a dependency-populated working directory.
4. Use Cosign with GitHub Actions OIDC to sign the OCI digest. Generate the
   manifest and sign its exact bytes using `cosign sign-blob --yes --bundle`.
   Keep transparency-log publication and verification enabled. There is no
   long-lived release private key in GitHub secrets.
5. Use [actions/attest][attest] in its default SLSA provenance mode: explicit
   `subject-name: ghcr.io/resoauth/sag` and the build's `subject-digest` for
   the container, with `push-to-registry: true`; a separate invocation uses
   explicit `subject-path` entries for the final release files and manifest.
   Capture both `bundle-path` outputs. Never attest a glob that accidentally
   includes temporary files or a previous run's outputs.
6. Verify everything from a fresh job, including downloaded candidate bytes
   and registry content, before attaching the complete set to a draft release.
   Download the draft assets again and check their hashes and signatures.
   Publish only after the whole set passes. Promote version and moving image
   tags to the verified digest; never rebuild. Registry promotion and GitHub
   publication are not atomic: a failure must be resumable with the same
   digest, and consumers must require a complete published release.

Use GitHub-hosted runners and SHA-pinned actions, with pinned Cosign and `gh`
versions exercised by the acceptance tests. `actions/attest-build-provenance`
now wraps `actions/attest`, which is recommended for new integrations. The
older [slsa-github-generator][old-generator] is no longer actively maintained;
do not introduce it just to obtain a particular filename.

Limit permissions per job: `contents: read` for checks; `packages: write`
for image publication; `id-token: write` only for signing/attestation;
`attestations: write` for GitHub attestations; and `contents: write` only for
release-asset publication. Set `create-storage-record: false` on the container
attestation unless storage records are deliberately enabled with their extra
`artifact-metadata: write` permission. Transfer artefacts only within the
same validated run, checking their digests. Do not accept arbitrary external
workflow artefacts or use privileged PR triggers to sign contributor code.

Serialise runs per tag without cancelling publication. A retry may resume a
matching draft or verify an already completed release, but must fail on a
conflicting digest or existing asset with different bytes. Never overwrite a
published version with a rebuild; release a new patch version. Publish
prereleases as prereleases and do not advance `latest`, major, or minor stable
aliases for them. Keep `bleeding-edge.yml` outside the stable release trust
policy; its branch identity must not pass release verification.

### 3. Export genuine provenance for Scorecard

GitHub's attestation API and GHCR alone are not GitHub release assets. Retain
the full `.sigstore.json` bundles for cryptographic verification, and export
their signed DSSE envelopes as JSON Lines:

```sh
jq -ce '.dsseEnvelope | select(.payloadType == "application/vnd.in-toto+json")
  | select((.payload | length) > 0 and (.signatures | length) > 0)' \
  files.provenance.sigstore.json container.provenance.sigstore.json \
  > release.intoto.jsonl
```

The implementation must validate each input separately and require exactly
one exported envelope per bundle; a missing envelope must fail even when the
other input is valid. Check that each decoded statement has SLSA provenance
type `https://slsa.dev/provenance/v1`, the expected subjects and digests, and
the expected source/run metadata. Compare each exported envelope with its
verified bundle. Preserve the signed payload and signatures unchanged.

This is a format export, not renaming a Sigstore bundle or inventing a
provenance assertion. The `.intoto.jsonl` alone omits the bundle's certificate
and transparency evidence; consumers verify with the full companion bundles.
Scorecard's filename heuristic is supplementary evidence, not the trust gate.
Do not claim a SLSA level merely because the check awards 10 points.

### 4. Give consumers an enforceable verification policy

Trust the repository, workflow, exact tag, and OIDC issuer, not any certificate
issued by GitHub. Obtain the expected tag and source commit from the approved
release change or independently verified signed tag. Do not take the expected
identity from the unverified manifest. These are illustrative commands for the
future artefacts, not claims that today's releases can be verified this way:

```sh
TAG='vX.Y.Z'
COMMIT='<approved full source commit>'
IDENTITY="https://github.com/RESOAuth/smart-access-gateway/.github/workflows/release.yml@refs/tags/${TAG}"

cosign verify-blob release-manifest.json \
  --bundle release-manifest.sigstore.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Only after verifying the manifest: require the expected schema, tag, commit,
# and repository, validate the image field, then read its digest reference.
IMAGE='<verified ghcr.io/resoauth/sag@sha256:digest>'
cosign verify "$IMAGE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify "oci://${IMAGE}" \
  --bundle container.provenance.sigstore.json \
  --repo RESOAuth/smart-access-gateway \
  --cert-identity "$IDENTITY" \
  --source-ref "refs/tags/${TAG}" --source-digest "$COMMIT" \
  --deny-self-hosted-runners
```

Verify file provenance with the same `gh attestation verify` policy, replacing
the OCI reference with each local payload path and using the files bundle.
Check every payload hash against the verified manifest before extraction or
deployment. The implementation adds a small verifier that rejects unexpected
subjects, incomplete release sets, and tag/commit mismatches, with a documented
minimum tool version. [Cosign][cosign] verifies the blob/image signatures;
[GitHub CLI][gh-verify] verifies the build attestations and source identity.

Deploy images by digest. For multi-platform images, sign the published index
digest and document that consumers pull through that index; separately attest
and sign child digests if operators deploy those directly. Ordinary Docker
pulls do not enforce this policy: put verification in the deployment job or
an admission policy and fail closed. Copies to another registry must preserve
the digest and verification material or be treated as a separately signed,
linked distribution. Retain payloads, signatures, bundles, and trusted-root
material for the supported rollback period; test offline verification before
promising it.

### 5. Extend to Lambda without forcing layers

Start with a self-contained function ZIP containing `package.json`, `src/`,
and `adapters/lambda/`, preserving their relative paths. Use handler
`adapters/lambda/handler.handler`; exclude dev dependencies, tests, local
configuration, and keys. Test on the selected supported Lambda Node runtime.
SAG has no runtime dependencies, so a layer currently adds version management
without solving a dependency-size problem.

If layers are needed, package SAG under `nodejs/node_modules/sag/` with its
package exports and relative imports intact. A small ESM function wrapper can
re-export `handler` from `sag/lambda`. Test that resolution on the selected
Lambda runtime. Publish immutable layer versions for explicit runtimes,
architectures, and regions; pin version ARNs and retain rollback versions.
Both wrapper ZIP and layer ZIP need authentication.

Detached Sigstore signatures are portable publisher evidence; they do not
activate Lambda's native code-signing enforcement. The optional AWS
distribution uses [AWS Signer][aws-signer], a versioned S3 bucket, and the
`AWSLambda-SHA384-ECDSA` signing profile. Wait for signing success, distribute
and hash the resulting signed ZIP, and never repackage it afterwards. Record
both original and signed digests when retaining both. Use short-lived AWS
credentials via narrowly scoped GitHub OIDC, not stored AWS access keys.

Attach a Lambda CodeSigningConfig to consuming functions with approved signing
profile **version** ARNs and `UntrustedArtifactOnDeployment: Enforce`. Ensure
the policy covers the function and every layer. Keep control of changing or
removing that configuration separate from routine deployment permissions.
For the first AWS implementation, let operators verify SAG's public bundle
and sign within their own account; organisation-wide public layer publishing
and cross-account signing permissions are a separate distribution commitment.

Lambda's [native code-signing configuration][aws-config] does not support
container-image functions. Any future Lambda runtime image therefore needs
its own ECR-compatible, single-architecture release and a deployment gate that verifies
the image before updating Lambda by digest. The existing Node-server image is
not interchangeable with it. Neither signing nor revocation stops already
running code: incident response must remove traffic from affected versions.

### 6. Roll out with measurable acceptance

Implement in two PRs: first the container/source release set, provenance
export, verifier, and release/deployment documentation; then function ZIPs and
an AWS Signer example. Layers remain optional. Keep this document a proposal
until accepted under the repository's RFC-to-ADR process.

| Gate | Required evidence |
| --- | --- |
| Authenticity | Clean runner verifies every payload and image with exact issuer, workflow, tag, commit, and digest policy |
| Negative tests | Modified manifest/ZIP, wrong image digest, different repository/workflow/tag, and missing signature/provenance all fail |
| Provenance export | Every JSONL envelope matches a verified bundle and covers the intended subject; absent/malformed inputs fail |
| Publication | Simulated signing/upload/promotion failures never mark an incomplete release successful; reruns cannot replace published bytes |
| Scorecard | Run the linked revision and the version used by `scorecard.yml` against the first complete public release; retain versions, asset names, assessed releases, and detailed Signed-Releases results |
| Consumer deployment | Verification failure blocks deployment; rollback selects a retained, verified, non-revoked digest |
| Optional Lambda | Live AWS accepts approved signed function/layers and rejects unsigned, altered, or unapproved packages with `Enforce` |

The initial three source-only releases should remain untouched; do not add
signatures that imply their historical builds were attested. If a future
Scorecard window includes older releases with unsigned uploaded assets, report
the partial result and let new complete releases replace them in the window.
Do not fabricate assets or delete history to improve the score. Merging this
RFC itself cannot change the score; a complete published release is required.

If Sigstore, GHCR, or GitHub is unavailable, delay publication. On compromise,
stop releases, identify affected source commits/digests and workflow runs,
publish an advisory, and block those digests in deployment policy. Keyless
signing removes private-key rotation, not repository/workflow compromise.
For AWS Signer, rotate allowed profile versions with a controlled overlap and
handle revocation/expiry when selecting rollback versions.

## Cost

The baseline adds release automation, Cosign/`gh` tooling, attestation bundles,
and deployment verification, but no SAG runtime dependency or signing-key
secret. Maintainers must keep tool pins and trust policy current and retain
registry attachments alongside supported images. Availability of signing and
publication services becomes a release dependency.

AWS distribution adds signing profiles, S3 storage, IAM policy, and live
integration tests; layers additionally require regional/version retention.
These costs are avoidable until ZIPs/layers are actually distributed. GPG or
Minisign release assets would meet the signature tier but introduce key
custody and do not provide build provenance. Container-only Cosign, signed
tags, or the existing BuildKit metadata alone leave the release-asset
discovery gap. The recommended baseline closes that gap while giving
operators a usable verification contract.

[scorecard-docs]: https://github.com/ossf/scorecard/blob/c395761df6afe1a69e476bc60a013a94bcbc153f/docs/checks.md#signed-releases
[signature-probe]: https://github.com/ossf/scorecard/blob/c395761df6afe1a69e476bc60a013a94bcbc153f/probes/releasesAreSigned/impl.go
[provenance-probe]: https://github.com/ossf/scorecard/blob/c395761df6afe1a69e476bc60a013a94bcbc153f/probes/releasesHaveProvenance/impl.go
[evaluation]: https://github.com/ossf/scorecard/blob/c395761df6afe1a69e476bc60a013a94bcbc153f/checks/evaluation/signed_releases.go
[attest]: https://github.com/actions/attest
[old-generator]: https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/generic/README.md
[cosign]: https://docs.sigstore.dev/quickstart/quickstart-cosign/
[gh-verify]: https://cli.github.com/manual/gh_attestation_verify
[aws-signer]: https://docs.aws.amazon.com/lambda/latest/dg/governance-code-signing.html
[aws-config]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning-create.html
