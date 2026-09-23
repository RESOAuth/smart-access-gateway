# Verify a signed release

Verify the complete published release before extracting its source or deploying
its image. SAG's baseline release set contains:

| Asset | Purpose |
| --- | --- |
| `sag-vX.Y.Z-source.tar.gz` | Source archived from the approved tagged Git object |
| `release-manifest.json` | Schema version 1, repository, tag, commit, workflow run/attempt, payload SHA-256, OCI digest, and supported platforms |
| `release-manifest.sigstore.json` | Keyless signature bundle for the exact manifest bytes |
| `files.provenance.sigstore.json` | SLSA provenance bundle for the source archive and manifest |
| `container.provenance.sigstore.json` | SLSA provenance bundle for the exact GHCR image digest, also attached in GHCR |
| `release.intoto.jsonl` | The unchanged signed envelopes from both provenance bundles, for discovery |

The manifest hashes payloads only. It does not hash itself, its signature, or
its provenance companions. The verifier requires this complete set and rejects
extra files, duplicate subjects, unsafe names, invalid digests, and mismatched
source or run metadata. BuildKit provenance and SBOMs remain in the OCI index;
there is no separately downloaded SBOM in this schema.

## Deployment gate

Use Node 20 or later, Cosign **3.1.3 or later within major 3**, and GitHub CLI
**2.101.0 or later within major 2**. The exact versions exercised by the release
workflow are 3.1.3 and 2.101.0. Linux amd64 users can install those pins with
`bash tools/release/install-tools.sh`, then add
`/tmp/sag-release-tools/bin` to `PATH` (or `$RUNNER_TEMP/sag-release-tools/bin`
on a runner). Other platforms need the matching upstream binaries.

Use the verifier from an independently trusted checkout of SAG. Obtain `TAG`
and `COMMIT` from the approved release change and its reviewed source commit.
Neither comes from the downloaded manifest. Authenticating the manifest with
the identity it supplies would trust the artefact to identify its own publisher.

```sh
set -euo pipefail
TAG='v0.3.0'
COMMIT='<approved-full-source-commit>'
REPO='RESOAuth/smart-access-gateway'

# A draft is not a release, even if some image aliases already exist.
test "$(gh release view "$TAG" --repo "$REPO" --json isDraft --jq .isDraft)" = false
mkdir "verified-$TAG"
gh release download "$TAG" --repo "$REPO" --dir "verified-$TAG"
node tools/release/verify.js "verified-$TAG" "$TAG" "$COMMIT"

# Read only after verification succeeded. A failed command above stops here.
IMAGE=$(node -p 'JSON.parse(require("node:fs").readFileSync(process.argv[1])).images[0].reference' "verified-$TAG/release-manifest.json")
docker pull "$IMAGE"
```

Use the verified `IMAGE` value in the deployment's image field. Ordinary
Docker pulls do not enforce this verification policy. Put the gate in the
deployment job or admission policy, and stop deployment on every non-zero
exit. Keep deployment approval and the expected source commit outside the
artefacts being verified.

The verifier invokes Cosign for the blob and registry signatures, with the
exact certificate identity
`https://github.com/RESOAuth/smart-access-gateway/.github/workflows/release.yml@refs/tags/<TAG>`
and OIDC issuer `https://token.actions.githubusercontent.com`. It invokes
`gh attestation verify` for every file and the registry digest, requiring the
same identity, source ref, source commit, signer commit, SLSA predicate type,
a `workflow_dispatch` event at the release tag, and GitHub-hosted runners. It
validates provenance subjects and the original run/attempt, then compares the
exported envelopes with the verified bundles.
Transparency-log verification remains enabled.

GitHub CLI may require authentication to download releases, and private
registries require registry credentials. The public signatures prove the
publisher and source identity; they do not assert that a release is free of
vulnerabilities. Consult release advisories before deployment.

## Platforms, retention, and rollback

The baseline container supports `linux/amd64`. Signatures cover its published
OCI index, including BuildKit's provenance/SBOM descriptors. Pull through that
index digest. Direct child-manifest deployment is not covered by this
contract; additional architectures and direct child signatures need an
explicit extension.

Retain payloads, manifest, signatures, provenance bundles, image digests, OCI
attachments, and trusted-root material for the deployment's supported rollback
period. Select a retained, independently approved, non-revoked digest and run
the same verification gate before rollback. Offline verification has not been
promised or acceptance-tested by this baseline.

Registry copies must preserve the digest and verification material or become
a separately signed, linked distribution. A registry copy or a rebuilt image
with the same version label is not interchangeable with the approved digest.
`bleeding-edge` uses a branch workflow and must fail the release identity
policy. Its separate verification policy is described below.

On repository/workflow compromise, stop releases, identify affected commits,
digests, and workflow runs, publish an advisory, and block affected digests in
deployment policy. Keyless signing removes private release-key custody, but
does not prevent an authorised compromised workflow signing malicious code.
Revocation does not stop running containers; remove traffic and replace them.

## Development images from main

The **Bleeding-edge image** workflow automatically builds and signs pushes to
`main` which affect buildable files. Documentation-only and test-only pushes
retain the existing exclusions. It needs no version bump, release changelog
entry, manual dispatch, or signing-key secret.

The workflow signs the exact `linux/amd64` OCI index, including its BuildKit
provenance and SBOM, and attaches GitHub SLSA provenance in GHCR. A fresh job
verifies both from the registry before moving `bleeding-edge-<short-sha>` and
`bleeding-edge` to that digest. Signing or verification failure leaves the
consumer tags unchanged. `bleeding-edge-candidate-<run>-<attempt>` tags are
intermediate build outputs and must not be used for deployment.

Use the same Node, Cosign, and GitHub CLI versions described above, with
registry authentication where required. Obtain the expected full `COMMIT`
from the independently approved `main` change. Resolve the moving image tag
once, verify that digest, and pull it without resolving the tag again:

```sh
set -euo pipefail
COMMIT='<approved-full-main-commit>'
IMAGE='ghcr.io/resoauth/sag'
DIGEST=$(docker buildx imagetools inspect "$IMAGE:bleeding-edge" --format '{{.Manifest.Digest}}')
node tools/release/bleeding-edge.js verify "$DIGEST" "$COMMIT"
docker pull "$IMAGE@$DIGEST"
```

The verifier requires the exact certificate identity
`https://github.com/RESOAuth/smart-access-gateway/.github/workflows/bleeding-edge.yml@refs/heads/main`,
GitHub's OIDC issuer, a push signature from the expected commit, and SLSA
provenance from that same source and signer commit on `main`. It retrieves
the attestation from GHCR and rejects self-hosted attestation runners. Both
cryptographic checks must succeed; transparency verification remains enabled.

These signatures establish development-build origin, without asserting that
versioned release gates passed. Development tags, including commit tags, may
change on rebuild; pin the verified digest in the deployment. The versioned
release verifier continues to reject this development workflow identity.
See [ADR 0022](adr/0022-signed-development-images.md).

## Lambda scope

This baseline does not distribute a Lambda function ZIP, layer, or runtime
image. The existing container starts the Node server and is not a Lambda
runtime image. The next distribution stage in
[ADR 0020](adr/0020-signed-releases.md) will authenticate final ZIP bytes and
provide an operator-account AWS Signer example. Native Lambda enforcement
requires AWS Signer and an enforced CodeSigningConfig; detached Sigstore
signatures alone do not activate it.
