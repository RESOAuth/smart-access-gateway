# ADR 0020: Signed releases with exact source and workflow identity

## Context

Signed Git tags authenticate source references, but do not authenticate the
container built from them. SAG's GitHub releases have no uploaded artefacts;
BuildKit provenance and SBOMs in GHCR alone do not provide a portable release
verification contract or discoverable OpenSSF Signed-Releases evidence.

RFC 0012 proposed keyless signing, release manifests, and signed provenance,
with container/source distribution first and Lambda packaging afterwards.

## Decision

Accept RFC 0012. Implement the container/source baseline for the next release.
A protected, signed `v*` tag authorises `.github/workflows/release.yml` only
when its peeled commit belongs to protected `main`, versions and changelog
match, and that commit's CI, CodeQL, and Scorecard runs passed. Maintained
public-key trust verifies the tag; tag names alone do not grant authority.

Build a single candidate image, retain BuildKit provenance/SBOMs, and sign its
exact OCI digest through GitHub Actions OIDC and Cosign. Archive source from
that same Git object. A versioned manifest binds the archive hash, image
digest, supported platforms, source commit, tag, and workflow run. Sign its
exact bytes and generate GitHub SLSA provenance for the image and files.
Export the signed DSSE envelopes as `release.intoto.jsonl`, retaining the full
Sigstore bundles for verification. There is no long-lived release signing
private key in GitHub, and no connection to SAG's runtime token-signing keys.

Verification trusts the repository, issuer, workflow, independently approved
tag and commit, and exact subjects. A fresh job verifies downloaded candidate
bytes and registry content; the publication job repeats verification after
uploading and downloading draft assets. Promote the verified digest and
publish the complete GitHub release last. Use a checkpoint within the same
workflow run to resume failures; conflicting assets or version digests fail
closed. Published bytes are never replaced, prereleases never move stable
aliases, and `bleeding-edge` is outside this trust policy.

Lambda ZIPs and an operator-account AWS Signer example are the next
implementation stage. They are not part of this baseline's manifest schema.
When implemented, distribute final signed ZIP bytes, preserve handler paths,
and require AWS Signer plus an enforced Lambda CodeSigningConfig for native
AWS enforcement. Detached Sigstore evidence does not enable that enforcement.
Layers and cross-account public distribution remain outside this decision's
initial implementation. The Node-server container is not a Lambda image.

## Consequences

Release availability depends on GitHub, GHCR, and Sigstore. Maintainers must
protect tags and workflow changes, maintain public-key trust and tool pins,
and retain signatures and provenance with supported rollback digests. Registry
promotion and GitHub publication are not atomic; consumers require a complete
published release and verify before deployment. Ordinary image pulls do not
enforce this policy.

The baseline adds release tooling and tests, but no runtime dependency.
[RELEASING.md](../../RELEASING.md) describes setup and recovery;
[release-verification.md](../release-verification.md) defines the consumer
contract. Existing source-only releases remain untouched. Scorecard evidence
is measured after publication, without claiming a SLSA level from its score.
