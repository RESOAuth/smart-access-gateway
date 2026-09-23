# ADR 0022: Sign development images with a separate main identity

## Context

ADR 0020 authenticates versioned releases. The `bleeding-edge` image also
distributes executable code, but its existing BuildKit provenance and SBOM do
not authenticate the publisher. Development builds must sign automatically
in GitHub without needing a release version, tag, or local signing key.

## Decision

Keep the existing buildable-push trigger on `main`. Build an attempt-specific
candidate, sign its exact OCI index digest with keyless Cosign, and attach
GitHub SLSA provenance in GHCR. Retain BuildKit provenance and the SBOM within
that signed index. Use the same pinned tools as versioned releases.

A fresh job fetches signatures and provenance from GHCR, requiring GitHub's
OIDC issuer, `.github/workflows/bleeding-edge.yml@refs/heads/main`, the exact
source and signer commit, and GitHub-hosted attestation runners. Only after
verification does it promote the unchanged digest to `bleeding-edge-<sha>`
and `bleeding-edge`. Signing or verification failure leaves those tags alone.

Keep the development verifier separate from the release verifier. A valid
development signature does not satisfy the versioned release policy. The
trusted repository and workflow identities are explicit; forks must choose
their own trust policy before enabling equivalent publication.

## Consequences

Development images gain publisher and source evidence without signing-key
secrets or a manual release step. They retain the existing push trigger and
path exclusions, rather than requiring the versioned release gates.

Registry tags remain mutable, including when a source commit is rebuilt.
Consumers must supply an independently approved commit, verify the exact
digest, and deploy that digest. Candidate tags may refer to incomplete work
and are not deployment entry points. Signed development images require the
same GHCR retention, permissions, and Sigstore availability as releases.
