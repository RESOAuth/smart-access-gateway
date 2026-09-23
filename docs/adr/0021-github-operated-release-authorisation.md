# ADR 0021: Authorise and run releases entirely in GitHub

## Context

ADR 0020's artefact signing already runs in GitHub Actions using Sigstore and
GitHub OIDC. Its separate requirement for a locally signed Git tag still makes
the maintainer operate a private key and publish a tag from a local machine.
The release process must be operable entirely from GitHub.

## Decision

Supersede only ADR 0020's release-authorisation mechanism. Remove the local
signed-tag requirement and the SSH/OpenPGP public-key trust variables. Keep
keyless artefact signing, provenance, verification, and publication unchanged.

A maintainer starts **Prepare release** with a version tag on `main`. The
workflow validates its fixed source commit against protected `main`, matching
versions and changelog, and green CI, CodeQL, and Scorecard checks. A separate
job with `contents: write` and `actions: write` creates a lightweight tag at
that commit and dispatches `.github/workflows/release.yml` at the tag. A tag
already pointing elsewhere is refused. Retries reuse an identical tag and
refer back to an existing signing run instead of starting another build.

Dispatch is explicit because ordinary tag writes with `GITHUB_TOKEN` do not
start push-triggered workflows. The signing workflow therefore requires a
`workflow_dispatch` event at `refs/tags/<version>`, and repeats source
validation. Its OIDC certificate still identifies the exact workflow and tag;
consumers continue to require the independently approved source commit and
complete, verified release set.

Repository write access and permission to run Actions are release authority.
Protect `main` and review workflow changes. Protect `v*` tags against updates
and deletion, while allowing `GITHUB_TOKEN` to create them. No personal access
token or long-lived signing key is needed by either workflow.

## Consequences

Maintainers can prepare the version through a PR and release from the GitHub
Actions interface without local signing. The Git tag is an unsigned version
reference; cryptographic publisher evidence covers the release artefacts and
provenance. GitHub access controls replace the independent local-key gate.

The two workflows retain a tag-specific signing identity and prevent a token-
created tag from silently failing to start its release. Retrying a failed
release remains an operation on the original signing run, preserving its
candidate digest and signing checkpoint. The configured token permissions and
tag rules must allow creation and workflow dispatch, but not tag replacement.
