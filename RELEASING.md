# Releasing SAG

Releases are built, signed, verified, and published by GitHub Actions.
Maintainers start **Prepare release** on `main` with a version tag such as
`v0.3.0`. That workflow creates the tag and starts
[release.yml](.github/workflows/release.yml) at the tag. Keep the signing
workflow path stable: it is part of the public certificate identity.
[ADR 0021](docs/adr/0021-github-operated-release-authorisation.md) supersedes
the local signed-tag gate in ADR 0020.

## Repository setup

Before merging the release workflows:

1. Protect `main`, including reviews of workflow changes. Treat repository
   write access and permission to run Actions as release authority, and grant
   them only to trusted maintainers. The preparation workflow accepts `main`
   only; the signing workflow accepts the requested tag only. Both check the
   source commit, versions, changelog, and successful checks on protected
   `main`.
2. Add an active tag ruleset for `v*` that restricts **updates and deletions**,
   with no routine bypass. Tag creation must remain permitted for the
   repository's `GITHUB_TOKEN`; do not enable a creation restriction that
   blocks the preparation workflow. Existing conflicting tags are refused,
   never moved or replaced.
3. Allow the workflows' scoped `GITHUB_TOKEN` permissions. Preparation needs
   `contents: write` to create a tag and `actions: write` to dispatch the
   signing workflow. Signing needs package/attestation writes and
   `id-token: write`; publication needs release/package writes. Grant this
   repository Actions access to the GHCR `sag` package, make it public, and
   retain its signature/provenance attachments.

No release signing-key secret, personal access token, SSH key, GPG key, or
public-key repository variable is required. The earlier draft's
`RELEASE_SSH_ALLOWED_SIGNERS` and `RELEASE_GPG_PUBLIC_KEYS` variables are no
longer used and can be removed if already configured.

Cosign creates a temporary signing key on the GitHub runner. GitHub's OIDC
token proves the workflow's identity to Sigstore, which issues a short-lived
certificate for that key. Signatures and transparency evidence let consumers
verify the artefacts after the temporary private key is gone. GitHub's
attestation action supplies the corresponding build provenance. The Git tag
itself is an unsigned version reference; the release artefacts are signed.

Cosign 3.1.3 and GitHub CLI 2.101.0 are installed from checksum-pinned binaries
on GitHub-hosted Ubuntu runners. All external actions are pinned to commit
SHAs. Update these pins together with verification tests when upgrading.

## Prepare and release

1. Review open security advisories, Dependabot alerts, CodeQL results, and
   publicly reported defects. Do not release with a confirmed exploitable
   vulnerability of medium or higher severity left unaddressed. This remains
   a maintainer review; a green workflow cannot replace it.
2. Prepare the release through reviewed changes in GitHub. CI runs syntax,
   lint, SAST, fuzzing, and tests; the signing workflow repeats the full
   release gates before building. No local build or signing is required.
3. Prepare a dated `## 0.3.0 - YYYY-MM-DD` entry in
   [CHANGELOG.md](CHANGELOG.md), summarising user-visible changes and upgrade
   impact. Under `### Security`, name every fixed vulnerability which had a
   CVE or equivalent public identifier when prepared. Write `None` when there
   are no such fixes.
4. Set `package.json`, `package-lock.json` (including its root package), and
   `src/version.js` to `0.3.0`. Merge the release preparation through `main`.
5. Wait for that exact `main` commit's CI, CodeQL, and OpenSSF Scorecard push
   runs to complete successfully. The release workflow requires their latest
   runs to be green and repeats syntax, lint, SAST, release fuzzing, and tests
   without signing or publication permissions.
6. In GitHub, open **Actions → Prepare release → Run workflow**, select
   **main**, enter **v0.3.0**, and run it. The selected `main` commit is fixed
   for that run. The workflow checks it, creates the tag, and dispatches
   **Signed release** at that tag. Follow the second run in the Actions tab.

   Use `v0.3.0-rc.1` with matching version files and changelog for a prerelease.
   Build metadata (`+...`) is not supported because OCI tags cannot contain
   it. Do not create the tag or publish a GitHub release manually.
7. Follow the Actions run. It archives the Git object, builds
   `ghcr.io/resoauth/sag:candidate-<run-id>`, signs the returned digest, and
   records the source/run metadata in a signed manifest. It retains the
   existing `linux/amd64` platform; neither ARM images nor Lambda ZIPs are
   included in this first release set.
8. A fresh runner verifies the candidate. The publication job uploads the
   complete set to a draft, downloads it again, and verifies signatures,
   provenance, and hashes. It promotes the same digest to `0.3.0`, and to the
   applicable `0.3`, `0`, and `latest` aliases, then publishes last. Prereleases
   get only their exact version tag. Older stable releases cannot move a
   newer stable alias backwards.
9. Verify the public release using the
   [consumer instructions](docs/release-verification.md), and retain the
   output with the approved tag and commit. Perform the Scorecard rollout
   check below. Publication itself is the first live OIDC/GHCR acceptance
   test; local fixtures cannot establish that the hosted signing services
   worked.

## Failure and recovery

Signing, registry, attestation, or verification failure stops publication.
Retry the original **Signed release** Actions run. If preparation failed
before dispatch, rerun **Prepare release**; it reuses an identical tag and
starts signing only when no matching signing run already exists. If a signing
run exists, preparation prints its URL instead of starting a new build. A
candidate already pushed under its run ID is reused by digest; a completed
`signed-release` Actions artefact restores
exactly the same signed bytes, including the original signing attempt.
Checkpoints are retained for 90 days. Upload retries compare existing bytes
and upload only missing assets. Existing assets are never overwritten.

A rerun after publication verifies the public release and makes no release or
image changes. If the checkpoint has expired while a draft exists, if a draft
belongs to another run, or if an asset/version digest conflicts, stop and
investigate. Do not delete public history or rebuild under a published tag;
prepare a new patch version. Keep the original run and candidate until the
release is complete.

Moving aliases and GitHub publication are separate operations. An interrupted
promotion can leave some aliases pointing at a verified draft. Consumers must
require a complete **published** release and deploy its verified digest. A
failed Scorecard observation after publication does not invalidate or justify
replacing an already verified release.

## Scorecard rollout evidence

The RFC inspected Scorecard commit
`c395761df6afe1a69e476bc60a013a94bcbc153f`. The currently pinned
`ossf/scorecard-action` commit
`2d1146689b8cda280b9bc96326124645441f03bc` declares Scorecard **v5.5.0** in its
`go.mod`; record the version actually reported by the executed binary too.
After the first complete public release, run both revisions against the
repository, retain JSON output, and record assessed releases and asset names:

```sh
export GITHUB_AUTH_TOKEN="$(gh auth token)"
mkdir -p scorecard-evidence
GOBIN="$PWD/scorecard-evidence" go install github.com/ossf/scorecard/v5@c395761df6afe1a69e476bc60a013a94bcbc153f
scorecard-evidence/scorecard --version > scorecard-evidence/rfc-version.txt
scorecard-evidence/scorecard --repo=github.com/RESOAuth/smart-access-gateway --checks=Signed-Releases --show-details --format=json > scorecard-evidence/rfc.json
GOBIN="$PWD/scorecard-evidence" go install github.com/ossf/scorecard/v5@v5.5.0
scorecard-evidence/scorecard --version > scorecard-evidence/action-version.txt
scorecard-evidence/scorecard --repo=github.com/RESOAuth/smart-access-gateway --checks=Signed-Releases --show-details --format=json > scorecard-evidence/action.json
gh api --paginate --slurp 'repos/RESOAuth/smart-access-gateway/releases?per_page=100' > scorecard-evidence/releases.json
unset GITHUB_AUTH_TOKEN
```

Use a supported Go toolchain for those revisions. Keep this evidence in the
release change record, outside the authenticated payload set. Also rerun
`scorecard.yml` through its manual trigger to update its usual report. A
release created with `GITHUB_TOKEN` does not start another release-triggered
workflow automatically.

`release.intoto.jsonl` contains the original signed in-toto envelopes, one per
verified bundle. It closes the release-asset discovery gap, but the filename
heuristic does not verify cryptography or establish a SLSA level. Do not
promise a score until measured. Leave the earlier source-only releases
`v0.1.0`, `v0.2.0`, and `v0.2.1` untouched.
