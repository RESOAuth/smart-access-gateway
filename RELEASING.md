# Releasing SAG

Prepare each release as a reviewed change on `main`, then start **Prepare
release** in GitHub Actions. That workflow creates the version tag and starts
[Signed release](.github/workflows/release.yml) at the tag. GitHub Actions
builds, signs, verifies, and publishes the release. No local build, signing,
tag creation, or manual GitHub release is required.

In this guide, `X.Y.Z` means the chosen semantic version and `vX.Y.Z` its Git
tag. A prerelease uses `X.Y.Z-rc.1` and `vX.Y.Z-rc.1`, respectively. Build
metadata (`+...`) is not supported because OCI tags cannot contain it.

## Repository requirements

Keep these controls in place, and review them when changing repository access
or release workflows:

1. Protect `main`, including reviews of workflow changes. Treat repository
   write access and permission to run Actions as release authority, and grant
   them only to trusted maintainers. The preparation workflow accepts `main`
   only; the signing workflow accepts the requested tag only. Both check the
   source commit, versions, changelog, and successful checks on protected
   `main`.
2. Maintain an active tag ruleset for `v*` that restricts **updates and
   deletions**, with no routine bypass. Tag creation must remain permitted
   for the repository's `GITHUB_TOKEN`; do not enable a creation restriction
   that blocks the preparation workflow. Existing conflicting tags are
   refused, never moved or replaced.
3. Allow the workflows' scoped `GITHUB_TOKEN` permissions, including the
   automatic development-image workflow. Preparation needs
   `contents: write` to create a tag and `actions: write` to dispatch the
   signing workflow. Signing needs package/attestation writes and
   `id-token: write`; publication needs release/package writes. Grant this
   repository Actions access to the GHCR `sag` package, make it public, and
   retain its signature/provenance attachments.

Keep `.github/workflows/release.yml` stable: its path is part of the public
certificate identity. [ADR 0021](docs/adr/0021-github-operated-release-authorisation.md)
defines release authorisation; [ADR 0020](docs/adr/0020-signed-releases.md)
defines artefact signing and verification. No release signing-key secret,
personal access token, SSH key, GPG key, or public-key repository variable is
required by the workflows. The Git tag is an unsigned version reference; the
release artefacts are signed.

Cosign creates a temporary signing key on the GitHub runner. GitHub's OIDC
token proves the workflow's identity to Sigstore, which issues a short-lived
certificate for that key. Signatures and transparency evidence let consumers
verify the artefacts after the temporary private key is gone. GitHub's
attestation action supplies the corresponding build provenance.

Cosign and GitHub CLI are installed from checksum-pinned binaries by
[install-tools.sh](tools/release/install-tools.sh). External actions are
pinned to commit SHAs. Update pins together with verification tests and the
supported versions in [release-verification.md](docs/release-verification.md).
Release jobs check out the run's fixed event SHA directly; validation requires
the version tag to resolve to that same commit on protected `main`. Automatic
package-manager caching is disabled in the release and development publication
workflows.

## Prepare the release change

1. Choose the next version based on the user-visible changes and upgrade
   impact since the previous release. Review the full diff and commit history,
   including changes missing from `Unreleased`.
2. Review open security advisories, Dependabot alerts, CodeQL results, and
   publicly reported defects. Do not release with a confirmed exploitable
   vulnerability of medium or higher severity left unaddressed. This remains
   a maintainer review; a green workflow cannot replace it.
3. Move the relevant `Unreleased` notes into a dated
   `## X.Y.Z - YYYY-MM-DD` entry in [CHANGELOG.md](CHANGELOG.md). Summarise
   user-visible changes and upgrade impact, and retain `## Unreleased` for
   subsequent development. Under `### Security`, name every fixed
   vulnerability which had a CVE or equivalent public identifier when
   prepared. Write `None` when there are no such fixes. The workflow uses
   this entry as the GitHub release notes.
4. Set all four version fields to `X.Y.Z`, without the `v` prefix:
   - `package.json`: `version`.
   - `package-lock.json`: top-level `version` and `packages[""].version`.
   - `src/version.js`: `VERSION`.
5. Run the local checks from the repository root:

   ```sh
   npm install
   npm run check
   npm run lint
   npm run sast
   npm run fuzz:release
   npm test
   ```

   Use the Node version selected by the release workflow for these checks.
   Review the resulting diff, including any lockfile or coverage badge changes.
6. Submit the preparation for review and merge it through `main`. Record the
   intended tag and full source commit in the release change record. Wait for
   that exact `main` commit's latest **push** runs of CI, CodeQL, and OpenSSF
   Scorecard to complete successfully. PR checks and manual runs do not
   satisfy this gate. If more changes reach `main` before dispatch, review
   that commit and wait for its checks too: preparation selects the current
   `main` commit when it starts.

The reviewed version and changelog change prepares the release. Starting the
workflow below authorises its publication.

## Publish through GitHub Actions

1. Open **Actions → Prepare release → Run workflow**, select **main**, enter
   **vX.Y.Z**, and run it. The selected `main` commit is fixed for that run.
   The workflow checks it, creates the tag, and dispatches **Signed release**
   at that tag. Follow the second run in the Actions tab. Do not create the
   tag or publish a GitHub release manually.
2. The signing workflow repeats source validation, syntax checks, lint, SAST,
   release fuzzing, and tests without signing or publication permissions.
   It then archives the Git object, builds
   `ghcr.io/resoauth/sag:candidate-<run-id>`, signs the returned digest, and
   records the source/run metadata in a signed manifest. The current release
   set contains source and a `linux/amd64` container; it does not include ARM
   images or Lambda ZIPs.
3. A fresh runner verifies the candidate. The publication job uploads the
   complete set to a draft, downloads it again, and verifies signatures,
   provenance, and hashes. It promotes the same digest to `X.Y.Z`, and to the
   applicable `X.Y`, `X`, and `latest` aliases, then publishes last.
   Prereleases get only their exact version tag. Older stable releases cannot
   move a newer stable alias backwards.

## Verify and record the release

1. Verify the complete public release using the
   [consumer instructions](docs/release-verification.md). Supply the intended
   tag and independently approved full source commit from the release change
   record, rather than trusting values from the downloaded manifest.
2. Retain the verification output, tag, commit, preparation/signing run URLs,
   and verified image digest with the release change record. Publication is
   the live OIDC/GHCR acceptance check; local fixtures cannot establish that
   the hosted signing services worked.
3. Run [scorecard.yml](.github/workflows/scorecard.yml) through its manual
   trigger after publication and retain the report. A release created with
   `GITHUB_TOKEN` does not start another release-triggered workflow
   automatically.
4. Record the Signed-Releases result, assessed releases and asset names, and
   the Scorecard version/revision used. For detailed JSON evidence, use the
   Scorecard revision shipped by the currently pinned `ossf/scorecard-action`
   and a supported Go toolchain:

   ```sh
   export GITHUB_AUTH_TOKEN="$(gh auth token)"
   SCORECARD_REV='<version-or-commit-shipped-by-the-pinned-action>'
   mkdir -p scorecard-evidence
   GOBIN="$PWD/scorecard-evidence" go install "github.com/ossf/scorecard/v5@$SCORECARD_REV"
   scorecard-evidence/scorecard --version > scorecard-evidence/version.txt
   scorecard-evidence/scorecard --repo=github.com/RESOAuth/smart-access-gateway --checks=Signed-Releases --show-details --format=json > scorecard-evidence/signed-releases.json
   gh api --paginate --slurp 'repos/RESOAuth/smart-access-gateway/releases?per_page=100' > scorecard-evidence/releases.json
   unset GITHUB_AUTH_TOKEN
   ```

   When upgrading Scorecard or changing release evidence, compare the previous
   and new revisions and retain both results. Keep this evidence outside the
   authenticated release asset set; the verifier rejects extra files.

`release.intoto.jsonl` contains the original signed in-toto envelopes, one per
verified bundle. It closes the release-asset discovery gap, but the filename
heuristic does not verify cryptography or establish a SLSA level. Report the
measured score without altering historical releases to improve it.

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

## Development images

Development images sign automatically on buildable pushes to `main` through
[bleeding-edge.yml](.github/workflows/bleeding-edge.yml). They use the same
keyless tools and registry permissions, with a separate workflow identity.
The workflow verifies the candidate before updating development tags; no
version bump, release changelog entry, or manual release is required. See the
[development verification instructions](docs/release-verification.md#development-images-from-main).
