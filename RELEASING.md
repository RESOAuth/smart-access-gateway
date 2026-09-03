# Releasing SAG

Releases use semantic versions and signed Git tags. The version in
`package.json` and `src/version.js` must match the tag.

Before publishing a release:

1. Confirm the commit is on `main` and its CI, CodeQL, and OpenSSF Scorecard
   checks passed. The npm SAST check and CodeQL are the static analysis gates
   for production releases.
2. Run `npm ci --ignore-scripts`, `npm run check`, `npm run lint`,
   `npm run sast`, `npm run fuzz:release`, and `npm test` from a clean checkout.
   Lint and SAST must finish without warnings, and fuzzing must report no
   finding or crash.
3. Review open security advisories, Dependabot alerts, CodeQL results, and
   publicly reported defects. Do not release with a confirmed exploitable
   vulnerability of medium or higher severity left unaddressed.
4. Update [CHANGELOG.md](CHANGELOG.md). Summarise user-visible changes and
   upgrade impact. Under `Security`, name every fixed vulnerability which had
   a CVE or equivalent public identifier when the release was prepared. Write
   `None` when there are no such fixes.
5. Update both version files, commit the change, create a signed `vX.Y.Z` tag,
   and publish a GitHub release using that changelog entry as its notes.

Publishing a GitHub release reruns syntax checks, zero-warning linting and SAST,
coverage-guided fuzzing, and the automated test suite before building and
pushing the versioned container image.
