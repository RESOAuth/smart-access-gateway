# Open questions

Working notes: questions that need an answer before something can be built,
and the answer once it lands. Once a question is answered inline and built,
its reasoning likely belongs in an ADR (see [adr/](adr/README.md)) instead,
and can be cleared from here.

## Still open

Questions from the session, OWASP, OpenSSF Best Practices, and OpenSSF
Scorecard review on 27 August 2026 follow. They are ordered roughly by risk.

### Must an interactive sign-in be bound to the browser that started it?

The sealed transaction and upstream `state` are bearer values. They can be
completed in a different browser, deliberately allowing an upstream callback
to work after every cookie has been discarded. That also leaves a login-CSRF
or session-swapping route: somebody can start and authenticate their own flow,
then induce another browser to submit the resulting OTP transaction or
upstream callback and install the first person's session there.

Should SAG set a short-lived, `HttpOnly`, `SameSite=Lax` interaction cookie,
bind its random value to every transaction, and require it on form submissions
and callbacks? The design must retain concurrent tabs. The cost is giving up
cookie-free continuation and explaining what happens when a browser clears the
cookie during an upstream round trip.

**Answer:**

### Must successful authentication transactions be single-use?

A valid OTP transaction and code can currently be submitted more than once to
mint more sessions and authorisation codes. Older copies also roll back the
attempt counter. The optional state store makes authorisation codes and client
assertions single-use, but does not claim a transaction identifier.

Should successful OTP and upstream completions claim `tx.id` when a state
store is configured, failing closed on reuse or a store outage? Should failed
OTP attempts also move into the store, or does the code's entropy plus edge
rate limiting remain the intended control?

**Answer:**

### Should local logout require a same-origin POST?

RP-initiated logout is a GET endpoint and per-RP sessions can be ended without
confirmation. A cross-site top-level navigation can therefore cause a logout.
This is an availability attack rather than account takeover, but it can be
used to interrupt work or repeatedly force authentication.

Should GET only validate the RP request and render a confirmation whose POST
performs the local logout, with an Origin or Referer check where available?
The answer must preserve OIDC RP-initiated logout interoperability and decide
whether `LOGOUT_CONFIRM=never` is allowed to waive the same-origin step.

**Answer:**

### Is a request-derived development issuer still acceptable?

A derived issuer is now refused whenever the resolved configuration is not in
development mode. There is a remaining bootstrap ambiguity: an unconfigured
process decides that it is in development from the request hostname, so a
request presented as `localhost` can select the development secret, client,
and sender. The Node adapter binds to loopback by default, but containers and
misconfigured proxies can expose it more widely.

Should deriving `SAG_ISSUER` require explicit `SAG_DEV=true`, with local
adapters or development templates setting that value? This removes the
Host-header ambiguity but gives up the current zero-configuration start.

**Answer:**

### What repository controls are enforced outside the tree?

The public API does not reveal the effective branch rules. OpenSSF Scorecard
expects protected branches and review; the repository also has no `CODEOWNERS`
file because no owner or team can be invented here.

Should `main` require pull requests, at least one independent approval,
dismissal of stale approvals, resolved conversations, and the CI, CodeQL, and
Scorecard checks, while blocking force-pushes and deletion? Which organisation
team should own `*`, workflows, adapters, and cryptographic code, and are
administrator bypasses audited? Confirm that maintainer accounts require MFA
and least-privilege tokens.

**Answer:**

### What is the security-response and disclosure deadline?

`SECURITY.md` now supplies a private reporting route and supported versions,
but promises no acknowledgement, remediation, or disclosure timetable.
OpenSSF Best Practices asks projects to respond to vulnerability reports
within a stated period, and Scorecard gives stronger credit to a complete
policy.

What acknowledgement target, status-update cadence, private-fix target, and
coordinated-disclosure window can the maintainers genuinely meet? Add only
commitments that will be monitored.

**Answer:**

Acknowledgement is due within 14 days. A confirmed exploitable vulnerability
of medium or higher severity must be fixed as soon as practical and within 60
days after it becomes public. No separate status-update or coordinated-
disclosure interval is promised yet. See `SECURITY.md`.

### What constitutes a verifiable release?

The workflows now request OCI provenance and an SBOM, but the existing GitHub
release contains source archives only. There is no documented release signing,
keyless Sigstore identity, SLSA provenance attached to release assets, or
verification command. Scorecard's Signed-Releases check needs a consumer to be
able to verify what was published.

Should releases attach a CycloneDX or SPDX SBOM, checksums, keyless signatures,
and SLSA provenance for each distributable and container digest? Decide which
artifacts are supported, how tags are authorised, and who verifies the
attestations before publication.

**Answer:**

### Should the Node development toolchain be reproducible?

The runtime has no npm dependencies, but `wrangler` is a caret-ranged
development dependency and no lockfile is committed. Local-stack and release
tooling can therefore resolve a different dependency graph on different days.
This remains a gap in Scorecard's Pinned-Dependencies check even though Actions
and container bases are now pinned.

Should `wrangler` be exact-pinned with a committed lockfile and automated
updates, or should it be removed from `package.json` and invoked as an
explicitly versioned external tool? Include the local-stack install path in the
decision.

**Answer:**

### Which additional automated security techniques are proportionate?

CI, CodeQL, dependency updates, and the core tests are present. There is no
dedicated linter, coverage threshold, parser/property fuzzing, continuous
fuzzing service, or dynamic scan against the local stack. Scorecard measures
SAST and fuzzing separately, while Best Practices expects documented automated
tests and static analysis.

Should the next increment be ESLint, property tests for URL/JWT/cookie/form
parsers, a libFuzzer-compatible target for sealed/JWT inputs, or an OWASP ZAP
baseline against the Node local stack? Pick controls the maintainers will keep
green rather than adding badge-only workflows.

**Answer:** Jazzer.js coverage-guided fuzzing exercises the authorisation,
JWT, environment, identity, IP-address, and OTP parsers in pull requests and
before releases. ESLint security analysis is the complementary static control.

**Answer:**

### Who will enrol and maintain the project metadata and badges?

The GitHub repository currently has no description, homepage, or topics, and
the project is not known to the Best Practices badge service. Those settings
and the badge questionnaire cannot be completed reliably from source code.

Who will set the repository metadata, enrol at bestpractices.dev, answer the
criterion evidence links, and review the answers on each release? Decide
whether Discussions are wanted or whether issues remain the only public
support route.

**Answer:**
