# OpenSSF Best Practices evidence

This page maps the passing badge's MUST and MUST NOT criteria to public
evidence. It follows the [current passing criteria](https://www.bestpractices.dev/en/criteria/0).
It is an aid to honest self-certification, not a badge claim by itself.

## Evidence in the repository

| Criterion | Evidence |
| --- | --- |
| `description_good` | [README](../README.md) states the problem SAG solves and its deployment model. |
| `interact`, `contribution` | The README covers obtaining and running SAG; [CONTRIBUTING](../CONTRIBUTING.md) links bug, enhancement, and pull-request routes and explains the process. |
| `floss_license`, `license_location` | [LICENSE](../LICENSE) contains the AGPL-3.0 licence, and `package.json` declares it. |
| `documentation_basics` | The published [quickstart](https://sag.resoauth.dev/self-host/quickstart), [deployment guide](https://sag.resoauth.dev/self-host/deployment), and [documentation home](https://sag.resoauth.dev) cover installation, configuration, deployment, and operation. |
| `documentation_interface` | OpenID Connect discovery describes a running instance. The published [configuration](https://sag.resoauth.dev/reference/configuration), [relying-party](https://sag.resoauth.dev/reference/relying-parties), [upstream](https://sag.resoauth.dev/reference/upstreams), and [profile-claim](https://sag.resoauth.dev/reference/profile-claims) references document the inputs and outputs. |
| `sites_https` | The source, issue tracker, release page, GHCR distribution, and linked project website are served over HTTPS. Production issuers and external endpoints are required to use HTTPS. |
| `discussion` | Public GitHub issues and pull requests are searchable, individually addressable, and open to new participants using a browser. |
| `repo_public`, `repo_track`, `repo_interim` | The [public Git repository](https://github.com/RESOAuth/smart-access-gateway) includes attributed, dated commits and pull-request changes between releases. |
| `version_unique` | Releases use semantic versions, Git tags, matching runtime versions, and versioned container tags. See [RELEASING](../RELEASING.md). |
| `release_notes` | [CHANGELOG](../CHANGELOG.md) and GitHub releases provide human-readable changes. The release process requires upgrade impact to be stated. |
| `report_process`, `report_archive` | [CONTRIBUTING](../CONTRIBUTING.md) links the public bug form and searchable issue archive. |
| `vulnerability_report_process`, `vulnerability_report_private` | [SECURITY](../SECURITY.md) links GitHub private vulnerability reporting and says what to include. |
| `test`, `test_policy`, `tests_are_added` | `npm test` runs the public `node:test` suite. CONTRIBUTING requires tests for changed behaviour and major functionality; feature tests in `test/` and their commit history are evidence of use. |
| `warnings`, `warnings_fixed` | `npm run check` performs syntax checks and `npm run lint` runs ESLint with zero warnings allowed. Both run for pull requests, `main`, and releases. |
| `crypto_published`, `crypto_floss`, `crypto_working` | SAG uses published AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, SHA-2, ES256/384, RS256, PS256, and FIPS 204 ML-DSA algorithms. It uses runtime Web Crypto, AWS KMS, or the Cloudflare HSM adapter. No default depends on MD4, MD5, SHA-1, DES, RC4, or an unsuitable cipher mode. All functions can run locally using Node and OpenSSL, which are FLOSS. See `src/crypto/`, `src/keys/`, and [post-quantum signing](post-quantum.md). |
| `crypto_keylength` | The default is P-256. The persistent key generator creates 3072-bit RSA keys, development generation uses at least 2048 bits, and configured RSA keys below 2048 bits are refused. AES and internal HMAC keys are derived at 256 bits from a 48-byte generated master secret. |
| `crypto_random` | Keys, secrets, IVs, nonces, codes, and tokens use Web Crypto `generateKey` or `getRandomValues`. Production code contains no `Math.random` use. |
| `delivery_mitm`, `delivery_unsigned` | Source, releases, and images are delivered through HTTPS GitHub and GHCR endpoints. The project does not retrieve a hash over plain HTTP as proof of a download. |
| `static_analysis` | CodeQL analyses JavaScript and workflow code on every pull request and push to `main`, and weekly. [RELEASING](../RELEASING.md) requires a passing CodeQL result before release. |
| `static_analysis_fixed`, `dynamic_analysis_fixed` | [SECURITY](../SECURITY.md) applies the same remediation policy to confirmed exploitable findings from static and dynamic analysis. |

## Not applicable answers

These MUST criteria permit N/A, and the following explanations can be used
while the facts remain true.

| Criterion | Explanation |
| --- | --- |
| `release_notes_vulns` | N/A until a release fixes a project vulnerability which already has a CVE or equivalent public identifier. The release process requires every such fix to be named when one exists. |
| `build` | N/A. SAG is plain JavaScript executed directly by Node, Workers, or Lambda. It has no compilation or generated production files. The container is reproducibly built from the public Dockerfile. |
| `crypto_password_storage` | N/A. SAG does not accept or store passwords for external users. Upstream providers authenticate their own users, and the fallback proves mailbox control with a short-lived code. |
| `vulnerability_report_response` | N/A only if no vulnerability report was received in the previous six months. Otherwise use the measured response time, which must be at most 14 days. |
| `dynamic_analysis_fixed` | N/A only if dynamic analysis has produced no confirmed exploitable medium-or-higher finding. Otherwise confirm that every such finding was fixed in line with SECURITY.md. |

## Maintainer attestations and site settings

Repository text cannot prove the following facts. A maintainer must verify each
one before selecting `Met` in the badge application.

- `maintained`: the project still intends to make releases and respond to
  reports.
- `report_responses`: a majority of bug reports from the previous 2-12 months
  were acknowledged. Check closed as well as open issues; if none were filed,
  use the badge application's accepted no-report answer.
- `vulnerability_report_response`: every report in the previous six months was
  acknowledged within 14 days, or no reports were received.
- `know_secure_design`, `know_common_errors`: at least one primary developer
  meets the criteria's secure-design and common-vulnerability knowledge test.
- `vulnerabilities_fixed_60_days`: there is no confirmed, publicly known,
  unpatched project vulnerability of medium or higher severity older than 60
  days. Check advisories, issues, CodeQL, and dependency alerts before answering.
- `no_leaked_credentials`: the repository and its history contain no valid
  private credential intended to restrict public access. The private JWK in
  `test/local-stack/` is an intentionally public test fixture and grants no
  access to a real system.
- GitHub Issues, private vulnerability reporting, required status checks, and
  suitable branch protection are enabled. The desired controls are recorded in
  [questions](questions.md) because the public repository API does not expose
  the organisation's effective settings.

Once a project entry exists and reaches passing, add its generated badge to the
top of the README. Do not add a badge URL before the entry exists.
