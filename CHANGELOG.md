# Changelog

All notable changes to SAG are recorded here. Releases use semantic versions.

## Unreleased

### Security

None.

## 0.2.1 - 2026-09-03

This corrective release records all notable changes since 0.1.0. Version
0.2.0 was published from the preceding commit without updated package or
runtime version metadata and without complete release notes. It remains
available, but is superseded by 0.2.1.

### Upgrade notes

- Existing production sessions are invalidated once because session cookies
  now use the browser-enforced `__Host-` prefix. Custom cookie names are
  prefixed too.
- Production deployments using Client ID Metadata Documents must set
  `CLIENTS_CIMD_ENABLED=true`; production now defaults it to `false`.
- A `UPSTREAM_MICROSOFT_COMMON_*` upstream must set
  `ALLOWED_TENANTS`, or its Entra application must request the `xms_edov`
  optional claim. Sign-ins which satisfy neither boundary now fail closed.
- `SAG_ISSUER` is required outside development and is no longer derived from
  request headers. It must not contain URL userinfo, a query, or a
  fragment.
- Peered deployments should use a durable `PEER_JWKS_CACHE_BACKEND`.
  `REQUIRE_PEER_JWKS_CACHE=true` makes that, and a non-empty peer list,
  start-up requirements.

### Added

- Any environment variable may now contain an `aws:kms:`,
  `aws:secretsmanager:`, or `aws:ssm:` reference. SAG resolves sealed values
  once at start-up using ambient AWS credentials and fails rather than using
  an unresolved reference as a literal secret.
- The sign-in form can remember a verified address in an encrypted, rolling
  one-year `__Host-RememberMe` cookie. The address is only stored after a
  successful sign-in and can be forgotten by clearing the checkbox.
- Relying parties can display a sign-in logo through
  `CLIENT_<SLUG>_LOGO_URI` or the standard `logo_uri` metadata field. The page
  CSP is restricted to the configured logo origin.
- `/token` and `/userinfo` now support browser CORS requests. All origins are
  allowed by default; `CORS_ALLOWED_ORIGINS` narrows the set, and
  `CORS_ENABLED=false` disables CORS. Registered static-client origins remain
  allowed when the set is narrowed.
- A configured state store now makes `private_key_jwt` assertions single-use
  by claiming each client and `jti` pair until expiry. It also revokes every
  copy of a logged-out session until that session's absolute expiry; session
  reads and logout fail closed if that store is unavailable.
- `CLIENTS_REDIRECT_URI_SCHEMES` can restrict the schemes accepted for
  authorisation and post-logout redirects. It defaults to `*` so registered
  native-application schemes continue to work.
- `UPSTREAM_<PROVIDER>_<SLUG>_ALLOWED_TENANTS` can restrict a common Microsoft
  upstream to specific Entra tenant IDs.
- `PEER_JWKS_RETRY_AFTER` adds a short backoff after failed peer fetches, and
  `/healthz` now reports `peer_jwks.peers[].key_count` to identify a peer
  which is not contributing keys.
- Added contribution, security, release, and OpenSSF Best Practices guidance,
  plus an RFC for structured SIEM event export.

### Changed

- An omitted or blank OAuth `prompt` now behaves as `prompt=consent`, showing
  which existing account will continue. Silent authentication requires an
  explicit `prompt=none`.
- CIMD hosts are resolved before fetching and must use public addresses;
  localhost remains available in development, and an empty domain allow-list
  accepts any public host. An allowed metadata host may now carry a distinct
  `client_id` and registered redirect URIs on other origins, including native
  loopback URIs, while `jwks_uri` remains bound to the document origin.
- Cloudflare Workers now use the runtime's `node:dns` resolver instead of an
  outbound DNS-over-HTTPS request. Returned records and resolver timeouts are
  constrained to those requested by the core.
- Active sessions roll their idle expiry forward when used, without extending
  their absolute lifetime.
- Production session cookies now use `Secure`, host-only `Path=/` scope, and
  the `__Host-` prefix. Development retains unprefixed cookies and issuer-path
  scope.
- Common Microsoft upstreams trust the `email` claim only, require an allowed
  `tid` or `xms_edov: true`, and reject `xms_edov: false`. Domain-specific
  upstreams retain their domain check and login-identifier fallbacks.
- Remote metadata, JWKS, DNS, token, client-store, and form bodies are bounded
  while streaming, and attacker-controlled in-memory metadata caches now have
  entry limits.
- The project licence is now AGPL-3.0, and the public documentation moved to
  `sag.resoauth.dev` while design records remain with the code.

### Removed

- Removed `PROMPT_NONE_SHARED_SESSION`, which had no runtime effect.

### Fixed

- Peered deployments no longer intermittently publish a `/jwks.json` missing
  an instance's keys. Peer requests return only that peer's local keys,
  concurrent cold-start requests share one fetch, empty key sets count as
  failures, incomplete documents receive a short cache lifetime, and a peer
  URL on the local issuer origin is refused at start-up.
- Failed peer fetches no longer impose their full timeout on every JWKS
  request. A peered deployment using the volatile `memory` cache now logs a
  warning because restarts discard its stale-key protection.
- Outbound requests use manually inspected redirects because Cloudflare
  Workers reject `redirect: 'error'`; redirects remain refused on every
  platform.
- Logout now honours per-client session-scope overrides, clears only the
  intended session unless global logout was requested, and does not turn an
  invalid confirmation token into a cookie-clearing operation.
- Invalid static or stored `session_scope` values are refused instead of
  silently changing session isolation, and malformed percent-encoded cookies
  no longer cause a request-wide error.
- Token exchange now requires the original `redirect_uri`; client-secret
  authentication must use its registered method, and plain client secrets are
  compared case-sensitively.
- Client and upstream JWKS selection now honours both `kid` and `alg`, refuses
  a missing requested key rather than falling back, and rejects RSA moduli
  below 2048 bits.
- The signing-key compromise runbook now explains how to withdraw a leaked key
  from every peer without leaving it published for the stale-key grace period.

### Security

- Hardened common Microsoft upstreams against nOAuth-style address spoofing by
  requiring a tenant or verified-domain boundary.
- CIMD fetches reject credentials, redirects, private and loopback targets,
  cloud metadata ranges, and IPv4-mapped, 6to4, and Teredo addresses.
- Logout return and cancellation links reject non-HTTP(S) schemes, including
  `javascript:` URLs.
- `/healthz` no longer exposes rejected configuration values; sensitive
  diagnostics remain in operator logs.
- Production responses now include a one-year HSTS policy, short
  `SUBJECT_SALT` values produce a start-up warning, JWT time claims must be
  finite numbers, and remote security endpoints require HTTPS outside
  development.

Public vulnerability identifiers: None.

## 0.2.0 - 2026-09-03

Published inadvertently without updated version metadata or complete release
notes. Superseded by 0.2.1, whose entry documents the changes since 0.1.0.

## 0.1.0 - 2026-08-24

Initial pre-release of the stateless OpenID Connect identity proxy, with Node,
AWS Lambda, Cloudflare Worker, and container adapters.

### Security

None.
