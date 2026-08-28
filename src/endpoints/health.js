// GET /healthz
//
// Enough to tell whether an instance is actually able to sign somebody in,
// without disclosing anything that helps an attacker. No configuration values,
// no client ids, no secrets - only whether each part of the machine is present
// and what it can do.
//
// Two things are deliberately absent. Whether a state store is configured, and
// therefore whether authorisation codes and client assertions are single-use
// and OTP sends are limited, is a map of which defences are on: useful to an
// operator, and more useful to somebody deciding whether replaying a value is
// worth trying. And the upstreams are reported as a count per provider,
// rather than by name,
// because the domain list is the deployment's customer list. Both are in the
// start-up banner and the logs instead, where the audience is known - see
// docs/operations.md.

import { json } from '../util/http.js';
import { cryptoReport } from '../crypto/capabilities.js';
import { VERSION } from '../version.js';

export async function handleHealth(ctx) {
  const { config, signerSet } = ctx;
  const signing = signerSet.describe();

  // Sorted, so the document is stable between restarts and diffs cleanly.
  const upstreams = {};
  for (const u of config.upstreams) upstreams[u.provider] = (upstreams[u.provider] || 0) + 1;

  const body = {
    status: 'ok',
    version: VERSION,
    issuer: config.issuer,
    signing,
    // A deployment running on an ephemeral key will invalidate every token it
    // has issued the next time it restarts, so it must be visible.
    warnings: [
      ...(signing.primary.ephemeral ? ['The signing key is ephemeral and will change when this instance restarts.'] : []),
      ...(config.devMode ? ['Running in development mode.'] : []),
      ...config.warnings,
    ],
    routes: {
      upstreams: Object.fromEntries(Object.keys(upstreams).sort().map((p) => [p, upstreams[p]])),
      otp: config.otp.enabled ? config.email.provider : false,
    },
    clients: {
      static: config.clients.static.length,
      cimd: config.clients.cimd.enabled,
      store: config.clients.store.backend,
    },
    // No fetch happens here - only what the cache already holds - so this
    // stays as cheap as everything else /healthz reports. See
    // docs/multi-region.md for what "within_grace_period: false" means: that
    // peer's keys have already dropped out of /jwks.json.
    peer_jwks: ctx.peerJwks ? { backend: ctx.peerJwks.backend, peers: await ctx.peerJwks.describe() } : false,
  };

  if (config.devMode) {
    // The probe generates throwaway keys, so it is kept out of the hot path on
    // a real deployment and only reported where a developer is looking.
    body.crypto = await cryptoReport();
  }

  return json(body);
}
