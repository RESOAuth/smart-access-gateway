// The private HSM Worker.
//
// Cloudflare has no native asymmetric key service, so the signing key would
// otherwise have to sit in the same Worker that parses untrusted input from the
// internet. This second Worker holds the key instead and is reachable only
// over a service binding, which is internal to the account and never routed
// publicly. A compromise of the main Worker then yields the ability to *ask*
// for signatures, but not the key itself.
//
// Deploy it with no routes at all. It should have no `routes` and no
// `workers_dev` in its configuration, so the only way in is the binding.

import { importPrivateJwk, publicPartOf, jwkThumbprint, webCryptoSignParams, ALGS } from '../../src/crypto/jose.js';
import { b64u, unb64u, timingSafeEqual } from '../../src/util/bytes.js';

const MAX_INPUT_BYTES = 8 * 1024;

let cache;

/**
 * Load every key this HSM holds.
 *
 * Keys are configured the same way as in the main Worker, so one keygen run
 * produces variables for either: SIGNING_PRIVATE_JWK plus, for additional
 * algorithms, SIGNING_PRIVATE_JWK_ML_DSA_44 and so on.
 */
async function loadKeys(env) {
  if (cache) return cache;
  const algs = [env.SIGNING_ALG || 'ES256', ...String(env.SIGNING_ADDITIONAL_ALGS || '').split(/[,\s]+/)].filter(Boolean);
  const keys = new Map();

  for (const alg of new Set(algs)) {
    if (!ALGS[alg]) throw new Error('unknown signing algorithm ' + alg);
    const suffix = alg.toUpperCase().replaceAll('-', '_');
    const raw = env['SIGNING_PRIVATE_JWK_' + suffix] || (alg === algs[0] ? env.SIGNING_PRIVATE_JWK : undefined);
    if (!raw) continue;
    let jwk;
    try {
      jwk = JSON.parse(raw);
    } catch (cause) {
      throw new Error('SIGNING_PRIVATE_JWK for ' + alg + ' is not valid JSON', { cause });
    }
    jwk = { ...jwk, alg };
    const kid = jwk.kid || (await jwkThumbprint(jwk));
    keys.set(alg, {
      alg,
      kid,
      key: await importPrivateJwk(jwk, alg),
      params: webCryptoSignParams(alg),
      publicJwk: publicPartOf({ ...jwk, kid }),
    });
  }

  if (keys.size === 0) throw new Error('this HSM Worker has no signing key configured');
  cache = { keys, primary: [...keys.keys()][0] };
  return cache;
}

/**
 * The shared secret check.
 *
 * A service binding is already private to the account, so this is the second
 * layer: it means a mistakenly bound Worker, or one deployed by somebody else
 * in the same account, still cannot obtain signatures.
 */
function authorised(request, env) {
  const expected = env.HSM_SHARED_SECRET;
  if (!expected) return false;
  const presented = request.headers.get('x-sag-hsm-secret') || '';
  return timingSafeEqual(presented, expected);
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!authorised(request, env)) {
      // Deliberately identical for a missing secret and a wrong one.
      return json({ error: 'forbidden' }, 403);
    }

    let loaded;
    try {
      loaded = await loadKeys(env);
    } catch (err) {
      console.error('[sag-hsm] ' + err.message);
      return json({ error: 'misconfigured' }, 500);
    }

    if (url.pathname === '/jwks' && request.method === 'GET') {
      // Ordered with the primary first, so a naive client picks it.
      const ordered = [loaded.keys.get(loaded.primary), ...[...loaded.keys.values()].filter((k) => k.alg !== loaded.primary)];
      return json({ keys: ordered.map((k) => k.publicJwk) });
    }

    if (url.pathname === '/sign' && request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: 'invalid_request' }, 400);
      }
      const entry = loaded.keys.get(body.alg || loaded.primary);
      if (!entry) return json({ error: 'unknown_alg' }, 400);

      let input;
      try {
        input = unb64u(body.input);
      } catch {
        return json({ error: 'invalid_input' }, 400);
      }
      // A signing oracle should only ever be asked to sign a JWS signing
      // input, which is small. Refusing anything larger keeps this from being
      // usable as a general-purpose signer.
      if (input.length === 0 || input.length > MAX_INPUT_BYTES) return json({ error: 'invalid_input' }, 400);

      const signature = new Uint8Array(await crypto.subtle.sign(entry.params, entry.key, input));
      return json({ signature: b64u(signature), kid: entry.kid, alg: entry.alg });
    }

    if (url.pathname === '/healthz' && request.method === 'GET') {
      return json({ status: 'ok', algs: [...loaded.keys.keys()], primary: loaded.primary });
    }

    return json({ error: 'not_found' }, 404);
  },
};

/** Exposed for tests. */
export { loadKeys as _loadKeys };
export function _resetCache() {
  cache = undefined;
}
