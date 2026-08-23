// Cloudflare Workers have no native asymmetric KMS, so SAG ships a second,
// tiny Worker that holds the private key and answers only over a service
// binding. Requests carry a shared secret so a leaked binding is not enough.

import { b64u, unb64u } from '../util/bytes.js';
import { fetchWithTimeout } from '../util/http.js';

const BASE = 'https://sag-hsm.internal';

async function call(binding, path, init, timeoutMs) {
  const request = new Request(BASE + path, init);
  // A service binding exposes fetch(); fall back to global fetch for an
  // HSM reachable over HTTPS (used by the Node dev server).
  const doFetch = typeof binding === 'string'
    ? (req) => fetchWithTimeout(req.url.replace(BASE, binding), req, timeoutMs)
    : (req) => binding.fetch(req);
  const res = await doFetch(request);
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error('HSM ' + path + ' failed with HTTP ' + res.status + ' ' + detail.slice(0, 200));
  }
  return res.json();
}

export async function createHsmSigner({ binding, sharedSecret, alg = 'ES256', timeoutMs = 3000 }) {
  if (!binding) throw new Error('HSM signer requires a service binding or URL');
  if (!sharedSecret) throw new Error('HSM signer requires HSM_SHARED_SECRET');
  const headers = { 'content-type': 'application/json', 'x-sag-hsm-secret': sharedSecret };

  let cachedJwks;
  return {
    backend: 'cloudflare-hsm',
    alg,
    kid: undefined,
    async sign(bytes) {
      const body = JSON.stringify({ alg, input: b64u(bytes) });
      const out = await call(binding, '/sign', { method: 'POST', headers, body }, timeoutMs);
      if (!out.signature) throw new Error('HSM returned no signature');
      this.kid = out.kid ?? this.kid;
      return unb64u(out.signature);
    },
    async keyId() {
      if (!this.kid) {
        const jwks = await this.publicJwks();
        this.kid = jwks.keys[0]?.kid;
      }
      return this.kid;
    },
    async publicJwks() {
      if (cachedJwks && cachedJwks.expiresAt > Date.now()) return cachedJwks.jwks;
      const jwks = await call(binding, '/jwks', { method: 'GET', headers }, timeoutMs);
      cachedJwks = { jwks, expiresAt: Date.now() + 60_000 };
      this.kid = this.kid ?? jwks.keys?.[0]?.kid;
      return jwks;
    },
  };
}
