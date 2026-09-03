// Making key material.
//
// Shared by the keygen tool, which prints environment variables for a real
// deployment, and by the container bootstrap, which writes them once into a
// volume so a restart does not invalidate every session it has issued.

import { ALGS, publicPartOf, jwkThumbprint } from '../crypto/jose.js';
import { supportsAlg } from '../crypto/capabilities.js';
import { b64 } from '../util/bytes.js';

/** A high-entropy master secret. 48 bytes exceeds what HKDF-SHA-256 can use. */
export const randomSecret = () => b64(crypto.getRandomValues(new Uint8Array(48)));

function generateParams(alg) {
  // eslint-disable-next-line security/detect-object-injection -- lookup in fixed ALGS mapping
  const spec = ALGS[alg];
  if (!spec) throw new Error('unknown algorithm ' + alg);
  if (spec.family === 'post-quantum') return { name: spec.name };
  if (spec.name === 'ECDSA') return { name: 'ECDSA', namedCurve: spec.namedCurve };
  if (spec.name === 'HMAC') throw new Error(alg + ' cannot sign id_tokens');
  return { name: spec.name, hash: spec.hash, modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]) };
}

/**
 * @param {string} alg  A JWS algorithm name, for example ES256 or ML-DSA-44
 * @returns {Promise<{alg: string, kid: string, privateJwk: object, publicJwk: object, family: string}>}
 */
export async function generateSigningKey(alg) {
  if (!(await supportsAlg(alg))) {
    throw new Error(
      alg + ' is not available on this runtime (' + (globalThis.process?.version ?? 'unknown') +
        '). A newer Node with a newer OpenSSL may support it.',
    );
  }
  const pair = await crypto.subtle.generateKey(generateParams(alg), true, ['sign', 'verify']);
  const privateJwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), alg };
  const kid = await jwkThumbprint(privateJwk);
  return {
    alg,
    kid,
    privateJwk: { ...privateJwk, kid },
    publicJwk: publicPartOf({ ...privateJwk, kid }),
    // eslint-disable-next-line security/detect-object-injection -- lookup in fixed ALGS mapping
    family: ALGS[alg].family,
  };
}
