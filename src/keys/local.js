// In-process signing key. The private key comes from configuration as a JWK
// or a PKCS#8 PEM; in local development an ephemeral key is generated.

import {
  importPrivateJwk,
  publicPartOf,
  jwkThumbprint,
  pemPrivateToJwk,
  webCryptoSignParams,
  ALGS,
} from '../crypto/jose.js';

function generateParams(alg) {
  const spec = ALGS[alg];
  if (!spec) throw new Error('unsupported signing algorithm: ' + alg);
  if (spec.family === 'post-quantum') return { name: spec.name };
  if (spec.name === 'ECDSA') return { name: 'ECDSA', namedCurve: spec.namedCurve };
  if (spec.name === 'HMAC') throw new Error('HS256 cannot sign id_tokens for public clients');
  return { name: spec.name, hash: spec.hash, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };
}

export async function createLocalSigner({ alg = 'ES256', privateJwk, privatePem, extraPublicJwks = [] }) {
  let jwk = privateJwk;
  let ephemeral = false;
  if (!jwk && privatePem) jwk = await pemPrivateToJwk(privatePem, alg);
  if (!jwk) {
    let pair;
    try {
      pair = await crypto.subtle.generateKey(generateParams(alg), true, ['sign', 'verify']);
    } catch (cause) {
      throw new Error('this runtime cannot generate a ' + alg + ' key: ' + cause.message, { cause });
    }
    jwk = { ...(await crypto.subtle.exportKey('jwk', pair.privateKey)), alg };
    ephemeral = true;
  }
  if (!jwk.alg) jwk = { ...jwk, alg };
  const key = await importPrivateJwk(jwk, alg);
  const kid = jwk.kid || (await jwkThumbprint(jwk));
  const publicJwk = publicPartOf({ ...jwk, alg, kid });
  const algorithm = webCryptoSignParams(alg);

  return {
    backend: 'local',
    alg,
    kid,
    ephemeral,
    async sign(bytes) {
      return new Uint8Array(await crypto.subtle.sign(algorithm, key, bytes));
    },
    async publicJwks() {
      return { keys: [publicJwk, ...extraPublicJwks] };
    },
    async publicJwk() {
      return publicJwk;
    },
    /** Exposed so the keygen tool and dev server can print the key to persist. */
    exportPrivateJwk() {
      return { ...jwk, alg, kid };
    },
  };
}
