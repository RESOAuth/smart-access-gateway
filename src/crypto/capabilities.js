// Which signature algorithms the host runtime can actually perform.
//
// SAG runs on several JavaScript runtimes whose WebCrypto coverage differs.
// Post-quantum signatures in particular are present on some (Node 24 with
// OpenSSL 3.5 or later) and absent on others, so the discovery document must
// advertise what this deployment can really do rather than a fixed list.

import { ALGS } from './jose.js';

const probeCache = new Map();

/** Probe one algorithm by generating a throwaway key pair. Result is cached. */
export async function supportsAlg(alg) {
  // eslint-disable-next-line security/detect-object-injection -- lookup in fixed ALGS mapping
  if (!ALGS[alg]) return false;
  if (probeCache.has(alg)) return probeCache.get(alg);
  const promise = (async () => {
    // eslint-disable-next-line security/detect-object-injection -- lookup in fixed ALGS mapping
    const spec = ALGS[alg];
    if (spec.family === 'symmetric') return true;
    try {
      let params;
      if (spec.family === 'post-quantum') params = { name: spec.name };
      else if (spec.name === 'ECDSA') params = { name: 'ECDSA', namedCurve: spec.namedCurve };
      else params = { name: spec.name, hash: spec.hash, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };
      const pair = await crypto.subtle.generateKey(params, true, ['sign', 'verify']);
      // Exporting as a JWK is also required, since that is how SAG publishes
      // keys; a runtime that can generate but not export is not usable.
      await crypto.subtle.exportKey('jwk', pair.publicKey);
      return true;
    } catch {
      return false;
    }
  })();
  probeCache.set(alg, promise);
  const result = await promise;
  probeCache.set(alg, result);
  return result;
}

/**
 * Filter a list of candidate algorithms down to those this runtime supports.
 * RSA probing is skipped unless asked for, because key generation is slow.
 */
export async function filterSupported(algs) {
  const out = [];
  for (const alg of algs) if (await supportsAlg(alg)) out.push(alg);
  return out;
}

/** A short report used by the health endpoint and the dev server banner. */
export async function cryptoReport(candidates = ['ES256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  const supported = [];
  const unsupported = [];
  for (const alg of candidates) ((await supportsAlg(alg)) ? supported : unsupported).push(alg);
  return {
    supported,
    unsupported,
    // eslint-disable-next-line security/detect-object-injection -- lookup in fixed ALGS mapping
    postQuantumSignatures: supported.some((a) => ALGS[a].family === 'post-quantum'),
  };
}

export function resetProbeCache() {
  probeCache.clear();
}
