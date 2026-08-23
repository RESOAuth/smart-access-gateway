// A deployment may sign with more than one algorithm at once.
//
// This exists for algorithm migration. A classical key such as ES256 stays the
// default while a post-quantum key is published alongside it, so relying
// parties can opt in to ML-DSA at their own pace by asking for it. When every
// relying party has moved, the post-quantum key becomes the primary and the
// classical one is retired, without any change to the OAuth endpoints.

import { createSigner, signerKid } from './index.js';
import { isPostQuantum, ALGS } from '../crypto/jose.js';
import { supportsAlg } from '../crypto/capabilities.js';

/**
 * Build every signer this deployment offers.
 *
 * @returns {Promise<object>} signer set with primary, per-alg lookup, and a
 *   merged JWKS containing the public half of every active key.
 */
export async function createSignerSet(config, env) {
  const wanted = [config.signing.alg, ...config.signing.additionalAlgs];
  const seen = new Set();
  const signers = new Map();
  const skipped = [];

  for (const alg of wanted) {
    if (seen.has(alg)) continue;
    seen.add(alg);
    // Only the local backend can be probed cheaply; a remote KMS or HSM is
    // trusted to support what it was configured for.
    if (config.signing.backend === 'local' && !(await supportsAlg(alg))) {
      skipped.push({ alg, reason: 'not supported by this runtime' });
      continue;
    }
    try {
      // Each algorithm has its own key material, read from the suffixed
      // variables in src/config.js. Passing the primary's key to every signer
      // would mean a configured additional key was silently ignored and an
      // ephemeral one generated instead - so the JWKS would advertise a key
      // that changed on every restart.
      const perAlg = config.signing.keysByAlg?.[alg] ?? {};
      const signer = await createSigner(
        {
          ...config,
          signing: {
            ...config.signing,
            alg,
            privateJwk: perAlg.privateJwk,
            privatePem: perAlg.privatePem,
            kmsKeyId: perAlg.kmsKeyId,
          },
        },
        env,
      );
      signers.set(alg, signer);
    } catch (err) {
      if (alg === config.signing.alg) throw err;
      skipped.push({ alg, reason: err.message });
    }
  }

  if (signers.size === 0) {
    throw new Error('no usable signing key: could not initialise ' + wanted.join(', '));
  }
  const primaryAlg = signers.has(config.signing.alg) ? config.signing.alg : [...signers.keys()][0];
  const primary = signers.get(primaryAlg);

  return {
    primary,
    primaryAlg,
    skipped,
    algs: [...signers.keys()],
    postQuantumAlgs: [...signers.keys()].filter(isPostQuantum),
    /** True when at least one published key is quantum-resistant. */
    get hasPostQuantum() {
      return this.postQuantumAlgs.length > 0;
    },
    /** Signer for a relying party's requested algorithm. */
    select(alg) {
      if (!alg) return primary;
      const signer = signers.get(alg);
      if (!signer) {
        throw new Error('id_token signing algorithm ' + alg + ' is not available here; this deployment offers ' + [...signers.keys()].join(', '));
      }
      return signer;
    },
    async kid(alg) {
      return signerKid(this.select(alg));
    },
    /** Merged JWKS. Ordered with the primary first so naive clients pick it. */
    async jwks() {
      const keys = [];
      const seenKids = new Set();
      const ordered = [primary, ...[...signers.values()].filter((s) => s !== primary)];
      for (const signer of ordered) {
        const set = await signer.publicJwks();
        for (const key of set.keys || []) {
          const id = key.kid || JSON.stringify(key);
          if (seenKids.has(id)) continue;
          seenKids.add(id);
          keys.push(key);
        }
      }
      return { keys };
    },
    /** Summary for the health endpoint. */
    describe() {
      return {
        primary: { alg: primaryAlg, backend: primary.backend, ephemeral: primary.ephemeral ?? false },
        algorithms: [...signers.keys()].map((alg) => ({ alg, family: ALGS[alg].family })),
        post_quantum_signatures: this.postQuantumAlgs.length > 0,
        skipped,
      };
    },
  };
}
