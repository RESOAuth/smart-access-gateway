import { createLocalSigner } from './local.js';
import { createHsmSigner } from './cfhsm.js';
import { createKmsSigner } from './awskms.js';
import { credentialsFromEnv } from '../crypto/sigv4.js';
import { jwkThumbprint } from '../crypto/jose.js';

/**
 * Build the id_token signer described by the resolved configuration.
 * Every backend exposes the same shape: { alg, sign(bytes), publicJwks() }.
 */
export async function createSigner(config, env) {
  const { signing } = config;
  switch (signing.backend) {
    case 'local':
      return createLocalSigner({
        alg: signing.alg,
        privateJwk: signing.privateJwk,
        privatePem: signing.privatePem,
        extraPublicJwks: signing.extraPublicJwks,
      });
    case 'cloudflare-hsm':
      return createHsmSigner({
        binding: signing.hsmBinding ?? env?.[signing.hsmBindingName || 'HSM'],
        sharedSecret: signing.hsmSharedSecret,
        alg: signing.alg,
      });
    case 'aws-kms':
      return createKmsSigner({
        keyId: signing.kmsKeyId,
        region: signing.kmsRegion,
        credentials: signing.kmsCredentials ?? credentialsFromEnv(env ?? {}),
        alg: signing.alg,
        endpoint: signing.kmsEndpoint,
        extraPublicJwks: signing.extraPublicJwks,
      });
    default:
      throw new Error('unknown signing backend: ' + signing.backend);
  }
}

/** Resolve the kid for a signer, whichever backend it uses. */
export async function signerKid(signer) {
  if (signer.kid) return signer.kid;
  if (typeof signer.keyId === 'function') return signer.keyId();
  const jwks = await signer.publicJwks();
  const first = jwks.keys?.[0];
  return first ? first.kid || jwkThumbprint(first) : undefined;
}
