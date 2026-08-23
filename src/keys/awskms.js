// AWS KMS signer. Signatures never leave KMS unwrapped, and the public key is
// fetched once and cached for the JWKS endpoint.

import { b64, unb64 } from '../util/bytes.js';
import { signRequest } from '../crypto/sigv4.js';
import { derToRawEcdsa, spkiToJwk, jwkThumbprint } from '../crypto/jose.js';
import { fetchWithTimeout } from '../util/http.js';

const SIGNING_ALGORITHMS = {
  ES256: 'ECDSA_SHA_256',
  ES384: 'ECDSA_SHA_384',
  RS256: 'RSASSA_PKCS1_V1_5_SHA_256',
  PS256: 'RSASSA_PSS_SHA_256',
};

const CURVES = { ES256: 'P-256', ES384: 'P-384' };

async function kms(target, payload, { region, credentials, timeoutMs = 5000, endpoint }) {
  const url = endpoint || 'https://kms.' + region + '.amazonaws.com/';
  const body = JSON.stringify(payload);
  const headers = await signRequest({
    method: 'POST',
    url,
    body,
    service: 'kms',
    region,
    credentials,
    headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.' + target },
  });
  const res = await fetchWithTimeout(url, { method: 'POST', headers, body }, timeoutMs);
  const outText = await res.text();
  if (!res.ok) throw new Error('KMS ' + target + ' failed with HTTP ' + res.status + ' ' + outText.slice(0, 300));
  return JSON.parse(outText);
}

export async function createKmsSigner({ keyId, region, credentials, alg = 'ES256', endpoint, extraPublicJwks = [] }) {
  const signingAlgorithm = SIGNING_ALGORITHMS[alg];
  if (!signingAlgorithm) throw new Error('KMS cannot sign with ' + alg);
  if (!keyId) throw new Error('KMS signer requires SIGNING_KMS_KEY_ID');
  if (!region) throw new Error('KMS signer requires SIGNING_KMS_REGION or AWS_REGION');

  let publicJwk;
  let kid;

  async function loadPublicKey() {
    if (publicJwk) return publicJwk;
    const out = await kms('GetPublicKey', { KeyId: keyId }, { region, credentials, endpoint });
    const der = unb64(out.PublicKey);
    publicJwk = await spkiToJwk(der, alg);
    kid = publicJwk.kid || (await jwkThumbprint(publicJwk));
    publicJwk = { ...publicJwk, kid, use: 'sig' };
    return publicJwk;
  }

  return {
    backend: 'aws-kms',
    alg,
    get kid() {
      return kid;
    },
    async keyId() {
      await loadPublicKey();
      return kid;
    },
    async sign(bytes) {
      const out = await kms(
        'Sign',
        { KeyId: keyId, Message: b64(bytes), MessageType: 'RAW', SigningAlgorithm: signingAlgorithm },
        { region, credentials, endpoint },
      );
      const sig = unb64(out.Signature);
      return CURVES[alg] ? derToRawEcdsa(sig, CURVES[alg]) : sig;
    },
    async publicJwks() {
      return { keys: [await loadPublicKey(), ...extraPublicJwks] };
    },
  };
}
