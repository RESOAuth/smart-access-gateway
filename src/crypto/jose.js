// Minimal JOSE: just enough JWS to issue id_tokens, verify upstream
// id_tokens, and authenticate clients with private_key_jwt.

import { b64u, unb64u, b64uJson, unb64uText, utf8, timingSafeEqual, nowSeconds } from '../util/bytes.js';
import { sha256b64u } from './secrets.js';
import { fetchWithTimeout, readJsonLimited } from '../util/http.js';

export const ALGS = {
  ES256: { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256', kty: 'EC', family: 'classical' },
  ES384: { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384', kty: 'EC', family: 'classical' },
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', kty: 'RSA', family: 'classical' },
  PS256: { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32, kty: 'RSA', family: 'classical' },
  HS256: { name: 'HMAC', hash: 'SHA-256', kty: 'oct', family: 'symmetric' },
  // Module-Lattice digital signatures (FIPS 204). In JOSE these use the
  // Algorithm Key Pair key type, where `pub` and `priv` carry raw key bytes
  // and `alg` is required because `kty` alone does not pin the parameter set.
  'ML-DSA-44': { name: 'ML-DSA-44', kty: 'AKP', family: 'post-quantum', signatureBytes: 2420, publicKeyBytes: 1312 },
  'ML-DSA-65': { name: 'ML-DSA-65', kty: 'AKP', family: 'post-quantum', signatureBytes: 3309, publicKeyBytes: 1952 },
  'ML-DSA-87': { name: 'ML-DSA-87', kty: 'AKP', family: 'post-quantum', signatureBytes: 4627, publicKeyBytes: 2592 },
};

/** Algorithms whose security does not rest on factoring or discrete logs. */
export const POST_QUANTUM_ALGS = Object.keys(ALGS).filter((a) => ALGS[a].family === 'post-quantum');

export const isPostQuantum = (alg) => ALGS[alg]?.family === 'post-quantum';

function algParams(alg) {
  const spec = ALGS[alg];
  if (!spec) throw new Error('unsupported JWS algorithm: ' + alg);
  return spec;
}

function importParams(alg) {
  const spec = algParams(alg);
  if (spec.family === 'post-quantum') return { name: spec.name };
  if (spec.name === 'ECDSA') return { name: 'ECDSA', namedCurve: spec.namedCurve };
  if (spec.name === 'HMAC') return { name: 'HMAC', hash: spec.hash };
  return { name: spec.name, hash: spec.hash };
}

function signParams(alg) {
  const spec = algParams(alg);
  if (spec.family === 'post-quantum') return { name: spec.name };
  if (spec.name === 'ECDSA') return { name: 'ECDSA', hash: spec.hash };
  if (spec.name === 'RSA-PSS') return { name: 'RSA-PSS', saltLength: spec.saltLength };
  return spec.name;
}

export { importParams as webCryptoImportParams, signParams as webCryptoSignParams };

/** RFC 7638 JWK thumbprint, used as the default kid. */
export async function jwkThumbprint(jwk) {
  let canonical;
  if (jwk.kty === 'EC') canonical = { crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y };
  else if (jwk.kty === 'RSA') canonical = { e: jwk.e, kty: 'RSA', n: jwk.n };
  else if (jwk.kty === 'oct') canonical = { k: jwk.k, kty: 'oct' };
  else if (jwk.kty === 'AKP') canonical = { alg: jwk.alg, kty: 'AKP', pub: jwk.pub };
  else throw new Error('cannot thumbprint kty ' + jwk.kty);
  return sha256b64u(JSON.stringify(canonical));
}

export function publicPartOf(jwk) {
  const pub = { kty: jwk.kty };
  for (const f of ['crv', 'x', 'y', 'n', 'e', 'pub']) if (jwk[f] !== undefined) pub[f] = jwk[f];
  if (jwk.alg) pub.alg = jwk.alg;
  else if (jwk.kty === 'AKP') throw new Error('an AKP JWK must carry an alg member');
  if (jwk.kid) pub.kid = jwk.kid;
  pub.use = jwk.use ?? 'sig';
  return pub;
}

export async function importPrivateJwk(jwk, alg) {
  return crypto.subtle.importKey('jwk', { ...jwk, ext: true }, importParams(alg), true, ['sign']);
}

export async function importPublicJwk(jwk, alg) {
  const pub = publicPartOf(jwk);
  return crypto.subtle.importKey('jwk', pub, importParams(alg), true, ['verify']);
}

/** Build the signing input for a JWS: base64url(header).base64url(payload). */
export function signingInput(header, payload) {
  return b64uJson(header) + '.' + b64uJson(payload);
}

/**
 * Produce a compact JWS. `signer` is either a CryptoKey or an async
 * function taking the signing input bytes and returning raw signature
 * bytes, which is how the KMS and HSM backends plug in.
 */
export async function signCompact(alg, signer, header, payload) {
  const input = signingInput({ ...header, alg }, payload);
  const bytes = utf8(input);
  let sig;
  if (typeof signer === 'function') sig = await signer(bytes);
  else sig = new Uint8Array(await crypto.subtle.sign(signParams(alg), signer, bytes));
  return input + '.' + b64u(sig);
}

export function decodeJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('not a compact JWS');
  return {
    header: JSON.parse(unb64uText(parts[0])),
    payload: JSON.parse(unb64uText(parts[1])),
    signature: unb64u(parts[2]),
    input: utf8(parts[0] + '.' + parts[1]),
  };
}

/** Verify a compact JWS against a public JWK. Returns the payload. */
export async function verifyCompact(token, jwk, { algs } = {}) {
  const { header, payload, signature, input } = decodeJwt(token);
  const alg = header.alg;
  if (!ALGS[alg]) throw new Error('unsupported alg ' + alg);
  if (algs && !algs.includes(alg)) throw new Error('alg ' + alg + ' not permitted here');
  const key = await importPublicJwk(jwk, alg);
  const ok = await crypto.subtle.verify(signParams(alg), key, signature, input);
  if (!ok) throw new Error('signature verification failed');
  return payload;
}

/** HS256 convenience wrapper - used by the GOV.UK Notify client. */
export async function signHs256(secret, payload, header = {}) {
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return signCompact('HS256', key, { typ: 'JWT', ...header }, payload);
}

/**
 * Standard JWT claim checks. Everything is explicit so callers cannot
 * accidentally skip audience or issuer validation.
 */
export function validateClaims(payload, { issuer, audience, nonce, clockSkew = 60, maxAge }) {
  const now = nowSeconds();
  if (issuer && payload.iss !== issuer) throw new Error('unexpected issuer ' + payload.iss);
  if (audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(audience)) throw new Error('token audience does not include ' + audience);
    if (aud.length > 1 && payload.azp && payload.azp !== audience) throw new Error('unexpected azp');
  }
  if (!Number.isFinite(payload.exp) || payload.exp + clockSkew < now) throw new Error('token expired');
  if (payload.nbf !== undefined && !Number.isFinite(payload.nbf)) throw new Error('invalid nbf');
  if (Number.isFinite(payload.nbf) && payload.nbf - clockSkew > now) throw new Error('token not yet valid');
  if (payload.iat !== undefined && !Number.isFinite(payload.iat)) throw new Error('invalid iat');
  if (Number.isFinite(payload.iat) && payload.iat - clockSkew > now) throw new Error('token issued in the future');
  if (nonce !== undefined && !timingSafeEqual(String(payload.nonce ?? ''), nonce)) throw new Error('nonce mismatch');
  if (maxAge !== undefined) {
    const authTime = payload.auth_time;
    if (!Number.isFinite(authTime)) throw new Error('auth_time required when max_age is requested');
    if (authTime + maxAge + clockSkew < now) throw new Error('authentication too old for max_age');
  }
  return payload;
}

// ---------------------------------------------------------------------------
// DER helpers. Cloud KMS backends return ECDSA signatures DER-encoded, while
// JWS needs the raw r||s form.
// ---------------------------------------------------------------------------

const COORD_BYTES = { 'P-256': 32, 'P-384': 48, 'P-521': 66 };

export function derToRawEcdsa(der, curve = 'P-256') {
  const size = COORD_BYTES[curve];
  if (!size) throw new Error('unknown curve ' + curve);
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('bad DER sequence');
  let seqLen = der[i++];
  if (seqLen & 0x80) {
    const n = seqLen & 0x7f;
    seqLen = 0;
    for (let k = 0; k < n; k++) seqLen = (seqLen << 8) | der[i++];
  }
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error('bad DER integer');
    const len = der[i++];
    let v = der.subarray(i, i + len);
    i += len;
    while (v.length > 1 && v[0] === 0x00) v = v.subarray(1);
    if (v.length > size) throw new Error('DER integer larger than curve');
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(size * 2);
  raw.set(r, 0);
  raw.set(s, size);
  return raw;
}

/** Convert a SubjectPublicKeyInfo DER blob into a public JWK. */
export async function spkiToJwk(der, alg) {
  const key = await crypto.subtle.importKey('spki', der, importParams(alg), true, ['verify']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  return publicPartOf({ ...jwk, alg });
}

/** Parse a PEM block into DER bytes. */
export function pemToDer(pem) {
  const body = String(pem)
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  if (!body) throw new Error('no PEM body found');
  return unb64u(body.replaceAll('+', '-').replaceAll('/', '_'));
}

/** Import a PKCS#8 PEM private key and export it as a JWK. */
export async function pemPrivateToJwk(pem, alg) {
  const der = pemToDer(pem);
  const key = await crypto.subtle.importKey('pkcs8', der, importParams(alg), true, ['sign']);
  return { ...(await crypto.subtle.exportKey('jwk', key)), alg };
}

const jwksCache = new Map();
const MAX_JWKS_BYTES = 256 * 1024;
const MAX_JWKS_CACHE_ENTRIES = 500;

function rememberJwks(uri, entry) {
  const now = nowSeconds();
  for (const [key, cached] of jwksCache) {
    if (cached.expiresAt <= now) jwksCache.delete(key);
  }
  jwksCache.delete(uri);
  if (jwksCache.size >= MAX_JWKS_CACHE_ENTRIES) {
    const oldest = jwksCache.keys().next().value;
    if (oldest !== undefined) jwksCache.delete(oldest);
  }
  jwksCache.set(uri, entry);
}

/** Fetch and cache a remote JWKS. Used for client private_key_jwt keys. */
export async function fetchJwks(
  uri,
  { ttlSeconds = 300, timeoutMs = 5000, maxBytes = MAX_JWKS_BYTES, allowHttp = false } = {},
) {
  let url;
  try {
    url = new URL(uri);
  } catch {
    throw new Error('JWKS URI is not an absolute URL');
  }
  if (url.username || url.password || (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:'))) {
    throw new Error('JWKS URI must use https');
  }
  const cacheKey = url.href;
  const cached = jwksCache.get(cacheKey);
  const now = nowSeconds();
  if (cached && cached.expiresAt > now) return cached.jwks;
  const res = await fetchWithTimeout(cacheKey, { headers: { accept: 'application/json' } }, timeoutMs);
  if (!res.ok) throw new Error('JWKS fetch failed with HTTP ' + res.status);
  const jwks = await readJsonLimited(res, maxBytes);
  if (!jwks || !Array.isArray(jwks.keys)) throw new Error('JWKS document has no keys array');
  rememberJwks(cacheKey, { jwks, expiresAt: now + ttlSeconds });
  return jwks;
}

/** Select a key from a JWKS by kid, falling back to a unique candidate. */
export function selectJwk(jwks, header) {
  const keys = (jwks.keys || []).filter(
    (k) => (!k.use || k.use === 'sig') && (!k.alg || k.alg === header.alg),
  );
  if (header.kid) {
    const byKid = keys.find((k) => k.kid === header.kid);
    if (byKid) return byKid;
    throw new Error('no matching key in JWKS');
  }
  if (keys.length === 1) return keys[0];
  throw new Error('no matching key in JWKS');
}

export function clearJwksCache() {
  jwksCache.clear();
}
