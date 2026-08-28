// Symmetric key handling: one master secret is stretched with HKDF into
// purpose-bound keys, so nothing is ever reused across contexts.

import { utf8, b64u, unb64u, toHex, timingSafeEqual } from '../util/bytes.js';

const HKDF_INFO_PREFIX = 'sag/v1/';

/** SHA-256 digest of a string or byte array. */
export async function sha256(input) {
  const bytes = typeof input === 'string' ? utf8(input) : input;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export const sha256b64u = async (input) => b64u(await sha256(input));
export const sha256hex = async (input) => toHex(await sha256(input));

/** HMAC-SHA-256 over data with raw key bytes. */
export async function hmac(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes));
}

/**
 * Derive `length` bytes for a named purpose from a master secret.
 * The salt is empty and the purpose goes in `info`, which is the
 * recommended split for a single high-entropy input key.
 */
export async function derive(masterSecret, purpose, length = 32) {
  const ikm = typeof masterSecret === 'string' ? utf8(masterSecret) : masterSecret;
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(HKDF_INFO_PREFIX + purpose) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

const aesCache = new Map();

async function aesKey(masterSecret, purpose) {
  const cacheKey = purpose + ' ' + (typeof masterSecret === 'string' ? masterSecret : toHex(masterSecret));
  let key = aesCache.get(cacheKey);
  if (!key) {
    const raw = await derive(masterSecret, 'aead/' + purpose, 32);
    key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    aesCache.set(cacheKey, key);
  }
  return key;
}

export class SealError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SealError';
  }
}

/**
 * Seal a JSON value into a compact, tamper-proof, confidential token.
 *
 * Format: version.purpose.iv.ciphertext (iv and ciphertext base64url).
 * The purpose is authenticated as additional data, so a token minted for
 * one purpose can never be replayed as another.
 */
export async function seal(masterSecret, purpose, payload, opts = {}) {
  const keyVersion = opts.keyVersion ?? 'k1';
  const key = await aesKey(masterSecret, purpose);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const aad = utf8(keyVersion + '.' + purpose);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      key,
      utf8(JSON.stringify(payload)),
    ),
  );
  return keyVersion + '.' + purpose + '.' + b64u(iv) + '.' + b64u(ct);
}

/**
 * Open a sealed token, returning the payload or throwing SealError.
 * `secrets` may be a single secret or an ordered list (current first) so
 * that a rotated secret can still open tokens minted by its predecessor.
 */
export async function unseal(secrets, purpose, token, opts = {}) {
  const list = (Array.isArray(secrets) ? secrets : [secrets]).filter(Boolean);
  const parts = String(token || '').split('.');
  if (parts.length !== 4) throw new SealError('malformed token');
  const [keyVersion, tokenPurpose, ivPart, ctPart] = parts;
  if (tokenPurpose !== purpose) throw new SealError('purpose mismatch');
  let iv;
  let ct;
  try {
    iv = unb64u(ivPart);
    ct = unb64u(ctPart);
  } catch {
    throw new SealError('malformed token');
  }
  const aad = utf8(keyVersion + '.' + purpose);
  for (const secret of list) {
    let pt;
    try {
      const key = await aesKey(secret, purpose);
      pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ct);
    } catch {
      continue; // Wrong key, try the next one.
    }
    let payload;
    try {
      payload = JSON.parse(new TextDecoder().decode(pt));
    } catch {
      throw new SealError('malformed payload');
    }
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && payload.exp < now) throw new SealError('token expired');
    if (opts.maxAgeSeconds && typeof payload.iat === 'number' && payload.iat + opts.maxAgeSeconds < now) {
      throw new SealError('token too old');
    }
    return payload;
  }
  throw new SealError('could not decrypt token');
}

/** Timing-safe check of a presented value against a stored digest. */
export async function verifyDigest(stored, presented) {
  const s = String(stored || '');
  const idx = s.indexOf(':');
  const scheme = idx > 0 ? s.slice(0, idx) : 'plain';
  const expected = idx > 0 ? s.slice(idx + 1) : s;
  let actual;
  if (scheme === 'sha256') actual = await sha256hex(presented);
  else if (scheme === 'plain') actual = String(presented);
  else throw new Error('unsupported secret digest scheme: ' + scheme);
  // Hex digests are notation and may be written in either case. A plain
  // secret is data: folding its case makes two distinct credentials equal.
  const left = scheme === 'sha256' ? actual.toLowerCase() : actual;
  const right = scheme === 'sha256' ? expected.toLowerCase() : expected;
  return expected.length > 0 && timingSafeEqual(left, right);
}
