// RFC 6238 time-based one-time passwords.
//
// Keeping the actual TOTP calculation on Web Crypto means the core
// remains portable even though the first identity-store backend is Node-only.

import { timingSafeEqual } from '../util/bytes.js';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decode an unpadded RFC 4648 base32 value. */
export function decodeBase32(value) {
  const text = String(value || '').toUpperCase().replaceAll(' ', '').replaceAll('-', '').replace(/=+$/, '');
  if (!text || !/^[A-Z2-7]+$/.test(text)) throw new Error('invalid base32 secret');
  const out = new Uint8Array(Math.floor((text.length * 5) / 8));
  let acc = 0;
  let bits = 0;
  let offset = 0;
  for (const char of text) {
    acc = (acc << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[offset++] = (acc >> bits) & 0xff;
    }
  }
  if (offset < 10) throw new Error('TOTP secret must contain at least 80 bits');
  return out.subarray(0, offset);
}

/** Encode bytes as unpadded RFC 4648 base32, used by the provisioning tool. */
export function encodeBase32(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(acc >> bits) & 31];
    }
  }
  if (bits > 0) out += BASE32[(acc << (5 - bits)) & 31];
  return out;
}

function hashName(algorithm) {
  const value = String(algorithm || 'SHA1').toUpperCase().replaceAll('-', '');
  if (value === 'SHA1') return 'SHA-1';
  if (value === 'SHA256') return 'SHA-256';
  if (value === 'SHA512') return 'SHA-512';
  throw new Error('unsupported TOTP algorithm');
}

function counterBytes(step) {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, BigInt(step), false);
  return bytes;
}

/** Generate one TOTP value for an exact time-step. */
export async function totpForStep(secret, step, { algorithm = 'SHA1', digits = 6 } = {}) {
  if (!Number.isSafeInteger(step) || step < 0) throw new Error('invalid TOTP time-step');
  if (digits !== 6 && digits !== 8) throw new Error('TOTP digits must be 6 or 8');
  const bytes = secret instanceof Uint8Array ? secret : decodeBase32(secret);
  const key = await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: hashName(algorithm) }, false, ['sign']);
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes(step)));
  const offset = digest[digest.length - 1] & 0x0f;
  const number =
    ((digest.at(offset) & 0x7f) << 24) |
    (digest.at(offset + 1) << 16) |
    (digest.at(offset + 2) << 8) |
    digest.at(offset + 3);
  return String(number % 10 ** digits).padStart(digits, '0');
}

/**
 * Verify a code across the configured skew without accepting a used step.
 *
 * Every candidate is calculated before the result is returned, so a code for
 * the first acceptable step does not take observably less HMAC work than one
 * for the last.
 */
export async function verifyTotp({ secret, code, now = Date.now(), algorithm = 'SHA1', digits = 6, period = 30, skew = 1, lastUsedStep }) {
  const presented = String(code || '').replace(/[\s-]/g, '');
  if (presented.length !== digits || !/^[0-9]+$/.test(presented)) return undefined;
  if (!Number.isInteger(period) || period < 15 || period > 120) throw new Error('invalid TOTP period');
  if (!Number.isInteger(skew) || skew < 0 || skew > 5) throw new Error('invalid TOTP skew');
  const current = Math.floor(now / 1000 / period);
  let matched;
  for (let delta = -skew; delta <= skew; delta += 1) {
    const step = current + delta;
    if (step < 0) continue;
    const expected = await totpForStep(secret, step, { algorithm, digits });
    if (timingSafeEqual(expected, presented) && (lastUsedStep === undefined || step > lastUsedStep)) {
      matched = matched === undefined ? step : Math.max(matched, step);
    }
  }
  return matched;
}
