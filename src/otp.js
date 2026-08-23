// Email one-time codes.
//
// This is the fallback when no upstream provider covers a person's domain, and
// it is the only route where SAG itself asserts the identity rather than
// relaying somebody else's. It therefore gets the weakest acr, and the
// tightest handling.

import { derive, hmac } from './crypto/secrets.js';
import { b64u, randomBytes, timingSafeEqual, nowSeconds } from './util/bytes.js';
import { domainOf } from './identity.js';

/**
 * The alphabets a code can be drawn from.
 *
 * The alphanumeric one has 0, 1, I, L and O removed, because they are the
 * pairs people mistype when reading a code off a screen, and U removed
 * because a random nine character string should not be able to spell
 * something unfortunate. Thirty symbols over nine characters is about
 * 2 x 10^13 combinations.
 */
export const CODE_ALPHABETS = {
  alphanumeric: '23456789ABCDEFGHJKMNPQRSTVWXYZ',
  numeric: '0123456789',
};

export const alphabetFor = (config) => CODE_ALPHABETS[config.otp.codeAlphabet] ?? CODE_ALPHABETS.alphanumeric;

/**
 * A uniformly distributed code.
 *
 * Rejection sampling rather than a modulo, because `random % 30` favours the
 * start of the alphabet and a biased one-time code is a smaller keyspace than
 * it looks. The bias would be small; avoiding it costs nothing.
 */
export function generateCode(length = 9, alphabet = CODE_ALPHABETS.alphanumeric) {
  const limit = 256 - (256 % alphabet.length); // largest whole multiple under 256
  let out = '';
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte >= limit) continue;
      out += alphabet[byte % alphabet.length];
      if (out.length === length) break;
    }
  }
  return out;
}

/**
 * Fold what somebody typed into the canonical form.
 *
 * Case, spaces and the hyphens people copy out of the email are all noise. No
 * character is silently substituted for another: the confusable ones are not
 * in the alphabet at all, so a code containing one was never issued here.
 */
export function normaliseCode(input) {
  return String(input ?? '')
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '');
}

/**
 * Digest of a code, bound to the transaction and the address.
 *
 * Binding to both means a code issued for one address in one transaction
 * cannot be replayed against another, even if the same characters come up again.
 */
export async function digestCode(config, { txId, email, code }) {
  const key = await derive(config.secrets[0], 'otp-digest', 32);
  return b64u(await hmac(key, [txId, email, normaliseCode(code)].join(' | ')));
}

/**
 * Check a submitted code.
 *
 * The comparison is timing-safe, and every failure returns the same shape, so
 * a caller cannot distinguish "wrong code" from "expired" by how long it took.
 */
export async function verifyCode(config, tx, submitted) {
  const otp = tx.otp;
  if (!otp?.digest) return { ok: false, reason: 'no-code' };
  const code = normaliseCode(submitted);
  const expected = otp.digest;
  const actual = await digestCode(config, { txId: tx.id, email: tx.email, code });
  const matches = timingSafeEqual(actual, expected);
  if (typeof otp.exp === 'number' && otp.exp < nowSeconds()) return { ok: false, reason: 'expired' };
  if ((otp.attempts ?? 0) >= config.otp.maxAttempts) return { ok: false, reason: 'too-many-attempts' };
  if (!matches) return { ok: false, reason: 'mismatch' };
  return { ok: true };
}

/**
 * Is OTP available for this address?
 *
 * An allow list, when set, is exclusive; a block list is always applied. The
 * caller must not tell the person which of these stopped them, because that
 * turns the sign-in screen into a way to enumerate an organisation's domains.
 */
export function otpAllowed(config, email) {
  if (!config.otp.enabled) return false;
  const domain = domainOf(email);
  if (!domain) return false;
  const { allowedDomains, blockedDomains } = config.otp;
  const matches = (list) =>
    list.some((entry) => {
      const e = entry.toLowerCase().replace(/^\*?\./, '');
      return domain === e || domain.endsWith('.' + e);
    });
  if (blockedDomains.length && matches(blockedDomains)) return false;
  if (allowedDomains.length && !matches(allowedDomains)) return false;
  return true;
}

/**
 * Group a code so it is easy to read back from an email.
 *
 * Threes when the length divides by three, fours otherwise, which covers every
 * length the configuration allows without a table of special cases.
 */
export function formatCodeForDisplay(code) {
  const s = String(code);
  const size = s.length % 3 === 0 ? 3 : 4;
  return (s.match(new RegExp('.{1,' + size + '}', 'g')) || [s]).join(' ');
}
