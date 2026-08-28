// The optional remembered email address.
//
// This is deliberately separate from the session cookie. It can prefill a
// form, but it proves nothing about who is using the browser and is only
// written after an authentication has completed.

import { seal, unseal, SealError } from './crypto/secrets.js';
import { looksLikeEmail, normaliseEmail } from './identity.js';
import { nowSeconds } from './util/bytes.js';
import { parseCookies, serialiseCookie } from './util/http.js';

export const REMEMBER_ME_COOKIE = '__Host-RememberMe';
export const REMEMBER_ME_TTL_SECONDS = 365 * 24 * 60 * 60;

const PURPOSE = 'remember-me';

export function hasRememberMeCookie(request) {
  return parseCookies(request).has(REMEMBER_ME_COOKIE);
}

/** Read an authenticated, unexpired remembered address. */
export async function readRememberedEmail(config, request) {
  const raw = parseCookies(request).get(REMEMBER_ME_COOKIE);
  if (!raw) return undefined;
  try {
    const remembered = await unseal(config.secrets, PURPOSE, raw);
    const email = normaliseEmail(remembered?.email);
    if (
      remembered?.v !== 1 ||
      !Number.isFinite(remembered.exp) ||
      remembered.exp < nowSeconds() ||
      !looksLikeEmail(email)
    ) {
      return undefined;
    }
    return email;
  } catch (err) {
    if (err instanceof SealError) return undefined;
    throw err;
  }
}

/** Set the remembered address for a rolling year. */
export async function rememberMeCookie(config, email) {
  const value = await seal(config.secrets[0], PURPOSE, {
    v: 1,
    email: normaliseEmail(email),
    exp: nowSeconds() + REMEMBER_ME_TTL_SECONDS,
  });
  return serialiseCookie(REMEMBER_ME_COOKIE, value, {
    maxAge: REMEMBER_ME_TTL_SECONDS,
    sameSite: 'Lax',
    // The __Host- prefix requires Secure and Path=/, including when SAG is
    // mounted below the origin root. No Domain attribute is ever supplied.
    secure: true,
    path: '/',
  });
}

export function clearRememberMeCookie() {
  return serialiseCookie(REMEMBER_ME_COOKIE, '', {
    maxAge: 0,
    sameSite: 'Lax',
    secure: true,
    path: '/',
  });
}
