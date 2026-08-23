import { OAuthError } from './errors.js';

export const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'cross-origin-opener-policy': 'same-origin',
};

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' };

export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...NO_STORE, ...SECURITY_HEADERS, ...headers },
  });
}

/** Cacheable JSON, for discovery documents and JWKS. */
export function cachedJson(body, maxAge = 300, headers = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': `public, max-age=${maxAge}`,
      'access-control-allow-origin': '*',
      ...SECURITY_HEADERS,
      ...headers,
    },
  });
}

export function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', ...NO_STORE, ...SECURITY_HEADERS, ...headers },
  });
}

export function text(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE, ...SECURITY_HEADERS, ...headers },
  });
}

export function redirect(location, headers = {}) {
  return new Response(null, {
    status: 303,
    headers: { location, ...NO_STORE, ...SECURITY_HEADERS, ...headers },
  });
}

export function methodNotAllowed(allow) {
  return text('Method not allowed', 405, { allow: allow.join(', ') });
}

/** Append a Set-Cookie header without clobbering existing ones. */
export function withCookie(response, cookie) {
  const headers = new Headers(response.headers);
  headers.append('set-cookie', cookie);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function withCookies(response, cookies) {
  let r = response;
  for (const c of cookies) if (c) r = withCookie(r, c);
  return r;
}

export function parseCookies(request) {
  const header = request.headers.get('cookie');
  const out = new Map();
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out.set(name, decodeURIComponent(value));
  }
  return out;
}

/**
 * Serialise a cookie. `maxAge: 0` expires it immediately.
 */
export function serialiseCookie(name, value, opts = {}) {
  const bits = [`${name}=${encodeURIComponent(value)}`];
  bits.push(`Path=${opts.path ?? '/'}`);
  bits.push(`SameSite=${opts.sameSite ?? 'Lax'}`);
  if (opts.maxAge !== undefined) {
    bits.push(`Max-Age=${Math.max(0, Math.floor(opts.maxAge))}`);
    if (opts.maxAge === 0) bits.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  }
  if (opts.httpOnly !== false) bits.push('HttpOnly');
  if (opts.secure !== false) bits.push('Secure');
  if (opts.domain) bits.push(`Domain=${opts.domain}`);
  return bits.join('; ');
}

const MAX_BODY = 64 * 1024;

/** Read an application/x-www-form-urlencoded body as URLSearchParams. */
export async function readForm(request) {
  const ct = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/x-www-form-urlencoded') {
    throw new OAuthError('invalid_request', 'Request body must be application/x-www-form-urlencoded');
  }
  const body = await request.text();
  if (body.length > MAX_BODY) throw new OAuthError('invalid_request', 'Request body too large');
  return new URLSearchParams(body);
}

/** First value of a repeated parameter, rejecting duplicates per OAuth 2.1. */
export function single(params, name) {
  const all = params.getAll(name);
  if (all.length > 1) throw new OAuthError('invalid_request', `Duplicate "${name}" parameter`);
  const v = all[0];
  return v === undefined || v === '' ? undefined : v;
}

/** fetch() with a timeout, used for every outbound call. */
export async function fetchWithTimeout(url, init = {}, timeoutMs = 5000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, redirect: 'error' });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * A URL that is safe to put in an href.
 *
 * Relying parties supply terms and privacy links, and a CIMD client needs no
 * registration at all, so "escaped" is not enough: escapeHtml leaves
 * `javascript:alert(1)` intact and an anchor will happily run it on the
 * issuer's own origin, which is where the session cookie lives. Only http(s)
 * gets through, and plain http only where a development instance would use it.
 *
 * @returns {string|undefined} undefined when the value cannot be trusted
 */
export function safeHttpUrl(value, { allowHttp = false } = {}) {
  if (value === undefined || value === null || value === '') return undefined;
  let url;
  try {
    url = new URL(String(value));
  } catch {
    return undefined;
  }
  if (url.protocol === 'https:') return url.href;
  if (allowHttp && url.protocol === 'http:') return url.href;
  return undefined;
}

export function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
