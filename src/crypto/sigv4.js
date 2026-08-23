// AWS Signature Version 4 over WebCrypto, so the same code runs on Lambda,
// Workers, and Node. Used by the KMS signer and the SES email sender.

import { utf8, toHex } from '../util/bytes.js';
import { sha256hex, hmac } from './secrets.js';

const UNRESERVED = /[A-Za-z0-9\-._~]/;

function encodeRfc3986(value) {
  let out = '';
  for (const ch of String(value)) {
    if (UNRESERVED.test(ch)) out += ch;
    else for (const byte of utf8(ch)) out += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

function canonicalQuery(searchParams) {
  const pairs = [];
  for (const [k, v] of searchParams) pairs.push([encodeRfc3986(k), encodeRfc3986(v)]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map(([k, v]) => k + '=' + v).join('&');
}

/** Format a Date as the AWS basic ISO8601 stamp, e.g. 20260822T101530Z. */
export function amzDate(date = new Date()) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}


/**
 * Sign a request and return the headers to send.
 *
 * @param {object} opts
 * @param {string} opts.method
 * @param {string} opts.url
 * @param {string} opts.body     Raw request body (may be empty)
 * @param {string} opts.service  e.g. 'kms', 'ses'
 * @param {string} opts.region
 * @param {object} opts.credentials {accessKeyId, secretAccessKey, sessionToken?}
 * @param {object} [opts.headers] Extra headers to include in the signature
 * @param {Date}   [opts.date]
 * @param {boolean} [opts.includeContentSha256] Send x-amz-content-sha256 (default true)
 */
export async function signRequest(opts) {
  const { method, url, body = '', service, region, credentials, date = new Date() } = opts;
  if (!credentials?.accessKeyId || !credentials?.secretAccessKey) {
    throw new Error('AWS credentials are required to sign a ' + service + ' request');
  }
  const u = new URL(url);
  const stamp = amzDate(date);
  const dateStamp = stamp.slice(0, 8);

  const headers = new Map();
  headers.set('host', u.host);
  headers.set('x-amz-date', stamp);
  const payloadHash = await sha256hex(body);
  if (opts.includeContentSha256 !== false) headers.set('x-amz-content-sha256', payloadHash);
  if (credentials.sessionToken) headers.set('x-amz-security-token', credentials.sessionToken);
  for (const [k, v] of Object.entries(opts.headers || {})) headers.set(k.toLowerCase(), String(v).trim());

  const signedNames = [...headers.keys()].sort();
  const canonicalHeaders = signedNames.map((n) => n + ':' + headers.get(n) + '\n').join('');
  const signedHeaders = signedNames.join(';');

  const canonicalRequest = [
    method.toUpperCase(),
    u.pathname || '/',
    canonicalQuery(u.searchParams),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const scope = [dateStamp, region, service, 'aws4_request'].join('/');
  const stringToSign = ['AWS4-HMAC-SHA256', stamp, scope, await sha256hex(canonicalRequest)].join('\n');

  let k = await hmac(utf8('AWS4' + credentials.secretAccessKey), dateStamp);
  k = await hmac(k, region);
  k = await hmac(k, service);
  k = await hmac(k, 'aws4_request');
  const signature = toHex(await hmac(k, stringToSign));

  const out = Object.fromEntries(headers);
  out.authorization =
    'AWS4-HMAC-SHA256 Credential=' +
    credentials.accessKeyId +
    '/' +
    scope +
    ', SignedHeaders=' +
    signedHeaders +
    ', Signature=' +
    signature;
  return out;
}

/** Read AWS credentials from the ambient environment (Lambda sets these). */
export function credentialsFromEnv(env) {
  const accessKeyId = env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) return undefined;
  return { accessKeyId, secretAccessKey, sessionToken: env.AWS_SESSION_TOKEN || undefined };
}
