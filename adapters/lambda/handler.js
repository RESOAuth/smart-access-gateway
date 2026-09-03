// AWS Lambda entry point.
//
// Handles both the API Gateway HTTP API v2 payload and a Lambda function URL,
// which share the same event shape. The v1 REST API shape is also accepted,
// because plenty of existing estates still front Lambda with it.
//
// The only real work is translating an event into a Request and a Response
// back into a result object, plus getting the source URL right: Lambda tells
// us the stage-prefixed path, which is not what the issuer should look like.

import { handleRequest } from '../../src/index.js';

/**
 * Reconstruct the URL the browser actually asked for.
 *
 * The Host header is what the person typed, so it is used in preference to the
 * API Gateway domain, and a stage prefix is stripped when the deployment is
 * behind a custom domain that does not include it.
 */
function urlFor(event, headers) {
  const isV2 = Boolean(event.requestContext?.http);
  const rawPath = isV2 ? event.rawPath || '/' : event.path || '/';
  const stage = event.requestContext?.stage;

  const host = headers.get('x-forwarded-host') || headers.get('host') || event.requestContext?.domainName || 'localhost';
  const proto = headers.get('x-forwarded-proto') || 'https';

  let path = rawPath;
  // A default stage on a custom domain is not part of the public path.
  if (stage && stage !== '$default' && path.startsWith('/' + stage + '/')) {
    path = path.slice(stage.length + 1);
  }

  const query = isV2
    ? event.rawQueryString
    : new URLSearchParams(flatten(event.multiValueQueryStringParameters, event.queryStringParameters)).toString();

  return proto + '://' + host + (path || '/') + (query ? '?' + query : '');
}

function flatten(multi, single) {
  const params = [];
  if (multi) {
    for (const [key, values] of Object.entries(multi)) for (const v of values) params.push([key, v]);
  } else if (single) {
    for (const [key, v] of Object.entries(single)) params.push([key, v]);
  }
  return params;
}

function headersFrom(event) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(event.headers || {})) {
    if (value === undefined || value === null) continue;
    // API Gateway v2 joins repeated headers with a comma, except cookies.
    headers.set(key, String(value));
  }
  // Cookies arrive separately on v2 and must be recombined.
  if (Array.isArray(event.cookies) && event.cookies.length) {
    headers.set('cookie', event.cookies.join('; '));
  }
  return headers;
}

function bodyFrom(event) {
  if (event.body === undefined || event.body === null || event.body === '') return undefined;
  if (event.isBase64Encoded) return Buffer.from(event.body, 'base64');
  return event.body;
}

/**
 * The Lambda handler.
 *
 * `process.env` is the environment bag, so a Lambda is configured with exactly
 * the same variables as a Worker or a container.
 */
export async function handler(event) {
  const headers = headersFrom(event);
  const method = event.requestContext?.http?.method || event.httpMethod || 'GET';
  const url = urlFor(event, headers);

  let response;
  try {
    const request = new Request(url, {
      method,
      headers,
      body: method === 'GET' || method === 'HEAD' ? undefined : bodyFrom(event),
    });
    response = await handleRequest(request, process.env, { requestUrl: url });
  } catch (err) {
    console.error('[sag] unhandled: ' + (err?.stack || err));
    return {
      statusCode: 500,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
      body: 'Internal error',
    };
  }

  return toLambdaResult(response);
}

/**
 * Turn a Response into a Lambda result.
 *
 * Set-Cookie has to go in `cookies` rather than `headers`: putting several in
 * the headers object would collapse them into one comma-joined value, and a
 * cookie value may legitimately contain a comma.
 */
export async function toLambdaResult(response) {
  const headers = {};
  response.headers.forEach((value, key) => {
    // eslint-disable-next-line security/detect-object-injection -- copying standard HTTP response header keys
    if (key.toLowerCase() !== 'set-cookie') headers[key] = value;
  });
  const cookies = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];

  const contentType = response.headers.get('content-type') || '';
  const isText = /^(text\/|application\/(json|javascript|x-www-form-urlencoded)|.*\+json)/.test(contentType);

  const buffer = Buffer.from(await response.arrayBuffer());
  return {
    statusCode: response.status,
    headers,
    ...(cookies.length ? { cookies } : {}),
    body: isText ? buffer.toString('utf8') : buffer.toString('base64'),
    isBase64Encoded: !isText,
  };
}

export default handler;
