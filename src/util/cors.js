// Cross-Origin Resource Sharing for /token and /userinfo.
//
// Both authenticate the caller by something other than the session cookie - a
// PKCE-bound authorization code, a bearer access token - so unlike the hosted
// sign-in pages there is nothing here for a third-party origin to ride on.
// The only question CORS answers is whether JavaScript on a given origin may
// read the response, which is what CORS_ALLOWED_ORIGINS decides.

const ALLOWED_METHODS = 'GET, POST, OPTIONS';
const ALLOWED_HEADERS = 'authorization, content-type';
// So a client library can see why a call failed without a same-origin proxy.
const EXPOSED_HEADERS = 'www-authenticate';

function allowedOrigin(config, origin) {
  if (!origin) return undefined;
  const allowed = config.cors.allowedOrigins;
  if (allowed.includes('*')) return '*';
  return allowed.includes(origin) ? origin : undefined;
}

/** Reply to a preflight OPTIONS request for a CORS-enabled route. */
export function corsPreflight(ctx) {
  const origin = ctx.request.headers.get('origin');
  const allow = allowedOrigin(ctx.config, origin);
  const headers = {
    'access-control-allow-methods': ALLOWED_METHODS,
    'access-control-allow-headers': ALLOWED_HEADERS,
    // Long-lived: a preflight repeated on every call would defeat the point
    // of a cache-friendly token endpoint.
    'access-control-max-age': '600',
  };
  if (allow) {
    headers['access-control-allow-origin'] = allow;
    if (allow !== '*') headers.vary = 'origin';
  }
  return new Response(null, { status: 204, headers });
}

/** Attach CORS headers to a CORS-enabled route's response, success or error. */
export function withCors(ctx, response) {
  const origin = ctx.request.headers.get('origin');
  const allow = allowedOrigin(ctx.config, origin);
  if (!allow) return response;
  const headers = new Headers(response.headers);
  headers.set('access-control-allow-origin', allow);
  headers.set('access-control-expose-headers', EXPOSED_HEADERS);
  if (allow !== '*') headers.append('vary', 'origin');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
