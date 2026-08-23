// Routing.
//
// A flat table rather than a framework: every platform adapter hands a
// standard Request in and gets a standard Response out, so there is nothing to
// abstract over.

import { json, text, methodNotAllowed, SECURITY_HEADERS } from './util/http.js';
import { OAuthError, UserFacingError } from './util/errors.js';
import { ConfigError } from './config.js';
import { createContext } from './context.js';
import { DEFAULT_CSS, CSS_VERSION, assetVersion } from './ui/css.js';
import { DEFAULT_JS, JS_VERSION } from './ui/js.js';
import {
  handleDiscovery,
  handleAuthorizationServerMetadata,
  handleProtectedResourceMetadata,
  handleJwks,
} from './endpoints/discovery.js';
import {
  handleAuthorize,
  handleEmailSubmit,
  handleOtpSubmit,
  handleOtpRequest,
  handleResend,
  handleRestart,
  handleContinue,
  handleChooseUpstream,
  handleCallback,
} from './endpoints/authorize.js';
import { handleToken } from './endpoints/token.js';
import { handleUserinfo } from './endpoints/userinfo.js';
import { handleLogout } from './endpoints/logout.js';
import { handleHealth } from './endpoints/health.js';
import { failureResponse } from './endpoints/respond.js';

const ROUTES = [
  { path: '/.well-known/openid-configuration', methods: ['GET'], handler: handleDiscovery },
  { path: '/.well-known/oauth-authorization-server', methods: ['GET'], handler: handleAuthorizationServerMetadata },
  { path: '/.well-known/oauth-protected-resource', methods: ['GET'], handler: handleProtectedResourceMetadata },
  { path: '/.well-known/jwks.json', methods: ['GET'], handler: handleJwks },
  // The pre-RFC 8414 location, kept because relying parties are configured
  // against it and a discovery document is not the only way people find a JWKS.
  { path: '/jwks.json', methods: ['GET'], handler: handleJwks },

  { path: '/authorize', methods: ['GET', 'POST'], handler: handleAuthorize },
  { path: '/authorize/email', methods: ['POST'], handler: handleEmailSubmit },
  { path: '/authorize/otp', methods: ['POST'], handler: handleOtpSubmit },
  { path: '/authorize/otp-request', methods: ['POST'], handler: handleOtpRequest },
  { path: '/authorize/resend', methods: ['POST'], handler: handleResend },
  { path: '/authorize/restart', methods: ['POST'], handler: handleRestart },
  { path: '/authorize/continue', methods: ['POST'], handler: handleContinue },
  { path: '/authorize/upstream', methods: ['POST'], handler: handleChooseUpstream },
  { path: '/callback', methods: ['GET'], handler: handleCallback },

  { path: '/token', methods: ['POST'], handler: handleToken },
  { path: '/userinfo', methods: ['GET', 'POST'], handler: handleUserinfo },
  { path: '/logout', methods: ['GET', 'POST'], handler: handleLogout },
  { path: '/healthz', methods: ['GET'], handler: handleHealth },
  { path: '/static/sag.css', methods: ['GET'], handler: handleStylesheet },
  { path: '/static/custom.css', methods: ['GET'], handler: handleCustomStylesheet },
  { path: '/static/sag.js', methods: ['GET'], handler: handleScript },
];

/**
 * A static asset.
 *
 * The pages ask for these with the current fingerprint in the query, so a
 * request that carries the right one can be cached for as long as a browser
 * will hold it: the URL changes when the file does. Anything else - somebody's
 * bookmark, an old page still in a tab - gets a short cache instead.
 */
function staticAsset(ctx, body, contentType, version) {
  const asked = ctx.url.searchParams.get('v');
  return new Response(body, {
    headers: {
      'content-type': contentType,
      'cache-control': asked === version ? 'public, max-age=31536000, immutable' : 'public, max-age=300',
      ...SECURITY_HEADERS,
    },
  });
}

const CSS_TYPE = 'text/css; charset=utf-8';

function handleStylesheet(ctx) {
  return staticAsset(ctx, DEFAULT_CSS, CSS_TYPE, CSS_VERSION);
}

/**
 * The operator's CUSTOM_CSS_SNIPPET, served as a stylesheet.
 *
 * It could be inlined in a <style> element, and used to be. Serving it means
 * the Content-Security-Policy can refuse inline styles outright rather than
 * carrying a nonce or a hash on every page, and it means a snippet cannot
 * interact with the surrounding HTML at all - there is no element to close.
 */
function handleCustomStylesheet(ctx) {
  const snippet = ctx.config.ui.customCssSnippet;
  if (!snippet) return text('Not found', 404);
  return staticAsset(ctx, snippet, CSS_TYPE, assetVersion(snippet));
}

function handleScript(ctx) {
  return staticAsset(ctx, DEFAULT_JS, 'text/javascript; charset=utf-8', JS_VERSION);
}

/**
 * Where RFC 8414 says an authorization server's metadata lives.
 *
 * OpenID Connect appends its well-known path to the issuer, so an issuer of
 * https://host/prod publishes at https://host/prod/.well-known/openid-configuration
 * - which the base path handling in createContext already resolves. RFC 8414
 * inserts it instead: https://host/.well-known/oauth-authorization-server/prod.
 * That path does not start with the base path, so it arrives here whole and is
 * recognised here rather than in the route table.
 */
function wellKnownPath(ctx) {
  const path = ctx.path;
  if (!ctx.basePath || !path.startsWith('/.well-known/')) return path;
  for (const prefix of ['/.well-known/oauth-authorization-server', '/.well-known/oauth-protected-resource']) {
    if (path === prefix + ctx.basePath) return prefix;
  }
  return path;
}

/**
 * Handle one request.
 *
 * @param {Request} request
 * @param {object} env    Environment bag
 * @param {object} [opts]
 */
export async function handleRequest(request, env, opts = {}) {
  // Ahead of configuration, and at a fixed path rather than one this
  // instance's base path could move: a liveness probe - a load balancer or
  // container orchestrator deciding whether a process is there to route to
  // at all - has to answer even when this instance's configuration is
  // broken, because a broken configuration must not also take down the one
  // signal saying "restart me" or "there is nothing listening here". That is
  // a different question from whether this instance can actually sign
  // somebody in, which is what /healthz is for, and which a broken
  // configuration correctly fails.
  if (new URL(request.url).pathname === '/alive') {
    return request.method === 'GET' ? text('ok') : methodNotAllowed(['GET']);
  }

  let ctx;
  try {
    ctx = await createContext(env, request, opts);
  } catch (err) {
    // Configuration failures are the operator's problem, so they are stated
    // plainly in the log; the response stays generic.
    if (err instanceof ConfigError) {
      console.error('[sag] ' + err.message);
      return text('This service is not configured correctly. Check the server log.', 500);
    }
    throw err;
  }

  const route = ROUTES.find((r) => r.path === wellKnownPath(ctx));
  if (!route) {
    if (ctx.path === '/' || ctx.path === '') {
      // Not a landing page: an identity provider has nothing to say to
      // somebody who arrived here on their own.
      return text('This is a sign-in service. Start from the application you want to use.', 404);
    }
    return text('Not found', 404);
  }
  if (!route.methods.includes(request.method)) {
    return methodNotAllowed(route.methods);
  }

  try {
    return withPolicy(ctx, await route.handler(ctx));
  } catch (err) {
    return withPolicy(ctx, handleFailure(ctx, err));
  }
}

/**
 * Attach the Content-Security-Policy to any page that has not set its own.
 *
 * Done here rather than at each call site so that a screen added later cannot
 * be served without one. The form_post response is the single page that needs
 * a different policy, and it says so itself.
 */
function withPolicy(ctx, response) {
  if (!response || response.headers.has('content-security-policy')) return response;
  if (!(response.headers.get('content-type') || '').startsWith('text/html')) return response;
  const headers = new Headers(response.headers);
  headers.set('content-security-policy', ctx.csp);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function handleFailure(ctx, err) {
  if (err instanceof OAuthError) {
    ctx.log.info('request refused', { code: err.code, path: ctx.path });
    // A machine endpoint gets JSON; a browser endpoint gets a page.
    if (isApiPath(ctx.path)) {
      const headers = err.code === 'invalid_client' ? { 'www-authenticate': 'Basic realm="token"' } : {};
      return json(err.toJSON(), err.status, headers);
    }
    return failureResponse(ctx, err);
  }
  if (err instanceof UserFacingError) {
    return failureResponse(ctx, new OAuthError('invalid_request', err.detail, { status: err.status }));
  }

  // Anything else is a bug. Log it in full and tell the caller nothing.
  ctx.log.error('unhandled failure', { path: ctx.path, error: err.message, stack: err.stack });
  if (isApiPath(ctx.path)) {
    return json({ error: 'server_error', error_description: 'An unexpected error occurred.' }, 500);
  }
  return failureResponse(ctx, new OAuthError('server_error', 'Something went wrong while signing you in.', { status: 500 }));
}

const isApiPath = (path) => path === '/token' || path === '/userinfo' || path.startsWith('/.well-known');

export { ROUTES };
