// GET/POST /userinfo
//
// The access token SAG issues is only ever meant for this endpoint, so this is
// the one place it is opened. A relying party that already trusts the
// id_token has no reason to call here; it exists because OpenID Connect
// libraries expect it, and because the id_token is short lived while an
// access token can be used to re-read claims within its own window.

import { json, readForm, single } from '../util/http.js';
import { readAccessToken } from '../oauth/tokens.js';
import { outboundClaims } from '../profile.js';

/**
 * RFC 6750 challenge, so a client library knows how to authenticate.
 *
 * `resource_metadata` is RFC 9728: a client that arrives here with the wrong
 * token, or none, is told where to read what this resource wants rather than
 * being left to guess which authorization server to go to.
 */
function unauthorised(ctx, error, description) {
  const params = ['Bearer realm="userinfo"'];
  if (error) params.push('error="' + error + '"');
  if (description) params.push('error_description="' + description.replaceAll('"', '') + '"');
  params.push('resource_metadata="' + ctx.absolute('/.well-known/oauth-protected-resource') + '"');
  return json(
    { error: error || 'invalid_token', error_description: description },
    error === 'invalid_request' ? 400 : 401,
    { 'www-authenticate': params.join(', ') },
  );
}

async function presentedToken(ctx) {
  const header = ctx.request.headers.get('authorization');
  if (header && /^bearer /i.test(header)) return header.slice(7).trim();
  // RFC 6750 also allows a form-encoded body parameter, which some libraries
  // still use. The query string form is deliberately not accepted: it would
  // put a credential in logs and Referer headers.
  if (ctx.request.method === 'POST') {
    const ct = (ctx.request.headers.get('content-type') || '').toLowerCase();
    if (ct.includes('application/x-www-form-urlencoded')) {
      return single(await readForm(ctx.request), 'access_token');
    }
  }
  return undefined;
}

export async function handleUserinfo(ctx) {
  const token = await presentedToken(ctx);
  if (!token) return unauthorised(ctx, undefined, 'Present an access token in the Authorization header.');

  const grant = await readAccessToken(ctx.config, token);
  if (!grant) return unauthorised(ctx, 'invalid_token', 'The access token is invalid or has expired.');

  const claims = { sub: grant.sub };
  const scope = grant.scope || [];
  if (scope.includes('email')) {
    claims.email = grant.email;
    claims.email_verified = true;
  }
  if (scope.includes('profile') && grant.claims) {
    Object.assign(claims, outboundClaims(ctx.config, grant.claims));
  }
  // Not standard userinfo claims, but a relying party doing step-up needs to
  // be able to see what the current authentication actually was.
  claims.acr = grant.acr;
  claims.amr = grant.amr;
  claims.auth_time = grant.auth_time;

  return json(claims);
}
