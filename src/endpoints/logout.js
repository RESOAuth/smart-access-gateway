// GET/POST /logout - RP-initiated logout.
//
// The awkward part of a shared session is that one relying party asking to
// sign out is asking on everybody's behalf. SAG therefore confirms first when
// the session is shared and the request would end more than the caller's own
// sign-in, and does it silently when the session is per relying party and only
// that one is affected.

import { html, readForm, single, withCookies, redirect, escapeHtml } from '../util/http.js';
import { decodeJwt } from '../crypto/jose.js';
import { seal, unseal } from '../crypto/secrets.js';
import { nowSeconds } from '../util/bytes.js';
import {
  readSession,
  clearSessionCookie,
  allSessionCookieNames,
  clearCookieByName,
  sessionClientFor,
  cookieNameFor,
  readSessionByName,
  revokeSession,
} from '../session.js';
import { postLogoutRedirectAllowed } from '../clients/index.js';
import { signedOutPage, confirmLogoutPage, legalFor } from '../ui/pages.js';
import { displayIdentity } from '../profile.js';

const PURPOSE = 'logout';

export async function handleLogout(ctx) {
  const params = ctx.request.method === 'POST' ? await readForm(ctx.request) : ctx.url.searchParams;

  // A confirmed logout comes back with its own sealed token, so the validated
  // redirect target does not have to be re-derived from untrusted input.
  const confirmToken = single(params, 'lt');
  if (confirmToken) return performLogout(ctx, confirmToken);

  const hint = single(params, 'id_token_hint');
  const requestedClientId = single(params, 'client_id') ?? clientFromHint(hint);
  const client = requestedClientId ? await ctx.resolveClient(requestedClientId) : undefined;

  const requested = single(params, 'post_logout_redirect_uri');
  let returnTo;
  if (requested) {
    // Only a registered post-logout URI, and only when we know which client is
    // asking. Otherwise this endpoint becomes an open redirector.
    if (client && postLogoutRedirectAllowed(client, requested, ctx.config.clients.redirectUriSchemes)) returnTo = requested;
    else {
      ctx.log.warn('rejected post_logout_redirect_uri', { client_id: requestedClientId });
    }
  }
  const state = single(params, 'state');
  const scope = client?.sessionScope || ctx.config.session.scope;
  const scopedClientId = sessionClientFor(ctx.config, client);
  const session = await readSession(ctx.config, ctx.request, scopedClientId, ctx.stateStore);

  const affectsOthers = scope === 'shared' && Boolean(session);

  // Whether to show the interstitial at all. The instance sets the default and
  // a relying party can override it, because an application that owns its own
  // sign-out button has already asked the person, whereas one that links here
  // from a menu has not.
  const confirmMode = client?.logoutConfirm || ctx.config.session.logoutConfirm;
  const confirm = confirmMode === 'always' ? true : confirmMode === 'never' ? false : affectsOthers;

  const token = await seal(ctx.config.secrets[0], PURPOSE, {
    v: 1,
    client_id: requestedClientId,
    scoped: scopedClientId,
    returnTo,
    state,
    // A client-scoped request only clears the cookie that client uses. A
    // generic logout under a shared instance remains an explicit global one.
    global: requestedClientId === undefined && ctx.config.session.scope === 'shared',
    iat: nowSeconds(),
    exp: nowSeconds() + 600,
  });

  if (!session) {
    // Nothing to end. Still clear anything stale and answer as asked.
    return finish(ctx, {
      returnTo,
      state,
      clientName: client?.clientName,
      scopedClientId,
      clearAll: false,
      legal: legalFor(ctx.config, client || {}),
    });
  }

  if (confirm) {
    return html(
      confirmLogoutPage(ctx, {
        token,
        email: session.email,
        identity: session ? displayIdentity(ctx.config, session) : undefined,
        clientName: client?.clientName,
        action: ctx.route('/logout'),
        cancelUrl: returnTo,
        shared: affectsOthers,
        legal: legalFor(ctx.config, client || {}),
      }),
    );
  }
  return performLogoutWith(ctx, {
    returnTo,
    state,
    clientName: client?.clientName,
    scopedClientId,
    clearAll: false,
    legal: legalFor(ctx.config, client || {}),
  });
}

async function performLogout(ctx, token) {
  let payload;
  try {
    payload = await unseal(ctx.config.secrets, PURPOSE, token);
  } catch {
    // An invented or expired confirmation token must not become a logout
    // primitive. Render the neutral result without changing any cookie.
    return html(signedOutPage(ctx, {}));
  }
  const client = payload.client_id ? await ctx.resolveClient(payload.client_id) : undefined;
  return performLogoutWith(ctx, {
    returnTo: payload.returnTo,
    state: payload.state,
    clientName: client?.clientName,
    scopedClientId: payload.scoped,
    clearAll: Boolean(payload.global),
    legal: legalFor(ctx.config, client || {}),
  });
}

async function performLogoutWith(ctx, opts) {
  ctx.log.info('session ended', { client_id: opts.clientName, global: opts.clearAll });
  return finish(ctx, opts);
}

/**
 * Clear the cookies and answer.
 *
 * Under a shared session every cookie this instance set is cleared, found by
 * name prefix rather than recomputed, because per-RP cookie names are hashes
 * and cannot be reconstructed without knowing every client id.
 */
async function finish(ctx, { returnTo, state, clientName, scopedClientId, clearAll, legal }) {
  const cookies = [];
  const names = clearAll
    ? allSessionCookieNames(ctx.config, ctx.request)
    : [await cookieNameFor(ctx.config, scopedClientId)];

  // Claim every sid before telling the browser to discard its copy. When a
  // store is configured, a failed claim must leave logout visibly failed
  // rather than pretending copied cookies were revoked when they were not.
  for (const name of names) {
    const session = await readSessionByName(ctx.config, ctx.request, name, ctx.stateStore);
    await revokeSession(ctx.stateStore, session);
    cookies.push(clearCookieByName(ctx.config, name));
  }
  if (cookies.length === 0) cookies.push(await clearSessionCookie(ctx.config, scopedClientId));

  let response;
  if (returnTo) {
    const url = new URL(returnTo);
    if (state !== undefined) url.searchParams.set('state', state);
    response = redirect(url.toString());
  } else {
    response = html(signedOutPage(ctx, { returnTo: undefined, returnLabel: clientName, legal }));
  }
  return withCookies(response, cookies);
}

/**
 * Read the audience out of an id_token_hint without verifying it.
 *
 * A hint is only ever used to work out which relying party is asking, and the
 * answer is then checked against that client's registered post-logout URIs, so
 * a forged hint gains nothing: it can only name a client that would have to
 * have registered the redirect target anyway.
 */
function clientFromHint(hint) {
  if (!hint) return undefined;
  try {
    const { payload } = decodeJwt(hint);
    const aud = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
    return typeof aud === 'string' ? aud : undefined;
  } catch {
    return undefined;
  }
}

export { escapeHtml };
