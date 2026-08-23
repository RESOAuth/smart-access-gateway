// Turning a decision into an HTTP response.

import { html, redirect, escapeHtml } from '../util/http.js';
import { OAuthError } from '../util/errors.js';
import { errorPage } from '../ui/pages.js';
import { formPostPolicy } from '../ui/csp.js';
import { successRedirect, errorRedirect } from '../oauth/request.js';

/**
 * The form_post response mode.
 *
 * Keeping the code out of the URL keeps it out of the browser history, the
 * Referer header and any proxy log, which is why a relying party handling
 * anything sensitive should prefer it. The form submits itself with script when
 * script is available and offers a button when it is not, so the flow still
 * completes with JavaScript disabled.
 */
export function formPostResponse(ctx, redirectUri, fields) {
  const e = escapeHtml;
  const inputs = Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => '<input type="hidden" name="' + e(k) + '" value="' + e(v) + '">')
    .join('\n        ');
  const body = `<!DOCTYPE html>
<html lang="${e(ctx.ui.locale || 'en-GB')}">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>Completing sign-in</title>
    <script src="${e(ctx.assets.js)}"></script>
  </head>
  <body>
    <noscript><p>Select continue to finish signing in.</p></noscript>
    <form method="post" action="${e(redirectUri)}" data-autosubmit>
        ${inputs}
      <noscript><button type="submit">Continue</button></noscript>
    </form>
  </body>
</html>
`;
  // This is the one page whose form does not post to our own origin, so it
  // carries its own policy naming the relying party it is allowed to post to.
  return html(body, 200, { 'content-security-policy': formPostPolicy(redirectUri) });
}

/** Send a successful authorisation back to the relying party. */
export function authorizationResponse(ctx, tx, code) {
  if (tx.response_mode === 'form_post') {
    return formPostResponse(ctx, tx.redirect_uri, {
      code,
      state: tx.state,
      iss: ctx.issuer,
    });
  }
  return redirect(successRedirect(tx.redirect_uri, { code, state: tx.state, issuer: ctx.issuer }));
}

/**
 * Report a failure.
 *
 * An error only goes to the relying party when its redirect URI has already
 * been validated *and* the error is one the specification says may be relayed.
 * Everything else is rendered here, because sending an unvalidated redirect
 * would make the authorisation endpoint an open redirector.
 */
export function failureResponse(ctx, error, { redirectUri, state, responseMode } = {}) {
  if (redirectUri && error instanceof OAuthError && error.redirectable) {
    const payload = { code: error.code, description: error.description, uri: error.uri };
    if (responseMode === 'form_post') {
      return formPostResponse(ctx, redirectUri, {
        error: payload.code,
        error_description: payload.description,
        state,
        iss: ctx.issuer,
      });
    }
    return redirect(errorRedirect(redirectUri, payload, state, ctx.issuer));
  }

  const title = titleFor(error);
  const { html: page, status } = errorPage(ctx, {
    title,
    detail: error instanceof OAuthError ? error.description : 'Something went wrong while signing you in.',
    status: error?.status ?? 400,
  });
  return html(page, status);
}

function titleFor(error) {
  const code = error instanceof OAuthError ? error.code : undefined;
  switch (code) {
    case 'invalid_client':
      return 'This application is not recognised';
    case 'invalid_request':
      return 'That sign-in request is not valid';
    case 'access_denied':
      return 'Sign-in was not completed';
    case 'login_required':
    case 'interaction_required':
      return 'Sign-in is needed';
    case 'unmet_authentication_requirements':
      return 'A stronger sign-in is required';
    case 'server_error':
      return 'Something went wrong';
    default:
      return 'Sign-in could not continue';
  }
}

/** The page shown when a transaction is gone and there is nowhere to go back to. */
export function startAgainResponse(ctx, detail) {
  const { html: page, status } = errorPage(ctx, {
    title: 'Start signing in again',
    detail:
      detail ||
      'This sign-in attempt has expired or was already finished. Nothing is wrong with your account.',
    status: 400,
  });
  return html(page, status);
}
