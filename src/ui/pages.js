// Every screen SAG shows a person. There are only six, deliberately.

import { escapeHtml, safeHttpUrl } from '../util/http.js';
import { layout, errorBlock, noticeBlock, hiddenFields, identityBlock } from './layout.js';

const e = escapeHtml;

/**
 * Screen 1: which email address.
 *
 * autocomplete and the email input type do the heavy lifting for usability;
 * `autofocus` is left off deliberately, because moving focus on load is
 * disorienting for screen reader and switch-access users and the field is the
 * first thing in the document anyway.
 */
export function emailPage(ctx, { tx, email, error, clientName, clientLogoUri, action, legal }) {
  const forWhom = clientName
    ? 'Continue to <strong>' + e(clientName) + '</strong> by confirming your email address.'
    : 'Enter your email address to continue.';
  const body = `
      <h1>Sign in</h1>
      <p class="lede">${forWhom}</p>
      ${errorBlock(error?.title, error?.detail)}
      <form method="post" action="${e(action)}">
        ${hiddenFields({ tx })}
        <div class="field">
          <label for="email">Email address</label>
          <input id="email" name="email" type="email" inputmode="email"
                 autocomplete="username email" spellcheck="false"
                 required value="${e(email || '')}"
                 ${error ? 'aria-invalid="true"' : ''}>
        </div>
        <button type="submit" data-busy-label="Continuing...">Continue</button>
      </form>`;
  return layout(ctx, { title: 'Sign in', body, legal, clientLogoUri, clientLogoAlt: clientName });
}

/**
 * Screen 2: the one-time code.
 *
 * `autocomplete="one-time-code"` lets iOS and Android offer the code from the
 * message itself. The address is repeated so a typo is obvious, with a way
 * back that does not rely on browser history.
 *
 * The `data-length` and `data-alphabet` attributes are for sag.js, which tidies
 * a pasted code and submits it once it is complete. Nothing here needs them:
 * the field and its button work on their own.
 */
export function otpPage(ctx, { tx, email, error, devCode, resent, action, changeAction, resendAction, codeLength, alphanumeric, clientLogoUri, clientLogoAlt, legal }) {
  const notice = devCode
    ? noticeBlock(
        'Development mode: your sign-in code is <code>' +
          e(devCode) +
          '</code> It is printed to the server console too, and no email was sent.',
      )
    : resent
      ? noticeBlock('A new code is on its way. The previous one no longer works.')
      : '';
  // Letters as well as digits, unless the deployment asked for a numeric code,
  // so the on-screen keyboard and the browser's own validation both match what
  // was actually sent.
  const describe = alphanumeric ? codeLength + '-character' : codeLength + '-digit';
  const hint = alphanumeric
    ? codeLength + ' letters and numbers, from the email we just sent. Capitals do not matter.'
    : codeLength + ' digits, from the email we just sent.';
  const body = `
      <h1>Check your email</h1>
      <p class="lede">We have sent a ${describe} code to <strong>${e(email)}</strong>.</p>
      ${errorBlock(error?.title, error?.detail)}
      ${notice}
      <form method="post" action="${e(action)}">
        ${hiddenFields({ tx })}
        <div class="field">
          <label for="code">Sign-in code</label>
          <span class="hint" id="code-hint">${hint}</span>
          <input id="code" name="code" type="text" class="code"
                 inputmode="${alphanumeric ? 'text' : 'numeric'}" autocomplete="one-time-code"
                 autocapitalize="characters" autocorrect="off" spellcheck="false"
                 pattern="${alphanumeric ? '[0-9A-Za-z \\-]*' : '[0-9 \\-]*'}" maxlength="${codeLength + 4}"
                 data-length="${codeLength}" data-alphabet="${alphanumeric ? 'alphanumeric' : 'numeric'}"
                 aria-describedby="code-hint" required
                 ${error ? 'aria-invalid="true"' : ''}>
        </div>
        <button type="submit" data-busy-label="Signing in...">Sign in</button>
      </form>
      <div class="also">
        <form method="post" action="${e(resendAction)}">
          ${hiddenFields({ tx })}
          <button type="submit" class="secondary">Send another code</button>
        </form>
        <form method="post" action="${e(changeAction)}">
          ${hiddenFields({ tx })}
          <button type="submit" class="secondary">Use a different email address</button>
        </form>
      </div>`;
  return layout(ctx, { title: 'Check your email', body, legal, clientLogoUri, clientLogoAlt });
}

/**
 * Screen 3: continue as, or sign in as somebody else.
 *
 * Shown when a session already exists and the relying party asked to confirm
 * (`prompt=consent`) or when the session cannot be used silently. The name and
 * picture, when the deployment carries them, are what make this recognisable
 * at a glance rather than an address to read character by character.
 */
export function continuePage(ctx, { tx, session, identity, clientName, clientLogoUri, action, switchAction, error, legal }) {
  const who = identity || { email: session.email };
  const body = `
      <h1>Continue signing in</h1>
      <p class="lede">${clientName ? e(clientName) + ' is asking you to sign in.' : 'Confirm the account to use.'}</p>
      ${errorBlock(error?.title, error?.detail)}
      ${identityBlock({ ...who, method: describeMethod(session) })}
      <form method="post" action="${e(action)}">
        ${hiddenFields({ tx })}
        <button type="submit" data-busy-label="Continuing...">Continue as ${e(who.name || who.email)}</button>
      </form>
      <div class="also">
        <form method="post" action="${e(switchAction)}">
          ${hiddenFields({ tx })}
          <button type="submit" class="secondary">Use a different account</button>
        </form>
      </div>`;
  return layout(ctx, { title: 'Continue', body, legal, clientLogoUri, clientLogoAlt: clientName });
}

/** Screen 4: signed out, or confirm signing out. */
export function signedOutPage(ctx, { returnTo, returnLabel, legal }) {
  const body = `
      <h1>You are signed out</h1>
      <p class="lede">Your sign-in session on this device has ended.</p>
      ${
        returnTo
          ? '<a class="button" href="' + e(returnTo) + '">Return to ' + e(returnLabel || 'the application') + '</a>'
          : ''
      }`;
  return layout(ctx, { title: 'Signed out', body, legal });
}

export function confirmLogoutPage(ctx, { token, email, identity, clientName, action, cancelUrl, shared, legal }) {
  const who = identity?.email ? identity : email ? { email } : undefined;
  const body = `
      <h1>Sign out?</h1>
      <p class="lede">${
        shared
          ? 'Signing out ends your session for every application that uses this sign-in service, not just ' +
            e(clientName || 'this one') +
            '.'
          : 'This will end your session for ' + e(clientName || 'this application') + '.'
      }</p>
      ${who ? identityBlock(who) : ''}
      <form method="post" action="${e(action)}">
        ${hiddenFields({ lt: token })}
        <button type="submit" data-busy-label="Signing out...">Sign out</button>
      </form>
      ${cancelUrl ? '<div class="also"><a class="button secondary" href="' + e(cancelUrl) + '">Stay signed in</a></div>' : ''}`;
  return layout(ctx, { title: 'Sign out', body, legal });
}

/**
 * Screen 5: something went wrong and we cannot safely return to the relying
 * party. Shown when there is no validated redirect_uri to send the error to.
 */
export function errorPage(ctx, { title, detail, status = 400, reference }) {
  const body = `
      <h1>${e(title)}</h1>
      <p class="lede">${e(detail)}</p>
      ${reference ? '<p class="notice">Reference: <code>' + e(reference) + '</code></p>' : ''}
      <p class="lede">If you were part-way through signing in, start again from the application you came from. Opening this page directly will not work.</p>`;
  return { html: layout(ctx, { title, body }), status };
}

/**
 * Screen 6: choose how to sign in, when more than one route is open.
 *
 * When the mail records for the domain point at one of the options, that option
 * comes first and is the only one styled as the primary action. It is presented
 * as a suggestion rather than a fact, because it is one: the guess comes from
 * DNS, and the provider itself is what decides.
 */
export function chooserPage(ctx, { tx, email, options, hinted, error, otpAction, clientLogoUri, clientLogoAlt, legal }) {
  // With a suggestion, one option is the primary action and the rest step back.
  // With none, they are all equal - which is the honest presentation, and also
  // leaves the screen with a primary action on it rather than a row of
  // outlines and nothing to press.
  const secondary = (id) => Boolean(hinted) && id !== hinted;
  const items = options
    .map(
      (o) =>
        '<li><form method="post" action="' +
        e(o.action) +
        '">' +
        hiddenFields({ tx, upstream: o.id }) +
        '<button type="submit"' +
        (secondary(o.id) ? ' class="secondary"' : '') +
        ' data-busy-label="Redirecting...">' +
        e(o.label) +
        '</button></form></li>',
    )
    .join('\n        ');
  const lede = hinted
    ? 'The mail records for <strong>' +
      e(email.split('@')[1]) +
      '</strong> suggest the first option. Choose another if that is not where your account is.'
    : 'More than one option is available for <strong>' + e(email) + '</strong>.';
  const body = `
      <h1>Choose how to sign in</h1>
      <p class="lede">${lede}</p>
      ${errorBlock(error?.title, error?.detail)}
      <ul class="choices">
        ${items}
      </ul>
      ${
        otpAction
          ? '<div class="also"><form method="post" action="' +
            e(otpAction) +
            '">' +
            hiddenFields({ tx }) +
            '<button type="submit" class="secondary">Email me a code instead</button></form></div>'
          : ''
      }`;
  return layout(ctx, { title: 'Choose how to sign in', body, legal, clientLogoUri, clientLogoAlt });
}

/**
 * Which terms and privacy links to show.
 *
 * A relying party's own links win when it has them, because the person is
 * signing in to that application rather than to SAG; the instance-wide links
 * are the fallback and cover the sign-in service itself.
 */
export function legalFor(config, source = {}) {
  // A relying party can describe itself - a CIMD client registers with nobody
  // at all - so these are untrusted input, and a scheme check is the control.
  const safe = (value) => safeHttpUrl(value, { allowHttp: config.devMode });
  return {
    terms: safe(source.tosUri || source.tos_uri) || safe(config.ui.termsUrl),
    privacy: safe(source.policyUri || source.policy_uri) || safe(config.ui.privacyUrl),
  };
}

function describeMethod(session) {
  if (session.upstreamLabel) return 'Signed in with ' + session.upstreamLabel;
  if (session.acr && session.acr.endsWith('email-otp')) return 'Verified by email code';
  return 'Already signed in';
}
