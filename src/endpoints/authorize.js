// The interactive flow.
//
// One state machine, driven by the sealed transaction the browser carries
// between steps. The stages are: work out who is asking, decide whether the
// existing session is enough, otherwise ask for an email address, route that
// address to an upstream provider or to an email code, and finally mint an
// authorisation code.

import { html, readForm, single, withCookie, redirect } from '../util/http.js';
import { OAuthError, accessDenied, loginRequired, interactionRequired, unmetAcr, serverError } from '../util/errors.js';
import { SealError } from '../crypto/secrets.js';
import { parseAuthorizationRequest, UnredirectableError } from '../oauth/request.js';
import {
  newTransaction,
  sealTransaction,
  openTransaction,
  openUpstreamState,
  advance,
  withOtp,
  withOtpAttempt,
  withoutOtp,
  withoutAttempt,
  expired,
  STAGE,
} from '../oauth/transaction.js';
import { issueCode } from '../oauth/code.js';
import { readSession, newSession, reauthenticate, sessionCookie, sessionIsFresh, sessionClientFor } from '../session.js';
import { subjectFor, identityEmail, normaliseEmail, looksLikeEmail, emailTag } from '../identity.js';
import { satisfies, requiresFederation, acrFromUpstream, acrForOtp } from '../acr.js';
import { generateCode, digestCode, verifyCode, otpAllowed, alphabetFor } from '../otp.js';
import { otpMessage } from '../email/message.js';
import { upstreamsFor, beginUpstream, completeUpstream, labelFor } from '../upstream/index.js';
import { hintUpstreams } from '../upstream/dns.js';
import { relayedClaims, inferredClaims, displayIdentity } from '../profile.js';
import { emailPage, otpPage, continuePage, chooserPage, legalFor } from '../ui/pages.js';
import { checkOtpSendAllowed } from '../store/limits.js';
import { authorizationResponse, failureResponse, startAgainResponse } from './respond.js';
import { nowSeconds } from '../util/bytes.js';

// ---------------------------------------------------------------------------
// GET/POST /authorize
// ---------------------------------------------------------------------------

export async function handleAuthorize(ctx) {
  const { config, request } = ctx;
  const params =
    request.method === 'POST' ? await readForm(request) : ctx.url.searchParams;

  let client;
  let req;
  try {
    ({ client, request: req } = await parseAuthorizationRequest(params, config, ctx));
  } catch (err) {
    if (err instanceof UnredirectableError || !(err instanceof OAuthError)) {
      return failureResponse(ctx, err);
    }
    // Past the client and redirect URI checks, so it is safe to report back.
    return failureResponse(ctx, err, {
      redirectUri: single(params, 'redirect_uri'),
      state: single(params, 'state'),
      responseMode: single(params, 'response_mode'),
    });
  }

  const tx = advance(newTransaction(config, req), {
    client_name: client.clientName,
    // Carried on the transaction rather than re-resolved on every screen: the
    // client is already known here, and the transaction is sealed.
    logo_uri: client.logoUri,
    tos_uri: client.tosUri,
    policy_uri: client.policyUri,
  });
  const session = await readSession(config, request, sessionClientFor(config, client), ctx.stateStore);

  return decide(ctx, { tx, client, session });
}

/**
 * Can this request be answered from what we already know?
 *
 * The order matters: prompt=none has to be resolved before anything that would
 * put a page on screen, because the whole contract of prompt=none is that no
 * page ever appears.
 */
async function decide(ctx, { tx, client, session }) {
  const { config } = ctx;
  const prompt = tx.prompt || [];
  const wantsSilent = prompt.includes('none');
  const forcesLogin = prompt.includes('login') || prompt.includes('select_account');

  const usable =
    session &&
    !forcesLogin &&
    sessionIsFresh(session, { maxAge: tx.max_age, clockSkew: config.tokens.clockSkewSeconds }) &&
    satisfies(session.acr, tx.acr_values);

  if (wantsSilent) {
    if (!session) {
      return failureResponse(ctx, loginRequired('There is no active session to answer this request from.'), redirectTargets(tx));
    }
    if (!sessionIsFresh(session, { maxAge: tx.max_age, clockSkew: config.tokens.clockSkewSeconds })) {
      return failureResponse(ctx, loginRequired('The existing session is too old for this request.'), redirectTargets(tx));
    }
    if (!satisfies(session.acr, tx.acr_values)) {
      return failureResponse(
        ctx,
        unmetAcr('The existing session does not meet the requested authentication context.'),
        redirectTargets(tx),
      );
    }
    if (forcesLogin) {
      return failureResponse(ctx, interactionRequired('prompt=none cannot be combined with a demand to re-authenticate.'), redirectTargets(tx));
    }
    return complete(ctx, { tx, client, session, refreshCookie: true });
  }

  if (usable && prompt.includes('consent')) {
    // The relying party wants the person to see which account is being used.
    return renderContinue(ctx, { tx: advance(tx, { stage: STAGE.CONTINUE }), session });
  }
  if (usable) {
    return complete(ctx, { tx, client, session, refreshCookie: true });
  }

  // Interaction is needed. A login_hint, or the address from a session we
  // cannot reuse, saves the person retyping it.
  const prefill = tx.login_hint || (forcesLogin ? undefined : session?.email);
  return renderEmail(ctx, { tx, email: prefill });
}

const redirectTargets = (tx) => ({
  redirectUri: tx.redirect_uri,
  state: tx.state,
  responseMode: tx.response_mode,
});

// ---------------------------------------------------------------------------
// Rendering a stage
// ---------------------------------------------------------------------------

async function renderEmail(ctx, { tx, email, error }) {
  const sealed = await sealTransaction(ctx.config, advance(tx, { stage: STAGE.EMAIL }));
  return html(
    emailPage(ctx, {
      tx: sealed,
      email,
      error,
      clientName: tx.client_name,
      clientLogoUri: tx.logo_uri,
      action: ctx.route('/authorize/email'),
      legal: legalFor(ctx.config, tx),
    }),
    error ? 400 : 200,
  );
}

async function renderOtp(ctx, { tx, error, devCode, resent }) {
  const sealed = await sealTransaction(ctx.config, tx);
  return html(
    otpPage(ctx, {
      tx: sealed,
      email: tx.email,
      error,
      devCode,
      resent,
      codeLength: ctx.config.otp.codeLength,
      alphanumeric: ctx.config.otp.codeAlphabet === 'alphanumeric',
      clientLogoUri: tx.logo_uri,
      clientLogoAlt: tx.client_name,
      legal: legalFor(ctx.config, tx),
      action: ctx.route('/authorize/otp'),
      resendAction: ctx.route('/authorize/resend'),
      changeAction: ctx.route('/authorize/restart'),
    }),
    error ? 400 : 200,
  );
}

async function renderContinue(ctx, { tx, session, error }) {
  const sealed = await sealTransaction(ctx.config, advance(tx, { stage: STAGE.CONTINUE }));
  return html(
    continuePage(ctx, {
      tx: sealed,
      session,
      identity: displayIdentity(ctx.config, session),
      error,
      clientName: tx.client_name,
      clientLogoUri: tx.logo_uri,
      legal: legalFor(ctx.config, tx),
      action: ctx.route('/authorize/continue'),
      switchAction: ctx.route('/authorize/restart'),
    }),
    error ? 400 : 200,
  );
}

async function renderChooser(ctx, { tx, upstreams, hinted, error }) {
  const sealed = await sealTransaction(ctx.config, advance(tx, { stage: STAGE.CHOOSE }));
  const options = upstreams.map((u) => ({
    id: u.id,
    label: 'Continue with ' + labelFor(u),
    action: ctx.route('/authorize/upstream'),
  }));
  return html(
    chooserPage(ctx, {
      tx: sealed,
      email: tx.email,
      options,
      hinted,
      error,
      clientLogoUri: tx.logo_uri,
      clientLogoAlt: tx.client_name,
      legal: legalFor(ctx.config, tx),
      otpAction: otpAllowed(ctx.config, tx.email) ? ctx.route('/authorize/otp-request') : undefined,
    }),
    error ? 400 : 200,
  );
}

// ---------------------------------------------------------------------------
// Reading a transaction back
// ---------------------------------------------------------------------------

/**
 * Recover the transaction from a submitted form.
 *
 * A missing or unopenable transaction is not something the person can act on
 * and there is no validated redirect URI to report it to, so it always ends at
 * the "start again" page.
 */
async function loadTransaction(ctx) {
  const params = await readForm(ctx.request);
  const token = single(params, 'tx');
  if (!token) return { fail: startAgainResponse(ctx) };
  let tx;
  try {
    tx = await openTransaction(ctx.config, token);
  } catch (err) {
    if (err instanceof SealError) return { fail: startAgainResponse(ctx) };
    throw err;
  }
  if (expired(tx)) {
    return {
      fail: startAgainResponse(
        ctx,
        'This sign-in attempt took too long and has expired. Go back to the application and try again.',
      ),
    };
  }
  const client = await ctx.resolveClient(tx.client_id);
  if (!client) return { fail: startAgainResponse(ctx, 'The application that started this sign-in is no longer registered here.') };
  return { tx, client, params };
}

// ---------------------------------------------------------------------------
// POST /authorize/email - an address was given
// ---------------------------------------------------------------------------

export async function handleEmailSubmit(ctx) {
  const loaded = await loadTransaction(ctx);
  if (loaded.fail) return loaded.fail;
  const { tx, params } = loaded;

  const email = normaliseEmail(single(params, 'email'));
  if (!email || !looksLikeEmail(email)) {
    return renderEmail(ctx, {
      tx,
      email: single(params, 'email'),
      error: { title: 'Check your email address', detail: 'Enter an address in the form name@example.com.' },
    });
  }

  return route(ctx, { tx: advance(tx, { email }) });
}

/**
 * Decide how this address should be authenticated.
 *
 * Domain-specific upstream, then a common one, then email OTP. When a demand
 * for a stronger authentication context rules OTP out, and no upstream covers
 * the domain, the honest answer is that this address cannot satisfy the
 * request - so say so rather than starting a flow that must fail at the end.
 */
async function route(ctx, { tx }) {
  const { config } = ctx;
  const candidates = upstreamsFor(config, tx.email);
  const otpPossible = otpAllowed(config, tx.email) && !requiresFederation(tx.acr_values);

  if (candidates.length === 1) return startUpstream(ctx, { tx, upstream: candidates[0] });
  if (candidates.length > 1) {
    // More than one provider could hold this account. Rather than asking, look
    // at where the domain's mail goes: it is nearly always the same provider,
    // and a redirect is a better answer than a screen. See upstream/dns.js.
    const { list, hinted, source } = await hintUpstreams(ctx, candidates, tx.email.split('@')[1]);
    if (hinted) ctx.log.debug('mail records suggest an upstream', { upstream: hinted.id, source });
    if (hinted && config.dns.hint === 'select') return startUpstream(ctx, { tx, upstream: hinted, hinted: true });
    return renderChooser(ctx, { tx, upstreams: list, hinted: hinted?.id });
  }
  if (otpPossible) return sendOtp(ctx, { tx });

  if (otpAllowed(config, tx.email)) {
    return failureResponse(
      ctx,
      unmetAcr('No sign-in method available for this address can satisfy the requested authentication context.'),
      redirectTargets(tx),
    );
  }

  // Nothing covers this domain. Saying so is kinder, and it also turns the
  // sign-in page into a way of asking which organisations a deployment is
  // configured for, one domain at a time. Which of those matters more is the
  // operator's call, and the default is to give nothing away.
  //
  // With email codes switched off entirely there is nothing to be quiet
  // about: the deployment sends no mail to anybody, so a code screen would
  // conceal nothing and leave the person at a dead end.
  if (config.signin.unknownAddress === 'explain' || !config.otp.enabled) {
    return renderEmail(ctx, {
      tx,
      email: tx.email,
      error: {
        title: 'We cannot sign you in with that address',
        detail: 'This service does not accept ' + tx.email.split('@')[1] + ' addresses. Try the address you use at work.',
      },
    });
  }
  return sendOtp(ctx, { tx });
}

// ---------------------------------------------------------------------------
// Email OTP
// ---------------------------------------------------------------------------

async function sendOtp(ctx, { tx, resend = false }) {
  const { config } = ctx;
  // An address no route can serve gets the same screens as one that can: the
  // same counters, the same limits, the same wording, and a digest of a code
  // nobody holds. Anything that behaved differently here - a resend notice
  // that never appeared, a limit that never bit - would answer the question
  // this is meant not to answer.
  const decoy = !otpAllowed(config, tx.email);

  const resends = resend ? (tx.otp?.resends ?? 0) + 1 : 0;
  if (resends > config.otp.maxResends) {
    return renderOtp(ctx, {
      tx,
      error: {
        title: 'Too many codes requested',
        detail: 'Go back to the application and start signing in again.',
      },
    });
  }

  // The counters that matter cannot live in the transaction, because the
  // person holding it can present an older copy. This is the check that stops
  // somebody using the deployment as a way to send mail to other people.
  const limit = await checkOtpSendAllowed(ctx, tx.email);
  if (!limit.allowed) {
    // No hint reaches the person or the page: not a title, not a wait time,
    // not a difference in timing or markup from a real send. The rate limit
    // is exactly the kind of thing question 6's enumeration defence exists to
    // keep quiet, so it fails the same way that defence does - silently, on
    // the backend, with the reason logged server-side only.
    ctx.log.warn('otp send refused by rate limit', { reason: limit.reason, recipient: await emailTag(tx.email) });
    const kept = tx.otp ? tx : withOtp(tx, { digest: undefined, expiresAt: nowSeconds() + config.otp.ttlSeconds, resends });
    return renderOtp(ctx, { tx: kept, resent: resend });
  }

  const code = generateCode(config.otp.codeLength, alphabetFor(config));
  const digest = await digestCode(config, { txId: tx.id, email: tx.email, code });
  const next = withOtp(tx, { digest, expiresAt: nowSeconds() + config.otp.ttlSeconds, resends });

  if (decoy) {
    // No mail, no development code on the page, and a digest of a code that
    // was never anywhere. Everything else about this response is identical.
    ctx.log.info('no sign-in route for this address; showing the code screen anyway', {
      recipient: await emailTag(tx.email),
    });
    return renderOtp(ctx, { tx: next, resent: resend });
  }

  const ttlMinutes = Math.round(config.otp.ttlSeconds / 60);
  const message = otpMessage({
    code,
    ttlMinutes,
    organisation: config.ui.organisation,
    clientName: tx.client_name,
    issuerHost: new URL(config.issuer).host,
  });

  let devCode;
  try {
    const result = await ctx.emailSender.send({
      to: tx.email,
      from: config.email.from,
      replyTo: config.email.replyTo,
      subject: message.subject,
      text: message.text,
      html: message.html,
      code,
      // GOV.UK Notify owns the wording, so it needs the values rather than a
      // rendered body. Every other sender ignores these.
      ttlMinutes,
      personalisation: { application: tx.client_name },
    });
    devCode = result?.code;
    ctx.log.info('otp sent', { provider: ctx.emailSender.name, recipient: await emailTag(tx.email) });
  } catch (err) {
    ctx.log.error('otp send failed', { provider: ctx.emailSender.name, error: err.message });
    // Do not reveal whether the failure was the address or our mail provider.
    return renderOtp(ctx, {
      tx: next,
      error: {
        title: 'We could not send your code',
        detail: 'Try requesting another code. If it keeps failing, contact whoever runs this service.',
      },
    });
  }

  return renderOtp(ctx, { tx: next, devCode, resent: resend });
}

export async function handleOtpRequest(ctx) {
  const loaded = await loadTransaction(ctx);
  if (loaded.fail) return loaded.fail;
  const { tx } = loaded;
  if (!otpAllowed(ctx.config, tx.email) || requiresFederation(tx.acr_values)) {
    return startAgainResponse(ctx, 'Signing in with an email code is not available for this request.');
  }
  return sendOtp(ctx, { tx });
}

export async function handleResend(ctx) {
  const loaded = await loadTransaction(ctx);
  if (loaded.fail) return loaded.fail;
  const { tx } = loaded;
  if (!tx.email || tx.stage !== STAGE.OTP) return startAgainResponse(ctx);
  return sendOtp(ctx, { tx, resend: true });
}

export async function handleOtpSubmit(ctx) {
  const loaded = await loadTransaction(ctx);
  if (loaded.fail) return loaded.fail;
  const { tx, client, params } = loaded;
  if (tx.stage !== STAGE.OTP || !tx.otp) return startAgainResponse(ctx);

  const result = await verifyCode(ctx.config, tx, single(params, 'code'));
  if (!result.ok) {
    const attempted = withOtpAttempt(tx);
    if (result.reason === 'expired') {
      return renderOtp(ctx, {
        tx: attempted,
        error: { title: 'That code has expired', detail: 'Request another code and enter the new one.' },
      });
    }
    if (result.reason === 'too-many-attempts') {
      return renderOtp(ctx, {
        tx: attempted,
        error: {
          title: 'Too many incorrect codes',
          detail: 'Request another code, or go back to the application and start again.',
        },
      });
    }
    const left = ctx.config.otp.maxAttempts - (attempted.otp.attempts ?? 0);
    return renderOtp(ctx, {
      tx: attempted,
      error: {
        title: 'That code is not right',
        detail:
          left > 0
            ? 'Check the code in the email and try again. ' + left + ' attempt' + (left === 1 ? '' : 's') + ' left.'
            : 'Request another code.',
      },
    });
  }

  const { acr, amr } = acrForOtp();
  // There is no upstream on this path, so anything beyond the address is a
  // guess. What is guessed, and whether anything is, is the operator's call;
  // see src/profile.js.
  const sessionArgs = { email: tx.email, acr, amr, claims: inferredClaims(ctx.config, tx.email) };
  const existing = await readSession(
    ctx.config,
    ctx.request,
    sessionClientFor(ctx.config, client),
    ctx.stateStore,
  );
  const session =
    existing && existing.email === tx.email
      ? reauthenticate(ctx.config, existing, sessionArgs)
      : newSession(ctx.config, sessionArgs);

  return complete(ctx, { tx, client, session, refreshCookie: true });
}

export async function handleRestart(ctx) {
  const loaded = await loadTransaction(ctx);
  if (loaded.fail) return loaded.fail;
  return renderEmail(ctx, { tx: withoutOtp(loaded.tx) });
}

// ---------------------------------------------------------------------------
// Continue with the existing session
// ---------------------------------------------------------------------------

export async function handleContinue(ctx) {
  const loaded = await loadTransaction(ctx);
  if (loaded.fail) return loaded.fail;
  const { tx, client } = loaded;
  const session = await readSession(
    ctx.config,
    ctx.request,
    sessionClientFor(ctx.config, client),
    ctx.stateStore,
  );
  if (!session) return renderEmail(ctx, { tx });
  if (!sessionIsFresh(session, { maxAge: tx.max_age, clockSkew: ctx.config.tokens.clockSkewSeconds })) {
    return renderEmail(ctx, { tx, email: session.email });
  }
  if (!satisfies(session.acr, tx.acr_values)) return renderEmail(ctx, { tx, email: session.email });
  return complete(ctx, { tx, client, session, refreshCookie: true });
}

// ---------------------------------------------------------------------------
// Upstream round trip
// ---------------------------------------------------------------------------

async function startUpstream(ctx, { tx, upstream, hinted = false }) {
  try {
    const { url } = await beginUpstream(ctx, upstream, tx, { hinted });
    return redirect(url);
  } catch (err) {
    ctx.log.error('upstream start failed', { upstream: upstream.id, error: err.message });
    const fallback = otpAllowed(ctx.config, tx.email) && !requiresFederation(tx.acr_values);
    if (fallback) {
      ctx.log.warn('falling back to email code', { upstream: upstream.id });
      return sendOtp(ctx, { tx });
    }
    return failureResponse(ctx, serverError('The sign-in provider for your organisation could not be reached.'), redirectTargets(tx));
  }
}

export async function handleChooseUpstream(ctx) {
  const loaded = await loadTransaction(ctx);
  if (loaded.fail) return loaded.fail;
  const { tx, params } = loaded;
  const chosen = single(params, 'upstream');
  // Only an upstream that genuinely serves this address, so a tampered form
  // cannot route somebody at a provider that was never offered to them.
  const upstream = upstreamsFor(ctx.config, tx.email).find((u) => u.id === chosen);
  if (!upstream) return startAgainResponse(ctx);
  return startUpstream(ctx, { tx, upstream });
}

/**
 * GET /callback - the upstream has sent the browser back.
 *
 * Everything needed is in `state`, so this works even in a browser that has
 * discarded every cookie in the meantime.
 */
export async function handleCallback(ctx) {
  const params = ctx.url.searchParams;
  const stateToken = single(params, 'state');
  if (!stateToken) return startAgainResponse(ctx, 'This sign-in response is missing its state and cannot be matched to a request.');

  let stateTx;
  try {
    stateTx = await openUpstreamState(ctx.config, stateToken);
  } catch (err) {
    if (err instanceof SealError) {
      return startAgainResponse(ctx, 'This sign-in response could not be matched to a request that started here.');
    }
    throw err;
  }
  if (expired(stateTx)) return startAgainResponse(ctx, 'This sign-in attempt took too long and has expired.');

  const client = await ctx.resolveClient(stateTx.client_id);
  if (!client) return startAgainResponse(ctx, 'The application that started this sign-in is no longer registered here.');

  const upstreamError = single(params, 'error');
  if (upstreamError) {
    const description = single(params, 'error_description') || 'The sign-in provider refused the request.';
    ctx.log.info('upstream returned an error', { upstream: stateTx.upstream.id, error: upstreamError });
    // prompt=none upstream failures are expected, not exceptional: relay them
    // so the relying party can decide what to do.
    if (stateTx.prompt?.includes('none')) {
      return failureResponse(ctx, loginRequired('The sign-in provider could not authenticate you without interaction.'), redirectTargets(stateTx));
    }
    if (upstreamError === 'access_denied') {
      // Normally this means the person cancelled, and relaying it is right. But
      // when SAG picked the provider itself from a DNS guess rather than being
      // told, `access_denied` is at least as likely to mean "no account here" -
      // and sending them back to the relying party would leave a wrong guess
      // with no way to reach the right provider. So the guess is offered the
      // same second chance a failed exchange gets.
      if (!stateTx.upstream?.hinted) {
        return failureResponse(ctx, accessDenied('You cancelled signing in, or the provider declined.'), redirectTargets(stateTx));
      }
      ctx.log.info('a guessed upstream refused; offering the alternatives', { upstream: stateTx.upstream.id });
    }
    return offerFallback(ctx, stateTx, description);
  }

  const code = single(params, 'code');
  if (!code) return startAgainResponse(ctx, 'This sign-in response has no authorization code.');

  const upstream = ctx.config.upstreams.find((u) => u.id === stateTx.upstream.id);
  if (!upstream) return startAgainResponse(ctx, 'The sign-in provider used for this attempt is no longer configured.');

  let outcome;
  try {
    outcome = await completeUpstream(ctx, upstream, { code, stateTx });
  } catch (err) {
    ctx.log.warn('upstream completion failed', { upstream: upstream.id, error: err.message });
    return offerFallback(ctx, stateTx, err.message);
  }

  const { acr, amr, upstreamAcr } = acrFromUpstream(outcome.claims);
  if (!satisfies(acr, stateTx.acr_values)) {
    return failureResponse(
      ctx,
      unmetAcr('The sign-in provider did not report an authentication strong enough for this request.'),
      redirectTargets(stateTx),
    );
  }

  const sessionArgs = {
    email: outcome.email,
    acr,
    amr,
    upstream: upstream.id,
    upstreamLabel: labelFor(upstream),
    claims: relayedClaims(ctx.config, outcome.claims, upstreamAcr),
  };
  const existing = await readSession(
    ctx.config,
    ctx.request,
    sessionClientFor(ctx.config, client),
    ctx.stateStore,
  );
  const session =
    existing && existing.email === outcome.email
      ? reauthenticate(ctx.config, existing, sessionArgs)
      : newSession(ctx.config, sessionArgs);

  // The transaction that comes back from the callback still carries the
  // upstream leg; strip it before it becomes a code.
  // eslint-disable-next-line no-unused-vars
  const { upstream: _leg, ...tx } = stateTx;
  return complete(ctx, { tx, client, session, refreshCookie: true });
}

/**
 * An upstream failed part way through.
 *
 * Which of the three answers is right depends on what else was available. When
 * more than one provider could serve the address - which is exactly the case
 * where the DNS hint may have guessed wrong - the chooser is the honest next
 * step, and this time nothing is suggested. Otherwise an email code, if one
 * could satisfy the request. Only with neither does the relying party get an
 * error back.
 */
async function offerFallback(ctx, tx, detail) {
  const candidates = upstreamsFor(ctx.config, tx.email);
  if (candidates.length > 1) {
    ctx.log.info('offering the other providers after an upstream failure', { detail });
    return renderChooser(ctx, {
      // withoutAttempt, not withoutOtp: the chooser shows the address and the
      // next step routes on it, so dropping it here would render an empty
      // screen whose every button then had nothing to route.
      tx: withoutAttempt(tx),
      upstreams: candidates,
      error: {
        title: 'That sign-in did not complete',
        detail: 'Try again, or choose a different way to sign in.',
      },
    });
  }
  if (otpAllowed(ctx.config, tx.email) && !requiresFederation(tx.acr_values)) {
    return renderEmail(ctx, {
      tx: withoutOtp(tx),
      email: tx.email,
      error: {
        title: 'That sign-in did not complete',
        detail: 'Try again, or continue with an email code instead.',
      },
    });
  }
  return failureResponse(ctx, accessDenied('Signing in with your organisation provider did not complete.'), redirectTargets(tx));
}

// ---------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------

/**
 * Mint the authorisation code and hand control back to the relying party.
 *
 * The session cookie is written on the same response as the redirect, so a
 * person who completes a sign-in is immediately able to answer the next
 * relying party silently.
 */
async function complete(ctx, { tx, client, session, refreshCookie }) {
  // The session holds the address as it was typed; this is where one relying
  // party's view of it is settled, so that a per-client SANITISE_PLUS_EMAILS
  // and a shared session can coexist.
  const email = identityEmail(ctx.config, session.email, client);
  const sub = await subjectFor(ctx.config, email, client);
  const code = await issueCode(ctx.config, { tx, session, sub, email });
  ctx.log.info('authorization code issued', {
    client_id: tx.client_id,
    acr: session.acr,
    upstream: session.upstream,
    subject: sub.slice(0, 8),
  });
  let response = authorizationResponse(ctx, tx, code);
  if (refreshCookie) {
    const cookie = await sessionCookie(ctx.config, session, sessionClientFor(ctx.config, client));
    response = withCookie(response, cookie);
  }
  return response;
}
