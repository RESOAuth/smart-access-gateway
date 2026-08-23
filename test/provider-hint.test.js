// Guessing the upstream from the domain's mail records.
//
// The point of this is to make "choose how to sign in" a screen almost nobody
// sees. It is a guess and nothing more: every check that matters happens after
// it - the upstream still validates its own tenant or hosted domain, and the
// chooser is still there when the guess is wrong or missing.
//
// The resolver is supplied as a binding, which is exactly how the Node adapter
// hands the platform resolver to the core, so these tests exercise the real
// path rather than a mock of it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, pkce, authorizeUrl, extractField } from './harness.js';
import { mailProviderFor, clearMailProviderCache } from '../src/upstream/dns.js';
import { loadConfig } from '../src/config.js';

/**
 * Every endpoint is set explicitly so that no test here makes a real network
 * call: SAG only fetches an upstream's discovery document when it has not been
 * told where the endpoints are. What is under test is the routing decision,
 * not whether Microsoft is up.
 */
function upstream(prefix, { clientId, issuer, label, mailProvider }) {
  const env = {
    [prefix + '_CLIENT_ID']: clientId,
    [prefix + '_ISSUER']: issuer,
    [prefix + '_AUTHORIZATION_ENDPOINT']: issuer + '/authorize',
    [prefix + '_TOKEN_ENDPOINT']: issuer + '/token',
    [prefix + '_JWKS_URI']: issuer + '/jwks',
  };
  if (label) env[prefix + '_LABEL'] = label;
  if (mailProvider) env[prefix + '_MAIL_PROVIDER'] = mailProvider;
  return env;
}

const THREE_UPSTREAMS = {
  ...upstream('UPSTREAM_MICROSOFT_COMMON', { clientId: 'common:ms-id', issuer: 'https://login.microsoftonline.test' }),
  ...upstream('UPSTREAM_GOOGLE_COMMON', { clientId: 'common:google-id', issuer: 'https://accounts.google.test' }),
  // Yahoo is a generic OpenID Connect upstream as far as SAG is concerned, so
  // it has to say which mail fingerprint it answers to.
  ...upstream('UPSTREAM_OIDC_YAHOO', {
    clientId: 'common:yahoo-id',
    issuer: 'https://api.login.yahoo.test',
    label: 'Yahoo',
    mailProvider: 'yahoo',
  }),
};

/**
 * A resolver binding with fixed answers, and a record of what was asked.
 * Records are in the textual shape both the platform resolver and the
 * DNS-over-HTTPS path produce.
 */
function stubResolver(zones) {
  const asked = [];
  return {
    asked,
    resolve(name, type) {
      asked.push(type + ' ' + name);
      const zone = zones[name];
      if (!zone) throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
      return Promise.resolve(zone[type] || []);
    },
  };
}

const MICROSOFT = { MX: ['10 acme-com.mail.protection.outlook.com.'] };
const GOOGLE = { MX: ['1 aspmx.l.google.com.', '5 alt1.aspmx.l.google.com.'] };
const YAHOO = { MX: ['1 mta7.am0.yahoodns.net.'] };
// A mail security gateway in front of Microsoft: the MX records say Mimecast
// and nothing about identity, and the SPF record is the only place the real
// provider is still named. This is the case the SPF fallback exists for.
const GATEWAYED = {
  MX: ['10 eu-smtp-inbound-1.mimecast.com.'],
  TXT: ['v=spf1 include:eu._netblocks.mimecast.com include:spf.protection.outlook.com -all'],
};

const instance = (zones, env = {}) =>
  createInstance({ ...THREE_UPSTREAMS, ...env, SAG_DNS: stubResolver(zones) });

/** Get to the point where an address has been submitted. */
async function submitEmail(sag, email) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge });
  const first = await sag.raw(path);
  const res = await sag.postForm('/authorize/email', { tx: extractField(await first.text()), email });
  return { res, html: res.status === 303 ? '' : await res.text() };
}

// ---------------------------------------------------------------------------
// Reading the records
// ---------------------------------------------------------------------------

test('each provider is recognised from its MX records', async (t) => {
  t.beforeEach(clearMailProviderCache);
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const cases = [
    ['acme.test', MICROSOFT, 'microsoft'],
    ['beta.test', GOOGLE, 'google'],
    ['gamma.test', YAHOO, 'yahoo'],
    ['delta.test', { MX: ['10 delta-test.mail.icloud.com.'] }, 'apple'],
    ['eps.test', { MX: ['10 mx.zoho.eu.'] }, 'zoho'],
    ['zeta.test', { MX: ['10 mail.protonmail.ch.'] }, 'proton'],
    ['eta.test', { MX: ['10 in1-smtp.messagingengine.com.'] }, 'fastmail'],
  ];
  for (const [domain, zone, expected] of cases) {
    clearMailProviderCache();
    const ctx = { config, env: { SAG_DNS: stubResolver({ [domain]: zone }) } };
    assert.deepEqual(await mailProviderFor(ctx, domain), { provider: expected, source: 'mx' }, domain);
  }
});

test('SPF is consulted when a mail gateway hides the MX answer', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const resolver = stubResolver({ 'acme.test': GATEWAYED });
  const ctx = { config, env: { SAG_DNS: resolver } };

  assert.deepEqual(await mailProviderFor(ctx, 'acme.test'), { provider: 'microsoft', source: 'spf' });
  assert.deepEqual(resolver.asked, ['MX acme.test', 'TXT acme.test'], 'MX first, then TXT');
});

test('an unrecognised or absent zone is simply not an answer', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const ctx = {
    config,
    env: {
      SAG_DNS: stubResolver({
        'plain.test': { MX: ['10 mail.plain.test.'], TXT: ['v=spf1 a mx -all'] },
      }),
    },
  };
  assert.equal(await mailProviderFor(ctx, 'plain.test'), undefined);
  assert.equal(await mailProviderFor(ctx, 'nothing.test'), undefined, 'a domain with no records at all');
});

test('a resolver that throws or hangs never breaks a sign-in', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const broken = { resolve: () => Promise.reject(new Error('resolver on fire')) };
  assert.equal(await mailProviderFor({ config, env: { SAG_DNS: broken } }, 'acme.test'), undefined);
});

test('anything that is not a hostname is refused before it reaches a resolver', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const resolver = stubResolver({});
  const ctx = { config, env: { SAG_DNS: resolver } };
  for (const bad of ['', 'localhost', 'acme', '-acme.test', 'acme.test/../x', 'acme test.com', 'a'.repeat(300) + '.test']) {
    assert.equal(await mailProviderFor(ctx, bad), undefined, JSON.stringify(bad));
  }
  assert.deepEqual(resolver.asked, [], 'nothing may be looked up');
});

test('an answer is cached, so one sign-in is one lookup', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787' });
  const resolver = stubResolver({ 'acme.test': MICROSOFT });
  const ctx = { config, env: { SAG_DNS: resolver } };
  await mailProviderFor(ctx, 'acme.test');
  await mailProviderFor(ctx, 'acme.test');
  await mailProviderFor(ctx, 'acme.test');
  assert.deepEqual(resolver.asked, ['MX acme.test']);
});

test('SIGNIN_PROVIDER_HINT=off asks nothing at all', async () => {
  clearMailProviderCache();
  const config = loadConfig({ SAG_ISSUER: 'http://localhost:8787', SIGNIN_PROVIDER_HINT: 'off' });
  const resolver = stubResolver({ 'acme.test': MICROSOFT });
  assert.equal(await mailProviderFor({ config, env: { SAG_DNS: resolver } }, 'acme.test'), undefined);
  assert.deepEqual(resolver.asked, []);
});

// ---------------------------------------------------------------------------
// What it does to the flow
// ---------------------------------------------------------------------------

test('a confident guess skips the chooser entirely', async () => {
  clearMailProviderCache();
  const sag = instance({ 'acme.test': MICROSOFT });
  const { res } = await submitEmail(sag, 'jamie@acme.test');
  assert.equal(res.status, 303, 'a guess that lands is a redirect, not a screen');
  const location = res.headers.get('location');
  assert.match(location, /^https:\/\/login\.microsoftonline\.test\/authorize\?/);
  assert.match(location, /client_id=ms-id/);
});

test('order mode still shows the chooser, with the guess first and primary', async () => {
  clearMailProviderCache();
  const sag = instance({ 'acme.test': GOOGLE }, { SIGNIN_PROVIDER_HINT: 'order' });
  const { res, html } = await submitEmail(sag, 'jamie@acme.test');
  assert.equal(res.status, 200);

  assert.match(html, /The mail records for <strong>acme\.test<\/strong> suggest the first option/);
  const options = [...html.matchAll(/<button type="submit"([^>]*)>Continue with ([^<]+)<\/button>/g)];
  assert.deepEqual(
    options.map((m) => m[2]),
    ['Google', 'Microsoft', 'Yahoo'],
    'the guess comes first',
  );
  assert.ok(!options[0][1].includes('secondary'), 'and is the only primary action');
  assert.ok(options[1][1].includes('secondary'));
  assert.ok(options[2][1].includes('secondary'));
});

test('with no usable guess the chooser suggests nothing', async () => {
  clearMailProviderCache();
  const sag = instance({ 'plain.test': { MX: ['10 mail.plain.test.'] } });
  const { res, html } = await submitEmail(sag, 'jamie@plain.test');
  assert.equal(res.status, 200);
  assert.match(html, /More than one option is available for <strong>jamie@plain\.test<\/strong>/);
  assert.ok(!html.includes('mail records'), 'nothing may be suggested');
  // Every option is offered on equal terms.
  const options = [...html.matchAll(/Continue with ([^<]+)<\/button>/g)].map((m) => m[1]);
  assert.deepEqual(options, ['Google', 'Microsoft', 'Yahoo']);
});

test('a guess never routes to an upstream that could not serve the address', async () => {
  clearMailProviderCache();
  // Yahoo's fingerprint matches, but this deployment has no Yahoo upstream, so
  // there is nothing to select and the chooser stands.
  const sag = createInstance({
    ...upstream('UPSTREAM_MICROSOFT_COMMON', { clientId: 'common:ms-id', issuer: 'https://login.microsoftonline.test' }),
    ...upstream('UPSTREAM_GOOGLE_COMMON', { clientId: 'common:google-id', issuer: 'https://accounts.google.test' }),
    SAG_DNS: stubResolver({ 'acme.test': YAHOO }),
  });
  const { res, html } = await submitEmail(sag, 'jamie@acme.test');
  assert.equal(res.status, 200);
  assert.ok(!html.includes('mail records'));
});

test('a domain-specific upstream is not second-guessed by DNS', async () => {
  clearMailProviderCache();
  // The operator has said which upstream serves acme.test. That is a decision,
  // not a guess, so there is only one candidate and no lookup happens.
  const resolver = stubResolver({ 'acme.test': GOOGLE });
  const sag = createInstance({
    ...THREE_UPSTREAMS,
    ...upstream('UPSTREAM_MICROSOFT_ACME', { clientId: 'acme.test:acme-id', issuer: 'https://login.microsoftonline.test' }),
    SAG_DNS: resolver,
  });
  const { res } = await submitEmail(sag, 'jamie@acme.test');
  assert.equal(res.status, 303);
  assert.match(res.headers.get('location'), /client_id=acme-id/);
  assert.deepEqual(resolver.asked, [], 'no lookup is needed when the operator has decided');
});

test('one upstream and email codes is not an ambiguity, so nothing is looked up', async () => {
  clearMailProviderCache();
  const resolver = stubResolver({ 'acme.test': MICROSOFT });
  const sag = createInstance({
    ...upstream('UPSTREAM_MICROSOFT_COMMON', { clientId: 'common:ms-id', issuer: 'https://login.microsoftonline.test' }),
    SAG_DNS: resolver,
  });
  const { res } = await submitEmail(sag, 'jamie@acme.test');
  assert.equal(res.status, 303);
  assert.deepEqual(resolver.asked, []);
});

test('the chooser it lands on is usable: the address survives the failure', async () => {
  clearMailProviderCache();
  // The regression this exists for: the failed attempt was being stripped from
  // the transaction with the address inside it, so the chooser rendered with no
  // address and every button on it had nothing left to route.
  const sag = instance({ 'acme.test': MICROSOFT });
  const { res } = await submitEmail(sag, 'jamie@acme.test');
  const state = new URL(res.headers.get('location')).searchParams.get('state');
  const back = await sag.raw('/callback?error=temporarily_unavailable&state=' + encodeURIComponent(state));
  const html = await back.text();

  assert.match(html, /jamie@acme\.test/, 'the chooser must still know whose sign-in this is');
  assert.ok(html.includes('Email me a code instead'), 'and still offer the email code route');

  // And every option on it still works: pick one and it starts that provider.
  const chosen = await sag.postForm('/authorize/upstream', {
    tx: extractField(html),
    upstream: 'google/common',
  });
  assert.equal(chosen.status, 303, 'a button on the chooser must go somewhere');
  assert.match(chosen.headers.get('location'), /^https:\/\/accounts\.google\.test\/authorize\?/);
  assert.match(chosen.headers.get('location'), /login_hint=jamie%40acme\.test/, 'and know who it is for');
});

test('a provider refusing a guess is a second chance, not a refusal to relay', async () => {
  clearMailProviderCache();
  // access_denied normally means the person cancelled, and relaying it to the
  // relying party is right. When SAG picked the provider itself it is at least
  // as likely to mean "no account here", and relaying it would leave a wrong
  // guess with no way to reach the right provider.
  const sag = instance({ 'acme.test': MICROSOFT });
  const { res } = await submitEmail(sag, 'jamie@acme.test');
  const state = new URL(res.headers.get('location')).searchParams.get('state');

  const back = await sag.raw('/callback?error=access_denied&state=' + encodeURIComponent(state));
  assert.equal(back.status, 400, 'not a redirect back to the relying party');
  const html = await back.text();
  assert.match(html, /<h1>Choose how to sign in<\/h1>/);
  assert.match(html, /Continue with Google/);
});

test('a provider the person chose themselves is taken at its word', async () => {
  clearMailProviderCache();
  const sag = instance({ 'plain.test': { MX: ['10 mail.plain.test.'] } });
  const { html } = await submitEmail(sag, 'jamie@plain.test');
  const chosen = await sag.postForm('/authorize/upstream', {
    tx: extractField(html),
    upstream: 'microsoft/common',
  });
  const state = new URL(chosen.headers.get('location')).searchParams.get('state');

  // Nobody guessed here, so access_denied means what it says and goes back to
  // the relying party rather than second-guessing the person.
  const back = await sag.raw('/callback?error=access_denied&state=' + encodeURIComponent(state));
  assert.equal(back.status, 303);
  assert.match(back.headers.get('location'), /error=access_denied/);
});

test('the chooser always has a primary action on it', async () => {
  clearMailProviderCache();
  // With nothing suggested every option is equal - which is honest, and also
  // leaves something to press rather than a column of outlines.
  const sag = instance({ 'plain.test': { MX: ['10 mail.plain.test.'] } });
  const { html } = await submitEmail(sag, 'jamie@plain.test');
  const options = [...html.matchAll(/<button type="submit"([^>]*)>Continue with/g)];
  assert.equal(options.length, 3);
  assert.ok(
    options.every((m) => !m[1].includes('secondary')),
    'with no suggestion, no option may be demoted below the others',
  );
});

test('a guess that turns out wrong lands back on the chooser, not a dead end', async () => {
  clearMailProviderCache();
  // The upstream is selected from the guess and then fails - which is exactly
  // what a wrong guess looks like, because the person has no account there.
  // Sending them to an email code would be worse than offering the others.
  const sag = instance({ 'acme.test': MICROSOFT });
  const { res } = await submitEmail(sag, 'jamie@acme.test');
  assert.equal(res.status, 303);

  // Come back the way the upstream would when it refuses.
  const state = new URL(res.headers.get('location')).searchParams.get('state');
  const back = await sag.raw('/callback?error=temporarily_unavailable&state=' + encodeURIComponent(state));
  // A screen carrying an error reports one, the same way the email screen does.
  assert.equal(back.status, 400);
  const html = await back.text();
  assert.match(html, /<h1>Choose how to sign in<\/h1>/);
  assert.match(html, /That sign-in did not complete/);
  assert.ok(!html.includes('mail records'), 'the guess is not repeated after it failed');
  for (const label of ['Microsoft', 'Google', 'Yahoo']) {
    assert.ok(html.includes('Continue with ' + label), label + ' must still be offered');
  }
});
