// Whose product this is, and whose terms apply.
//
// SAG is a RESOAuth product and the default pages say so, because a sign-in
// page on an unfamiliar domain with no attribution is exactly what a phishing
// page looks like. An operator can put their own organisation in front of it;
// the attribution stays in the footer either way, because a person is
// entitled to know who is handling their sign-in.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInstance, extractField, authorizeUrl, pkce, DEV_CLIENT, DEV_REDIRECT } from './harness.js';

async function screen(sag, extra = {}) {
  const { challenge } = await pkce();
  const { path } = authorizeUrl({ challenge, ...extra });
  const res = await sag.raw(path);
  return { res, html: await res.text() };
}

test('an unbranded deployment keeps its attribution in the footer', async () => {
  const { html } = await screen(createInstance());
  assert.ok(!/class="brand"|class="product"/.test(html));
  assert.match(html, /Powered by <a href="https:\/\/resoauth\.dev" rel="noopener">RESOAuth<\/a> Smart Access Gateway/);
});

test('an operator name is not rendered without a logo', async () => {
  const { html } = await screen(createInstance({ UI_ORG_NAME: 'Borsetshire Council' }));
  assert.ok(!/Borsetshire Council/.test(html));
  assert.match(html, /Powered by <a[^>]*>RESOAuth<\/a>/);
});

test('whitelabelling drops the product name and keeps the attribution', async () => {
  const { html } = await screen(createInstance({ UI_WHITELABEL: 'true' }));
  assert.ok(!/Smart Access Gateway/.test(html), 'no product name anywhere');
  assert.match(html, /Powered by <a[^>]*>RESOAuth<\/a>/);
});

test('a fork can rename the attribution rather than remove it', async () => {
  // Honest about provenance rather than pretending: the name is configuration,
  // the presence of a name is not.
  const { html } = await screen(createInstance({ UI_BRAND_NAME: 'Example Ltd', UI_BRAND_URL: 'https://example.test' }));
  assert.match(html, /Powered by <a href="https:\/\/example\.test" rel="noopener">Example Ltd<\/a>/);
});

test('instance-wide terms and privacy links appear on every screen', async () => {
  const sag = createInstance({
    UI_TERMS_URL: 'https://example.test/terms',
    UI_PRIVACY_URL: 'https://example.test/privacy',
  });
  const { html } = await screen(sag);
  assert.match(html, /<a href="https:\/\/example\.test\/terms">Terms of use<\/a>/);
  assert.match(html, /<a href="https:\/\/example\.test\/privacy">Privacy notice<\/a>/);

  // And on the code screen, which is where somebody actually stops to read.
  const otp = await sag.postForm('/authorize/email', {
    tx: extractField(html),
    email: 'person@example.org',
  });
  assert.match(await otp.text(), /Privacy notice/);
});

test("a relying party's own links win, because that is what the person is signing in to", async () => {
  const sag = createInstance({
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_NAME: 'Ledger',
    CLIENT_APP_TOS_URI: 'https://ledger.test/terms',
    CLIENT_APP_POLICY_URI: 'https://ledger.test/privacy',
    UI_TERMS_URL: 'https://example.test/terms',
    UI_PRIVACY_URL: 'https://example.test/privacy',
  });
  const { html } = await screen(sag);
  assert.match(html, /<a href="https:\/\/ledger\.test\/terms">Terms of use<\/a>/);
  assert.match(html, /<a href="https:\/\/ledger\.test\/privacy">Privacy notice<\/a>/);
  assert.ok(!/example\.test\/terms/.test(html), 'the instance links are the fallback, not an addition');
});

test('nothing is shown when nothing is configured, rather than a dead link', async () => {
  const { html } = await screen(createInstance());
  assert.ok(!/Terms of use|Privacy notice/.test(html));
});

test('operator supplied text is escaped, wherever it lands', async () => {
  const { html } = await screen(
    createInstance({ UI_ORG_NAME: '<script>alert(1)</script>', UI_TERMS_URL: 'https://example.test/"onmouseover="x' }),
  );
  assert.ok(!/<script>alert/.test(html));
  assert.match(html, /&lt;script&gt;/);
  assert.ok(!/"onmouseover="/.test(html));
});

test('a store-held relying party carries its own links too', async () => {
  // The same fields, whether a client is described by environment variables,
  // by a stored record, or by its own metadata document.
  const kv = {
    get: async (key) =>
      key === 'clients/kv-client.json'
        ? {
            client_name: 'From KV',
            redirect_uris: ['http://127.0.0.1:8788/callback'],
            tos_uri: 'https://kv.test/terms',
            policy_uri: 'https://kv.test/privacy',
          }
        : null,
  };
  const sag = createInstance({ CLIENTS_STORE_BACKEND: 'cf-kv', SAG_CLIENTS: kv });
  const { html } = await screen(sag, { clientId: 'kv-client' });
  assert.match(html, /<a href="https:\/\/kv\.test\/terms">Terms of use<\/a>/);
  assert.match(html, /<a href="https:\/\/kv\.test\/privacy">Privacy notice<\/a>/);
});

test('a relying party cannot put a script URI on the sign-in page', async () => {
  // A CIMD client registers with nobody, so tos_uri and policy_uri are
  // untrusted input. Escaping is not enough: an anchor will happily run
  // javascript: on the issuer's own origin, which is where the session cookie
  // lives.
  const sag = createInstance({
    CLIENT_APP_ID: DEV_CLIENT,
    CLIENT_APP_REDIRECT_URIS: DEV_REDIRECT,
    CLIENT_APP_TOS_URI: 'javascript:alert(document.domain)',
    CLIENT_APP_POLICY_URI: 'data:text/html,<script>alert(1)</script>',
  });
  const { html } = await screen(sag);
  assert.ok(!/javascript:/i.test(html), 'no script URI may reach an href');
  assert.ok(!/data:text\/html/i.test(html));
  assert.ok(!/Terms of use|Privacy notice/.test(html), 'an unusable link is dropped, not rendered dead');
});

test('an operator link that is not http(s) is dropped too', async () => {
  const { html } = await screen(createInstance({ UI_TERMS_URL: 'javascript:alert(1)', UI_SUPPORT_URL: 'javascript:alert(2)' }));
  assert.ok(!/javascript:/i.test(html));
});

test('a configured logo follows the theme control at the bottom of the footer', async () => {
  const { html } = await screen(
    createInstance({ UI_ORG_NAME: 'Borsetshire Council', UI_LOGO_URL: 'https://example.test/logo.svg' }),
  );
  assert.match(
    html,
    /<footer>[\s\S]*<div data-theme-control data-label="Colour theme"><\/div>\s*<p class="logo"><img src="https:\/\/example\.test\/logo\.svg" alt="Borsetshire Council"><\/p>\s*<\/footer>/,
  );
});
