// The document shell every page shares.

import { escapeHtml, safeHttpUrl } from '../util/http.js';

const e = escapeHtml;

/**
 * @param {object} ctx     Request context, for config and paths
 * @param {object} page    { title, heading, body, description }
 */
export function layout(ctx, page) {
  const { ui, issuer } = ctx;
  const title = page.title ? page.title + ' - ' + (ui.title || 'Sign in') : ui.title || 'Sign in';

  return `<!DOCTYPE html>
<html lang="${e(ui.locale || 'en-GB')}">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <meta name="referrer" content="no-referrer">
    <meta name="color-scheme" content="light dark">
    <title>${e(title)}</title>
    ${headAssets(ctx)}
  </head>
  <body>
    <main>
      ${brandBlock(ui)}
      ${page.body}
    </main>
    <footer>
      ${footerBlock(ui, issuer, page.legal)}
      ${themeSlot()}
    </footer>
  </body>
</html>
`;
}

/**
 * What the document loads.
 *
 * A remote stylesheet replaces the default one entirely, because an operator
 * who supplies a whole theme does not want to fight ours. A snippet is always
 * applied last so it can adjust whichever base is in play, and it is served as
 * its own stylesheet rather than inlined in a <style> element: that is what
 * lets the Content-Security-Policy refuse inline styles outright instead of
 * carrying a nonce on every response.
 *
 * The script is loaded synchronously rather than deferred because the first
 * thing it does is apply a stored colour theme, and deferring that would paint
 * the wrong one first.
 */
function headAssets(ctx) {
  const { ui, assets } = ctx;
  const parts = [];
  const base = ui.customCssRemoteUrl ? safeHttpUrl(ui.customCssRemoteUrl, { allowHttp: true }) : assets.css;
  if (base) parts.push('<link rel="stylesheet" href="' + e(base) + '">');
  if (assets.custom) parts.push('<link rel="stylesheet" href="' + e(assets.custom) + '">');
  parts.push('<script src="' + e(assets.js) + '"></script>');
  return parts.join('\n    ');
}

/**
 * Where the colour theme control goes.
 *
 * Empty in the HTML: the control is built by sag.js and inserted here, so a
 * page whose script was blocked or failed to load shows no control at all
 * rather than one that does nothing. That is the whole reason it is not markup.
 *
 * It is last in the document, in the footer, rather than up beside the brand
 * where it would look at home. A sign-in page has one job, and the first Tab
 * should land on the field rather than on a control somebody will use once. It
 * also means the page reads the same way to a screen reader as it does to
 * anybody else: the form, then the small print, then the preferences.
 */
function themeSlot() {
  return '<div data-theme-control data-label="Colour theme"></div>';
}

/**
 * Whose sign-in page this is.
 *
 * An operator's own name and logo come first when they are set, because the
 * person signing in knows the organisation and not the software. With nothing
 * configured the page says what it actually is, which for an unbranded
 * deployment is more trustworthy than a bare form on an unfamiliar domain.
 */
function brandBlock(ui) {
  const logo = safeHttpUrl(ui.logoUrl, { allowHttp: true });
  if (logo) {
    // The organisation's name, or nothing: a logo with no name beside it is
    // decorative, and announcing "RESOAuth" as the name of somebody else's
    // logo would be worse than silence.
    return '<p class="brand"><img src="' + e(logo) + '" alt="' + e(ui.organisation || '') + '"></p>';
  }
  if (ui.organisation) return '<p class="brand">' + e(ui.organisation) + '</p>';
  if (ui.whitelabel) return '';
  return (
    '<p class="brand">' + e(ui.brandName) + ' <span class="product">' + e(ui.productName) + '</span></p>'
  );
}

/**
 * The footer.
 *
 * Three things, in order of use to the person: how to get help, which service
 * is actually handling the sign-in (so a phishing page is one look away from
 * being caught), the legal links, and who built it. The attribution stays
 * even on a whitelabelled instance, because a person is entitled to know who
 * is processing their sign-in.
 */
function footerBlock(ui, issuer, legal = {}) {
  const parts = [];
  const support = safeHttpUrl(ui.supportUrl, { allowHttp: true });
  if (support) parts.push('<p><a href="' + e(support) + '">Get help signing in</a></p>');
  parts.push('<p>Sign-in is handled by <span class="host">' + e(new URL(issuer).host) + '</span>.</p>');

  const links = [];
  // The caller has usually resolved these already, but the fallback has to be
  // checked here too: an href is an href wherever the value came from.
  const terms = legal.terms || safeHttpUrl(ui.termsUrl, { allowHttp: true });
  const privacy = legal.privacy || safeHttpUrl(ui.privacyUrl, { allowHttp: true });
  if (terms) links.push('<a href="' + e(terms) + '">Terms of use</a>');
  if (privacy) links.push('<a href="' + e(privacy) + '">Privacy notice</a>');
  if (links.length) parts.push('<p class="legal">' + links.join(' <span aria-hidden="true">&middot;</span> ') + '</p>');

  const product = ui.whitelabel ? '' : ' ' + e(ui.productName);
  parts.push(
    '<p class="powered">Powered by <a href="' + e(ui.brandUrl) + '" rel="noopener">' + e(ui.brandName) + '</a>' + product + '</p>',
  );
  return parts.join('\n      ');
}

/**
 * An error block. `title` is short; `detail` is a sentence.
 *
 * role="alert" makes a screen reader announce it when the page loads, which
 * matters because the error is above the field it refers to.
 */
export function errorBlock(title, detail) {
  if (!title && !detail) return '';
  return (
    '<div class="error" role="alert">' +
    (title ? '<strong>' + e(title) + '</strong>' : '') +
    (detail ? e(detail) : '') +
    '</div>'
  );
}

export function noticeBlock(html) {
  return html ? '<div class="notice">' + html + '</div>' : '';
}

/**
 * Who is about to be signed in.
 *
 * The address is always shown, because that is the thing being asserted. A
 * display name and a picture are shown when SAG holds them and the deployment
 * allows it: they are what make "continue as" recognisable rather than a
 * string to parse. The picture is decorative - the name and address beside it
 * carry the meaning - so it has an empty alt attribute.
 */
export function identityBlock({ email, name, picture, method }) {
  const avatar = picture ? '<img class="avatar" src="' + e(picture) + '" alt="" width="44" height="44">' : '';
  const primary = name || email;
  const secondary = [name ? email : undefined, method].filter(Boolean);
  return (
    '<div class="identity">' +
    avatar +
    '<span class="who"><strong>' +
    e(primary) +
    '</strong>' +
    secondary.map((line) => '<span>' + e(line) + '</span>').join('') +
    '</span></div>'
  );
}

/** Hidden inputs carry the transaction, so no cookie is needed for a POST. */
export function hiddenFields(fields) {
  return Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => '<input type="hidden" name="' + e(k) + '" value="' + e(v) + '">')
    .join('\n        ');
}
