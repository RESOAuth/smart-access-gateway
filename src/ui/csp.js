// Content-Security-Policy for the pages SAG serves.
//
// A sign-in page is the highest-value injection target a deployment has, so the
// policy starts at nothing and names only what the page actually uses. That is
// affordable here because of two deliberate choices elsewhere: the script is a
// file on our own origin rather than an inline block, and an operator's custom
// CSS is served as a stylesheet rather than a <style> element. Between them
// there is no inline anything to allow, so the policy needs neither a nonce nor
// a hash and is a constant per deployment.
//
// The policy is built from configuration rather than fixed, because two things
// an operator sets do widen it: a remote stylesheet, and a logo hosted
// somewhere else.
//
// One directive is deliberately absent, and it is the one a reviewer will reach
// for first, so: `form-action` is not set on these pages, and must not be.
// Browsers enforce it across the whole redirect chain, not just the initial
// submission, and completing a sign-in here *is* a same-origin form POST that
// is answered with a 303 to somewhere else - the relying party at the end of
// the flow, or the upstream provider in the middle of it. Measured in Chromium
// against a running instance: a POST to /authorize/otp answered with a page is
// allowed under `form-action 'self'`, and the same POST answered with a 303 to
// the relying party is blocked with "Sending form data to ... violates the
// following Content Security Policy directive". So `'self'` breaks every
// sign-in, and naming the real targets would mean knowing each upstream's
// authorization endpoint origin before the page that redirects there is
// rendered - a discovery fetch on the critical path, and a guess that fails
// closed if it is wrong.
//
// What is lost is small: `form-action` only bites once somebody can already
// inject markup into one of these pages, `base-uri 'none'` closes the <base>
// route to retargeting the forms that are there, and every action attribute is
// a server-side constant rather than anything derived from input. The one page
// whose form legitimately posts across origins - the form_post response mode -
// posts directly with no redirect, so it can and does name its exact target.
// See docs/limitations.md.

/** The origin of a URL, or undefined if it is not one we can use in a policy. */
function originOf(value) {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}

/**
 * Build the policy for this deployment.
 *
 * @param {object} config
 * @returns {string}
 */
export function contentSecurityPolicy(config) {
  const remote = originOf(config.ui.customCssRemoteUrl);
  const style = ["'self'"];
  if (remote) style.push(remote);

  // A whole theme is not just rules: it will have a webfont and probably a
  // background image, and both are fetched from wherever the stylesheet lives.
  // Allowing the stylesheet and then blocking what it references would be a
  // theme that half works, which is worse than one that does not load at all.
  const font = ["'self'"];
  if (remote) font.push(remote);

  const img = ["'self'", 'data:'];
  if (remote) img.push(remote);
  const logo = originOf(config.ui.logoUrl);
  if (logo && logo !== remote) img.push(logo);
  // An upstream profile picture is a URL at a host we do not know in advance -
  // Google serves them from lh3.googleusercontent.com today and need not
  // tomorrow - so allowing pictures at all means allowing https images. A
  // deployment that will not have that sets PROFILE_PICTURE=off, and then this
  // stays at our own origin and data URIs.
  if (config.profile.showPicture) img.push('https:');

  return [
    "default-src 'none'",
    "base-uri 'none'",
    "script-src 'self'",
    'style-src ' + style.join(' '),
    'img-src ' + img.join(' '),
    'font-src ' + font.join(' '),
    "connect-src 'none'",
    // No form-action here, on purpose. See the note at the top of this file:
    // it is checked across the redirect chain, and finishing a sign-in is a
    // form POST answered with a cross-origin 303.
    "frame-ancestors 'none'",
  ].join('; ');
}

/**
 * The policy for a form_post response, which has one job: POST to the relying
 * party. Nothing else on the page is allowed to go anywhere.
 */
export function formPostPolicy(redirectUri) {
  const target = originOf(redirectUri);
  return [
    "default-src 'none'",
    "base-uri 'none'",
    "script-src 'self'",
    'form-action ' + (target || "'none'"),
    "frame-ancestors 'none'",
  ].join('; ');
}
