// Profile claims: what SAG will carry, and what it will guess.
//
// SAG is a proxy, so most of this is relay: an upstream returns `name`,
// `picture` and friends, and a relying party that asked for the `profile` scope
// gets them. Two rules bound that. Only claims on a fixed allow list cross,
// because an upstream must not be able to inject arbitrary claims into somebody
// else's id_token; and an operator can narrow the list further, because a
// deployment that has no business relaying a photograph should not have to.
//
// The interesting question is the email code path, where there is no upstream
// and therefore no name at all. The honest position is that `name` means the
// person's name and a guess is not that, so inference is off by default. It is
// offered because the alternative that deployments actually reach for is worse:
// relying parties printing a raw email address into a greeting, or asking every
// new person to type a name SAG could have offered them. When it is on, the
// guess is marked as one - `urn:sag:name_inferred` - so a relying party can
// treat it as a default to confirm rather than a fact.
//
// See docs/profile-claims.md for the reasoning in full, including why the
// avatar fallback draws its own initials rather than calling Gravatar.

import { PROFILE_CLAIMS } from './config.js';
import { assetVersion } from './ui/css.js';

/** Is this claim allowed out of this deployment at all? */
function permitted(config, claim) {
  if (!config.profile.claims.includes(claim)) return false;
  if (claim === 'picture' && !config.profile.showPicture) return false;
  return true;
}

/**
 * The profile claims a relying party might actually be given here.
 *
 * Used by discovery: listing `picture` on a deployment with no upstream and no
 * avatar fallback would be a promise nothing can keep.
 */
export function reachableProfileClaims(config) {
  const reachable = new Set();
  if (config.upstreams.length > 0) {
    for (const claim of PROFILE_CLAIMS) if (permitted(config, claim)) reachable.add(claim);
  }
  if (config.otp.enabled && config.profile.nameFromEmail === 'infer' && permitted(config, 'name')) {
    reachable.add('name');
    reachable.add('urn:sag:name_inferred');
  }
  if (config.otp.enabled && config.profile.avatarFallback === 'initials' && permitted(config, 'picture')) {
    reachable.add('picture');
  }
  // Order follows the allow list rather than insertion, so the document is
  // stable between restarts and diffs cleanly.
  return [...PROFILE_CLAIMS.filter((c) => reachable.has(c)), ...(reachable.has('urn:sag:name_inferred') ? ['urn:sag:name_inferred'] : [])];
}

/**
 * Keep only the profile claims this deployment relays, from an upstream token.
 *
 * @param {object} config
 * @param {object} claims       The upstream id_token claims
 * @param {string} [upstreamAcr] The upstream's own acr, kept for step-up
 */
export function relayedClaims(config, claims = {}, upstreamAcr) {
  const out = {};
  for (const claim of PROFILE_CLAIMS) {
    if (!permitted(config, claim)) continue;
    const value = claims[claim];
    if (typeof value !== 'string' || value === '') continue;
    // A picture is a URL a relying party will put in an <img>, so it has to be
    // one. An upstream offering `javascript:` or `data:` here is either broken
    // or hostile, and neither is worth passing on.
    if (claim === 'picture' && !/^https:\/\//i.test(value)) continue;
    // A URL cannot be truncated and still be a URL, so an over-long picture is
    // dropped rather than relayed as something a relying party would put in an
    // <img> and get a 404 from. A name is only text, so it is capped.
    if (value.length > 512) {
      if (claim === 'picture') continue;
      out[claim] = value.slice(0, 512);
    } else {
      out[claim] = value;
    }
  }
  // Capped like the rest, and for the same reason: everything kept here travels
  // in the session cookie and in the authorisation code, so an upstream
  // returning a kilobyte of `acr` would produce a cookie the browser silently
  // drops and a code too long to survive a redirect.
  if (upstreamAcr) out.upstream_acr = String(upstreamAcr).slice(0, 128);
  return Object.keys(out).length ? out : undefined;
}

// A local part that is a machine identifier rather than a person's name: a
// long hexadecimal string, a UUID, a numeric account reference. Guessing from
// one of these produces nonsense, so it is better not to guess.
const OPAQUE = /^[0-9]+$|^[0-9a-f]{12,}$|^[0-9a-f]{8}-[0-9a-f]{4}-/i;
// Role addresses name a function rather than a person.
const ROLES = new Set([
  'admin', 'administrator', 'info', 'contact', 'support', 'help', 'hello', 'hi',
  'sales', 'billing', 'accounts', 'noreply', 'no-reply', 'donotreply', 'postmaster',
  'webmaster', 'abuse', 'security', 'privacy', 'legal', 'hr', 'jobs', 'careers',
  'team', 'office', 'enquiries', 'inquiries', 'mail', 'email', 'test', 'root',
]);

/**
 * Guess a display name from an email address.
 *
 * Handles the shapes that are actually common: `jamie.taylor@`, `jamie_taylor@`,
 * `j.taylor@`, and a bare `jamie@`. Returns undefined whenever the local part is
 * not plausibly a name, which is the case that matters - a wrong guess is worse
 * than none, so this errs towards none.
 *
 * @returns {string|undefined}
 */
export function nameFromEmail(email) {
  const local = String(email || '').split('@')[0];
  if (!local) return undefined;
  // Drop a plus tag, and anything after it: `jamie.taylor+shop` is still Jamie.
  const base = local.split('+')[0].trim();
  if (base.length < 2 || base.length > 40) return undefined;
  if (OPAQUE.test(base)) return undefined;
  if (ROLES.has(base.toLowerCase())) return undefined;
  // Digits inside a name are almost always a disambiguator or an employee
  // number, and there is no way to tell which, so the whole guess is dropped.
  if (/[0-9]/.test(base)) return undefined;

  // Separators are all there is to go on. Splitting on a case boundary would
  // turn `jamieTaylor` into two words, but the address has already been through
  // normaliseEmail by the time a guess is made and its local part is folded to
  // lower case, so there is never a case boundary left to find. `jamietaylor`
  // stays one word, which is the only honest reading of it.
  const words = base
    .replace(/[._-]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length === 0 || words.length > 4) return undefined;
  if (!words.every((w) => /^[a-z]+$/i.test(w))) return undefined;

  const name = words
    .map((word) => (word.length === 1 ? word.toUpperCase() + '.' : word[0].toUpperCase() + word.slice(1).toLowerCase()))
    .join(' ');
  // A single initial is not a name.
  return /^[A-Z]\.$/.test(name) ? undefined : name;
}

/** One or two initials for an avatar, from a name if there is one. */
export function initialsFor({ name, email }) {
  const source = name || nameFromEmail(email) || String(email || '');
  const words = source.replace(/@.*$/, '').split(/[\s._-]+/).filter((w) => /[a-z]/i.test(w));
  if (words.length === 0) return '?';
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[words.length - 1][0]).toUpperCase();
}

// Backgrounds chosen to hold a contrast ratio of at least 4.5:1 against white
// text, so the initials are legible in either colour scheme without the avatar
// having to know which one is in play.
const AVATAR_COLOURS = ['#1f4b99', '#7a2e6d', '#0f5c46', '#8a3d10', '#403a8c', '#8a1538', '#155e75', '#4a5320'];

/**
 * A self-contained initials avatar, as a data URI.
 *
 * Deliberately not Gravatar or any other avatar service: those need the
 * address, usually as an MD5 or SHA-256 hash, which hands a third party a
 * record of every person who signs in anywhere on this deployment. An SVG we
 * draw ourselves costs a few hundred bytes in the token and tells nobody
 * anything.
 *
 * @returns {string} `data:image/svg+xml,...`
 */
export function initialsAvatar({ name, email }) {
  const initials = initialsFor({ name, email });
  // Stable per person, so the avatar does not change colour between sign-ins.
  const index = parseInt(assetVersion(String(email || '')), 36) % AVATAR_COLOURS.length;
  const svg =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" role="img">' +
    '<rect width="96" height="96" rx="48" fill="' + AVATAR_COLOURS[index] + '"/>' +
    '<text x="48" y="48" fill="#fff" font-family="system-ui,sans-serif" font-size="38" font-weight="600" ' +
    'text-anchor="middle" dominant-baseline="central">' +
    initials.replace(/[<>&"']/g, '') +
    '</text></svg>';
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

/**
 * The claims to keep on a session authenticated by email code.
 *
 * Nothing unless the operator asked for it. When they did, a guessed name is
 * flagged as guessed, and an avatar is only drawn once there is something to
 * draw with - initials from an opaque local part would be noise.
 */
export function inferredClaims(config, email) {
  const out = {};
  const name = config.profile.nameFromEmail === 'infer' ? nameFromEmail(email) : undefined;
  if (name && permitted(config, 'name')) {
    out.name = name;
    out.name_inferred = true;
  }
  if (config.profile.avatarFallback === 'initials' && permitted(config, 'picture') && name) {
    out.picture = initialsAvatar({ name, email });
  }
  return Object.keys(out).length ? out : undefined;
}

/**
 * The profile claims to put in an id_token or a userinfo response.
 *
 * `name_inferred` is carried on the session as a plain flag and emitted under a
 * namespaced claim name, because there is no standard claim that says "this is
 * our best guess" and pretending otherwise is the thing this is meant to avoid.
 */
export function outboundClaims(config, held = {}) {
  const out = {};
  for (const claim of PROFILE_CLAIMS) {
    if (!permitted(config, claim)) continue;
    if (held[claim] !== undefined) out[claim] = held[claim];
  }
  if (held.name_inferred && out.name !== undefined) out['urn:sag:name_inferred'] = true;
  return out;
}

/** What the sign-in screens should show about the person, if anything. */
export function displayIdentity(config, session = {}) {
  if (!config.profile.showOnScreen) return { email: session.email };
  const held = session.claims || {};
  const picture = config.profile.showPicture ? held.picture : undefined;
  return {
    email: session.email,
    name: typeof held.name === 'string' ? held.name : undefined,
    picture: typeof picture === 'string' ? picture : undefined,
  };
}
