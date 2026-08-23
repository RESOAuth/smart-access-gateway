// Subject identifiers, and what counts as the same person.
//
// A `sub` is derived from the verified email address and never from an
// upstream's own subject - see
// [ADR 0011](../docs/adr/0011-subject-derived-from-the-verified-address.md)
// for why, and for what that costs when somebody's address changes.
//
// Both shapes are an HKDF of SUBJECT_SALT, so a relying party cannot recover
// the address from a `sub`. `pairwise` mixes in the relying party's sector so
// that two of them cannot compare notes; `public` mixes in a fixed string
// instead, so every relying party sees the same value. The salt must never be
// rotated - doing so gives every person a new `sub` everywhere.

import { derive, sha256b64u } from './crypto/secrets.js';
import { b64u } from './util/bytes.js';

/** Normalise an address for identity purposes. */
export function normaliseEmail(input) {
  const raw = String(input || '').trim();
  const at = raw.lastIndexOf('@');
  if (at < 1 || at === raw.length - 1) return undefined;
  const local = raw.slice(0, at).toLowerCase();
  const domain = raw.slice(at + 1).toLowerCase();
  // The local part is case sensitive per RFC 5321, but no real mail system
  // treats it that way and folding it stops one person holding two accounts.
  return local + '@' + domain;
}

/**
 * Drop a plus tag: `jamie+shop@example.com` becomes `jamie@example.com`.
 *
 * Every mail system that implements `+` routes both to the same mailbox, so
 * two tagged addresses are one person with two spellings. Left as a separate
 * step from normaliseEmail because it is a policy an operator - or a single
 * relying party - can turn off, whereas case folding is not.
 */
export function stripPlusTag(email) {
  const raw = String(email || '');
  const at = raw.lastIndexOf('@');
  if (at < 1) return email;
  const local = raw.slice(0, at);
  // A quoted local part may legitimately contain a `+`, and a leading `+` is
  // the whole local part rather than a tag on one. Both are left alone.
  if (local.startsWith('"')) return email;
  const plus = local.indexOf('+');
  if (plus < 1) return email;
  return local.slice(0, plus) + raw.slice(at);
}

/** Does this relying party see tagged addresses, or the mailbox behind them? */
export function sanitisesPlusEmails(config, client) {
  return client?.sanitisePlusEmails ?? config.identity.sanitisePlusEmails;
}

/**
 * The address as one relying party should see it, and as its `sub` is derived
 * from.
 *
 * Applied once, when the authorisation code is minted, rather than when the
 * address is first typed: the session is shared across relying parties, so
 * baking one party's policy into it would make the other party's wrong. What
 * the person typed is what the sign-in screens keep showing them.
 */
export function identityEmail(config, email, client) {
  return sanitisesPlusEmails(config, client) ? stripPlusTag(email) : email;
}

export const domainOf = (email) => String(email || '').split('@')[1]?.toLowerCase();

/**
 * Basic address shape check. Deliberately permissive: the authoritative test
 * is whether the code we email actually arrives.
 */
export function looksLikeEmail(email) {
  if (!email || email.length > 254) return false;
  if (!/^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(email)) return false;
  const domain = domainOf(email);
  return Boolean(domain) && domain.length <= 253 && !domain.startsWith('-') && !domain.endsWith('-');
}

/**
 * The sector a pairwise subject is scoped to.
 *
 * A declared `sector_identifier`, or the client id. Nothing is inferred from
 * the redirect URIs: sharing an account across a group of applications is a
 * decision somebody makes, and deriving it from a hostname would mean a
 * relying party that changes where it redirects silently loses every account.
 */
export function sectorFor(client) {
  if (client?.sectorIdentifier) return String(client.sectorIdentifier).toLowerCase();
  return 'client:' + String(client?.clientId || '');
}

// A separator that cannot occur in a sector or an address, so that two
// different inputs can never produce the same derivation input.
const SEP = ' | ';

/**
 * Derive the `sub` claim.
 *
 * The issuer is deliberately not in the derivation. A relying party keys on
 * the pair of `iss` and `sub`, so it already separates two deployments; mixing
 * the issuer in as well would mean renaming the deployment orphans every
 * account, on top of the salt already being unrotatable.
 *
 * @param {object} config
 * @param {string} email    Already normalised, and already through identityEmail
 * @param {object} [client]
 * @returns {Promise<string>}
 */
export async function subjectFor(config, email, client) {
  const type = client?.subjectType || config.subject.type;
  const salt = config.subject.salt;
  if (!salt) throw new Error('subjects require SUBJECT_SALT to be set');
  const scope = type === 'pairwise' ? sectorFor(client) : 'public';
  return b64u(await derive(salt, ['sub', type, scope, email].join(SEP), 24));
}

/**
 * A stable, non-reversible tag for an address, used in logs.
 *
 * The untagged mailbox, so that one line correlates with another and with the
 * OTP send limit, which counts the mailbox for the same reason.
 */
export async function emailTag(email) {
  return (await sha256b64u(stripPlusTag(String(email || '')))).slice(0, 10);
}
