// Guessing which upstream serves a domain, from its mail records.
//
// The problem this solves: a deployment with Microsoft, Google and Yahoo all
// configured as `common` upstreams cannot tell from an address alone which one
// holds the account, so it has to ask - and "choose how to sign in" is a screen
// most people should never see. Almost always the answer is already published,
// because an organisation that has its identity at Microsoft has its mail there
// too. Reading the MX record turns a question into a redirect.
//
// Two records are consulted, in order:
//
//   MX  - the direct answer, and right for the great majority of domains.
//   SPF - the fallback, and it matters more than it looks. Plenty of
//         organisations run their mail through a security gateway (Mimecast,
//         Proofpoint, Barracuda) whose MX records say nothing about identity,
//         while the SPF record still names the provider that actually sends
//         their mail. Without this, exactly the enterprise deployments SAG is
//         for would fall through to the chooser.
//
// Nothing here is a security control. A domain owner can publish whatever they
// like, and all that gets them is a redirect to a provider that will refuse to
// authenticate them. Every guess is checked against the upstreams that were
// already eligible for the address, and the upstream itself still validates the
// tenant or hosted domain of whatever comes back.

import { fetchWithTimeout, readJsonLimited } from '../util/http.js';
import { nowSeconds } from '../util/bytes.js';

/**
 * How each provider's mail infrastructure signs itself.
 *
 * `mx` entries are matched as hostname suffixes; `spf` entries as substrings of
 * the joined TXT records, which is how an SPF include actually appears.
 */
const FINGERPRINTS = [
  {
    provider: 'microsoft',
    mx: ['mail.protection.outlook.com', 'mail.eo.outlook.com', 'olc.protection.outlook.com', 'outlook.com'],
    spf: ['spf.protection.outlook.com', 'spf.messaging.microsoft.com', 'spf.protection.office365.us'],
  },
  {
    provider: 'google',
    mx: ['aspmx.l.google.com', 'googlemail.com', 'aspmx.google.com', 'smtp.google.com'],
    spf: ['_spf.google.com'],
  },
  {
    provider: 'yahoo',
    mx: ['yahoodns.net', 'yahoo.com'],
    spf: ['spf.mail.yahoo.com'],
  },
  {
    provider: 'apple',
    mx: ['icloud.com', 'mail.icloud.com'],
    spf: ['spf.icloud.com'],
  },
  {
    provider: 'zoho',
    mx: ['zoho.com', 'zoho.eu', 'zohomail.com'],
    spf: ['zoho.com', 'zoho.eu'],
  },
  {
    provider: 'proton',
    mx: ['protonmail.ch', 'proton.me'],
    spf: ['_spf.protonmail.ch'],
  },
  {
    provider: 'fastmail',
    mx: ['messagingengine.com', 'fastmail.com'],
    spf: ['spf.messagingengine.com'],
  },
];

const cache = new Map();
// A domain that resolves to nothing recognisable is remembered for less time
// than one that does, because it is the case most likely to change - an
// organisation being migrated onto a provider, mid-migration.
const MISS_TTL_SECONDS = 300;
const MAX_CACHED = 500;
const MAX_DNS_RESPONSE_BYTES = 64 * 1024;

export function clearMailProviderCache() {
  cache.clear();
}

function remember(domain, result, ttlSeconds) {
  // A bounded cache, evicting oldest-inserted first. Map preserves insertion
  // order, so the first key is the oldest.
  if (cache.size >= MAX_CACHED) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(domain, { result, expiresAt: nowSeconds() + ttlSeconds });
  return result;
}

/**
 * Resolve one record type for a domain.
 *
 * The platform resolver is used when the adapter supplied one, because a
 * deployment that has a resolver of its own should not be sending the domain
 * of every sign-in to a public DNS service. Workers and Lambda have none, so
 * they fall back to DNS-over-HTTPS.
 *
 * @returns {Promise<string[]>} Record data, lowercased; empty on any failure
 */
async function resolve(ctx, domain, type) {
  const resolver = ctx.env?.[ctx.config.dns.bindingName];
  if (resolver && typeof resolver.resolve === 'function') {
    try {
      const records = await resolver.resolve(domain, type);
      return (records || []).map((r) => String(r).toLowerCase());
    } catch {
      return [];
    }
  }

  const url = new URL(ctx.config.dns.resolverUrl);
  url.searchParams.set('name', domain);
  url.searchParams.set('type', type);
  try {
    const res = await fetchWithTimeout(
      url.toString(),
      { headers: { accept: 'application/dns-json' } },
      ctx.config.dns.timeoutMs,
    );
    if (!res.ok) return [];
    const body = await readJsonLimited(res, MAX_DNS_RESPONSE_BYTES);
    // Both Cloudflare and Google answer in this shape. NXDOMAIN and friends
    // come back with a Status and no Answer, which is an empty list here.
    if (!Array.isArray(body.Answer)) return [];
    const wanted = type === 'MX' ? 15 : 16;
    return body.Answer.filter((a) => a.type === wanted && typeof a.data === 'string').map((a) =>
      a.data.toLowerCase(),
    );
  } catch {
    return [];
  }
}

/** `10 mail.protection.outlook.com.` -> `mail.protection.outlook.com` */
const mxHost = (data) => data.trim().split(/\s+/).pop().replace(/\.$/, '');

function matchMx(records) {
  for (const record of records) {
    const host = mxHost(record);
    for (const print of FINGERPRINTS) {
      if (print.mx.some((suffix) => host === suffix || host.endsWith('.' + suffix))) return print.provider;
    }
  }
  return undefined;
}

function matchSpf(records) {
  // DNS-over-HTTPS returns TXT data quoted, and a long record split into
  // several quoted chunks that have to be joined before matching.
  const text = records.map((r) => r.replace(/"\s*"/g, '').replaceAll('"', '')).join(' ');
  if (!text.includes('v=spf1')) return undefined;
  for (const print of FINGERPRINTS) {
    if (print.spf.some((needle) => text.includes(needle))) return print.provider;
  }
  return undefined;
}

/**
 * Which mail provider serves this domain, as far as DNS will say.
 *
 * @returns {Promise<{provider: string, source: 'mx'|'spf'}|undefined>}
 */
export async function mailProviderFor(ctx, domain) {
  if (!domain || ctx.config.dns.hint === 'off') return undefined;
  // A hostname, and nothing that could be read as anything else: this value
  // goes into a URL and, on the Node adapter, into a resolver call.
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) return undefined;
  if (domain.length > 253) return undefined;

  const cached = cache.get(domain);
  if (cached && cached.expiresAt > nowSeconds()) return cached.result;

  const ttl = ctx.config.dns.cacheTtlSeconds;
  const mx = matchMx(await resolve(ctx, domain, 'MX'));
  if (mx) return remember(domain, { provider: mx, source: 'mx' }, ttl);

  const spf = matchSpf(await resolve(ctx, domain, 'TXT'));
  if (spf) return remember(domain, { provider: spf, source: 'spf' }, ttl);

  return remember(domain, undefined, Math.min(ttl, MISS_TTL_SECONDS));
}

/**
 * Order the eligible upstreams so the one DNS points at comes first.
 *
 * An upstream declares which mail fingerprint it answers to with
 * UPSTREAM_<PROVIDER>_<SLUG>_MAIL_PROVIDER, which is how a Yahoo or an Apple
 * upstream configured as a generic OpenID Connect provider takes part. Failing
 * that, the provider name is the fingerprint, which covers Microsoft and Google
 * without any configuration at all.
 *
 * @returns {Promise<{list: object[], hinted?: object, source?: string}>}
 */
export async function hintUpstreams(ctx, upstreams, domain) {
  if (ctx.config.dns.hint === 'off' || upstreams.length < 2) return { list: upstreams };

  const hint = await mailProviderFor(ctx, domain);
  if (!hint) return { list: upstreams };

  const hinted = upstreams.find((u) => (u.mailProvider || u.provider) === hint.provider);
  if (!hinted) return { list: upstreams };

  return {
    list: [hinted, ...upstreams.filter((u) => u !== hinted)],
    hinted,
    source: hint.source,
  };
}
