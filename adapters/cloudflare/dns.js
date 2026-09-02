// DNS lookups on Workers, using the platform resolver.
//
// The core falls back to DNS-over-HTTPS when it is handed no resolver, and that
// path does not work here: a Worker's own `fetch` to a public DNS-over-HTTPS
// endpoint does not come back, so every lookup fails and every client whose id
// is a metadata document URL is refused. `node:dns` does work, because the
// runtime performs the query itself rather than routing it through `fetch`.
//
// Same arrangement as adapters/node/dns.js and as the file-backed client store:
// node: modules stay on this side of the line and the core is handed a binding.
// It needs the `nodejs_compat` flag, which this adapter's Worker already sets
// because the AWS signing path and the email senders need it too.

import { Resolver } from 'node:dns/promises';

// `lookup`, `lookupService`, and the generic `resolve` throw "Not implemented"
// on Workers, so this maps each record type to its own resolveX function and
// never reaches for them. That is the whole difference from the Node adapter,
// which resolves A and AAAA through `lookup`.
const BY_TYPE = {
  A: (resolver, name) => resolver.resolve4(name),
  AAAA: (resolver, name) => resolver.resolve6(name),
  MX: async (resolver, name) => {
    const records = await resolver.resolveMx(name);
    return records.map((r) => r.priority + ' ' + r.exchange);
  },
  TXT: async (resolver, name) => {
    // node:dns hands back an array of chunks per record; the core expects one
    // string per record, joined the way SPF is meant to be read.
    const records = await resolver.resolveTxt(name);
    return records.map((chunks) => chunks.join(''));
  },
};

/**
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs]
 * @param {object} [opts.resolver] Stands in for node:dns's Resolver. Only the
 *   tests pass one: node:dns is the platform here, and a test that reached the
 *   real thing would be asserting against whatever DNS answers today.
 * @returns {{resolve(name: string, type: string): Promise<string[]>}}
 */
export function createDnsResolver({ timeoutMs = 1500, resolver: injected } = {}) {
  const resolver = injected || new Resolver();
  return {
    /**
     * @returns {Promise<string[]>} Records in the same textual shape the
     *   DNS-over-HTTPS path and the Node adapter produce, so the core needs no
     *   special case.
     */
    async resolve(name, type) {
      const query = BY_TYPE[type];
      if (!query) throw new Error('unsupported record type ' + type);
      // Enforced here rather than through Resolver's own timeout option, which
      // the Workers implementation does not honour. A hung lookup must not hold
      // an invocation open, the same reason every outbound call in the core is
      // wrapped.
      let timer;
      try {
        return await Promise.race([
          query(resolver, name),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('DNS lookup for ' + name + ' timed out')), timeoutMs);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
