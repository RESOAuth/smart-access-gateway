// DNS lookups, using the platform resolver.
//
// The core falls back to DNS-over-HTTPS when it is handed no resolver. Node has
// one of its own, so a container or a VM should use it: the answers are the
// same, they come from whatever resolver the host is already configured to
// trust, and the domain of every sign-in stays inside the deployment rather
// than going to a public DNS service.
//
// adapters/cloudflare/dns.js does the same for Workers, and cannot share this
// file: `lookup` and the generic `resolve` are not implemented there, so A and
// AAAA have to go through resolve4 and resolve6 instead.
//
// Same arrangement as the file-backed client store: node: modules stay on this
// side of the line and the core is handed a binding.

import { Resolver, lookup } from 'node:dns/promises';

/**
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs]
 * @returns {{resolve(name: string, type: string): Promise<string[]>}}
 */
export function createDnsResolver({ timeoutMs = 1500 } = {}) {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 1 });
  return {
    /**
     * @returns {Promise<string[]>} Records in the same textual shape the
     *   DNS-over-HTTPS path produces, so the core needs no special case.
     */
    async resolve(name, type) {
      if (type === 'MX') {
        const records = await resolver.resolveMx(name);
        return records.map((r) => r.priority + ' ' + r.exchange);
      }
      if (type === 'TXT') {
        // node:dns hands back an array of chunks per record; the core expects
        // one string per record, joined the way SPF is meant to be read.
        const records = await resolver.resolveTxt(name);
        return records.map((chunks) => chunks.join(''));
      }
      if (type === 'A') return (await lookup(name, { family: 4, all: true })).map((record) => record.address);
      if (type === 'AAAA') return (await lookup(name, { family: 6, all: true })).map((record) => record.address);
      throw new Error('unsupported record type ' + type);
    },
  };
}
