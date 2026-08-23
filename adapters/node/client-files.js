// Relying party records held as files in a directory.
//
// Cloudflare KV and S3 are the right answer when a deployment has hundreds of
// relying parties and something else manages them. A container on somebody's
// machine, or a single VM, wants neither: it wants a directory of JSON files
// that can be edited with an editor and read by SAG on the next request.
//
// This lives in the Node adapter rather than in src/ deliberately. The core
// has to bundle for Cloudflare Workers, where node:fs does not exist, so the
// filesystem stays on this side of the line and is handed to the core as a
// binding - exactly the shape a KV namespace already has.

import { readFile, readdir } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';

/**
 * @param {string} dir Directory holding <client id>.json files
 * @returns {{get(key: string, opts?: object): Promise<object|null>, dir: string}}
 */
export function createFileClientStore(dir) {
  const root = resolve(dir);
  return {
    dir: root,
    /** The KV binding interface, so the core needs no special case. */
    async get(key) {
      const path = resolve(join(root, key));
      // The key cannot contain a slash by the time it reaches here, but a
      // store that reads outside its own directory is the kind of thing worth
      // making impossible rather than unlikely.
      if (path !== root && !path.startsWith(root + sep)) return null;
      let text;
      try {
        text = await readFile(path, 'utf8');
      } catch (err) {
        if (err.code === 'ENOENT' || err.code === 'EISDIR') return null;
        throw err;
      }
      try {
        return JSON.parse(text);
      } catch (cause) {
        throw new Error(path + ' is not valid JSON: ' + cause.message);
      }
    },
    /** For the start-up report only: how many records are sitting there. */
    async list() {
      try {
        return (await readdir(root)).filter((name) => name.endsWith('.json'));
      } catch {
        return [];
      }
    },
  };
}
