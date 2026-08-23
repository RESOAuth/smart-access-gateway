#!/usr/bin/env node
// Turn an already-issued relying party secret into the digest a client
// record stores. Use `npm run generate-client-secret` instead when the
// secret does not exist yet - it creates a high-entropy one for you.
//
// A store holds "sha256:<hex>" and never the secret itself, so that reading
// the record - a bucket listing, a stray backup, a container volume - is not
// enough to impersonate the relying party.

import { sha256hex } from '../src/crypto/secrets.js';

const secret = process.argv[2];
if (!secret) {
  console.log(`
  Hash an existing relying party secret for a client record.

    npm run hash-secret -- 'the-secret'

  Put the result in the record as client_secret_digest. Give the secret
  itself to the relying party, and keep it nowhere else.

  Minting a brand new secret instead? Use:

    npm run generate-client-secret
`);
  process.exit(secret === undefined ? 1 : 0);
}

console.log('sha256:' + (await sha256hex(secret)));
