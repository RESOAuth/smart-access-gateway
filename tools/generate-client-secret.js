#!/usr/bin/env node
// Generate a fresh, high-entropy relying party secret and its digest.
//
// The `r-cs-` prefix and fixed hex shape are deliberate: register the
// pattern with a secret scanner (GitHub, Gitleaks, TruffleHog) so a leaked
// SAG client secret is caught the same way a leaked cloud key would be.
// Regex for the secret: `r-cs-[0-9a-f]{32}-[0-9a-f]{48}`

import { randomBytes, toHex } from '../src/util/bytes.js';
import { sha256hex } from '../src/crypto/secrets.js';

const secret = 'r-cs-' + toHex(randomBytes(16)) + '-' + toHex(randomBytes(24));

console.log(`
  Secret (give this to the relying party, store it nowhere else):

    ${secret}

  Digest (put this in the client record as client_secret_digest):

    sha256:${await sha256hex(secret)}
`);
