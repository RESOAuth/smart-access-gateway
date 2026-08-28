# Post-quantum readiness

Notes on where SAG stands against a quantum adversary, what has already been
done, and what is left. Written 2026-08-22; review at least annually, and
whenever a deployment platform changes what it supports.

An identity provider is an unusual case. Most of what it holds is short lived -
a code lasts a minute, an `id_token` five - so "harvest now, decrypt later" is
much less of a threat to the tokens themselves than to, say, an archive of
encrypted mail. The lasting risks are the signing key, because a forged
`id_token` is a complete authentication bypass, and the transport, because that
is the only place a long-lived recording is plausible.

## Where the cryptography sits

| Purpose | Primitive | Quantum position |
| --- | --- | --- |
| Session cookie, transaction, authorisation code, access token | AES-256-GCM, key from HKDF-SHA-256 | Already resistant. Grover's algorithm reduces a 256-bit key search to roughly 2^128 work, which is not a practical attack. |
| Subject derivation, OTP digest, PKCE, JWK thumbprints | SHA-256, HMAC-SHA-256 | Already resistant at these sizes. Collision resistance halves under Brillouin-style attacks but 128 bits of it remains. |
| `id_token` signature | ES256 by default, ML-DSA-44/65/87 available | **This is the exposure.** ECDSA is broken by Shor's algorithm. |
| Upstream `id_token` verification | Whatever Microsoft or Google signs with | Not ours to choose. Tracked below. |
| Client `private_key_jwt` | Whatever the relying party registers | Their choice; SAG accepts ML-DSA if they offer it. |
| Transport | TLS as provided by the platform | Depends on the platform; see below. |

The deliberate design decision is that **nothing confidential depends on
asymmetric cryptography**. Sessions and state are sealed with AES-256-GCM under
a key derived from the master secret, not encrypted to a public key. That means
a future quantum adversary who recorded every request SAG ever served still
cannot read a session or forge a transaction. Only the signature layer needs to
migrate, and that layer was built to be swapped - see
[ADR 0006](adr/0006-algorithm-agile-signing.md).

## What is already implemented

- **Algorithm-agile signing.** `src/crypto/jose.js` treats the algorithm as
  data, and `src/keys/` exposes one interface - `{alg, sign(bytes),
  publicJwks()}` - implemented by a local key, AWS KMS and the Cloudflare HSM
  Worker. Adding a scheme means adding a table entry, not touching an endpoint.
- **ML-DSA support.** FIPS 204 parameter sets 44, 65 and 87 are wired in as
  JOSE `AKP` keys, where `pub` and `priv` carry raw key bytes and `alg` is
  required because `kty` alone does not pin the parameter set.
- **Runtime probing.** `src/crypto/capabilities.js` generates a throwaway key
  pair to find out what the host runtime can really do, and requires that the
  public half exports as a JWK, because a runtime that can sign but not export
  is no use for publishing keys. Discovery then advertises only what works.
  Node 24 with OpenSSL 3.5 or later has ML-DSA; other platforms may not, and a
  deployment that advertised it anyway would leave relying parties asking for
  something that fails.
- **Several keys at once.** `src/keys/registry.js` publishes a classical and a
  post-quantum key side by side, with the classical one primary. Discovery
  lists both in `id_token_signing_alg_values_supported`, so a relying party can
  ask for `ML-DSA-44` per request while everybody else stays on ES256. This is
  the whole migration story: no flag day.
- **A hint for relying parties.** Discovery carries
  `urn:sag:post_quantum_signing_supported` and `urn:sag:post_quantum_algs`, so
  a relying party can discover the option rather than having to be told.
- **A way to insist.** `REQUIRE_POST_QUANTUM_SIGNING=true` refuses to start
  unless a post-quantum algorithm is configured, for a deployment that has
  decided classical signatures are no longer acceptable. See
  [ADR 0007](adr/0007-require-prefix-for-fail-fast-flags.md) for the naming
  pattern this and every flag like it follows.
- **Key generation.** `npm run keygen -- --alg ES256,ML-DSA-44` produces both
  keys in one go, and the tool says so when only a classical key was made.

## How a migration actually runs

1. Generate a post-quantum key alongside the existing one and configure it as
   an additional algorithm. Nothing changes for any relying party: the primary
   is still ES256, and the new public key simply appears in the JWKS.
2. Relying parties that are ready start sending
   `id_token_signed_response_alg=ML-DSA-44`, or have it set on their client
   record. A registered value cannot be overridden by a request. They get
   post-quantum signatures; everybody else does not.
3. When enough have moved, swap `SIGNING_ALG` and `SIGNING_ADDITIONAL_ALGS`
   round so the post-quantum key becomes primary. The classical key stays
   published, so nothing breaks.
4. Once no relying party is using it, drop the classical key.

Steps 1 and 3 are configuration changes. No endpoint, no database, no
coordinated release.

## What is not done, and why

- **KMS and HSM parameter sets.** AWS KMS added ML-DSA key support but not in
  every region, and the Cloudflare HSM Worker can only hold what its runtime
  can import. Both are configuration rather than code, but a deployment cannot
  be promised post-quantum signing until its chosen backend offers it in its
  chosen region. Check before promising it to a customer.
- **Transport.** This is where harvest-now-decrypt-later actually applies to
  SAG, because a recorded TLS session contains a bearer token. It is not ours
  to fix, so it has to be documented per platform:
  - Cloudflare has offered hybrid post-quantum key agreement (X25519MLKEM768)
    to browsers that support it for some time, and to origins over its own
    network. A Workers deployment therefore gets it largely for free on the
    browser leg.
  - AWS added hybrid key agreement to several services; API Gateway and
    CloudFront coverage should be confirmed for the specific edge in use rather
    than assumed.
  - A self-hosted Node deployment depends on its OpenSSL build and its reverse
    proxy. Node 24 with OpenSSL 3.5 can negotiate ML-KEM hybrids; whether it
    does depends on the proxy in front.

  Action: record the negotiated group for each RESOAuth-operated deployment,
  and re-check when platforms update.
- **Upstream providers.** Microsoft and Google sign their `id_token`s with
  RS256. SAG cannot change that, and it is a bounded exposure: forging an
  upstream `id_token` also requires defeating the nonce binding and the TLS
  channel to the token endpoint, and the token is only accepted for a few
  minutes. Worth tracking, not worth blocking on. SAG's verification path
  already accepts ML-DSA, so no work is needed here when they move.
- **Signature size.** ML-DSA-44 signatures are 2,420 bytes against roughly 64
  for ES256, which makes an `id_token` around 3.5 KB rather than 700 bytes.
  That is fine in a POST body and fine in a cookie, but a relying party that
  puts an `id_token` in a URL or a header will notice. Worth mentioning to
  anybody migrating.
- **Hybrid signatures.** Signing an `id_token` twice, classically and
  post-quantum, is possible but no JOSE standard for it is settled. Publishing
  both keys and letting relying parties choose achieves the same migration
  outcome with less invention, so it has not been attempted.

## Open decisions

`REQUIRE_POST_QUANTUM_SIGNING` stays an option rather than a requirement, and
is off by default - see [ADR 0006](adr/0006-algorithm-agile-signing.md).
Whether a given deployment should set it once the platforms support it more
consistently is a decision for the day that happens rather than now.
