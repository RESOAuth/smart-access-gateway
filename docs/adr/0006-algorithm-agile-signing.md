# 0006. Algorithm-agile signing, with post-quantum support as an option rather than a rewrite

Date: 2026-08-23
Status: Accepted

## Context

An identity provider signs tokens for years, and the algorithms considered
adequate for that change on a longer timeline than any single deployment's
release cycle - post-quantum signatures being the current example.
Committing to one algorithm, or forcing every relying party to move on the
same day, was rejected as unworkable: relying parties integrate against a
specific algorithm and migrate on their own schedule, not SAG's.

## Decision

Build the signing backend as algorithm-agile from the start: one interface
(`src/keys/`) behind local keys, AWS KMS and a Cloudflare HSM Worker, and a
signer *set* (`src/keys/registry.js`) that can hold several keys at once
and publish all of them, with one marked primary. A relying party asks for
a specific algorithm per request, or pins one on its client record;
everybody else keeps getting the primary. This is what makes a migration a
configuration change - add a key as an additional algorithm, let relying
parties move at their own pace, then swap which one is primary - rather
than a coordinated release.

Post-quantum support (ML-DSA) is built on exactly this mechanism rather
than a parallel path: it is simply another algorithm a deployment can add,
published alongside a classical one, discoverable by a relying party
through `urn:sag:post_quantum_signing_supported` in discovery. It stays
optional and off by default, because KMS and HSM runtime support for it is
inconsistent across platforms and regions today.
`REQUIRE_POST_QUANTUM_SIGNING` exists for a deployment that has decided
classical signatures are no longer acceptable and wants that enforced at
start-up - see [0007](0007-require-prefix-for-fail-fast-flags.md).

## Consequences

Confidentiality in the session and transaction path (AES-256-GCM with
HKDF-SHA-256) was deliberately kept out of the asymmetric path entirely, so
none of this migration story touches it - a lattice signing key changes
nothing about how a session is sealed. What this does not reach: transport-
level harvest-now-decrypt-later risk, which is a platform and
TLS-configuration question, not a SAG one - see
[post-quantum.md](../post-quantum.md) for what is and is not done, and why.
