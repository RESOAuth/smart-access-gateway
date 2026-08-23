# 0009. Multi-region and multi-cloud key distribution by federating public keys, not sharing private ones

Date: 2026-08-23
Status: Accepted

## Context

One issuer served by more than one running instance - several AWS regions,
several clouds, or both - has to publish a byte-identical JWKS everywhere a
relying party might ask, because a token signed by any instance has to
verify against whichever JWKS a relying party happens to have cached. The
obvious way to get that is to configure the same raw private key into every
instance's signing backend. There is no shared managed HSM or KMS across
clouds, and even within one cloud that means the same private key material
sitting in more than one place - a real step down from "the private key
never leaves an HSM," which the single-instance signing design (see
[0006](0006-algorithm-agile-signing.md)) otherwise holds to exactly.

## Decision

Let each instance keep its own, separate signing key, generated and held in
its own region's KMS or HSM, and federate the *public* half instead.
`PEER_JWKS_URLS` lists an instance's peers; each instance fetches, caches
and merges their published public keys into its own `/jwks.json`, so a
relying party sees the union of every instance's keys no matter which one
it asks, and no private key ever crosses a region or cloud boundary.
Listing a peer is treated explicitly as a full trust decision, not a
convenience: whatever a peer's JWKS returns becomes as fully able to sign
for this issuer as the instance's own keys, so only ever list
infrastructure the same operator actually controls.

A peer that stops answering does not have its keys dropped immediately -
they stay valid for a generous grace period (twice `SESSION_MAX_LIFETIME`
by default) before finally expiring from the cache, because the cost of
keeping a stale-but-correct key a little too long is a few kilobytes of
harmless JWKS; the cost of dropping it too soon is a token that instance
signed while healthy failing verification somewhere, for a reason that
looks nothing like what actually happened, and typically during an
incident.

## Consequences

What federation does not solve: the algorithm *set* still has to be
planned once for the whole deployment rather than per region, because a
region that cannot produce a signature in some algorithm is not helped by
knowing another region's public key for it; and the peer list is an
unchecked, asymmetric configuration - nothing today notices if region A
lists B but B does not list A. Keeping the mesh complete is an operator
discipline. See [multi-region.md](../multi-region.md) for the full
mechanism, the cache backends, and what still has to be identical across
every region regardless of this decision (the master secret, the pairwise
subject salt).
