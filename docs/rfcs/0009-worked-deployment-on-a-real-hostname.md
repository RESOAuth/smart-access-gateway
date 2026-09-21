# 0009. A worked deployment on a real hostname

Status: Proposed

## Context

The [local stack](../../test/local-stack/README.md) exercises real runtimes
and stores. It cannot prove public DNS and TLS, production issuer routing,
browser cookie behaviour, registered upstream callbacks, or OTP delivery to
real mail systems.

## Proposal

Deploy the worked relying party and SAG on real HTTPS hostnames using
Cloudflare. Keep an executable, redacted deployment recipe and expected
outcomes in `docs/deployment.md`, with the SAG revision and tested topology.
Use synthetic accounts and external secret storage; do not commit credentials.

Verify the complete deployed contract:

- Discovery, JWKS, redirects, and UserInfo share the configured issuer,
  including an issuer path where supported. Spoofed Host and forwarded
  headers cannot change that identity or trusted redirect targets.
- TLS, Secure cookies, SameSite behaviour, shared and per-RP session scope,
  CORS, sign-in, session reuse, and logout work in supported browsers.
- Microsoft and Google callbacks, tenant restrictions, consent refusal, and
  unsatisfied authentication requirements produce the expected outcome.
- OTP reaches representative mail providers; check sender DNS, SPF, DKIM,
  DMARC, spam placement, resend, expiry, and generic failure messages.
- A qualifying shared store permits one code redemption across instances,
  rejects a duplicate, and denies redemption during a claim-store outage.
- Signing-key rotation retains verification continuity. Document master-secret
  changes separately because they invalidate sealed browser and token state.
  Exercise configuration rollback and confirm logs do not contain credentials.

Record failures and feed reproducible bugs into core tests. Document which
checks require human interaction or external account access. The resulting
example establishes this Cloudflare topology, not untested Lambda or Node
production behaviour.

## Cost

A domain, Cloudflare resources, upstream registrations, email delivery, and
maintenance of the worked example. Allow time for fixes exposed by the real
boundary. Acceptance requires repeatable instructions and evidence for both
successful and refused flows, rather than documentation alone.
