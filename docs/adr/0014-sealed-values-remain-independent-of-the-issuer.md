# 0014. Sealed values remain independent of the issuer

Date: 2026-08-27
Status: Accepted

## Context

Sealed sessions, transactions, codes, and access tokens are bound to their
purpose, but not to the issuer name. Including the issuer would contain damage
when one master secret is mistakenly reused by two issuers, at the cost of
invalidating every sealed value whenever an issuer is renamed.

## Decision

Do not bind sealed values to the issuer. Treat a unique `SAG_SECRET` per issuer
as an operational invariant, and keep issuer renames independent of session and
transaction encryption.

## Consequences

An issuer rename does not sign everybody out or abandon an in-flight flow.
Reusing a master secret across issuers remains unsafe and is called out in the
operations guide. A suspected reuse requires replacing the secret without a
previous-secret grace period.
