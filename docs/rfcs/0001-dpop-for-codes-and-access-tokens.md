# 0001. DPoP for authorisation codes and access tokens

Status: Proposed

## Context

A stolen authorisation code is useful to whoever holds it. PKCE already
means the thief also needs the verifier, and a state store means the code
can only be spent once, but neither binds the code to a *key*. RFC 9449
(DPoP) does: the client proves possession of a private key at both the
authorisation and the token endpoint, so a code lifted from a log, a
referrer or a compromised redirect is inert.

## Proposal

A `dpop_jkt` parameter carried on the sealed transaction and into the code,
a `DPoP` header verified at `/token`, and the `cnf.jkt` claim on the access
token so `/userinfo` can check it too. It should be advertised in discovery
(`dpop_signing_alg_values_supported`) so a client can find it, and
negotiated rather than demanded, so no relying party that does not opt in
sees any change.

## Cost

Perhaps a day of work. The awkward parts are clock skew on the proof's
`iat`, and the `jti` replay check, which wants the same state store that
single-use codes already use - one more reason the store earns its keep.
