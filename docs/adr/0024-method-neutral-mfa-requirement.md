# 0024: A method-neutral MFA requirement

## Context

Local and federated authentication contexts name different methods. A local
password and TOTP must not satisfy a request specifically for federated MFA,
but many relying parties need MFA without requiring either source. The demo's
generic **Demand MFA** action previously asked specifically for federation,
which a correctly authenticated local identity could never satisfy.

## Decision

Add `urn:sag:acr:mfa` as a request requirement satisfied by either
`urn:sag:acr:local-mfa` or `urn:sag:acr:federated-mfa`. It does not accept a
local password alone, email OTP alone, or federation without reported MFA.
Explicit method-specific requirements retain their existing boundaries.

Sessions and issued tokens continue to carry the actual method-specific
`acr` and `amr`. SAG never substitutes the generic requirement for evidence
of the method used. Local authentication continues to omit `email_verified`.

Advertise the generic requirement when the instance supports a corresponding
MFA method. Use it for the demo's method-neutral **Demand MFA** action.

## Consequences

Relying parties can request MFA independently of its source while still
inspecting the actual authentication method. No session format, credential
format, or existing requirement changes. A client which specifically needs
federation must continue to ask for a federated context rather than the
generic one.

This does not make every second factor equally strong or phishing-resistant.
Local recovery codes retain their existing MFA semantics, and upstream MFA
still depends on the evidence accepted from that provider.
