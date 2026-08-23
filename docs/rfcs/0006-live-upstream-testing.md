# 0006. Live upstream testing against Microsoft and Google

Status: Proposed

## Context

Federation is tested against a stub provider that serves a real discovery
document and a genuinely signed `id_token`. Microsoft and Google have not
been exercised for real, and they will have opinions about redirect URI
registration, tenant restrictions and consent screens that a stub does not.

## Proposal

Register a real application with each provider and run the full federation
flow against it, folding whatever it surfaces back into `docs/upstreams.md`
and, where it is a genuine behavioural difference rather than a
configuration gap, into the stub provider used by the rest of the test
suite.

## Cost

No code cost by itself, but needs real tenant registrations with Microsoft
and Google, which are a one-off but ongoing maintenance burden (client
secrets to rotate, consent screens to keep verified).
