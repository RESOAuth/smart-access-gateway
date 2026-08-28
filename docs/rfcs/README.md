# RFCs

A pending ADR: a proposal for something SAG does not do yet, written up in
enough detail to build from, but not yet decided in the way an
[ADR](../adr/README.md) is. Anything still too vague to build from lives in
the private, untracked `docs/questions.md` instead - see `.gitignore` - and
graduates here once there is an actual proposal, or straight to `docs/adr/`
if the decision is obvious enough not to need one.

An RFC that is accepted gets a numbered file in `docs/adr/`, written up as a
decision rather than a proposal, and is deleted from here. One that is
rejected is deleted too - unlike an ADR, an RFC is not a historical record,
so nothing is kept once it stops being live.

## Format

Each record is short: **Context** (the problem, and why it is not solved
today), **Proposal** (the shape it would take), **Cost** (what it takes to
build, and what it costs once built - a new dependency, a new failure mode,
ongoing maintenance). An RFC is allowed to leave things open; an ADR is not.

## Index

| # | Proposal |
| --- | --- |
| [0001](0001-dpop-for-codes-and-access-tokens.md) | DPoP for authorisation codes and access tokens |
| [0002](0002-refresh-tokens-backed-by-upstream.md) | Refresh tokens, backed by the upstream token |
| [0003](0003-otp-send-burst-sizing.md) | Whether the OTP send-burst size is right |
| [0004](0004-per-relying-party-otp-policy.md) | Per-relying-party OTP policy |
| [0006](0006-live-upstream-testing.md) | Live upstream testing against Microsoft and Google |
| [0007](0007-screen-reader-accessibility-review.md) | Accessibility review with a real screen reader |
| [0008](0008-translation.md) | Translation of user-facing strings |
| [0009](0009-worked-deployment-on-a-real-hostname.md) | A worked deployment on a real hostname |
| [0010](0010-siem-event-export.md) | Relaying authentication events to a SIEM, one destination per instance |

Sign outbound requests to relying parties and upstreams was also on the
backlog this replaced, but it already had a decision -
[ADR 0010](../adr/0010-signed-outbound-requests.md) - so it moved straight
there rather than through here; that ADR's Consequences section is where its
outstanding implementation work is tracked.
