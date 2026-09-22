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

Each RFC stands on its own: include the requirements needed to assess and
implement it, without depending on another pending RFC. Reference accepted
ADRs for existing decisions, and say explicitly which decisions the proposal
would change. Link protocol specifications directly where they inform the
proposal.

SAG is pre-release. Proposals may invalidate sessions or in-flight requests and
change client configuration. State any necessary deployment ordering, but do
not add extended migration windows or legacy acceptance without a concrete need.

Keep existing RFC numbers when adding proposals; allocate new numbers after
the highest one in this index. Gaps left by accepted or rejected proposals
are not reused. Numbers identify proposals, not implementation priority.

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
| [0011](0011-lambda-snapstart.md) | Lambda SnapStart with preloaded configuration and restore-safe credentials |
| [0013](0013-single-kid-withdrawal.md) | Withdrawing one signing key across a peered deployment without cache deletion |
| [0015](0015-production-replay-guarantees.md) | Production replay guarantees |
| [0016](0016-trusted-authentication-assurance.md) | Trusted authentication assurance |
| [0017](0017-client-trust-and-assertion-audiences.md) | Client trust and assertion audiences |
| [0018](0018-pushed-authorisation-requests.md) | Pushed authorisation requests |
| [0019](0019-back-channel-logout.md) | Back-channel logout |
| [0020](0020-resource-and-scope-contract.md) | Resource and scope contract |
| [0021](0021-upstream-claim-contracts.md) | Upstream claim contracts |
| [0022](0022-device-authorisation.md) | Device authorisation |

Sign outbound requests to relying parties and upstreams was also on the
backlog this replaced, but it already had a decision -
[ADR 0010](../adr/0010-signed-outbound-requests.md) - so it moved straight
there rather than through here; that ADR's Consequences section is where its
outstanding implementation work is tracked.
