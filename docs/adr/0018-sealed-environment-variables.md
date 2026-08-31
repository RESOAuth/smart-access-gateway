# 0018. Any environment variable's value can be a sealed reference into an AWS secret store

Date: 2026-08-31
Status: Accepted

## Context

SAG has no database, so every secret an operator holds - an upstream
client secret, `SAG_SECRET` itself, an SES key - is an environment
variable, in plain text, in whatever the deploy platform's console or
Terraform state happens to be. AWS offers three ways to keep that secret
out of plain text: a KMS-encrypted ciphertext, a Secrets Manager secret, or
an SSM `SecureString` parameter. Several platforms (Lambda's console
encryption helpers among them) already lean on the first of these, but each
does it slightly differently and usually only for Lambda specifically. An
operator running the same build on ECS or a plain EC2 instance had no
equivalent, and SAG's own architecture already signs its own requests to
KMS (`src/keys/awskms.js`) rather than carrying an SDK, so there was no
reason a call to any of the three needed a different mechanism to a sign or
a get-public-key call.

The options were: a Lambda-specific hook using the platform's own
decrypt-at-cold-start convention; a separate suffixed variable per secret,
with code to map one name to the other; or a self-describing value that
any environment variable can hold, resolved the same way regardless of
platform.

## Decision

Any environment variable's value can be one of three sealed forms, resolved
before configuration is parsed:

- `aws:kms:<ciphertext>` - the base64 `aws kms encrypt` produces
- `aws:secretsmanager:<secret id>` - a Secrets Manager secret, by name or ARN
- `aws:ssm:<name>` - an SSM parameter, always requested `WithDecryption`

This lives in `src/keys/sealedEnv.js`, using the same signed-HTTPS call as
the rest of `src/keys/`, so it costs nothing to run on Lambda, ECS, EC2 or a
bare Node process: whichever one hands SAG ambient AWS credentials and
`AWS_REGION` is all it needs. It is wired into `src/context.js` alongside
the signer set and the stores, so the round trip happens once per warm
instance, never per request, and an environment with nothing sealed makes
no AWS call and needs no AWS credentials at all. A failed resolution is
always a startup error; there is no silent fallback to using the reference
as a literal value, so this needed no `REQUIRE_*` flag - see
[0007](0007-require-prefix-for-fail-fast-flags.md).

The suffixed-variable-name approach was rejected because it doubles the
number of variable names an operator has to keep in sync for every sealed
secret, for no benefit over a self-describing value.

`loadConfig` itself refuses to start if any value it is given is still one
of the three sealed forms, rather than treating the reference as the literal
secret. This matters because a shape check alone would not catch the
mistake - a ciphertext blob or a secret ARN is easily long enough to pass,
for example, `SAG_SECRET`'s minimum-length check - so a bypass of
`unsealEnv` (a future code path reading `process.env` directly, a test
building config from a raw env) would otherwise derive real cryptography
from the wrong material with no visible failure at all.

## Consequences

A deployment that wants this can seal any variable, including ones SAG
does not know the name of in advance - a client secret set via
`CLIENT_<SLUG>_SECRET`, for instance - because detection is by value, not
by a fixed list of variable names. The cost is one AWS call at cold start
for each sealed variable, and a hard dependency on the relevant AWS API
being reachable at start-up wherever this is used; a deployment that uses
none of the three forms is entirely unaffected. See
[configuration.md](../configuration.md#sealed-environment-variables).
