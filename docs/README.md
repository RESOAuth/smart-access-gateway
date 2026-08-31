# SAG documentation

User documentation is published at
[sag.resoauth.dev](https://sag.resoauth.dev). Use the published site when
configuring or operating a release: it covers both RESOAuth's hosted gateway
and self-hosted deployments, and its version picker keeps instructions aligned
with the release being run.

## User documentation

- [Documentation home](https://sag.resoauth.dev) - choose the hosted gateway or
  a self-hosted deployment.
- [Use the hosted gateway](https://sag.resoauth.dev/hosted) - connect an
  application to `auth.resoauth.cloud`.
- [Deploy your own](https://sag.resoauth.dev/self-host/quickstart) - quickstart,
  containers, deployment, multi-region operation, state, and limits.
- [Reference](https://sag.resoauth.dev/reference/configuration) - configuration,
  endpoints, relying parties, upstreams, branding, and profile claims.

The self-hosting and reference Markdown files in this directory are working
copies kept beside the behaviour they describe. They are ported to the
documentation repository and versioned when SAG is released. Keeping them here
also lets source comments link to the relevant explanation without depending
on a website. Do not copy the design notes below to the user documentation.

## Repository documentation

- [limitations.md](limitations.md) - what SAG does not do, and what closes
  each gap.
- [post-quantum.md](post-quantum.md) - where the cryptography stands and how a
  migration runs.
- [best-practices.md](best-practices.md) - evidence for the OpenSSF Best
  Practices passing criteria.
- [security-review.md](security-review.md) - a point-in-time review against
  OWASP, MITRE ATT&CK, and the OpenSSF criteria, with what it found.
- [adr/](adr/README.md) - why SAG's decisions were made, one record each.
- [rfcs/](rfcs/README.md) - proposed but not yet decided, with the reasoning.
- [../test/local-stack/](../test/local-stack/README.md) - a container, workerd,
  and a Lambda against KMS, DynamoDB, and S3, tested together locally.
