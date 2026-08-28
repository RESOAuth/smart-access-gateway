# Contributing

Bug reports, enhancement proposals, documentation fixes, and pull requests are
welcome. Use the GitHub issue tracker for a bug or proposal. Report a suspected
vulnerability through the private route in [SECURITY.md](SECURITY.md), not in a
public issue.

For a substantial change, open an issue first so the interface and operational
cost can be discussed before implementation. Small, self-contained fixes may
go straight to a pull request.

## Pull requests

- Keep the change focused and explain its user-visible effect.
- Add or update automated tests for changed behaviour. Major new functionality
  must have tests before it is merged.
- Run `npm test` locally. There is no build step for the core suite.
- Put platform-independent behaviour in `src/`; keep adapters thin.
- Document every new public environment variable.
- Use British English, Oxford commas, and hyphens in prose and comments.
- Do not add personal or identifying information to examples or fixtures.

Architectural decisions belong in a numbered ADR. An undecided proposal belongs
in `docs/rfcs/`. Comments should explain a non-obvious reason, not repeat code.

By submitting a contribution, you agree that it is licensed under the
repository's AGPL-3.0 licence.
