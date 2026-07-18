# Contributing to expose

Thanks for your interest in improving expose!

## Getting Started

Requirements: Go 1.26+ and `make`. Optional but recommended: [golangci-lint](https://golangci-lint.run/).

```bash
git clone https://github.com/koltyakov/expose
cd expose
make deps
make test
```

`make help` lists all targets. The most useful during development:

| Target | What it does |
| --- | --- |
| `make test` | Run the test suite |
| `make test-race` | Run tests with the race detector |
| `make cov` | Generate a coverage report |
| `make fmt` / `make vet` / `make lint` | Formatting, vet, and lint checks |
| `make ci` | Everything CI runs, locally |
| `make run-server` / `make run-client` | Run a local server/client for manual testing |

See [docs/local-testing.md](./docs/local-testing.md) for an end-to-end local setup.

## Pull Requests

- Open an issue first for large changes so the approach can be discussed.
- Keep PRs focused — one logical change per PR.
- Run `make ci` before pushing; CI enforces formatting, vet, lint, tests (including `-race`), and a GoReleaser config check.
- Add or update tests for behavior changes. Security-sensitive code (auth, WAF, tunnel transport, server routing) must be covered by tests.
- Update the relevant file in [docs/](./docs/) when behavior or configuration changes.

## Reporting Bugs

Use GitHub issues for bugs and feature requests. For security vulnerabilities, follow [SECURITY.md](./SECURITY.md) instead of opening a public issue.
