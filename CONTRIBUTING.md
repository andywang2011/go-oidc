# Contributing

## Development

1. Fork and clone this repository.
2. Create a feature branch from `master`.
3. Run `go test ./...` and `go vet ./...` before opening a pull request.
4. Keep documentation English-only. Put design constraints in `doc.go`, Quick start code in `example_test.go`, and extra scenarios under `examples/`.

## Pull requests

- One logical change per pull request.
- Include tests for new or changed behavior.
- Update `CHANGELOG.md` under `[Unreleased]` when the public API or behavior changes.
