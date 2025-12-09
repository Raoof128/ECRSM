# Contributing Guidelines

Thank you for your interest in improving this educational runtime security monitor. Please follow these steps for contributions:

1. **Discuss**: Open a GitHub issue describing the change or proposal.
2. **Fork & Branch**: Create a feature branch (`feature/<short-title>`).
3. **Coding standards**:
   - Go: run `gofmt` and `go test ./...`.
   - JS/React: run `npm run lint` (if configured) and `npm run build`.
   - eBPF C: keep helpers minimal and safe; avoid unsafe kernel helpers.
4. **Testing**: Add or update tests under `tests/`.
5. **Commits**: Use clear, conventional messages (e.g., `feat: add reverse shell rule`).
6. **PR**: Reference related issues, describe testing performed, and include screenshots for UI changes.

## Code style
- Prefer explicit names and docstrings for every function.
- Handle errors explicitly; avoid silent failures.
- Keep security in mind: no hard-coded secrets, least-privilege assumptions.

## Reporting issues
- Include reproduction steps, expected vs actual behavior, logs if available, and environment details (OS, kernel, Go/Node versions).
