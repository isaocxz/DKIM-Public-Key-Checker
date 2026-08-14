# AGENTS.md

## Project overview

This repository contains a client-side DKIM public-key checker. The application is implemented as a single `index.html` file and runs entirely in the browser. There is no build step or package manager.

## Working rules

- Keep changes small, focused, and easy to review.
- Use one commit per Issue. Do not combine fixes for multiple Issues in one commit unless the user explicitly approves an exception.
- Keep feature additions and behavior changes separate from refactoring. Do not mix them in the same change unless separating them is impractical and the user agrees.
- Do not stage, commit, push, or create branches unless the user explicitly asks.
- Preserve unrelated modifications and untracked files. Never discard or rewrite user changes to make the worktree clean.
- Inspect the current diff before editing and again before handing off work.
- Keep source and documentation files UTF-8 encoded.
- Do not add or use external libraries, frameworks, CDNs, or package dependencies unless the user explicitly approves them.
- The application may send processed data externally only through DNS-over-HTTPS (DoH) requests required for DNS lookups. User-initiated navigation through an explicitly clicked external link is permitted and is not considered application data transmission. Do not add analytics, telemetry, tracking, error reporting, or calls to any other external service.
- Write code for straightforward human review. Prefer explicit, conventional control flow over clever, compressed, or difficult-to-recognize idioms.
- Add a concise comment when a reviewer cannot readily determine why a statement is necessary or how standards-driven behavior is implemented. Explain intent or constraints rather than restating the code.
- If a requested change would substantially increase the code size or complexity, stop before making the large change and ask the user to confirm the approach. Briefly explain why the growth is necessary, its expected scope, and any smaller alternatives.
- Update `README.md` when behavior, supported algorithms, validation limits, or user-visible terminology changes.

## Standards and correctness

- Treat RFC 6376 as the primary DKIM specification, together with its applicable updates.
- Relevant supporting specifications include RFC 8301, RFC 8463, RFC 8484, RFC 6891, RFC 2045 for DKIM `qp-section`, and RFC 8032 for Ed25519.
- DKIM tag names and registered tag values must follow the case-sensitivity rules in their ABNF. Do not normalize input unless the applicable RFC permits it.
- Preserve the distinction between optional folding whitespace and characters that belong to a tag value.
- For `k=ed25519`, the current implementation validates Base64 decoding and the required 32-byte raw public-key length. It does not validate whether the decoded value is a valid Ed25519 curve point. Keep that limitation explicit in the UI and documentation.
- DNSSEC reporting is based on the resolver's DNS response, including the AD bit. Do not describe it as independent cryptographic validation performed by this application.
- Preserve DNS wire-format semantics when parsing, joining, displaying, or validating DNS data. In particular, do not confuse DNS TXT character-string boundaries with whitespace or content in the resulting TXT record.

## Testing and verification

- Test every feature addition, behavior change, and refactoring. For refactoring, verify that existing observable behavior remains unchanged.
- For every change, run the most focused relevant test first, then check for regressions in adjacent behavior.
- Run `git diff --check` before handing off changes.
- Serve the repository over localhost for browser tests, for example:

  ```powershell
  python -m http.server 8765 --bind 127.0.0.1
  ```

- Use Chrome or the in-app browser to verify user-visible behavior. Do not rely only on static code inspection for UI, DNS, or Web Crypto changes.
- Test direct TXT input where practical. Run the full DNS-backed regression set when the registered DNS fixtures are available.
- When changing `dkim-validation-test-zone.txt`, keep it valid BIND-style zone data that can be imported directly into Cloudflare Authoritative DNS, and preserve the 255-octet limit for each quoted TXT character-string.
- Test each validation rule with a fixture that violates exactly one rule. Keep all other fields valid so that the reason for failure and the expected result remain unambiguous.

## Test data and privacy

- Keep the configured `$ORIGIN` in `dkim-validation-test-zone.txt` unchanged unless the user explicitly requests a different test domain.
- Use the test domain only in test documentation and fixtures. Do not embed it unnecessarily in the application code.
- `DKIM-VALIDATION-TEST-CASES.md` and `dkim-validation-expected-results.tsv` may be local, untracked working files. Do not add or commit them unless the user explicitly asks.
- BIND zone-file syntax and the Route 53 record editor/import formats are not interchangeable. Confirm the target format before rewriting DNS fixtures.
