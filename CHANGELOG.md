# Changelog

All notable changes to this project.

## [Unreleased]

### Added

- Optional global IP gate (`GuardFairing::with_ip_gate` over the new engine `IpGateConfig`): `whitelist`, `blacklist`, and `exempt_ips` lists parsed once at startup (invalid entry is a config error, fail closed), evaluated in `on_request` before the metadata scan on the request's client IP - a blacklisted client IP, or one a non-empty `whitelist` matches neither directly nor through `exempt_ips`, is refused with `403 Forbidden`, including the unrouted-path `404` rewrite so probe traffic never reveals route inventory. `exempt_ips` is the skip-list for known-friendly automation: it sets the same skip state a whitelist match sets but never adds a deny path and never opens the whitelist gate; the blacklist and detection still apply to exempt IPs. Requests without a client IP (Rocket's local test client) are not attributed and still screened by detection

### Changed

- The request body is no longer scanned as one lossy blob: it is routed by content type through the engine's body-value extraction (guard-core 4.0.4 parity, upstream commit 5f399234), and every extracted value is scanned through the normal detect path with its reference context - urlencoded field values under `request_body:form_field`, multipart part entries (label scan, `filename="..."` entry with RFC 2231 handling, raw part headers, payload) under `request_body:multipart_field`, embedded JSON leaves under the `:embedded_json` suffix, JSON mongo operator keys (`$where`, `$ne`, ...) as direct `nosql` hits, and the whole-body blob only as the fallback for plain or unparseable bodies
- Binary-dense multipart file-part payloads are reduced to printable runs of at least `detection_binary_min_run_length` (default 16) before pattern scanning, so compressed upload bytes stop producing attack-shaped matches while text embedded in uploads still scans in full; text uploads, text parts without a filename, and whole-body fallback scans keep their full scan

## [1.0.0] - 2026-09-24

### Added

- First stable release of `rocket-guard-rs` 1.0.0: application-layer security Fairing for Rocket 0.5, powered by `guard-core-engine` 4.0.4 (17/17 checks parity with guard-core 4.0.4, binary-noise gates)
- Guard Fairing: one engine call per request view (path, query string, headers, buffered body), 403/413/500 fail-secure responses with the ecosystem JSON `detail` shape, configurable body cap (default: engine full-scan cap), `catch_unwind` panic recovery
- Example apps: `examples/simple_app` and `examples/advanced_app` with Dockerfiles and docker-compose smoke stacks
- Dockerized live smoke workflow (`.github/workflows/live-smoke.yml`): compose run of `simple_app` with curl assertions of real engine behavior (XSS block, traversal block, 413 body cap, passthrough)
- Upstream drift guard (`.github/workflows/upstream-drift.yml`): daily test suite run against `guard-core-rs@master`
- Security audit workflow (`cargo deny`), release gate (fmt/clippy/test at tag on stable and MSRV 1.92, tag/version consistency), automated crates.io publish on GitHub release via `CARGO_REGISTRY_TOKEN`
- `Makefile` (`install`, `test`, `lint`, `fix`, `bump-version`, `clean`) and `.github/scripts/bump_version.py` (stdlib-only version bump across the crate, example pins, `Cargo.lock`, and a CHANGELOG scaffold)

### Changed

- `guard-core-engine` dependency pinned to the published 4.0.4 release (path dep kept for local builds and CI against a sibling `guard-core-rs` checkout)

## [Unreleased]

### Changed

- 403/413/500 short-circuit responses now carry the bare message (`Suspicious activity detected`, `Payload too large`, `Security check failed`) as `text/plain; charset=utf-8`, matching the Python family's block-response convention, instead of the JSON `{"detail":"..."}` shape
