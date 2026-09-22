# rocket-guard-rs

Application-layer security middleware for [Rocket](https://rocket.rs) 0.5, powered by the [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/rennf93).

**Status:** Implemented, version 0.1.0. `GuardFairing`, `BlockGuard`, and `GuardBody` are working Rocket integration, screened by the engine. Not yet published to crates.io: the engine is a local path dependency for now (see [Engine dependency](#engine-dependency)).

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/rennf93/fastapi-guard), [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), [dj-api-guard](https://github.com/rennf93/djapi-guard), [tornado-api-guard](https://github.com/rennf93/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/rennf93/guard-core-rs) with adapters for [tower](https://github.com/rennf93/tower-guard-rs), [axum](https://github.com/rennf93/axum-guard-rs), [actix-web](https://github.com/rennf93/actix-guard-rs), and rocket (this repo)

Per the ecosystem boundary rules, this crate holds framework glue only: every detection decision comes from the engine.

## Wiring: two steps, because Rocket needs two

Rocket has no middleware chain that can abort a request: a fairing's `on_request` cannot short-circuit, and Rocket's own source calls request guards "the correct mechanism" for refusal. The adapter splits the work accordingly:

1. **Attach the fairing.** `GuardFairing` scans the path, query, and header views of every request in `on_request` and stashes the verdict in request-local state; it also registers the `403`/`413`/`500` catchers that render refusals (skipping statuses the application already registered, since Rocket treats same-code catchers at the same base as a fatal collision).
2. **Add a guard argument to each protected route.** `BlockGuard` for routes without a body, `GuardBody` for routes with one. This is the part Rocket cannot automate: protection is per-route by design.

```rust
use rocket::{get, post, routes};
use rocket_guard_rs::{BlockGuard, GuardBody, GuardFairing, default_config};

#[get("/health")]
fn health(_guard: BlockGuard) -> &'static str {
    "ok"
}

#[post("/submit", data = "<body>")]
fn submit(body: GuardBody) -> Vec<u8> {
    body.into_inner()
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::build()
        .attach(GuardFairing::new(default_config()))
        .mount("/", routes![health, submit])
}
```

Routes without either guard argument are scanned but not blocked. The fairing additionally rewrites a `404` to the guarded `403` when the verdict is a threat, so a threat to a path that matches no route does not leak a `404`; a `404` is proof that no handler ran, which is why that rewrite is safe.

The full crate documentation is in [`src/lib.rs`](src/lib.rs) (build it with `cargo doc --open`).

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered by `GuardBody`, capped (see below) |

The HTTP method is not fed to the engine: the engine's `detect(content, context, config)` takes content plus a context, and the reference adapters do not scan the method either.

## Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `403 Forbidden` | `{"detail":"Suspicious activity detected"}` |
| Body exceeds the cap | `413 Payload Too Large` | `{"detail":"Payload too large"}` |
| Body read error or engine panic | `500 Internal Server Error` | `{"detail":"Security check failed"}` |

The bodies mirror the ecosystem's JSON `detail` error shape (same as the Python and TypeScript adapters), but the adapter is deliberately **fail-secure**: unlike the TypeScript adapters, whose check pipeline logs and skips on error, any failure to complete the security check answers `500`, never an uninspected passthrough. A guard with no stashed verdict (fairing not attached) also refuses with `500`.

Engine panics are caught with `catch_unwind`, so a detected panic still produces a response instead of unwinding out of the request. `panic = "abort"` in the release profile disables that recovery.

## Body cap

Rocket streams request bodies to data guards, and a fairing can only peek at the first 512 bytes (`Data::peek` is capped at `PEEK_BYTES`). Scanning a truncated prefix as if it were the body would be a bypass vector, so the body view is scanned by `GuardBody`, which owns the data stream.

Bodies are buffered up to the cap configured on the fairing, defaulting to the engine's full-scan cap (`DetectConfig::max_full_scan_bytes`, 262 144 bytes in the ecosystem default):

```rust
let fairing = rocket_guard_rs::GuardFairing::with_defaults()
    .with_body_cap(1_048_576);
```

A body larger than the cap is rejected with `413` rather than forwarded unscanned. Rocket's own `limits` continue to apply inside handlers; a limit violation raised by Rocket's guards (for example `Json`) is also a `413` error outcome and therefore also gets the `{"detail":"Payload too large"}` body.

## Engine dependency

The engine is consumed as a local path dependency on the `guard-core-rs` workspace (`../guard-core-rs/crates/guard-core-engine`), because `guard-core-rs` has no tagged crates.io release yet. CI checks out `rennf93/guard-core-rs` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `tower-guard-rs` and `actix-guard-rs`. **TODO:** switch to the versioned crate once the engine is tagged and published.

The engine crate is `guard-core-engine` rather than the `guard-core-rs` facade because the facade currently re-exports only `compiler`, `preprocessor`, and `semantic`; `detect` (the entry point this adapter uses) is not re-exported there yet.

## Development

- MSRV: 1.92 (matches guard-core-rs); edition 2024
- Requires a sibling `guard-core-rs` checkout at `../guard-core-rs`

```bash
cargo check --all-targets
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

CI (`.github/workflows/ci.yml`) runs the same checks on stable plus an MSRV 1.92 job, checking out `guard-core-rs` first so the path dependency resolves.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
