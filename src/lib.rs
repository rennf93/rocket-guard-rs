//! # rocket-guard-rs
//!
//! Application-layer security middleware for
//! [Rocket](https://rocket.rs) 0.5, powered by the
//! [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection
//! engine. Part of the [Guard ecosystem](https://github.com/rennf93).
//!
//! ## Status: implemented (v0.1.0)
//!
//! [`GuardFairing`] screens every request through the engine,
//! [`BlockGuard`] and [`GuardBody`] enforce the verdict before a route
//! handler runs. The engine is wired in through `guard-core-engine` (a path
//! dependency until the engine is tagged and published). Per the ecosystem
//! boundary rules, this adapter holds framework glue only: every detection
//! decision comes from the engine.
//!
//! ## Wiring: two steps, because Rocket needs two
//!
//! Rocket has no middleware chain that can abort a request. A fairing's
//! `on_request` cannot short-circuit (there is no outcome return), and a
//! request guard cannot read bodies. Rocket's own source rejects the idea of
//! making request fairings abortable, calling request guards "the correct
//! mechanism". The adapter therefore splits the work the way Rocket
//! requires:
//!
//! 1. **Attach [`GuardFairing`]** (`Kind::Ignite | Kind::Request |
//!    Kind::Response`). Its `on_request` scans the path, query, and header
//!    views and stashes the verdict in request-local state. Its `on_ignite`
//!    registers the `403`/`413`/`500` catchers that render refusals as the
//!    ecosystem's plain-text error shape (skipping any status the application
//!    already registered a catcher for, because Rocket treats same-code
//!    catchers at the same base as a fatal collision).
//! 2. **Add a guard argument to each protected route**: [`BlockGuard`] for
//!    routes without a body, [`GuardBody`] for routes with one. This is the
//!    part Rocket cannot do for you: protection is per-route, and the guard
//!    argument is Rocket's own mechanism for it.
//!
//! ```no_run
//! use rocket::{get, post, routes};
//! use rocket_guard_rs::{BlockGuard, GuardBody, GuardFairing, default_config};
//!
//! #[get("/health")]
//! fn health(_guard: BlockGuard) -> &'static str {
//!     "ok"
//! }
//!
//! #[post("/submit", data = "<body>")]
//! fn submit(body: GuardBody) -> Vec<u8> {
//!     body.into_inner()
//! }
//!
//! #[rocket::launch]
//! fn rocket() -> _ {
//!     rocket::build()
//!         .attach(GuardFairing::new(default_config()))
//!         .mount("/", routes![health, submit])
//! }
//! ```
//!
//! Routes without either guard argument are scanned but not blocked; the
//! fairing additionally rewrites a `404` to the guarded `403` when the
//! verdict is a threat, so a threat to a path that matches no route does not
//! leak a `404`. A `404` is proof that no handler ran, which is why that
//! rewrite is safe; a route that *did* run cannot be un-run, so the guard
//! argument is the only real enforcement point.
//!
//! ## What it inspects
//!
//! One engine call per request view, mirroring the mapping used by the
//! sibling adapters (`tower-guard-rs`, `actix-guard-rs`, `guard-core-ts`):
//!
//! | Request part | Engine context | Notes |
//! |---|---|---|
//! | Path | `url_path` | Skipped for `/` |
//! | Query string | `query_param` | Skipped when empty |
//! | Header values | `header` | Skips `sec-*` and hop-by-hop/negotiation headers (see `EXCLUDED_HEADERS` in `src/scan.rs`) |
//! | Body | `request_body` | Buffered by [`GuardBody`], capped (see below) |
//!
//! The HTTP method is not fed to the engine: the engine's `detect` signature
//! takes content plus a context, and the reference adapters do not scan the
//! method either.
//!
//! ## Body scanning and the cap
//!
//! Rocket streams request bodies and hands them to a route's data guard; a
//! fairing can only peek at the first 512 bytes (`Data::peek` is capped at
//! `PEEK_BYTES`). Scanning a truncated prefix as if it were the body would be
//! a bypass vector, so the body view is scanned by [`GuardBody`], which owns
//! the data stream.
//!
//! Bodies are buffered up to the cap configured on
//! [`GuardFairing::with_body_cap`], defaulting to the engine's full-scan cap
//! (`DetectConfig::max_full_scan_bytes`, 262,144 bytes in the ecosystem
//! default). A request whose body exceeds the cap is refused with
//! `413 Payload Too Large` rather than forwarded unscanned. Rocket's own
//! `limits` continue to apply inside handlers; a limit violation raised by
//! Rocket's guards (for example `Json`) is also a `413` error outcome, and
//! therefore also gets the `Payload too large` body.
//!
//! ## Responses
//!
//! | Situation | Status | Body |
//! |---|---|---|
//! | Engine flags a view | `403 Forbidden` | `Suspicious activity detected` |
//! | Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
//! | Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |
//!
//! These bodies follow the ecosystem's plain-text convention (the bare
//! message, `text/plain; charset=utf-8`, same as the Python family)
//! but the adapter is deliberately **fail-secure**, unlike the TypeScript
//! adapters whose check pipeline logs and skips on error: any failure to
//! complete the security check results in `500`, never in an uninspected
//! passthrough.
//!
//! A panic is caught with [`std::panic::catch_unwind`], so the default panic
//! hook still prints. `panic = "abort"` in the release profile disables that
//! recovery, because the process dies before the guard can respond.

mod fairing;
mod guards;
mod response;
mod scan;

pub use crate::fairing::GuardFairing;
pub use crate::guards::{BlockGuard, GuardBody, GuardBodyError};
pub use crate::response::{BLOCKED_MESSAGE, FAILURE_MESSAGE, OVERSIZE_MESSAGE, guard_catchers};
pub use guard_core_engine::detect::{DetectConfig, DetectVerdict, Threat};

/// Engine entry point stored in the fairing.
///
/// Indirection exists so unit tests can substitute a panicking detector and
/// exercise the fail-secure path; production builds always call
/// [`guard_core_engine::detect::detect`].
#[cfg(test)]
pub(crate) type DetectFn = fn(&str, &str, &DetectConfig) -> DetectVerdict;

/// Reference default detection configuration.
///
/// The engine's [`DetectConfig`] carries no `Default` impl, so the adapter
/// pins the ecosystem defaults here. They are the values the conformance
/// corpus records for the reference implementation:
///
/// | Knob | Value |
/// |---|---|
/// | `max_content_length` | `10_000` |
/// | `max_full_scan_bytes` | `262_144` |
/// | `preserve_attack_patterns` | `true` |
/// | `semantic_threshold` | `0.7` |
/// | `threat_score_threshold` | `1.0` |
///
/// # Example
///
/// ```
/// let config = rocket_guard_rs::default_config();
/// let fairing = rocket_guard_rs::GuardFairing::new(config);
/// # let _ = fairing;
/// ```
#[must_use]
pub const fn default_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_corpus_knobs() {
        let config = default_config();
        assert_eq!(config.max_content_length, 10_000);
        assert_eq!(config.max_full_scan_bytes, 262_144);
        assert!(config.preserve_attack_patterns);
        assert!((config.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.threat_score_threshold - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn body_cap_defaults_to_full_scan_cap_and_is_overridable() {
        let fairing = GuardFairing::with_defaults();
        assert_eq!(fairing.engine_body_cap(), 262_144);
        let fairing = fairing.with_body_cap(1024);
        assert_eq!(fairing.engine_body_cap(), 1024);
    }
}
