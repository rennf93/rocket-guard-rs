//! # rocket-guard-rs
//!
//! Application-layer security Fairing for
//! [Rocket](https://github.com/rwf2/Rocket), part of the
//! [Guard ecosystem](https://github.com/rennf93).
//!
//! ## Status: scaffold
//!
//! This crate is an intentionally minimal scaffold. The Guard Rust engine
//! ([guard-core-rs](https://github.com/rennf93/guard-core-rs)) is not yet a
//! published, consumable crate, so there is no integration code here yet.
//! What this scaffold establishes is package metadata, CI governance, and
//! the integration contract documented below, so the engine can be wired in
//! with minimal friction.
//!
//! Per the ecosystem boundary rules, adapter crates hold all framework glue
//! and no security logic: detection, rate limiting, and IP policy live in
//! the engine, never here.
//!
//! ## Planned integration: Rocket `Fairing`
//!
//! Rocket has no middleware chain like tower or actix-service;
//! cross-cutting concerns are attached to the rocket instance as
//! `Fairing`s. The adapter will provide a `GuardFairing` attached with
//! `Rocket::attach`, declared with `Kind::Request | Kind::Response`:
//!
//! 1. `on_request` receives each incoming `Request` and runs the Guard
//!    pipeline (IP reputation, rate limiting, penetration-attempt
//!    detection); the verdict is stashed in request-local state.
//! 2. `on_response`, plus a registered catcher if needed, enforces the
//!    verdict. Rocket fairings cannot abort routing directly, so the exact
//!    short-circuit mechanics (request-local verdict plus catcher) are a
//!    Rocket-specific detail to be finalized when the engine API exists.
//!
//! The adapter will expose the fairing roughly as follows (illustrative
//! only; the engine API does not exist yet):
//!
//! ```ignore
//! // Ignored on purpose: rocket is not a dependency of this scaffold, so
//! // this example cannot compile yet. It documents the shape the
//! // integration will take.
//! use rocket::fairing::{Fairing, Info, Kind};
//! use rocket::{Data, Request, Response};
//!
//! pub struct GuardFairing {
//!     // engine configuration
//! }
//!
//! #[rocket::async_trait]
//! impl Fairing for GuardFairing {
//!     fn info(&self) -> Info {
//!         Info {
//!             name: "Guard",
//!             kind: Kind::Request | Kind::Response,
//!         }
//!     }
//!
//!     async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
//!         // Run the Guard pipeline, stash the verdict in request-local state.
//!     }
//!
//!     async fn on_response<'r>(&self, _req: &'r Request<'_>, res: &mut Response<'r>) {
//!         // Enforce the verdict where a fairing can.
//!     }
//! }
//! ```
//!
//! ## Placeholder API
//!
//! [`add`] exists only so the scaffold has a testable public symbol while
//! the real API surface is designed. It will be removed when the engine
//! integration lands.

/// Placeholder smoke-test symbol for the scaffold.
///
/// It exists only so the crate has a testable public item while the real
/// API surface is designed; it will be removed when the engine integration
/// lands.
///
/// # Example
///
/// ```
/// assert_eq!(rocket_guard_rs::add(2, 2), 4);
/// ```
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
