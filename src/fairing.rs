//! The `on_request` / `on_ignite` / `on_response` fairing.

use crate::response;
use crate::scan::{GuardEngine, Metadata, Verdict};
use rocket::Data;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::Response;
use rocket::{Build, Rocket};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Screens every request through the Guard engine before routing, and
/// registers the catchers that render the refusals.
///
/// Attach it to the application, then add [`crate::BlockGuard`] (routes
/// without a body) or [`crate::GuardBody`] (routes with one) to the handler
/// signatures that should be protected:
///
/// ```
/// use rocket::{get, routes, Build, Rocket};
/// use rocket_guard_rs::{BlockGuard, GuardFairing, default_config};
///
/// #[get("/hello")]
/// fn hello(_guard: BlockGuard) -> &'static str {
///     "hello"
/// }
///
/// fn rocket() -> Rocket<Build> {
///     rocket::build()
///         .attach(GuardFairing::new(default_config()))
///         .mount("/", routes![hello])
/// }
/// ```
///
/// Why two pieces: a Rocket fairing cannot abort a request (there is no
/// short-circuit return from `on_request`), so the fairing can only record a
/// verdict. Enforcement needs a request guard, the one Rocket extension point
/// that can refuse a request before its handler runs. Rocket's own source
/// makes the same call: request fairings were considered for this and
/// rejected in favor of request guards.
///
/// ## What runs where
///
/// | Phase | Work |
/// |---|---|
/// | `on_ignite` | Manage the engine configuration; register the `403`/`413`/`500` catchers for statuses the application has not claimed |
/// | `on_request` | Scan path, query, and header views; stash the verdict in request-local state |
/// | `on_response` | Rewrite a `404` to the guarded `403` when the stashed verdict is a threat |
///
/// The body view is **not** scanned here. Rocket's `Data::peek` is capped at
/// 512 bytes, so a fairing can only ever see a prefix of the body, and a
/// truncated scan is a bypass vector. Body scanning lives in
/// [`crate::GuardBody`], which owns the data stream and can read to the cap.
///
/// The `on_response` rewrite exists because a threat to a path that matches
/// no route would otherwise answer `404`: no guard runs, so nothing can block
/// it earlier. A `404` is proof that no route handler ran, so rewriting it
/// cannot discard work an application did. Threats that reach a route
/// *without* a guard argument are only scanned, not blocked: in Rocket,
/// protection is per-route, and that is what the guard argument is for.
#[derive(Clone)]
pub struct GuardFairing {
    engine: GuardEngine,
}

impl GuardFairing {
    /// Build the fairing from an engine detection configuration.
    ///
    /// The body cap starts at `config.max_full_scan_bytes` (262,144 bytes in
    /// [`crate::default_config`]), the engine's own full-scan cap.
    #[must_use]
    pub fn new(config: guard_core_engine::detect::DetectConfig) -> Self {
        Self {
            engine: GuardEngine::new(config),
        }
    }

    /// Build the fairing with [`crate::default_config`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(crate::default_config())
    }

    /// Replace the body buffering cap, in bytes.
    ///
    /// A body larger than the cap is refused with `413 Payload Too Large`
    /// rather than forwarded unscanned.
    ///
    /// # Example
    ///
    /// ```
    /// let fairing = rocket_guard_rs::GuardFairing::with_defaults()
    ///     // Refuse bodies larger than 1 MiB with 413.
    ///     .with_body_cap(1_048_576);
    /// # let _ = fairing;
    /// ```
    #[must_use]
    pub fn with_body_cap(mut self, body_cap: usize) -> Self {
        self.engine.body_cap = body_cap;
        self
    }

    /// The configured body buffering cap, in bytes.
    #[cfg(test)]
    pub(crate) const fn engine_body_cap(&self) -> usize {
        self.engine.body_cap
    }

    /// Substitute the detector. Test-only: exercises the fail-secure path.
    #[cfg(test)]
    pub(crate) fn with_detect_fn(mut self, detect_fn: crate::DetectFn) -> Self {
        self.engine.detect_fn = detect_fn;
        self
    }
}

impl std::fmt::Debug for GuardFairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardFairing")
            .field("body_cap", &self.engine.body_cap)
            .finish_non_exhaustive()
    }
}

#[rocket::async_trait]
impl Fairing for GuardFairing {
    fn info(&self) -> Info {
        Info {
            name: "Guard",
            kind: Kind::Ignite | Kind::Request | Kind::Response,
        }
    }

    async fn on_ignite(&self, mut rocket: Rocket<Build>) -> rocket::fairing::Result {
        if rocket.state::<GuardEngine>().is_none() {
            rocket = rocket.manage(self.engine.clone());
        }

        // Rocket aborts the launch when two catchers claim the same code at
        // the same base, so never register over an application's catcher. An
        // application catcher for one of these statuses then renders guard
        // refusals too; make that the application's call, not a launch error.
        let claimed: Vec<u16> = rocket
            .catchers()
            .filter_map(|catcher| catcher.code)
            .collect();
        for catcher in response::guard_catchers() {
            let unclaimed = catcher.code.is_some_and(|code| !claimed.contains(&code));
            if unclaimed {
                rocket = rocket.register("/", vec![catcher]);
            }
        }

        Ok(rocket)
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        let verdict = catch_unwind(AssertUnwindSafe(|| {
            if self.engine.scan_metadata(request) {
                Verdict::Threat
            } else {
                Verdict::Clean
            }
        }))
        .unwrap_or(Verdict::Failed);

        request.local_cache(|| Metadata(Some(verdict)));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        let threat = request.local_cache(|| Metadata(None)).0 == Some(Verdict::Threat);
        if threat && response.status() == Status::NotFound {
            *response = response::blocked_response();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockGuard, FAILURE_MESSAGE};
    use guard_core_engine::detect::{DetectConfig, DetectVerdict};
    use rocket::get;
    use rocket::local::asynchronous::Client;
    use rocket::routes;

    fn panicking_detect(_content: &str, _view: &str, _config: &DetectConfig) -> DetectVerdict {
        panic!("engine exploded");
    }

    #[get("/hello")]
    fn hello(_guard: BlockGuard) -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let fairing = GuardFairing::with_defaults().with_detect_fn(panicking_detect);
        let client = Client::tracked(rocket::build().attach(fairing).mount("/", routes![hello]))
            .await
            .expect("valid rocket");

        let response = client.get("/hello").dispatch().await;
        assert_eq!(response.status(), Status::InternalServerError);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(format!(r#"{{"detail":"{FAILURE_MESSAGE}"}}"#).as_str()),
        );
    }
}
