//! Short-circuit responses and the registered catchers that render them.
//!
//! Rocket guards cannot respond directly: an error outcome is dispatched to
//! the error catcher for its status. The adapter therefore registers catchers
//! for the three statuses its guards can produce, so every refusal carries
//! the ecosystem's error shape (the bare message, `text/plain; charset=utf-8`,
//! same as the Python family).
//!
//! Scoping: the `403` and `500` catchers only emit the guard body when
//! request-local state shows the refusal came from this adapter's guards
//! ([`Enforced`](crate::scan::Enforced) or a stashed metadata verdict);
//! otherwise they fall back to a minimal default body, because Rocket has no
//! public way to delegate to its own default catcher. The `413` catcher is
//! deliberately unscoped: "payload too large" has one meaning regardless of
//! which limit tripped, and Rocket's own `Json` guard maps a limit violation
//! to a `413` error outcome, which then gets the same body.

use crate::scan::{Verdict, enforced_verdict, metadata_verdict};
use rocket::catcher::{BoxFuture, Catcher};
use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::Response;
use std::io::Cursor;

/// Detail message carried by the `403 Forbidden` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500 Internal Server Error`
/// response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

/// Minimal default bodies for statuses a catcher receives without any
/// adapter state on the request.
///
/// Rocket's own default catcher is `pub(crate)`, so there is no way to
/// delegate to it; these keep the status (and content type) honest without
/// trying to reproduce Rocket's templated pages.
const DEFAULT_403: &str = "403 Forbidden";
const DEFAULT_500: &str = "500 Internal Server Error";

/// The catchers this adapter registers, scoped to the base they are passed
/// to.
///
/// [`crate::GuardFairing`] registers these automatically during `on_ignite`,
/// skipping any status the application already registered a catcher for
/// (Rocket treats same-code catchers at the same base as a fatal collision).
/// Register them manually instead when the application attaches no fairing
/// but uses [`crate::BlockGuard`] or [`crate::GuardBody`]:
///
/// ```ignore
/// rocket::build().register("/", rocket_guard_rs::guard_catchers())
/// ```
#[must_use]
pub fn guard_catchers() -> Vec<Catcher> {
    vec![
        Catcher::new(403, forbidden),
        Catcher::new(413, oversize),
        Catcher::new(500, failure),
    ]
}

/// `403` catcher: the guard body when a guard blocked this request, a
/// minimal default otherwise.
fn forbidden<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    let guard_caused = metadata_verdict(request) == Some(Verdict::Threat)
        || enforced_verdict(request) == Some(Verdict::Threat);
    finish(
        status,
        if guard_caused {
            BLOCKED_MESSAGE
        } else {
            DEFAULT_403
        },
    )
}

/// `413` catcher: always the oversize body.
///
/// Unscoped on purpose: a `413` error outcome has one meaning whichever
/// guard or framework limit produced it (Rocket's own `Json` guard maps
/// limit violations to `413`).
fn oversize<'r>(status: Status, _request: &'r Request<'_>) -> BoxFuture<'r> {
    finish(status, OVERSIZE_MESSAGE)
}

/// `500` catcher: the fail-secure body when a guard failed this request, a
/// minimal default otherwise.
fn failure<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    let guard_caused = metadata_verdict(request) == Some(Verdict::Failed)
        || enforced_verdict(request) == Some(Verdict::Failed);
    finish(
        status,
        if guard_caused {
            FAILURE_MESSAGE
        } else {
            DEFAULT_500
        },
    )
}

/// The catcher response: the bare message, `text/plain; charset=utf-8`.
fn finish<'r>(status: Status, message: &'static str) -> BoxFuture<'r> {
    Box::pin(async move {
        Ok(Response::build()
            .status(status)
            .header(ContentType::Plain)
            .sized_body(message.len(), Cursor::new(message.as_bytes().to_vec()))
            .finalize())
    })
}

/// A standalone `403` response with the blocked body, used by
/// [`crate::GuardFairing`] when rewriting unrouted threat responses.
pub(crate) fn blocked_response() -> Response<'static> {
    Response::build()
        .status(Status::Forbidden)
        .header(ContentType::Plain)
        .sized_body(
            BLOCKED_MESSAGE.len(),
            Cursor::new(BLOCKED_MESSAGE.as_bytes().to_vec()),
        )
        .finalize()
}
