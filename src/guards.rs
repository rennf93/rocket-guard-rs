//! The enforcement guards: `BlockGuard` for requests without a body,
//! `GuardBody` for requests with one.

use crate::scan::{GuardEngine, Verdict, metadata_verdict, record_enforced};
use rocket::data::{Data, FromData, Outcome as DataOutcome, ToByteUnit};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// A request guard that refuses a request the fairing flagged as a threat.
///
/// The fairing scans path, query, and headers in `on_request` and stashes
/// the verdict in request-local state; this guard enforces it:
///
/// | Stashed verdict | Outcome |
/// |---|---|
/// | Clean | `Success`: the handler runs |
/// | Threat | `Error(403)`: `{"detail":"Suspicious activity detected"}` |
/// | Failed (engine panic) | `Error(500)`: `{"detail":"Security check failed"}` |
/// | Missing (fairing not attached) | `Error(500)`: fail-secure |
///
/// Add it as an unused argument to every route without a body argument:
///
/// ```
/// use rocket::get;
/// use rocket_guard_rs::BlockGuard;
///
/// #[get("/hello")]
/// fn hello(_guard: BlockGuard) -> &'static str {
///     "hello"
/// }
/// ```
///
/// Routes with a body argument should use [`GuardBody`] instead, which
/// enforces the same verdict plus its own body scan. Fail-secure rule: if
/// this guard cannot find a verdict, the security system is not running, and
/// the request is refused rather than passed uninspected.
#[derive(Debug)]
pub struct BlockGuard {
    _private: (),
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BlockGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match metadata_verdict(request) {
            Some(Verdict::Clean) => Outcome::Success(Self { _private: () }),
            verdict => {
                let enforced = verdict.unwrap_or(Verdict::Failed);
                record_enforced(request, enforced);
                let status = if enforced == Verdict::Threat {
                    Status::Forbidden
                } else {
                    Status::InternalServerError
                };
                Outcome::Error((status, ()))
            }
        }
    }
}

/// The scanned request body, usable as a data guard.
///
/// Buffering, scanning, and handing the body to the handler are fused into
/// one data guard because Rocket's `Data` is a one-shot stream: an adapter
/// that reads the body must also be the thing that hands it on.
///
/// As a data argument (`data = "<body>"`), it refuses the request on any of
/// the fairing's metadata views *and* scans the body itself:
///
/// ```
/// use rocket::post;
/// use rocket_guard_rs::GuardBody;
///
/// #[post("/submit", data = "<body>")]
/// fn submit(body: GuardBody) -> Vec<u8> {
///     body.into_inner()
/// }
/// ```
///
/// ## Cap
///
/// The body is buffered up to the cap configured on
/// [`GuardFairing::with_body_cap`](crate::GuardFairing::with_body_cap)
/// (default: the engine's full-scan cap, 262,144 bytes). A body over the cap
/// is refused with `413 Payload Too Large` rather than forwarded unscanned:
/// the engine would only ever see a truncated prefix, which would be a
/// bypass vector. This is the adapter's own cap; Rocket's per-guard
/// `limits` (for example `limits = { json = "1 MiB" }`) still apply to
/// whatever the handler does with the scanned bytes afterwards.
///
/// | Situation | Status | Body |
/// |---|---|---|
/// | Engine flags any view | `403 Forbidden` | `{"detail":"Suspicious activity detected"}` |
/// | Body exceeds the cap | `413 Payload Too Large` | `{"detail":"Payload too large"}` |
/// | Body read error or engine panic | `500 Internal Server Error` | `{"detail":"Security check failed"}` |
#[derive(Debug)]
pub struct GuardBody {
    bytes: Vec<u8>,
}

impl GuardBody {
    /// Consume the guard into the raw scanned bytes.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }

    /// The raw scanned bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for GuardBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// The error produced when [`GuardBody`] refuses the request.
///
/// The response body is rendered by the registered catcher, so nothing
/// beyond Rocket's required `Debug` is carried here.
#[derive(Debug)]
pub struct GuardBodyError;

#[rocket::async_trait]
impl<'r> FromData<'r> for GuardBody {
    type Error = GuardBodyError;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> DataOutcome<'r, Self> {
        let Some(engine) = request.rocket().state::<GuardEngine>() else {
            // Fail-secure: a `GuardBody` route without the fairing (or a
            // manually managed engine) means the security system is not
            // running. Refuse rather than pass uninspected.
            return DataOutcome::Error((Status::InternalServerError, GuardBodyError));
        };

        let capped = data
            .open((engine.body_cap as u64).bytes())
            .into_bytes()
            .await;
        let bytes = match capped {
            Ok(capped) if capped.is_complete() => capped.into_inner(),
            // The cap was hit: the engine would only ever see a truncated
            // prefix, so the request is refused, not forwarded unscanned.
            Ok(_) => return DataOutcome::Error((Status::PayloadTooLarge, GuardBodyError)),
            Err(_) => return refused(request, Verdict::Failed, Status::InternalServerError),
        };

        let verdict = catch_unwind(AssertUnwindSafe(|| {
            let metadata = metadata_verdict(request).unwrap_or(Verdict::Clean);
            if matches!(metadata, Verdict::Threat | Verdict::Failed) {
                return metadata;
            }
            if engine.scan_body(&bytes) {
                Verdict::Threat
            } else {
                Verdict::Clean
            }
        }))
        .unwrap_or(Verdict::Failed);

        match verdict {
            Verdict::Clean => DataOutcome::Success(Self { bytes }),
            Verdict::Threat => refused(request, Verdict::Threat, Status::Forbidden),
            Verdict::Failed => refused(request, Verdict::Failed, Status::InternalServerError),
        }
    }
}

/// Record why the request is being refused and map it to an error outcome.
fn refused<'r>(
    request: &Request<'_>,
    verdict: Verdict,
    status: Status,
) -> DataOutcome<'r, GuardBody> {
    record_enforced(request, verdict);
    DataOutcome::Error((status, GuardBodyError))
}
