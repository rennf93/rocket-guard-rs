//! The engine call surface shared by the fairing and the guards.
//!
//! Everything in this module is adapter glue: one [`GuardEngine::detect`] call
//! per request view, plus the request-local slots the fairing and the guards
//! use to hand verdicts to each other (and to the catchers).

use guard_core_engine::detect::DetectConfig;
use rocket::Request;
use rocket::http::uncased::UncasedStr;

/// Header names that are never scanned, mirroring the TypeScript adapters'
/// `EXCLUDED_HEADERS` (plus every `sec-*` header).
///
/// Negotiation and routing headers carry attacker-influenced-but-expected
/// values (`Accept`, `User-Agent`, ...) whose scanning costs false positives
/// without buying coverage: a payload smuggled into them must still survive
/// the path, query, and body views.
pub(crate) const EXCLUDED_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "origin",
    "referer",
];

/// The outcome of one security evaluation, as stashed in request-local state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing tripped the engine.
    Clean,
    /// At least one view was flagged as a threat.
    Threat,
    /// The engine panicked; fail secure.
    Failed,
}

/// Request-local slot written by [`crate::GuardFairing`] during `on_request`.
///
/// A distinct type from [`Enforced`] on purpose: Rocket's request-local cache
/// keeps the _first_ value written for a type, so the fairing's metadata
/// verdict and a guard's later enforcement verdict need separate slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Metadata(pub(crate) Option<Verdict>);

/// Request-local slot written by a guard when it refuses a request.
///
/// This is what lets the registered catchers tell a guard refusal (which gets
/// the ecosystem `{"detail":...}` body) apart from an application error with
/// the same status (which keeps a minimal default body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Enforced(pub(crate) Option<Verdict>);

/// The engine entry point, stored once per application in managed state.
///
/// [`crate::GuardFairing::on_ignite`] manages it (unless the application
/// already managed one), so the fairing and every guard read the same
/// configuration and the same detector.
#[derive(Clone)]
pub(crate) struct GuardEngine {
    /// Detection knobs passed to every engine call.
    pub(crate) config: DetectConfig,
    /// Body buffering cap in bytes, enforced by [`crate::GuardBody`].
    pub(crate) body_cap: usize,
    /// Detector indirection so unit tests can substitute a panicking
    /// detector and exercise the fail-secure path; production builds always
    /// store [`guard_core_engine::detect::detect`].
    #[cfg(test)]
    pub(crate) detect_fn: crate::DetectFn,
}

impl GuardEngine {
    /// Build an engine from a detection configuration.
    ///
    /// The body cap starts at `config.max_full_scan_bytes`, the engine's own
    /// full-scan cap, so a body the engine would fully scan is never rejected
    /// by the adapter for being too large.
    pub(crate) fn new(config: DetectConfig) -> Self {
        Self {
            body_cap: config.max_full_scan_bytes,
            config,
            #[cfg(test)]
            detect_fn: guard_core_engine::detect::detect,
        }
    }

    /// One engine call: `true` when the engine flags `content` in `view`.
    fn flagged(&self, content: &str, view: &str) -> bool {
        #[cfg(test)]
        let verdict = (self.detect_fn)(content, view, &self.config);
        #[cfg(not(test))]
        let verdict = guard_core_engine::detect::detect(content, view, &self.config);
        verdict.is_threat
    }

    /// Scan every metadata view, in the documented order: path, query,
    /// headers. The first view the engine flags wins.
    pub(crate) fn scan_metadata(&self, request: &Request<'_>) -> bool {
        let path = request.uri().path().as_str();
        if path != "/" && self.flagged(path, "url_path") {
            return true;
        }

        if let Some(query) = request.uri().query() {
            let query = query.as_str();
            if !query.is_empty() && self.flagged(query, "query_param") {
                return true;
            }
        }

        for header in request.headers().iter() {
            if is_excluded_header(header.name()) {
                continue;
            }
            if self.flagged(header.value(), "header") {
                return true;
            }
        }

        false
    }

    /// Scan the `request_body` view. An empty (or whitespace-only) body is
    /// not scanned, mirroring the sibling adapters.
    pub(crate) fn scan_body(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        !text.trim().is_empty() && self.flagged(&text, "request_body")
    }
}

/// Whether a header name is on the exclusion list.
///
/// Matching is case-insensitive, so the decision does not depend on the
/// casing the client sent.
pub(crate) fn is_excluded_header(name: &UncasedStr) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.iter().any(|excluded| name == *excluded)
}

/// Read the fairing's metadata verdict, if the fairing ran.
pub(crate) fn metadata_verdict(request: &Request<'_>) -> Option<Verdict> {
    request.local_cache(|| Metadata(None)).0
}

/// Read the enforcement verdict written by a guard, if one refused.
pub(crate) fn enforced_verdict(request: &Request<'_>) -> Option<Verdict> {
    request.local_cache(|| Enforced(None)).0
}

/// Record why a guard is refusing this request, so the catcher can produce
/// the ecosystem's JSON body instead of a generic default.
pub(crate) fn record_enforced(request: &Request<'_>, verdict: Verdict) {
    request.local_cache(|| Enforced(Some(verdict)));
}
