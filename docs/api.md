# API reference

The public surface of `rocket_guard_rs` `1.0.0`. The full crate documentation
is also in `src/lib.rs` (build it with `cargo doc --open`).

## Fairing

### `GuardFairing`

The Rocket fairing that screens every request and registers the refusal
catchers. Attach it once on `rocket::build()`:

```rust
rocket::build().attach(rocket_guard_rs::GuardFairing::new(config))
```

Attach with `Kind::Ignite | Kind::Request | Kind::Response` (the default
`Kind` set the fairing declares): `on_ignite` registers the `403`/`413`/`500`
catchers, `on_request` scans the path, query, and header views and stashes
the verdict in request-local state, and `on_response` supports the `404` to
`403` rewrite described below.

Constructors and builders:

| Method | Description |
|---|---|
| `GuardFairing::new(config: DetectConfig)` | Build the fairing from an engine `DetectConfig`. The body cap starts at `config.max_full_scan_bytes` |
| `GuardFairing::with_defaults()` | Build the fairing with `default_config()` |
| `.with_body_cap(body_cap: usize)` | Replace the body buffering cap, in bytes. A body larger than the cap is refused with `413` rather than forwarded unscanned |

Routes without a guard argument are only scanned, not blocked: in Rocket,
protection is per-route, and that is what the guard argument is for. When the
verdict is a threat and the request would otherwise answer `404`, the fairing
rewrites the `404` to the guarded `403` so probe traffic never reveals route
inventory.

### Catchers

`guard_catchers() -> Vec<Catcher>` returns the `403`/`413`/`500` catchers
that render refusals as the ecosystem's plain-text error shape. The fairing
registers them itself, skipping any status the application already registered
a catcher for (Rocket treats same-code catchers at the same base as a fatal
collision).

## Guards

### `BlockGuard`

A request guard for routes without a body argument:

```rust
use rocket::get;
use rocket_guard_rs::BlockGuard;

#[get("/health")]
fn health(_guard: BlockGuard) -> &'static str {
    "hello"
}
```

It enforces the verdict stashed by the fairing: a threat answers `403`, a
failed check answers `500`. Fail-secure rule: if the guard cannot find a
verdict, the security system is not running, and the request is refused
rather than passed uninspected.

### `GuardBody`

The scanned request body, usable as a data guard. Buffering, scanning, and
handing the body to the handler are fused into one data guard because
Rocket's `Data` is a one-shot stream:

```rust
use rocket::post;
use rocket_guard_rs::GuardBody;

#[post("/submit", data = "<body>")]
fn submit(body: GuardBody) -> Vec<u8> {
    body.into_inner()
}
```

As a data argument (`data = "<body>"`), it refuses the request on any of the
fairing's metadata views and scans the body itself. The body is buffered up
to the cap configured on `GuardFairing::with_body_cap` (default: the engine's
full-scan cap, 262,144 bytes). Rocket's own per-guard `limits` still apply to
whatever the handler does with the scanned bytes afterwards.

Methods:

| Method | Description |
|---|---|
| `.into_inner() -> Vec<u8>` | Consume the guard and return the scanned bytes |
| `.as_slice() -> &[u8]` | Borrow the scanned bytes |

### `GuardBodyError`

The error type produced when the body cannot be buffered or scanned.

## Configuration

### `default_config()`

Returns the reference default `DetectConfig`:

| Knob | Value |
|---|---|
| `max_content_length` | `10_000` |
| `max_full_scan_bytes` | `262_144` |
| `preserve_attack_patterns` | `true` |
| `semantic_threshold` | `0.7` |
| `threat_score_threshold` | `1.0` |

### `DetectConfig`

Re-exported from `guard_core_engine::detect`. Fields:

| Field | Type | Meaning |
|---|---|---|
| `max_content_length` | `usize` | Semantic budget and truncation budget |
| `max_full_scan_bytes` | `usize` | Preprocessor full-scan cap (also the default body cap) |
| `preserve_attack_patterns` | `bool` | Keep attack patterns in the processed view |
| `semantic_threshold` | `f64` | Semantic analysis threshold |
| `threat_score_threshold` | `f64` | Threat score threshold for a verdict |

## Behavior

### What it inspects

One engine call per request view:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers |
| Body | `request_body` | Buffered by `GuardBody`, capped |

The HTTP method is not scanned.

### Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `403 Forbidden` | `Suspicious activity detected` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The adapter is fail-secure: any failure to complete the security check
answers `500`, never an uninspected passthrough. Engine panics are caught
with `catch_unwind` (note that `panic = "abort"` in a release profile
disables that recovery).

### Constants

Re-exported refusal message bodies:

| Constant | Value |
|---|---|
| `BLOCKED_MESSAGE` | `"Suspicious activity detected"` |
| `OVERSIZE_MESSAGE` | `"Payload too large"` |
| `FAILURE_MESSAGE` | `"Security check failed"` |

### Engine re-exports

`DetectConfig`, `DetectVerdict`, and `Threat` are re-exported from
`guard_core_engine::detect`. A `DetectVerdict` carries `is_threat`, a
`threat_score`, and the list of `Threat` findings (regex or semantic).
