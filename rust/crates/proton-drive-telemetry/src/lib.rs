//! Telemetry sink trait. Mirrors `client/js/src/interface/telemetry.ts`.
//!
//! Variants chosen to cover what the JS SDK actually emits — the `pdtui`
//! impl is `NullTelemetry` (drops everything) for personal use.

#![forbid(unsafe_code)]

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricVolumeType {
    Main,
    Photos,
    Shared,
    Device,
}

#[derive(Debug, Clone)]
pub enum MetricEvent {
    Upload {
        size_bytes: u64,
        duration_ms: u64,
        error: Option<String>,
    },
    Download {
        size_bytes: u64,
        duration_ms: u64,
        error: Option<String>,
    },
    DecryptionError {
        field: String,
        detail: String,
    },
    VerificationError {
        field: String,
        detail: String,
    },
    BlockVerificationError {
        detail: String,
        /// Whether retrying the block encryption resolved the integrity
        /// failure. Mirrors JS `UploadTelemetry.logBlockVerificationError`'s
        /// `retryHelped` argument
        /// (`client/js/src/internal/upload/telemetry.ts:29-41`).
        retry_helped: bool,
    },
    ApiRetrySucceeded {
        attempts: u32,
    },
    VolumeEventsSubscriptionsChanged {
        volume_type: MetricVolumeType,
        active_count: u32,
    },
}

#[async_trait]
pub trait Telemetry: Send + Sync {
    async fn emit(&self, event: MetricEvent);
}

/// Drop-everything sink. Suitable for personal-use builds (ADR-0007).
pub struct NullTelemetry;

#[async_trait]
impl Telemetry for NullTelemetry {
    async fn emit(&self, _event: MetricEvent) {}
}
