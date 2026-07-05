//! Host-supplied HTTP client trait. Mirrors `client/js/src/interface/httpClient.ts`.
//!
//! The SDK does **not** ship an HTTP impl — `apps/pdtui` provides one over `reqwest`.

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

#[derive(Debug, Clone)]
pub struct JsonRequest {
    pub method: HttpMethod,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct JsonResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[derive(Debug)]
pub struct BlobRequest {
    pub method: HttpMethod,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[async_trait]
pub trait ProtonDriveHttpClient: Send + Sync {
    /// Issue a JSON-shaped request. Implementations must:
    /// - prepend the Proton base URL
    /// - inject `x-pm-appversion`
    /// - retry transient failures with exponential backoff + jitter
    /// - surface `Error::RateLimited` (HTTP 429) with `Retry-After`
    async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse>;

    /// Issue a binary blob request (upload/download blocks).
    async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse>;
}
