//! Static SDK configuration. Mirrors `client/js/src/interface/config.ts`.

#[derive(Debug, Clone)]
pub struct ProtonDriveConfig {
    /// Base URL of the Proton API. Locked to official endpoints in production
    /// `pdtui` builds.
    pub api_base_url: String,

    /// Value injected into the `x-pm-appversion` header. Must follow
    /// `external-drive-{name}@{semver}-{channel}[+suffix]` per Proton's
    /// operational requirements.
    pub app_version: String,

    /// Max concurrent transfers — conservative cap shared with first-party
    /// rate-limit budget. Default 3.
    pub max_parallel_transfers: usize,
}

impl Default for ProtonDriveConfig {
    fn default() -> Self {
        Self {
            api_base_url: "https://drive.proton.me/api".to_owned(),
            app_version: format!("external-drive-pdtui@{}-stable", env!("CARGO_PKG_VERSION")),
            max_parallel_transfers: 3,
        }
    }
}
