//! `pdtui mcp` — an MCP server over stdio giving an agent control of Proton
//! Drive plus hash-based smart sync (PRD `docs/PRD-mcp-agentic-sync.md`,
//! ADR-0013).
//!
//! The server reuses `pdtui`'s existing keyring session bootstrap unchanged —
//! no new auth surface — constructs the same [`ProtonDriveClient`] the rest of
//! the app uses, and serves the tool catalogue over **stdio only** via `rmcp`
//! (never a listening socket, ADR-0007). Because **stdout is the MCP
//! transport**, this path emits nothing to stdout: all diagnostics go to stderr
//! via the tracing subscriber `main.rs` installs (`with_writer(io::stderr)`).
//!
//! Tool semantics live in [`tools`]; the MCP wiring in [`server`]; the pure,
//! unit-tested glue in [`bridge`].

mod bridge;
mod server;
mod tools;

use std::path::PathBuf;
use std::sync::Arc;

use proton_drive::{
    MaybeNode, NodeUid, ProtonDriveClient, ProtonDriveClientOptions, ProtonDriveConfig,
    ProtonDriveHttpClient, RpgpCrypto,
};
use proton_drive_cache::MemoryCache;
use rmcp::ServiceExt as _;

use crate::account::PdtuiAccount;
use crate::http::{ReqwestHttpClient, SessionAwareHttpClient};
use crate::session::{Session, SessionManager};

const BASE_URL: &str = "https://drive.proton.me/api";

/// Bootstrap the session/client and serve MCP over stdio until stdin closes.
pub async fn run() -> Result<(), String> {
    let ctx = bootstrap().await?;

    let checkpoint_dir = checkpoint_dir();
    if let Err(e) = std::fs::create_dir_all(&checkpoint_dir) {
        // Non-fatal: checkpoints are best-effort; the plan store is in-memory.
        tracing::warn!(
            "could not create checkpoint dir {}: {e}",
            checkpoint_dir.display()
        );
    }
    let max_parallel = ctx.client.config().max_parallel_transfers.max(1);

    let handler = server::DriveMcpServer::new(
        ctx.client,
        ctx.http,
        ctx.root_uid,
        ctx.volume_id,
        checkpoint_dir,
        max_parallel,
    );

    // stdout/stdin are the MCP transport; the tracing subscriber writes to stderr.
    let service = handler
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| format!("failed to start MCP service over stdio: {e}"))?;
    service
        .waiting()
        .await
        .map_err(|e| format!("MCP service terminated abnormally: {e}"))?;
    Ok(())
}

/// The bootstrapped context the server needs.
struct BootstrapCtx {
    client: Arc<ProtonDriveClient>,
    http: Arc<dyn ProtonDriveHttpClient>,
    root_uid: NodeUid,
    volume_id: String,
}

/// Resume the persisted session and assemble a live client, resolving the My
/// Files root + true volume id up front. Mirrors `mvp::build_client` but is
/// silent (no stdout) and additionally returns the transport + volume id the
/// events tool needs. A missing session is a clear "run `pdtui login` first".
async fn bootstrap() -> Result<BootstrapCtx, String> {
    let app_version = format!("external-drive-pdtui@{}-stable", proton_drive::VERSION);
    let transport: Arc<dyn ProtonDriveHttpClient> = Arc::new(
        ReqwestHttpClient::new(BASE_URL, &app_version).map_err(|e| format!("http client: {e}"))?,
    );

    let session = SessionManager::from_keyring(Arc::clone(&transport))
        .await
        .map_err(|e| format!("session resume (run `pdtui login` first): {e}"))?;
    let key_password = session.key_password().await;
    let session = Arc::new(session);

    let http: Arc<dyn ProtonDriveHttpClient> =
        Arc::new(SessionAwareHttpClient::new(transport, Arc::clone(&session)));
    let crypto = Arc::new(RpgpCrypto::new());

    let account = PdtuiAccount::bootstrap(
        Arc::clone(&http),
        Arc::clone(&crypto) as Arc<dyn proton_drive::OpenPgpCrypto>,
        String::new(),
        key_password,
    )
    .await
    .map_err(|e| format!("account bootstrap: {e}"))?;

    let opts = ProtonDriveClientOptions {
        http_client: Arc::clone(&http),
        entities_cache: Arc::new(MemoryCache::<String>::new()),
        crypto_cache: Arc::new(MemoryCache::<proton_drive::CachedCryptoMaterial>::new()),
        account: Arc::new(account),
        openpgp: Arc::clone(&crypto) as Arc<dyn proton_drive::OpenPgpCrypto>,
        srp: crypto as Arc<dyn proton_drive::SrpModule>,
        config: ProtonDriveConfig::default(),
        telemetry: None,
        latest_event_id: None,
    };
    let client = Arc::new(ProtonDriveClient::new(opts));

    let root_uid = match client
        .my_files_root()
        .await
        .map_err(|e| format!("my_files_root: {e}"))?
    {
        MaybeNode::Node(n) => n.uid,
        other => return Err(format!("My Files root is not a live node: {other:?}")),
    };

    // NodeUid.volume_id from the listing endpoints holds a *share id*; the
    // Events API needs the true volume id. Resolve it once at startup.
    let volume_id = proton_drive_core::download::resolve_volume_id(&http, &root_uid.volume_id)
        .await
        .map_err(|e| format!("resolve My Files volume id: {e}"))?;

    Ok(BootstrapCtx {
        client,
        http,
        root_uid,
        volume_id,
    })
}

/// Where remote-snapshot checkpoints live: a sibling of the session file, under
/// the same `pdtui` config directory (`$XDG_CONFIG_HOME/pdtui/mcp-checkpoints/`).
fn checkpoint_dir() -> PathBuf {
    let mut p = Session::config_path();
    p.set_file_name("mcp-checkpoints");
    p
}
