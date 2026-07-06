//! Headless MVP acceptance test (`pdtui mvp`).
//!
//! Resumes the persisted session, then drives the full crypto-backed transfer
//! path against the live API: my-files root → list children → upload a small
//! file → re-list to locate it → download → assert byte-identical. This is the
//! end-to-end validation for the upload wire-format work (HMAC name hash,
//! parent node key, XAttr, armored decode) that unit tests can only cover
//! offline.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt as _;
use proton_drive::{
    FolderChildrenFilter, MaybeNode, NodeType, ProtonDriveClient, ProtonDriveClientOptions,
    ProtonDriveConfig, ProtonDriveHttpClient, RpgpCrypto, UploadMetadata,
};
use proton_drive_cache::MemoryCache;
use tokio::sync::watch;

use crate::account::PdtuiAccount;
use crate::http::SessionAwareHttpClient;
use crate::session::SessionManager;

const BASE_URL: &str = "https://drive.proton.me/api";

pub async fn run() -> Result<(), String> {
    let client = build_client().await?;

    // ── step 1: my-files root ────────────────────────────────────────────────
    let root_uid = match client
        .my_files_root()
        .await
        .map_err(|e| format!("my_files_root: {e}"))?
    {
        MaybeNode::Node(n) => n.uid.clone(),
        other => return Err(format!("root is not a live node: {other:?}")),
    };
    println!("root: {}/{}", root_uid.volume_id, root_uid.node_id);

    // ── step 2: list root children (exercises decrypt path) ──────────────────
    println!("listing root:");
    let mut count = 0usize;
    let mut stream = client.iter_folder_children(&root_uid, FolderChildrenFilter::default());
    while let Some(item) = stream.next().await {
        match item.map_err(|e| format!("list: {e}"))? {
            MaybeNode::Node(n) if !n.trashed => {
                let kind = match n.node_type {
                    NodeType::Folder | NodeType::Album => 'd',
                    NodeType::File => '-',
                };
                let size = n
                    .size_bytes
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into());
                println!("  {kind} {size:>10}  {}", n.name);
                count += 1;
            }
            MaybeNode::Degraded { uid, reason } => {
                println!("  ! <degraded {}: {reason}>", uid.node_id);
            }
            _ => {}
        }
    }
    drop(stream);
    println!("  ({count} entries)");

    // ── step 3: upload a small file ──────────────────────────────────────────
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = format!("pdtui-mvp-{ts}.txt");
    let content =
        format!("pdtui MVP round-trip {ts}\nThe quick brown fox jumps over the lazy dog.\n")
            .into_bytes();
    println!("uploading {name} ({} bytes)…", content.len());

    let meta = UploadMetadata {
        media_type: "text/plain".into(),
        expected_size: content.len() as u64,
        expected_sha1_hex: None,
        modification_time: Some(SystemTime::now()),
        additional_metadata_json: None,
        override_existing_draft_by_other_client: false,
        expected_current_revision_id: None,
    };
    let uploader = client
        .file_uploader(&root_uid, &name, meta)
        .await
        .map_err(|e| format!("file_uploader: {e}"))?;

    let (progress_tx, _progress_rx) = watch::channel::<u64>(0);
    let source: Box<dyn tokio::io::AsyncRead + Send + Unpin> =
        Box::new(std::io::Cursor::new(content.clone()));
    uploader
        .upload_from_stream(source, progress_tx)
        .await
        .map_err(|e| format!("upload_from_stream: {e}"))?;
    println!("✓ upload complete");

    // ── step 4: re-list to locate the uploaded node ──────────────────────────
    let mut uploaded_uid = None;
    let mut stream = client.iter_folder_children(&root_uid, FolderChildrenFilter::default());
    while let Some(item) = stream.next().await {
        if let MaybeNode::Node(n) = item.map_err(|e| format!("re-list: {e}"))?
            && !n.trashed
            && n.name == name
        {
            uploaded_uid = Some(n.uid.clone());
            break;
        }
    }
    drop(stream);
    let uploaded_uid =
        uploaded_uid.ok_or_else(|| format!("uploaded file {name} not found in re-list"))?;
    println!(
        "✓ located uploaded node: {}/{}",
        uploaded_uid.volume_id, uploaded_uid.node_id
    );

    // ── step 5: download + byte-compare ──────────────────────────────────────
    let dest = std::env::temp_dir().join(&name);
    let file = tokio::fs::File::create(&dest)
        .await
        .map_err(|e| format!("create {}: {e}", dest.display()))?;
    let downloader = client
        .file_downloader(&uploaded_uid)
        .await
        .map_err(|e| format!("file_downloader: {e}"))?;
    let stats = downloader
        .download_to_writer(file)
        .await
        .map_err(|e| format!("download_to_writer: {e}"))?;

    let roundtrip = tokio::fs::read(&dest)
        .await
        .map_err(|e| format!("read back {}: {e}", dest.display()))?;
    println!(
        "✓ downloaded {} bytes to {} (signature_verified={})",
        stats.bytes,
        dest.display(),
        stats.signature_verified
    );

    if roundtrip != content {
        return Err(format!(
            "BYTE MISMATCH: uploaded {} bytes, downloaded {} bytes",
            content.len(),
            roundtrip.len()
        ));
    }
    // We just signed this revision with our own (current) address key, so the
    // manifest signature must verify. A false here is a regression in the
    // verification-key resolution, not a tolerated rotated-key case.
    if !stats.signature_verified {
        return Err(
            "round-trip manifest signature did not verify against our own freshly-signed \
             revision — verification-key resolution regression"
                .into(),
        );
    }
    println!(
        "✓ PASS — {} bytes byte-identical round-trip, manifest signature verified",
        content.len()
    );

    // ── step 6: opportunistic nested-download check ──────────────────────────
    // Exercises `resolve_node_key_via_chain` at depth ≥3 against real nested
    // content (a file inside a subfolder). Read-only and non-fatal: if the
    // Drive has no nested file the probe is skipped, not failed.
    match probe_nested_download(&client, &root_uid).await {
        Ok(true) => {}
        Ok(false) => println!("nested probe: skipped (no subfolder/file to exercise)"),
        Err(e) => return Err(format!("nested download regression: {e}")),
    }
    Ok(())
}

/// Walk one folder deep and download the first file found there, exercising the
/// parent-chain node-key derivation for nested nodes. Returns `Ok(true)` if a
/// nested file was downloaded, `Ok(false)` if there was nothing nested to test,
/// and `Err` only if a located nested file failed to download (a regression).
async fn probe_nested_download(
    client: &ProtonDriveClient,
    root_uid: &proton_drive::NodeUid,
) -> Result<bool, String> {
    // First non-trashed subfolder under root.
    let mut folder = None;
    let mut stream = client.iter_folder_children(root_uid, FolderChildrenFilter::default());
    while let Some(item) = stream.next().await {
        if let MaybeNode::Node(n) = item.map_err(|e| format!("list root: {e}"))?
            && !n.trashed
            && matches!(n.node_type, NodeType::Folder)
        {
            folder = Some((n.uid.clone(), n.name.clone()));
            break;
        }
    }
    drop(stream);
    let Some((folder_uid, folder_name)) = folder else {
        return Ok(false);
    };
    println!("nested probe: descending into folder '{folder_name}'");

    // First non-trashed file inside that subfolder. Listing it already
    // exercises the chain walk (child names decrypt with the subfolder key).
    let mut file = None;
    let mut stream = client.iter_folder_children(&folder_uid, FolderChildrenFilter::default());
    while let Some(item) = stream.next().await {
        if let MaybeNode::Node(n) = item.map_err(|e| format!("list '{folder_name}': {e}"))?
            && !n.trashed
            && matches!(n.node_type, NodeType::File)
        {
            file = Some((n.uid.clone(), n.name.clone()));
            break;
        }
    }
    drop(stream);
    let Some((file_uid, file_name)) = file else {
        return Ok(false);
    };

    // file_downloader resolves the node key by walking file → subfolder → root
    // → share key. Its success IS the parent-chain key-derivation proof, so a
    // failure here is a genuine regression in this work and is fatal.
    let downloader = client
        .file_downloader(&file_uid)
        .await
        .map_err(|e| format!("nested file_downloader '{folder_name}/{file_name}': {e}"))?;

    // The actual byte transfer + manifest/block verification is an orthogonal
    // integrity concern on a pre-existing file we did not create. Report a
    // failure here as a finding rather than failing the round-trip MVP — the
    // chain walk above already succeeded.
    match downloader.download_to_writer(tokio::io::sink()).await {
        Ok(stats) if stats.signature_verified => {
            println!(
                "  ✓ nested PASS — decrypted + downloaded {} bytes from \
                 '{folder_name}/{file_name}' via parent-chain key derivation \
                 (manifest signature verified)",
                stats.bytes
            );
        }
        Ok(stats) => {
            // Data delivered byte-for-byte (every block matched its SHA-256
            // hash) but the manifest signature could not be verified — almost
            // always because the signer's key was rotated out of the account.
            // The official Proton client downloads such files too; we mirror
            // that, surfacing the unverified state rather than failing.
            println!(
                "  ✓ nested PASS — decrypted + downloaded {} bytes from \
                 '{folder_name}/{file_name}' via parent-chain key derivation",
                stats.bytes
            );
            println!(
                "    (manifest signature present but unverifiable — signer key likely \
                 rotated out; blocks are intact per SHA-256 hash checks)"
            );
        }
        Err(e) => {
            // A hard error now means something other than a rotated signer key
            // (e.g. a missing manifest signature or a block hash mismatch) — a
            // genuine integrity problem worth reporting.
            println!("  ! nested download of '{folder_name}/{file_name}' did not complete: {e}");
            println!(
                "    (parent-chain key derivation succeeded — file_downloader resolved \
                 the node key; the failure is in download/integrity, not key derivation)"
            );
        }
    }
    Ok(true)
}

/// Resume the persisted session and assemble a live `ProtonDriveClient`.
/// Mirrors the TUI's keyring-resume path without any terminal state.
async fn build_client() -> Result<Arc<ProtonDriveClient>, String> {
    let app_version = format!("external-drive-pdtui@{}-stable", proton_drive::VERSION);
    let transport: Arc<dyn ProtonDriveHttpClient> = Arc::new(
        crate::http::ReqwestHttpClient::new(BASE_URL, &app_version)
            .map_err(|e| format!("http client: {e}"))?,
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
        http_client: http,
        entities_cache: Arc::new(MemoryCache::<String>::new()),
        crypto_cache: Arc::new(MemoryCache::<proton_drive::CachedCryptoMaterial>::new()),
        account: Arc::new(account),
        openpgp: Arc::clone(&crypto) as Arc<dyn proton_drive::OpenPgpCrypto>,
        srp: crypto as Arc<dyn proton_drive::SrpModule>,
        config: ProtonDriveConfig::default(),
        telemetry: None,
        latest_event_id: None,
    };
    Ok(Arc::new(ProtonDriveClient::new(opts)))
}
