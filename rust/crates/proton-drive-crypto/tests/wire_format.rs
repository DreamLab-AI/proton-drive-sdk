//! Wire-format validation tests (ADR-0012, milestone MB).
//!
//! These tests load JS-encoded SEIPDv1 fixtures from `tests/fixtures/wire/`
//! and validate that the Rust crypto layer can decrypt and verify them.
//! A pure rpgp self-roundtrip proves internal consistency only; these tests
//! prove interoperability with the OpenPGP.js path used by the Proton JS SDK.
//!
//! The wrong-signer test (`wire_wrong_signer_is_rejected`, test 3 below) is
//! **not** ignored: the C1 fix (ADR-0012) landed — `decrypt_and_verify`
//! inspects the individual `VerificationResult` variants rather than
//! collapsing a non-empty `verify_nested` `Ok` to `VerificationStatus::Ok`,
//! so it correctly asserts `VerificationStatus::SignatureWrongSigner`.
//!
//! The only `#[ignore]`d test in this file is
//! `wire_rust_encrypted_decryptable_by_node` (a Rust-encrypts /
//! Node-decrypts round-trip), and it is ignored purely because it shells out
//! to `node` + the `openpgp` npm package, which CI does not provision — not
//! because of any known bug. Run it manually with `cargo test -- --ignored`
//! once `tests/fixtures/wire/node_modules` is populated (see README.md).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cloned_ref_to_slice_refs
)]

use proton_drive_crypto::{
    CryptoError, EncryptOptions, OpenPgpCrypto, PrivateKey, PublicKey, RpgpCrypto,
    VerificationStatus,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

// ── helpers ───────────────────────────────────────────────────────────────────

fn fixture_dir() -> PathBuf {
    // Integration tests run with cwd = workspace root (rust/) or crate root.
    // Try workspace-relative first.
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/wire"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/wire"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.canonicalize().unwrap();
        }
    }
    // Fall back — the test will fail with a clear file-not-found error.
    candidates[0].clone()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {name} not found at {}: {e}", path.display()))
}

fn fixture_str(name: &str) -> String {
    String::from_utf8(fixture(name)).expect("fixture is valid UTF-8")
}

// ── shared test state ─────────────────────────────────────────────────────────

struct Fixtures {
    /// Full PKESK + SEIPD ciphertext, JS-encoded.
    signed_bin: Vec<u8>,
    /// Expected plaintext (256 deterministic bytes).
    plaintext: Vec<u8>,
    /// Armored private key for decryption (empty passphrase).
    priv_key: PrivateKey,
    /// Armored public key for the signer.
    signer_pub: PublicKey,
}

async fn load_fixtures(crypto: &RpgpCrypto) -> Fixtures {
    let key_priv_armored = fixture_str("key_priv.asc");
    let signer_pub_armored = fixture_str("signer_pub.asc");

    // The private key uses an empty passphrase (test fixture).
    let priv_key = crypto
        .decrypt_key(&key_priv_armored, "")
        .await
        .expect("decrypt_key with empty passphrase");

    Fixtures {
        signed_bin: fixture("seipdv1_signed.bin"),
        plaintext: fixture("seipdv1_signed.plaintext.bin"),
        priv_key,
        signer_pub: PublicKey {
            armored: signer_pub_armored,
            fingerprint_hex: String::new(), // not used by verify path
        },
    }
}

// ── test 1: happy path — decrypt + verify JS-encoded SEIPDv1 ──────────────────

/// Rust decrypts a JS-encoded SEIPDv1 message and verifies the signature.
/// Both the plaintext bytes and the verification status must be correct.
#[tokio::test]
async fn wire_js_encrypted_decrypts_and_verifies() {
    let crypto = RpgpCrypto::new();
    let fx = load_fixtures(&crypto).await;

    // Step 1: extract the session key from the PKESK packet.
    let session_key = crypto
        .decrypt_session_key(&fx.signed_bin, &[fx.priv_key.clone()])
        .await
        .expect("decrypt_session_key");

    // Step 2: decrypt and verify signature.
    let (decrypted, status) = crypto
        .decrypt_and_verify(&fx.signed_bin, &session_key, &[fx.signer_pub.clone()])
        .await
        .expect("decrypt_and_verify");

    // Plaintext must be byte-identical to the committed fixture.
    assert_eq!(
        decrypted, fx.plaintext,
        "decrypted plaintext does not match seipdv1_signed.plaintext.bin"
    );

    // SHA-256 must match meta.json for belt-and-suspenders.
    let meta_raw = fixture_str("seipdv1_signed.meta.json");
    let meta: serde_json::Value = serde_json::from_str(&meta_raw).expect("valid JSON");
    let expected_sha256 = meta["plaintext_sha256"].as_str().expect("sha256 field");
    let actual_sha256 = hex::encode(Sha256::digest(&decrypted));
    assert_eq!(
        actual_sha256, expected_sha256,
        "plaintext SHA-256 mismatch vs meta.json"
    );

    assert_eq!(
        status,
        VerificationStatus::Ok,
        "expected Ok but got {status:?}"
    );
}

// ── test 2: tampered ciphertext must NOT silently decrypt ─────────────────────

/// A tampered SEIPD body must not produce a successful decryption.
/// rpgp enforces the MDC (SHA-1 integrity check) on SEIPDv1 packets;
/// a flipped body byte must cause an error, not silent garbage output.
#[tokio::test]
async fn wire_tampered_ciphertext_is_rejected() {
    let crypto = RpgpCrypto::new();
    let fx = load_fixtures(&crypto).await;
    let tampered = fixture("seipdv1_tampered.bin");

    // Session key decryption targets the PKESK packet which is unchanged —
    // it should still succeed (the tamper is in the SEIPD body, not PKESK).
    let session_key = crypto
        .decrypt_session_key(&tampered, &[fx.priv_key.clone()])
        .await
        .expect("session key from tampered message — PKESK is untouched");

    // decrypt_and_verify must fail with an integrity error, NOT return plaintext.
    let result = crypto
        .decrypt_and_verify(&tampered, &session_key, &[fx.signer_pub.clone()])
        .await;

    assert!(
        result.is_err(),
        "expected Err for tampered ciphertext, got Ok({:?})",
        result.map(|(pt, st)| (pt.len(), st))
    );

    // The error must be a Decrypt variant (MDC failure), not a key error etc.
    match result.unwrap_err() {
        CryptoError::Decrypt(_) => {} // expected
        other => panic!("expected CryptoError::Decrypt, got {other:?}"),
    }
}

// ── test 3: wrong signer fixture — verify rejects unknown key ─────────────────

/// The `seipdv1_wrong_signer.bin` fixture was signed by a throwaway key
/// whose public key is NOT in `signer_pub.asc`.  The plaintext should still
/// decrypt correctly (the encryption key is unchanged), but the verification
/// status must not be `Ok`.
///
/// `decrypt_and_verify` inspects the individual `VerificationResult` variants:
/// a present-but-unvalidated signature maps to `SignatureWrongSigner`, not
/// `Ok`.  This is the security fix for the defect formerly tracked by ADR-0012.
#[tokio::test]
async fn wire_wrong_signer_is_rejected() {
    let crypto = RpgpCrypto::new();
    let fx = load_fixtures(&crypto).await;
    let wrong_signer_bin = fixture("seipdv1_wrong_signer.bin");

    let session_key = crypto
        .decrypt_session_key(&wrong_signer_bin, &[fx.priv_key.clone()])
        .await
        .expect("decrypt_session_key");

    let (decrypted, status) = crypto
        .decrypt_and_verify(&wrong_signer_bin, &session_key, &[fx.signer_pub.clone()])
        .await
        .expect("decrypt_and_verify should succeed — encryption key is correct");

    // The plaintext should still decrypt correctly even with a bad signer.
    assert_eq!(
        decrypted, fx.plaintext,
        "plaintext bytes should match despite wrong signer"
    );

    // Verification must NOT return Ok — we don't have the signer's public key.
    assert_ne!(
        status,
        VerificationStatus::Ok,
        "wrong-signer verification should not return Ok"
    );
    assert_eq!(
        status,
        VerificationStatus::SignatureWrongSigner,
        "expected SignatureWrongSigner, got {status:?}"
    );
}

// ── test 4: compressed + signed fixture — decompress before verify ───────────

/// `seipdv1_signed_compressed.bin`'s SEIPD wraps an OpenPGP-compressed (ZIP)
/// packet around the signed literal — exactly the shape JS produces for
/// ExtendedAttributes (`compress: true`, see
/// reference/js/sdk/src/crypto/driveCrypto.ts:556
/// `encryptExtendedAttributes` -> openPGPCrypto.ts:124-132
/// `encryptAndSignArmored`). Before the `finalize_decrypted` fix this either
/// mis-verified the signature (rpgp's `verify_nested` refuses a
/// `Message::Compressed`) or returned corrupted (still-compressed)
/// "plaintext"; both are exercised here with real, non-empty verification
/// keys against a validly-signed payload.
#[tokio::test]
async fn wire_compressed_signed_decrypts_and_verifies() {
    let crypto = RpgpCrypto::new();
    let fx = load_fixtures(&crypto).await;
    let compressed_bin = fixture("seipdv1_signed_compressed.bin");

    let session_key = crypto
        .decrypt_session_key(&compressed_bin, &[fx.priv_key.clone()])
        .await
        .expect("decrypt_session_key");

    let (decrypted, status) = crypto
        .decrypt_and_verify(&compressed_bin, &session_key, &[fx.signer_pub.clone()])
        .await
        .expect("decrypt_and_verify");

    // Plaintext must be byte-identical to the committed fixture — i.e.
    // actually decompressed, not the raw compressed bytes.
    assert_eq!(
        decrypted, fx.plaintext,
        "decompressed plaintext does not match seipdv1_signed.plaintext.bin"
    );

    let meta_raw = fixture_str("seipdv1_signed_compressed.meta.json");
    let meta: serde_json::Value = serde_json::from_str(&meta_raw).expect("valid JSON");
    let expected_sha256 = meta["plaintext_sha256"].as_str().expect("sha256 field");
    let actual_sha256 = hex::encode(Sha256::digest(&decrypted));
    assert_eq!(
        actual_sha256, expected_sha256,
        "plaintext SHA-256 mismatch vs meta.json"
    );

    // With real verification keys against a validly-signed compressed
    // payload, the status must be Ok — not SignatureInvalid (verify_nested
    // erroring on an undecompressed Message::Compressed) and not NoSignature.
    assert_eq!(
        status,
        VerificationStatus::Ok,
        "expected Ok but got {status:?}"
    );
}

// ── test 5: truncated ciphertext — short read must not silently decrypt ──────

/// A message cut off mid-`SEIPD`-body (simulating a network interruption /
/// short read) must not produce a successful decryption. The PKESK packet
/// is untouched (the cut lands well inside the SEIPD body), so session-key
/// extraction still succeeds; the final decrypt+verify step must fail
/// cleanly instead of panicking or returning truncated "plaintext".
#[tokio::test]
async fn wire_truncated_ciphertext_is_rejected() {
    let crypto = RpgpCrypto::new();
    let fx = load_fixtures(&crypto).await;
    let truncated = fixture("seipdv1_truncated.bin");

    let session_key = crypto
        .decrypt_session_key(&truncated, &[fx.priv_key.clone()])
        .await
        .expect("session key from truncated message — PKESK precedes the cut");

    let result = crypto
        .decrypt_and_verify(&truncated, &session_key, &[fx.signer_pub.clone()])
        .await;

    assert!(
        result.is_err(),
        "expected Err for truncated ciphertext, got Ok({:?})",
        result.map(|(pt, st)| (pt.len(), st))
    );

    match result.unwrap_err() {
        CryptoError::Decrypt(_) => {} // expected
        other => panic!("expected CryptoError::Decrypt, got {other:?}"),
    }
}

// ── test 6: wrong recipient — a key that isn't the message's target ──────────

/// `seipdv1_wrong_recipient.bin` is encrypted to a throwaway key, not
/// `key_pub.asc`. A parent-key-resolution bug that hands the decryptor the
/// wrong node/share key would look exactly like this: no PKESK in the
/// message matches `key_priv.asc`, so session-key extraction must fail
/// cleanly (`CryptoError::Decrypt`), never panic or return a bogus key.
#[tokio::test]
async fn wire_wrong_recipient_is_rejected() {
    let crypto = RpgpCrypto::new();
    let fx = load_fixtures(&crypto).await;
    let wrong_recipient_bin = fixture("seipdv1_wrong_recipient.bin");

    let result = crypto
        .decrypt_session_key(&wrong_recipient_bin, &[fx.priv_key.clone()])
        .await;

    assert!(
        result.is_err(),
        "expected Err: key_priv.asc is not a recipient of this message"
    );
    match result.unwrap_err() {
        CryptoError::Decrypt(_) => {} // expected — "no key could decrypt the session key"
        other => panic!("expected CryptoError::Decrypt, got {other:?}"),
    }
}

// ── test 7 (JS roundtrip): Rust encrypts → Node/openpgp.js decrypts ──────────

/// Rust encrypts + signs the fixture plaintext, then a small Node.js script
/// (`wire_roundtrip.mjs`) decrypts it using openpgp.js and writes the
/// plaintext to stdout.  Asserts that Node's output matches the original
/// plaintext.
///
/// Requires: `node` on PATH and `openpgp` installed in
/// `tests/fixtures/wire/node_modules/`.  Skip with
/// `cargo test -- --include-ignored` if Node is unavailable.
#[tokio::test]
#[ignore = "requires node + openpgp npm (see tests/fixtures/wire/README.md)"]
async fn wire_rust_encrypted_decryptable_by_node() {
    let crypto = RpgpCrypto::new();
    let fx = load_fixtures(&crypto).await;

    // Load the signing key (signer_priv.asc, empty passphrase).
    let signer_priv_armored = fixture_str("signer_priv.asc");
    let signer_priv = crypto
        .decrypt_key(&signer_priv_armored, "")
        .await
        .expect("signer private key");

    // Load the encryption public key from the fixture pub key.
    let enc_pub_armored = fixture_str("key_pub.asc");
    let enc_pub = PublicKey {
        armored: enc_pub_armored,
        fingerprint_hex: String::new(),
    };

    // Generate a fresh session key for this encrypt-round.
    let session_key = crypto
        .generate_session_key(&[enc_pub.clone()], EncryptOptions::default())
        .await
        .expect("generate_session_key");

    // Encrypt and sign with Rust.
    let ciphertext = crypto
        .encrypt_and_sign(
            &fx.plaintext,
            &session_key,
            &[enc_pub.clone()],
            &signer_priv,
            EncryptOptions::default(),
        )
        .await
        .expect("encrypt_and_sign");

    // Spawn `node wire_roundtrip.mjs`, feed ciphertext on stdin, read stdout.
    // CARGO_MANIFEST_DIR = rust/crates/proton-drive-crypto
    let mjs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wire_roundtrip.mjs");

    assert!(
        mjs_path.exists(),
        "wire_roundtrip.mjs not found at {}",
        mjs_path.display()
    );

    use std::process::{Command, Stdio};
    let mut child = Command::new("node")
        .arg(&mjs_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node");

    // Write ciphertext to stdin.
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin.write_all(&ciphertext).expect("write ciphertext");
    }

    let output = child.wait_with_output().expect("wait for node");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "wire_roundtrip.mjs failed (exit {:?}):\n{stderr}",
            output.status.code()
        );
    }

    assert_eq!(
        output.stdout, fx.plaintext,
        "Node-decrypted output does not match original plaintext"
    );
}
