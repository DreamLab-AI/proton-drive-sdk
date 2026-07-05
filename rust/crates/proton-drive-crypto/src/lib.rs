//! OpenPGP crypto (ADR-0002) — rpgp v0.16 implementation.
//!
//! Mirrors `client/js/src/crypto/interface.ts`.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use thiserror::Error;
use zeroize::Zeroizing;

use pgp::{
    composed::{
        Deserializable,
        KeyType,
        MessageBuilder,
        PlainSessionKey,
        // Key builder types are re-exported from pgp::composed via key::*
        SecretKeyParamsBuilder,
        SignedPublicKey,
        SignedSecretKey,
        StandaloneSignature,
        SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{
        Notation, PacketParser, PacketTrait, PublicKeyEncryptedSessionKey, SignatureConfig,
        SignatureType, Subpacket, SubpacketData, SymEncryptedProtectedData,
        SymKeyEncryptedSessionKey,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, EskType, KeyDetails, Password, PkeskVersion, PublicKeyTrait,
        StringToKey,
    },
};

/// Proton binds a signature to a purpose ("signature context") via a critical
/// notation with this name. Matches gopenpgp / OpenPGP.js; a verifier that
/// requires a different context value rejects the signature.
const PROTON_SIGNATURE_CONTEXT_NOTATION: &[u8] = b"context@proton.ch";

/// Iterated+Salted S2K iteration-count byte for password-encrypted session
/// keys. `0xC0` (192) is OpenPGP.js' default for `encryptSessionKey` and
/// decodes to ~4M hashed octets per RFC 9580 §3.7.1.3 — strong and
/// interoperable. The count byte is serialised into the SKESK packet, so any
/// compliant decrypter recovers it without out-of-band agreement.
const DEFAULT_S2K_ITERATION_COUNT: u8 = 0xC0;

// ── error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("key error: {0}")]
    Key(String),
    #[error("SRP: {0}")]
    Srp(String),
    #[error("AEAD/SEIPDv2 not supported in v1 (see ADR-0006)")]
    AeadNotSupported,
}

impl From<proton_srp::SRPError> for CryptoError {
    fn from(e: proton_srp::SRPError) -> Self {
        CryptoError::Srp(e.to_string())
    }
}

impl From<proton_srp::MailboxHashError> for CryptoError {
    fn from(e: proton_srp::MailboxHashError) -> Self {
        CryptoError::Srp(e.to_string())
    }
}

// ── key types ─────────────────────────────────────────────────────────────────

/// An unlocked PGP private key. `passphrase` is preserved so rpgp can re-derive
/// the key material on every crypto operation (rpgp does not cache unlocked state).
///
/// `Debug` is hand-written (not derived) to avoid printing the armored private
/// key or the cleartext passphrase — `Zeroizing<T>`'s own `Debug` impl just
/// forwards to `T`'s and performs no redaction (it only scrubs memory on
/// `Drop`), so a derived impl here would leak both secrets to any `{:?}`,
/// `dbg!`, or panic message.
#[derive(Clone)]
pub struct PrivateKey {
    pub armored: String,
    pub fingerprint_hex: String,
    /// Passphrase used to lock/unlock this key. Empty for unencrypted keys.
    /// Wrapped in `Zeroizing` so the secret is wiped on drop (ADR-0011).
    pub passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("armored", &"[redacted]")
            .field("fingerprint_hex", &self.fingerprint_hex)
            .field("passphrase", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub armored: String,
    pub fingerprint_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// SEIPDv1 — default in v1 (ADR-0006).
    None,
    /// AEAD-GCM, gated by per-key feature flag. v1 rejects when set.
    Gcm,
}

/// Symmetric session key. `cipher_algorithm` is the OpenPGP numeric ID
/// (9 = AES-256, 7 = AES-128).
///
/// `Debug` is hand-written (not derived) — see [`PrivateKey`]'s impl for why:
/// `Zeroizing<Vec<u8>>`'s derived `Debug` prints the raw key bytes verbatim.
#[derive(Clone)]
pub struct SessionKey {
    /// Raw key bytes. Wrapped in `Zeroizing` so the secret is wiped on drop (ADR-0011).
    pub data: Zeroizing<Vec<u8>>,
    pub cipher_algorithm: u8,
    pub aead: AeadAlgorithm,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("data", &format!("[redacted {} bytes]", self.data.len()))
            .field("cipher_algorithm", &self.cipher_algorithm)
            .field("aead", &self.aead)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    Ok,
    NoSignature,
    SignatureInvalid,
    SignatureWrongSigner,
}

#[derive(Debug, Clone, Default)]
pub struct EncryptOptions {
    /// Mirrors JS `enableAeadWithEncryptionKeys`. Must be false in v1.
    pub enable_aead_with_encryption_keys: bool,
    pub compress: bool,
}

// ── ASCII armor ─────────────────────────────────────────────────────────────

/// ASCII-armor block type for [`armor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorKind {
    /// `-----BEGIN PGP MESSAGE-----` — encrypted messages (PKESK + SEIPD).
    Message,
    /// `-----BEGIN PGP SIGNATURE-----` — detached signatures.
    Signature,
}

/// RFC 4880 ASCII-armor a binary OpenPGP packet stream.
///
/// Proton's wire format delivers `PGPMessage` / `PGPSignature` fields as armored
/// text (per the Drive OpenAPI schema). The binary output of
/// [`OpenPgpCrypto::sign`] / [`OpenPgpCrypto::encrypt_and_sign`] must be wrapped
/// in an armor block before it is placed on the wire.
pub fn armor(binary: &[u8], kind: ArmorKind) -> String {
    use base64::Engine as _;

    fn crc24(data: &[u8]) -> u32 {
        let mut crc: u32 = 0x00B7_04CE;
        for &b in data {
            crc ^= (b as u32) << 16;
            for _ in 0..8 {
                crc <<= 1;
                if crc & 0x0100_0000 != 0 {
                    crc ^= 0x0186_4CFB;
                }
            }
        }
        crc & 0x00FF_FFFF
    }

    let label = match kind {
        ArmorKind::Message => "PGP MESSAGE",
        ArmorKind::Signature => "PGP SIGNATURE",
    };

    let b64 = base64::engine::general_purpose::STANDARD.encode(binary);
    let crc = crc24(binary);
    let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
    let crc_b64 = base64::engine::general_purpose::STANDARD.encode(crc_bytes);

    let mut out = String::with_capacity(b64.len() + 96);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n\n");
    for chunk in b64.as_bytes().chunks(64) {
        // base64 output is ASCII, so every chunk is valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push('=');
    out.push_str(&crc_b64);
    out.push('\n');
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

// ── SRP types + trait ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SrpVerifier {
    pub modulus_id: String,
    pub version: u32,
    pub salt: String,
    pub verifier: String,
}

#[derive(Debug, Clone)]
pub struct SrpExchange {
    pub expected_server_proof: String,
    pub client_proof: String,
    pub client_ephemeral: String,
}

#[async_trait]
pub trait SrpModule: Send + Sync {
    async fn get_srp(
        &self,
        version: u32,
        modulus: &str,
        server_ephemeral: &str,
        salt: &str,
        password: &str,
    ) -> Result<SrpExchange, CryptoError>;

    async fn get_srp_verifier(&self, password: &str) -> Result<SrpVerifier, CryptoError>;

    async fn compute_key_password(&self, password: &str, salt: &str)
    -> Result<String, CryptoError>;

    fn generate_key_salt(&self) -> String;
}

// ── OpenPGP trait ─────────────────────────────────────────────────────────────

#[async_trait]
pub trait OpenPgpCrypto: Send + Sync {
    /// Generate a fresh random passphrase for locking a new node key.
    ///
    /// Zeroize boundary (ADR-0011): this is credential/key material — the
    /// passphrase locks a PGP private key — so it is wrapped in `Zeroizing`
    /// end to end. Plain decrypted *content* (e.g. `decrypt_and_verify`'s
    /// plaintext) is not key material and stays `Vec<u8>`; only secrets that
    /// themselves protect or constitute key material (passphrases, session
    /// keys, HMAC keys derived from them) cross this trait boundary zeroizing.
    fn generate_passphrase(&self) -> Zeroizing<String>;

    /// Parse `armored` as a PGP private key and verify `passphrase` unlocks it.
    async fn decrypt_key(&self, armored: &str, passphrase: &str)
    -> Result<PrivateKey, CryptoError>;

    /// Encrypt `data` with `session_key` (SEIPDv1) and sign with `signing_key`.
    /// Prepends PKESK packets when `encryption_keys` is non-empty (node names /
    /// passphrases). Empty `encryption_keys` → bare SEIPD (block content).
    async fn encrypt_and_sign(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
        signing_key: &PrivateKey,
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Encrypt `data` with `session_key` (SEIPDv1) **without signing**, prepending
    /// PKESK packets for each of `encryption_keys`. Mirrors JS `encryptArmored`
    /// — used for the per-block encrypted-signature scheme (the detached block
    /// signature is encrypted, not re-signed).
    async fn encrypt(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt `data` (SEIPD, possibly with leading PKESK) using `session_key`.
    async fn decrypt_and_verify(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        verification_keys: &[PublicKey],
    ) -> Result<(Vec<u8>, VerificationStatus), CryptoError>;

    /// Extract the session key from PKESK packet(s) in `data`.
    async fn decrypt_session_key(
        &self,
        data: &[u8],
        decryption_keys: &[PrivateKey],
    ) -> Result<SessionKey, CryptoError>;

    /// Wrap `session_key` in PKESK packets for each of `encryption_keys`.
    async fn encrypt_session_key(
        &self,
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
    ) -> Result<Vec<u8>, CryptoError>;

    async fn encrypt_session_key_with_password(
        &self,
        session_key: &SessionKey,
        password: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Generate a random AES-256 session key.
    async fn generate_session_key(
        &self,
        encryption_keys: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<SessionKey, CryptoError>;

    /// Generate an Ed25519Legacy+X25519 keypair locked with `passphrase`.
    /// Returns `(PrivateKey, armored_public_key)`.
    async fn generate_key(
        &self,
        passphrase: &str,
        opts: EncryptOptions,
    ) -> Result<(PrivateKey, String), CryptoError>;

    /// Detached binary signature over `data`.
    async fn sign(
        &self,
        data: &[u8],
        signing_key: &PrivateKey,
        signature_context: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Verify a detached signature produced by `sign`.
    async fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        verification_keys: &[PublicKey],
    ) -> Result<VerificationStatus, CryptoError>;

    /// Derive the public key from a private key. Used for the node-key
    /// signature-verification fallback when no signer address is available
    /// (JS `getRevisionVerificationKeys` returns `[nodeKey]`).
    async fn public_key(&self, key: &PrivateKey) -> Result<PublicKey, CryptoError>;

    /// Extract the public key from an armored private-key block **without
    /// unlocking it** (no passphrase required — the public portion of a locked
    /// secret key is plaintext). Proton addresses retain rotated-out keys
    /// alongside the current one, and a revision may be signed by any of them,
    /// so verification needs every address key's public portion. Mirrors the
    /// full key list JS `account.getPublicKeys(email)` returns.
    async fn public_key_from_armored(&self, armored: &str) -> Result<PublicKey, CryptoError>;
}

// ── RpgpCrypto ───────────────────────────────────────────────────────────────

/// A server-issued, signed SRP modulus plus the `ModulusID` that names it.
///
/// Proton's `GET /core/v4/auth/modulus` route returns a fresh PGP-signed
/// modulus (`Modulus`) and an opaque `ModulusID`. An SRP *verifier* must be
/// derived against that exact modulus and registered alongside its id, so
/// [`SrpModule::get_srp_verifier`] requires the host to have configured one via
/// [`RpgpCrypto::with_srp_modulus`]. (SRP *login* takes its modulus per-call
/// from `/auth/info`, so it needs no configured modulus.)
#[derive(Debug, Clone, Default)]
struct SrpModulus {
    /// `ModulusID` from `/auth/modulus`, echoed back at registration time.
    id: String,
    /// The full ASCII-armored, server-signed PGP modulus message.
    signed: String,
}

#[derive(Debug, Clone, Default)]
pub struct RpgpCrypto {
    /// Server modulus used to derive SRP verifiers. `None` until configured;
    /// SRP login and all OpenPGP operations work without it.
    srp_modulus: Option<SrpModulus>,
}

impl RpgpCrypto {
    pub fn new() -> Self {
        Self { srp_modulus: None }
    }

    /// Configure the server-signed SRP modulus and its `ModulusID` (from
    /// `GET /core/v4/auth/modulus`) so [`SrpModule::get_srp_verifier`] can
    /// derive a verifier bound to that modulus. Consumes and returns `self`
    /// for builder-style construction; leaves all other behaviour unchanged.
    #[must_use]
    pub fn with_srp_modulus(
        mut self,
        modulus_id: impl Into<String>,
        signed_modulus: impl Into<String>,
    ) -> Self {
        self.srp_modulus = Some(SrpModulus {
            id: modulus_id.into(),
            signed: signed_modulus.into(),
        });
        self
    }

    #[inline]
    fn reject_aead(opts: &EncryptOptions) -> Result<(), CryptoError> {
        if opts.enable_aead_with_encryption_keys {
            return Err(CryptoError::AeadNotSupported);
        }
        Ok(())
    }

    fn random_passphrase() -> Zeroizing<String> {
        use base64::Engine as _;
        use rand::RngCore as _;
        let mut buf = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *buf);
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(*buf))
    }

    fn parse_sym_alg(id: u8) -> SymmetricKeyAlgorithm {
        SymmetricKeyAlgorithm::from(id)
    }

    /// Map a `SymmetricKeyAlgorithm` back to its OpenPGP numeric id.
    fn sym_alg_id(alg: SymmetricKeyAlgorithm) -> u8 {
        match alg {
            SymmetricKeyAlgorithm::Plaintext => 0,
            SymmetricKeyAlgorithm::IDEA => 1,
            SymmetricKeyAlgorithm::TripleDES => 2,
            SymmetricKeyAlgorithm::CAST5 => 3,
            SymmetricKeyAlgorithm::Blowfish => 4,
            SymmetricKeyAlgorithm::AES128 => 7,
            SymmetricKeyAlgorithm::AES192 => 8,
            SymmetricKeyAlgorithm::AES256 => 9,
            SymmetricKeyAlgorithm::Twofish => 10,
            SymmetricKeyAlgorithm::Camellia128 => 11,
            SymmetricKeyAlgorithm::Camellia192 => 12,
            SymmetricKeyAlgorithm::Camellia256 => 13,
            _ => 9,
        }
    }

    /// Explicit SEIPDv2/AEAD rejection guard (ADR-0006: v1 supports SEIPDv1
    /// only). Walks the packet stream and inspects each
    /// `SymEncryptedProtectedData` packet's own version tag directly, so
    /// rejection is a deliberate, testable check rather than an incidental
    /// side effect of `decrypt_and_verify` always building a
    /// `PlainSessionKey::V3_4`: rpgp's SEIPDv2 decrypt arm does `bail!` on a
    /// V3_4 key (pgp-0.16.0 composed/message/reader/sym_encrypted_protected.rs
    /// `PlainSessionKey::V3_4 => bail!("mismatch between session key and
    /// edata config")`), but that is a generic mismatch error, not a typed
    /// `CryptoError::AeadNotSupported` the caller can rely on, and it would
    /// silently stop being true if this crate ever passed a V6 session key.
    fn reject_seipd_v2(binary: &[u8]) -> Result<(), CryptoError> {
        let parser = PacketParser::new(std::io::BufReader::new(binary));
        for packet_result in parser {
            // A malformed packet stream is not this guard's concern — let
            // the real decrypt path surface the parse error with full context.
            let Ok(packet) = packet_result else {
                continue;
            };
            if let pgp::packet::Packet::SymEncryptedProtectedData(seipd) = packet {
                if seipd.version() != 1 {
                    return Err(CryptoError::AeadNotSupported);
                }
            }
        }
        Ok(())
    }

    /// Decrypt a bare SEIPD payload (no preceding ESK) with a known session
    /// key. rpgp's composed `Message` parser refuses a SEIPD that isn't
    /// preceded by an ESK, so we walk the packet stream and decrypt the
    /// protected-data packet directly. Returns the SEIPD's inner plaintext
    /// (itself a sequence of OpenPGP packets — literal, or signed literal).
    fn decrypt_bare_seipd(
        binary: &[u8],
        session_key: &[u8],
        sym_alg: SymmetricKeyAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let parser = PacketParser::new(std::io::BufReader::new(binary));
        for packet_result in parser {
            let packet = packet_result.map_err(|e| CryptoError::Decrypt(e.to_string()))?;
            if let pgp::packet::Packet::SymEncryptedProtectedData(seipd) = packet {
                return seipd
                    .decrypt(session_key, Some(sym_alg))
                    .map_err(|e| CryptoError::Decrypt(e.to_string()));
            }
        }
        Err(CryptoError::Decrypt(
            "no SEIPD packet in bare payload".into(),
        ))
    }

    /// Recover a session key from an SKESK (Symmetric-Key Encrypted Session
    /// Key) packet stream using `password`. The S2K specifier embedded in the
    /// packet (type, hash, salt, count) drives key derivation, so this is the
    /// inverse of [`OpenPgpCrypto::encrypt_session_key_with_password`] and of
    /// any RFC-9580 SKESK (OpenPGP.js, gopenpgp). rpgp 0.16 has no composed
    /// password-decrypt for a bare SKESK, so we walk the packet layer: parse
    /// the SKESK, derive the wrapping key via S2K, then `decrypt`.
    ///
    /// Test-gated: the SDK never password-*decrypts* a session key on the live
    /// path (registration only *encrypts*), but the round-trip test needs the
    /// exact inverse to prove the SKESK we emit is recoverable.
    #[cfg(test)]
    fn decrypt_session_key_with_password(
        binary: &[u8],
        password: &str,
    ) -> Result<SessionKey, CryptoError> {
        let parser = PacketParser::new(std::io::BufReader::new(binary));
        for packet_result in parser {
            let packet = packet_result.map_err(|e| CryptoError::Decrypt(e.to_string()))?;
            let pgp::packet::Packet::SymKeyEncryptedSessionKey(skesk) = packet else {
                continue;
            };

            let s2k = skesk
                .s2k()
                .ok_or_else(|| CryptoError::Decrypt("SKESK has no S2K specifier".into()))?;
            let sym_alg = skesk
                .sym_algorithm()
                .ok_or_else(|| CryptoError::Decrypt("SKESK has no symmetric algorithm".into()))?;

            // Derive the S2K wrapping key from the password, then unwrap the
            // session key. For a v4 SKESK the wrapped blob carries its own
            // symmetric-algorithm byte, which `decrypt` returns in the
            // PlainSessionKey; the SKESK's `sym_algorithm` only sizes the
            // wrapping cipher's key.
            let derived = s2k
                .derive_key(password.as_bytes(), sym_alg.key_size())
                .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
            let plain = skesk
                .decrypt(&derived)
                .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
            return Self::plain_to_session_key(plain);
        }
        Err(CryptoError::Decrypt(
            "no SKESK packet in password-encrypted session key".into(),
        ))
    }

    /// Drain a decrypted message into plaintext and resolve its verification
    /// verdict against the supplied keys. Shared by both the composed
    /// (ESK + SEIPD) and bare-SEIPD decrypt paths.
    fn finalize_decrypted(
        decrypted: pgp::composed::Message<'_>,
        verification_keys: &[PublicKey],
    ) -> Result<(Vec<u8>, VerificationStatus), CryptoError> {
        // JS sets `compress: true` when encrypting ExtendedAttributes
        // (reference/client/js/src/crypto/driveCrypto.ts:556 `encryptExtendedAttributes`
        // -> openPGPCrypto.ts:124-132 `encryptAndSignArmored`, which forwards
        // `compress: options.compress || false` into the encrypt call), so a
        // SEIPD's inner plaintext can be an OpenPGP-compressed packet wrapping
        // the signed literal. rpgp's own decrypt path can hand back a
        // top-level `Message::Compressed { .. }` in that case (see pgp
        // 0.16.0's own composed-message tests, e.g.
        // `utf8_reader_partial_size_compression_zip_roundtrip_public_key_x25519_seipdv1_sign`,
        // which asserts `is_compressed()` then calls `.decompress()` before
        // `.verify_nested()`), and `verify_nested`/`as_data_vec` on an
        // undecompressed `Compressed` message either bail with an error or
        // silently return the still-compressed bytes. Decompress unconditionally
        // before inspecting or verifying — a no-op for already-uncompressed
        // messages.
        let mut decrypted = decrypted
            .decompress()
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

        // Capture signature presence before draining; a bare literal payload
        // (no signature) must map to NoSignature, not a spurious verdict.
        let has_signature = matches!(
            decrypted,
            pgp::composed::Message::Signed { .. } | pgp::composed::Message::SignedOnePass { .. }
        );

        let plaintext = decrypted
            .as_data_vec()
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

        if verification_keys.is_empty() {
            return Ok((plaintext, VerificationStatus::NoSignature));
        }

        let pub_keys: Vec<SignedPublicKey> = verification_keys
            .iter()
            .filter_map(|k| Self::parse_public_key(k).ok())
            .collect();

        let key_refs: Vec<&dyn PublicKeyTrait> = pub_keys
            .iter()
            .map(|k| &k.primary_key as &dyn PublicKeyTrait)
            .collect();

        let status = match decrypted.verify_nested(&key_refs) {
            Ok(results)
                if results
                    .iter()
                    .any(|r| matches!(r, pgp::composed::VerificationResult::Valid(_))) =>
            {
                VerificationStatus::Ok
            }
            Ok(_) if has_signature => VerificationStatus::SignatureWrongSigner,
            Ok(_) => VerificationStatus::NoSignature,
            Err(_) => VerificationStatus::SignatureInvalid,
        };

        Ok((plaintext, status))
    }

    fn plain_to_session_key(sk: PlainSessionKey) -> Result<SessionKey, CryptoError> {
        // PlainSessionKey implements Drop (zeroize), so match by ref + clone.
        let (raw_data, cipher_algorithm) = match &sk {
            PlainSessionKey::V3_4 { key, sym_alg } => (key.clone(), Self::sym_alg_id(*sym_alg)),
            PlainSessionKey::V6 { key } => (key.clone(), 9u8),
            PlainSessionKey::Unknown { key, sym_alg } => (key.clone(), Self::sym_alg_id(*sym_alg)),
            PlainSessionKey::V5 { key } => (key.clone(), 9u8),
        };
        Ok(SessionKey {
            data: Zeroizing::new(raw_data),
            cipher_algorithm,
            aead: AeadAlgorithm::None,
        })
    }

    fn parse_secret_key(priv_key: &PrivateKey) -> Result<SignedSecretKey, CryptoError> {
        let (key, _) =
            SignedSecretKey::from_armor_single(std::io::Cursor::new(priv_key.armored.as_bytes()))
                .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(key)
    }

    fn parse_public_key(pub_key: &PublicKey) -> Result<SignedPublicKey, CryptoError> {
        let (key, _) =
            SignedPublicKey::from_armor_single(std::io::Cursor::new(pub_key.armored.as_bytes()))
                .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(key)
    }

    /// Normalise a PGP message to binary packets.
    ///
    /// Proton's API delivers `PGPMessage` fields as ASCII-armored text (per the
    /// OpenAPI spec), but the binary packet parsers (`PacketParser`,
    /// `Message::from_bytes`) reject armor. Dearmor when the input carries an
    /// armor header; pass binary input (e.g. a base64-decoded ContentKeyPacket)
    /// through untouched.
    fn to_binary_pgp(data: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>, CryptoError> {
        const ARMOR_PREFIX: &[u8] = b"-----BEGIN PGP";
        let start = data
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        let trimmed = &data[start..];
        if !trimmed.starts_with(ARMOR_PREFIX) {
            return Ok(std::borrow::Cow::Borrowed(data));
        }
        let mut dearmor = pgp::armor::Dearmor::new(std::io::BufReader::new(trimmed));
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut dearmor, &mut out)
            .map_err(|e| CryptoError::Decrypt(format!("dearmor: {e}")))?;
        Ok(std::borrow::Cow::Owned(out))
    }

    /// Write a PKESK packet that wraps `session_key` for `pub_key`'s
    /// first encryption subkey (or primary key if no subkeys exist).
    fn write_pkesk(
        session_key: &SessionKey,
        sym_alg: SymmetricKeyAlgorithm,
        pub_key: &SignedPublicKey,
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        // Prefer the first encryption subkey; fall back to primary.
        let pkesk = if let Some(subkey) = pub_key.public_subkeys.first() {
            PublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key.data,
                sym_alg,
                &subkey.key,
            )
        } else {
            PublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key.data,
                sym_alg,
                &pub_key.primary_key,
            )
        }
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        pkesk
            .to_writer_with_header(out)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))
    }
}

// ── SrpModule impl ────────────────────────────────────────────────────────────

#[async_trait]
impl SrpModule for RpgpCrypto {
    async fn get_srp(
        &self,
        version: u32,
        modulus: &str,
        server_ephemeral: &str,
        salt: &str,
        password: &str,
    ) -> Result<SrpExchange, CryptoError> {
        let hash_version = proton_srp::SrpHashVersion::try_from(version as u8)?;
        let auth = proton_srp::SRPAuth::with_pgp(
            None,
            password,
            hash_version,
            salt,
            modulus,
            server_ephemeral,
        )?;
        let proof = auth.generate_proofs()?;
        let b64 = proton_srp::SRPProofB64::from(proof);
        Ok(SrpExchange {
            client_ephemeral: b64.client_ephemeral,
            client_proof: b64.client_proof,
            expected_server_proof: b64.expected_server_proof,
        })
    }

    async fn get_srp_verifier(&self, password: &str) -> Result<SrpVerifier, CryptoError> {
        // The verifier is `g^x mod N`, where `x` is Proton's SRP password hash
        // (bcrypt-derived, version 4) and `N` is the server-signed modulus.
        // proton-srp's `generate_verifier_with_pgp` performs exactly this:
        // it verifies the modulus signature against Proton's bundled server
        // key, generates a fresh random salt, computes the SRP password hash
        // (always version 4, matching the working login path's V4 hashing),
        // and returns `g^x mod N`. We bind the result to the `ModulusID` the
        // host fetched alongside the signed modulus.
        let modulus = self.srp_modulus.as_ref().ok_or_else(|| {
            CryptoError::Srp(
                "no SRP modulus configured: call RpgpCrypto::with_srp_modulus with the \
                 ModulusID and signed modulus from GET /core/v4/auth/modulus before \
                 deriving a verifier"
                    .into(),
            )
        })?;

        // `salt_opt = None` → proton-srp generates a fresh CSPRNG salt, exactly
        // as the web client does on registration / password change.
        let verifier =
            proton_srp::SRPAuth::generate_verifier_with_pgp(password, None, &modulus.signed)?;
        let b64 = proton_srp::SRPVerifierB64::from(verifier);

        Ok(SrpVerifier {
            modulus_id: modulus.id.clone(),
            version: u8::from(b64.version) as u32,
            salt: b64.salt,
            verifier: b64.verifier,
        })
    }

    async fn compute_key_password(
        &self,
        password: &str,
        salt: &str,
    ) -> Result<String, CryptoError> {
        use base64::Engine as _;
        let salt_bytes = base64::engine::general_purpose::STANDARD
            .decode(salt)
            .map_err(|e| CryptoError::Key(format!("key-salt base64: {e}")))?;
        let hashed = proton_srp::mailbox_password_hash(password, &salt_bytes)?;
        // Proton's key password is the 31-char bcrypt hash portion only, NOT
        // the full `$2y$10$[salt][hash]` string — the web client does
        // `hash.slice(29)`, which strips the 29-char `$2y$10$`+salt prefix.
        // Handing the full string to key-unlock makes every direct unlock fail.
        std::str::from_utf8(hashed.hashed_password())
            .map(str::to_owned)
            .map_err(|e| CryptoError::Key(format!("bcrypt output not utf-8: {e}")))
    }

    fn generate_key_salt(&self) -> String {
        use base64::Engine as _;
        use rand::RngCore as _;
        let mut buf = [0u8; proton_srp::SALT_LEN_BYTES];
        rand::thread_rng().fill_bytes(&mut buf);
        base64::engine::general_purpose::STANDARD.encode(buf)
    }
}

// ── OpenPgpCrypto impl ────────────────────────────────────────────────────────

#[async_trait]
impl OpenPgpCrypto for RpgpCrypto {
    fn generate_passphrase(&self) -> Zeroizing<String> {
        Self::random_passphrase()
    }

    async fn decrypt_key(
        &self,
        armored: &str,
        passphrase: &str,
    ) -> Result<PrivateKey, CryptoError> {
        let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored.as_bytes()))
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        // Verify passphrase by attempting to unlock the key.
        let pw = Password::from(passphrase);
        key.unlock(&pw, |_, _| Ok(()))
            .map_err(|e| CryptoError::Key(format!("unlock: {e}")))?
            .map_err(|e| CryptoError::Key(format!("unlock inner: {e}")))?;

        let fingerprint_hex = hex::encode(key.primary_key.fingerprint().as_bytes());
        Ok(PrivateKey {
            armored: armored.to_owned(),
            fingerprint_hex,
            passphrase: Zeroizing::new(passphrase.to_owned()),
        })
    }

    async fn decrypt_session_key(
        &self,
        data: &[u8],
        decryption_keys: &[PrivateKey],
    ) -> Result<SessionKey, CryptoError> {
        let binary = Self::to_binary_pgp(data)?;
        let parser = PacketParser::new(std::io::BufReader::new(binary.as_ref()));
        for packet_result in parser {
            let packet = packet_result.map_err(|e| CryptoError::Decrypt(e.to_string()))?;

            let pgp::packet::Packet::PublicKeyEncryptedSessionKey(pkesk) = packet else {
                continue;
            };

            let values = pkesk
                .values()
                .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
            // ESK type must match the PKESK packet version, not a hardcoded
            // guess — a V6 PKESK decrypted as V3_4 (or vice-versa) fails.
            let typ = match pkesk.version() {
                PkeskVersion::V3 => EskType::V3_4,
                PkeskVersion::V6 => EskType::V6,
                PkeskVersion::Other(_) => continue,
            };

            for priv_key in decryption_keys {
                let key = Self::parse_secret_key(priv_key)?;
                let pw = Password::from(priv_key.passphrase.as_str());

                if let Ok(Ok(sk)) = key.decrypt_session_key(&pw, values, typ) {
                    return Self::plain_to_session_key(sk);
                }
                for subkey in &key.secret_subkeys {
                    if let Ok(Ok(sk)) = subkey.decrypt_session_key(&pw, values, typ) {
                        return Self::plain_to_session_key(sk);
                    }
                }
            }
        }
        Err(CryptoError::Decrypt(
            "no key could decrypt the session key".into(),
        ))
    }

    async fn decrypt_and_verify(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        verification_keys: &[PublicKey],
    ) -> Result<(Vec<u8>, VerificationStatus), CryptoError> {
        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);
        let binary = Self::to_binary_pgp(data)?;

        // ADR-0006: v1 rejects SEIPDv2/AEAD explicitly rather than relying on
        // rpgp's incidental session-key-type mismatch error (see
        // `reject_seipd_v2` for the full citation).
        Self::reject_seipd_v2(&binary)?;

        // Two payload shapes reach this function:
        //   1. ESK (PKESK/SKESK) + SEIPD — the standard composed message. The
        //      caller already extracted the session key, so we hand it to the
        //      composed decryptor which skips the ESK packet.
        //   2. Bare SEIPD with no preceding ESK — how Proton encrypts content
        //      blocks (`encryptAndSignDetached(data, sessionKey, [], ...)`).
        //      rpgp's composed parser rejects this (`unexpected packet type:
        //      SymEncryptedProtectedData`), so we drop to the packet layer and
        //      decrypt the SEIPD directly, then parse its plaintext as a message.
        match pgp::composed::Message::from_bytes(std::io::BufReader::new(binary.as_ref())) {
            Ok(msg) => {
                let plain_sk = PlainSessionKey::V3_4 {
                    sym_alg,
                    key: (*session_key.data).clone(),
                };
                let decrypted = msg
                    .decrypt_with_session_key(plain_sk)
                    .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
                Self::finalize_decrypted(decrypted, verification_keys)
            }
            Err(_) => {
                let inner = Self::decrypt_bare_seipd(&binary, &session_key.data, sym_alg)?;
                let decrypted =
                    pgp::composed::Message::from_bytes(std::io::BufReader::new(inner.as_slice()))
                        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
                Self::finalize_decrypted(decrypted, verification_keys)
            }
        }
    }

    async fn encrypt(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::reject_aead(&opts)?;

        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);

        // Unsigned literal message as the SEIPD plaintext. `opts.compress`
        // mirrors JS `compress` (see `encrypt_and_sign` below for the
        // detailed JS citation); ZIP is RFC 4880 §9.3's mandatory-to-implement
        // algorithm, so any compliant reader (OpenPGP.js, gopenpgp) decompresses it.
        let mut inner_builder = MessageBuilder::from_bytes("", data.to_vec());
        if opts.compress {
            inner_builder.compression(CompressionAlgorithm::ZIP);
        }
        let inner_bytes = inner_builder
            .to_vec(rand::thread_rng())
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        let seipd = SymEncryptedProtectedData::encrypt_seipdv1(
            rand::thread_rng(),
            sym_alg,
            &session_key.data,
            &inner_bytes,
        )
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        let mut out = Vec::new();
        for pub_key in encryption_keys {
            let key = Self::parse_public_key(pub_key)?;
            Self::write_pkesk(session_key, sym_alg, &key, &mut out)?;
        }
        seipd
            .to_writer_with_header(&mut out)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        Ok(out)
    }

    async fn encrypt_and_sign(
        &self,
        data: &[u8],
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
        signing_key: &PrivateKey,
        opts: EncryptOptions,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::reject_aead(&opts)?;

        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);
        let sec_key = Self::parse_secret_key(signing_key)?;
        let pw = Password::from(signing_key.passphrase.as_str());

        // Build a signed-but-unencrypted literal message as the SEIPD plaintext.
        //
        // `opts.compress` mirrors JS `compress` (reference/client/js/src/crypto/
        // driveCrypto.ts:556 `encryptExtendedAttributes` -> openPGPCrypto.ts:
        // 124-132 `encryptAndSignArmored`, which sets `compress: true` for
        // ExtendedAttributes and forwards it straight to the encrypt call).
        // When set, compress the signed literal before it is SEIP-encrypted —
        // the counterpart to `finalize_decrypted`'s unconditional `decompress()`
        // on the read path. ZIP is RFC 4880 §9.3's mandatory-to-implement
        // compression algorithm (the exact algorithm the host-injected
        // @proton/crypto CryptoProxy selects isn't vendored under reference/,
        // so ZIP is the safe interoperable choice — decompression is
        // algorithm-agnostic and doesn't require a byte-for-bit match).
        let inner_bytes = {
            let mut builder = MessageBuilder::from_bytes("", data.to_vec());
            builder.sign_binary();
            // primary_key implements SecretKeyTrait via the packet layer.
            builder.sign(&sec_key.primary_key, pw, HashAlgorithm::Sha256);
            if opts.compress {
                builder.compression(CompressionAlgorithm::ZIP);
            }
            builder
                .to_vec(rand::thread_rng())
                .map_err(|e| CryptoError::Encrypt(e.to_string()))?
        };

        // Encrypt the inner bytes with the provided session key.
        let seipd = SymEncryptedProtectedData::encrypt_seipdv1(
            rand::thread_rng(),
            sym_alg,
            &session_key.data,
            &inner_bytes,
        )
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        let mut out = Vec::new();
        for pub_key in encryption_keys {
            let key = Self::parse_public_key(pub_key)?;
            Self::write_pkesk(session_key, sym_alg, &key, &mut out)?;
        }
        seipd
            .to_writer_with_header(&mut out)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        Ok(out)
    }

    async fn encrypt_session_key(
        &self,
        session_key: &SessionKey,
        encryption_keys: &[PublicKey],
    ) -> Result<Vec<u8>, CryptoError> {
        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);
        let mut out = Vec::new();
        for pub_key in encryption_keys {
            let key = Self::parse_public_key(pub_key)?;
            Self::write_pkesk(session_key, sym_alg, &key, &mut out)?;
        }
        Ok(out)
    }

    async fn encrypt_session_key_with_password(
        &self,
        session_key: &SessionKey,
        password: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let sym_alg = Self::parse_sym_alg(session_key.cipher_algorithm);

        // Mirror OpenPGP.js' `encryptSessionKey({ passwords })`: a v4 SKESK with
        // an Iterated+Salted S2K (type 3), SHA-256 hash, fresh 8-byte salt, and
        // the default iteration count. The S2K specifier (hash + salt + count)
        // is serialised into the packet, so any RFC-9580 decrypter re-reads the
        // exact parameters — wire-interoperable with OpenPGP.js / gopenpgp.
        let s2k = StringToKey::new_iterated(
            rand::thread_rng(),
            HashAlgorithm::Sha256,
            DEFAULT_S2K_ITERATION_COUNT,
        );
        let pw = Password::from(password);

        let skesk = SymKeyEncryptedSessionKey::encrypt_v4(&pw, &session_key.data, s2k, sym_alg)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        let mut out = Vec::new();
        skesk
            .to_writer_with_header(&mut out)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
        Ok(out)
    }

    async fn generate_session_key(
        &self,
        _encryption_keys: &[PublicKey],
        opts: EncryptOptions,
    ) -> Result<SessionKey, CryptoError> {
        Self::reject_aead(&opts)?;
        use rand::RngCore as _;
        let mut data = Zeroizing::new(vec![0u8; 32]);
        rand::thread_rng().fill_bytes(&mut data);
        Ok(SessionKey {
            data,
            cipher_algorithm: 9, // AES-256
            aead: AeadAlgorithm::None,
        })
    }

    async fn generate_key(
        &self,
        passphrase: &str,
        opts: EncryptOptions,
    ) -> Result<(PrivateKey, String), CryptoError> {
        Self::reject_aead(&opts)?;
        let mut rng = rand::thread_rng();
        let pass_opt = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase.to_owned())
        };

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id("Drive Key".into())
            .passphrase(pass_opt.clone())
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::X25519)
                    .can_encrypt(true)
                    .passphrase(pass_opt)
                    .build()
                    .map_err(|e| CryptoError::Key(format!("subkey builder: {e}")))?,
            )
            .build()
            .map_err(|e| CryptoError::Key(format!("key builder: {e}")))?;

        let sec_key = key_params
            .generate(&mut rng)
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        let signed = sec_key
            .sign(&mut rng, &passphrase.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        let armored_private = signed
            .to_armored_string(None.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        let armored_public = signed
            .signed_public_key()
            .to_armored_string(None.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        let fingerprint_hex = hex::encode(signed.primary_key.fingerprint().as_bytes());

        Ok((
            PrivateKey {
                armored: armored_private,
                fingerprint_hex,
                passphrase: Zeroizing::new(passphrase.to_owned()),
            },
            armored_public,
        ))
    }

    async fn sign(
        &self,
        data: &[u8],
        signing_key: &PrivateKey,
        signature_context: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = Self::parse_secret_key(signing_key)?;
        let pw = Password::from(signing_key.passphrase.as_str());

        let mut rng = rand::thread_rng();
        let mut sig_config =
            SignatureConfig::from_key(&mut rng, &key.primary_key, SignatureType::Binary)
                .map_err(|e| CryptoError::Key(e.to_string()))?;

        // `from_key` leaves the subpacket sets empty; a v4 detached signature is
        // only RFC-valid (and verifiable by OpenPGP.js / Proton) with a
        // creation-time and an issuer subpacket.
        let now = chrono::Utc::now();
        let mut hashed = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(now))
                .map_err(|e| CryptoError::Key(e.to_string()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                key.primary_key.fingerprint(),
            ))
            .map_err(|e| CryptoError::Key(e.to_string()))?,
        ];

        // A non-empty context is bound into the signature as a critical notation
        // (mirrors openPGPCrypto.ts `sign`). Empty context = no binding, matching
        // `signArmored` / the detached block & manifest signatures.
        if !signature_context.is_empty() {
            hashed.push(
                Subpacket::critical(SubpacketData::Notation(Notation {
                    readable: true,
                    name: PROTON_SIGNATURE_CONTEXT_NOTATION.to_vec().into(),
                    value: signature_context.as_bytes().to_vec().into(),
                }))
                .map_err(|e| CryptoError::Key(e.to_string()))?,
            );
        }

        sig_config.hashed_subpackets = hashed;
        sig_config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::Issuer(key.primary_key.key_id()))
                .map_err(|e| CryptoError::Key(e.to_string()))?,
        ];

        let sig = sig_config
            .sign(&key.primary_key, &pw, std::io::Cursor::new(data))
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        let standalone = StandaloneSignature::new(sig);
        let mut out = Vec::new();
        standalone
            .to_writer(&mut out)
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(out)
    }

    async fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        verification_keys: &[PublicKey],
    ) -> Result<VerificationStatus, CryptoError> {
        if verification_keys.is_empty() {
            return Ok(VerificationStatus::NoSignature);
        }

        // Detached signatures arrive armored (`-----BEGIN PGP SIGNATURE-----`)
        // or as raw binary packets; `StandaloneSignature::from_bytes` is
        // binary-only, so dearmor first when needed.
        let signature = Self::to_binary_pgp(signature)?;
        let standalone =
            StandaloneSignature::from_bytes(std::io::BufReader::new(signature.as_ref()))
                .map_err(|e| CryptoError::Verify(e.to_string()))?;

        for pub_key in verification_keys {
            let key = Self::parse_public_key(pub_key)?;
            if standalone.verify(&key.primary_key, data).is_ok() {
                return Ok(VerificationStatus::Ok);
            }
            for subkey in &key.public_subkeys {
                if standalone.verify(&subkey.key, data).is_ok() {
                    return Ok(VerificationStatus::Ok);
                }
            }
        }
        Ok(VerificationStatus::SignatureWrongSigner)
    }

    async fn public_key(&self, key: &PrivateKey) -> Result<PublicKey, CryptoError> {
        let sec = Self::parse_secret_key(key)?;
        let armored = sec
            .signed_public_key()
            .to_armored_string(None.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(PublicKey {
            armored,
            fingerprint_hex: key.fingerprint_hex.clone(),
        })
    }

    async fn public_key_from_armored(&self, armored: &str) -> Result<PublicKey, CryptoError> {
        let sec = Self::parse_secret_key(&PrivateKey {
            armored: armored.to_owned(),
            fingerprint_hex: String::new(),
            passphrase: Zeroizing::new(String::new()),
        })?;
        let fingerprint_hex = hex::encode(sec.primary_key.fingerprint().as_bytes());
        let pub_armored = sec
            .signed_public_key()
            .to_armored_string(None.into())
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(PublicKey {
            armored: pub_armored,
            fingerprint_hex,
        })
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::cloned_ref_to_slice_refs,
    clippy::unnecessary_fallible_conversions
)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_is_44_char_base64() {
        let crypto = RpgpCrypto::new();
        let p = crypto.generate_passphrase();
        assert_eq!(p.len(), 44, "passphrase: {p:?}");
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "non-base64: {p:?}"
        );
    }

    #[test]
    fn passphrases_are_unique() {
        let crypto = RpgpCrypto::new();
        assert_ne!(crypto.generate_passphrase(), crypto.generate_passphrase());
    }

    #[test]
    fn aead_option_is_rejected() {
        let opts = EncryptOptions {
            enable_aead_with_encryption_keys: true,
            ..Default::default()
        };
        assert!(matches!(
            RpgpCrypto::reject_aead(&opts),
            Err(CryptoError::AeadNotSupported)
        ));
    }

    #[tokio::test]
    async fn generate_key_roundtrip() {
        let crypto = RpgpCrypto::new();
        let (priv_key, pub_armored) = crypto
            .generate_key("test-pass", EncryptOptions::default())
            .await
            .unwrap();
        assert!(!priv_key.armored.is_empty());
        assert!(!priv_key.fingerprint_hex.is_empty());
        assert!(!pub_armored.is_empty());

        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "test-pass")
            .await
            .unwrap();
        assert_eq!(unlocked.fingerprint_hex, priv_key.fingerprint_hex);
    }

    #[tokio::test]
    async fn session_key_encrypt_decrypt_roundtrip() {
        let crypto = RpgpCrypto::new();
        let (priv_key, pub_armored) = crypto
            .generate_key("key-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        let session_key = crypto
            .generate_session_key(&[pub_key.clone()], EncryptOptions::default())
            .await
            .unwrap();
        assert_eq!(session_key.data.len(), 32);

        let pkesk_bytes = crypto
            .encrypt_session_key(&session_key, &[pub_key])
            .await
            .unwrap();
        assert!(!pkesk_bytes.is_empty());

        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "key-pass")
            .await
            .unwrap();
        let recovered = crypto
            .decrypt_session_key(&pkesk_bytes, &[unlocked])
            .await
            .unwrap();
        assert_eq!(recovered.data, session_key.data);
    }

    /// RFC 4880 ASCII-armor a binary OpenPGP packet stream as a PGP MESSAGE
    /// block — exactly the shape Proton delivers NodePassphrase / NodeHashKey in.
    fn armor_pgp_message(binary: &[u8]) -> String {
        armor(binary, ArmorKind::Message)
    }

    /// Proton delivers PKESK and encrypted-message fields as ASCII-armored text
    /// (OpenAPI `PGPMessage` = "An armored PGP Message"), but rpgp's PacketParser /
    /// Message::from_bytes are binary-only. `to_binary_pgp` must dearmor first.
    /// This locks in that path end-to-end on armored input.
    #[tokio::test]
    async fn decrypt_accepts_armored_input() {
        let crypto = RpgpCrypto::new();
        let plaintext = b"armored wire payload";
        let (priv_key, pub_armored) = crypto
            .generate_key("armor-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        let session_key = crypto
            .generate_session_key(&[pub_key.clone()], EncryptOptions::default())
            .await
            .unwrap();

        let pkesk_binary = crypto
            .encrypt_session_key(&session_key, &[pub_key.clone()])
            .await
            .unwrap();
        let msg_binary = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                &[pub_key.clone()],
                &priv_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();

        // Re-frame both binary blobs as armored text, mirroring the real wire.
        let pkesk_armored = armor_pgp_message(&pkesk_binary);
        let msg_armored = armor_pgp_message(&msg_binary);
        assert!(pkesk_armored.starts_with("-----BEGIN PGP MESSAGE-----"));

        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "armor-pass")
            .await
            .unwrap();
        let recovered_sk = crypto
            .decrypt_session_key(pkesk_armored.as_bytes(), &[unlocked])
            .await
            .unwrap();
        assert_eq!(recovered_sk.data, session_key.data);

        let (decrypted, status) = crypto
            .decrypt_and_verify(msg_armored.as_bytes(), &recovered_sk, &[pub_key])
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(status, VerificationStatus::Ok);
    }

    #[tokio::test]
    async fn encrypt_sign_decrypt_roundtrip() {
        let crypto = RpgpCrypto::new();
        let plaintext = b"hello proton drive";
        let (signing_key, pub_armored) = crypto
            .generate_key("sign-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: signing_key.fingerprint_hex.clone(),
        };
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let encrypted = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                &[pub_key.clone()],
                &signing_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();

        let unlocked = crypto
            .decrypt_key(&signing_key.armored, "sign-pass")
            .await
            .unwrap();
        let recovered_sk = crypto
            .decrypt_session_key(&encrypted, &[unlocked])
            .await
            .unwrap();
        let (decrypted, status) = crypto
            .decrypt_and_verify(&encrypted, &recovered_sk, &[pub_key])
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(
            status,
            VerificationStatus::Ok,
            "embedded signature must verify (no double-wrap / lost signature)"
        );
    }

    /// `EncryptOptions.compress` end to end: `encrypt_and_sign` with
    /// `compress: true` must produce a message whose inner plaintext is
    /// OpenPGP-compressed, and `decrypt_and_verify` must decompress it before
    /// verifying (the `finalize_decrypted` fix) so the round trip still
    /// yields the original plaintext and `VerificationStatus::Ok`. Mirrors
    /// JS's `compress: true` path for ExtendedAttributes (driveCrypto.ts:556).
    #[tokio::test]
    async fn encrypt_sign_compressed_roundtrip() {
        let crypto = RpgpCrypto::new();
        let plaintext = b"{\"Common\":{\"Size\":123456}}";
        let (signing_key, pub_armored) = crypto
            .generate_key("compress-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: signing_key.fingerprint_hex.clone(),
        };
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let opts = EncryptOptions {
            compress: true,
            ..Default::default()
        };
        let encrypted = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                &[pub_key.clone()],
                &signing_key,
                opts,
            )
            .await
            .unwrap();

        let unlocked = crypto
            .decrypt_key(&signing_key.armored, "compress-pass")
            .await
            .unwrap();
        let recovered_sk = crypto
            .decrypt_session_key(&encrypted, &[unlocked])
            .await
            .unwrap();
        let (decrypted, status) = crypto
            .decrypt_and_verify(&encrypted, &recovered_sk, &[pub_key])
            .await
            .unwrap();
        assert_eq!(
            decrypted, plaintext,
            "must decompress before returning plaintext"
        );
        assert_eq!(
            status,
            VerificationStatus::Ok,
            "must decompress before verify_nested, not just as_data_vec"
        );
    }

    #[tokio::test]
    async fn sign_verify_roundtrip() {
        let crypto = RpgpCrypto::new();
        let data = b"manifest data";
        let (priv_key, pub_armored) = crypto
            .generate_key("sig-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "sig-pass")
            .await
            .unwrap();
        let sig = crypto.sign(data, &unlocked, "").await.unwrap();
        let status = crypto.verify(data, &sig, &[pub_key]).await.unwrap();
        assert_eq!(status, VerificationStatus::Ok);

        // An empty context must NOT add a notation (matches signArmored).
        let parsed = StandaloneSignature::from_bytes(std::io::Cursor::new(&sig)).unwrap();
        assert!(
            parsed.signature.notations().is_empty(),
            "empty context must not embed a notation"
        );
    }

    #[tokio::test]
    async fn sign_embeds_critical_context_notation() {
        let crypto = RpgpCrypto::new();
        let data = b"key packet bytes";
        let (priv_key, pub_armored) = crypto
            .generate_key("ctx-pass", EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        let unlocked = crypto
            .decrypt_key(&priv_key.armored, "ctx-pass")
            .await
            .unwrap();

        let sig = crypto
            .sign(data, &unlocked, "drive.sharing.member")
            .await
            .unwrap();

        // Cryptographically valid even with the extra hashed subpackets.
        let status = crypto.verify(data, &sig, &[pub_key]).await.unwrap();
        assert_eq!(status, VerificationStatus::Ok);

        // The context is bound as a critical `context@proton.ch` notation.
        let parsed = StandaloneSignature::from_bytes(std::io::Cursor::new(&sig)).unwrap();
        let notations = parsed.signature.notations();
        let ctx = notations
            .iter()
            .find(|n| n.name.as_ref() == PROTON_SIGNATURE_CONTEXT_NOTATION)
            .unwrap();
        assert_eq!(ctx.value.as_ref(), b"drive.sharing.member");
    }

    // ── SRP verifier ────────────────────────────────────────────────────────

    /// A server-signed SRP modulus whose signature verifies against the Proton
    /// server key bundled in `proton-srp`. Lifted from proton-srp's own
    /// verifier test vectors, so it exercises the real PGP-signature
    /// verification path inside `generate_verifier_with_pgp`.
    const TEST_SIGNED_MODULUS: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\ny6TtufhYg2mIeauZYOti+GPbd/0vP66kP34TgE6elK/kXkTW/Yfrp1jMmtLiWWSq5cszTMRIEighuwPbZ/z3RrWPxsOg0+jYgbFu8yZ8vOAwrPtLxZl94x0PFTAZBrVapmCn+VYcM+UXdO9v70xFDLwj34tpPbvpODHVWHSlGlhOwndWg3XBE2D9PJopFZajNZiqOScBXree5rDgzU5BBaPbIb6nySpyaeThMCcNzpcEqE8r3ro+E/VdXBvSSJpusr1dvAwHc3IDGUzAhodqV5mjYy9nXwq/9gHWpYNtm76Ols7ReWAhZwy1+cQllQZwGfzzOVGpc+3WutOntQjM6Q==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j8JEDUFhcTpUY8mAADfEAD8DFdNXn4TsgbfbAZRDa9a\nyywqa/2W9Qyg5MJaNZd2a+0BAPg04gEZI+G8RaoPVh/SYvWx7jpP3L1O8bEi\nM/j1cjIO\n=5RYw\n-----END PGP SIGNATURE-----";

    /// The derivation `verifier = g^x mod N` is deterministic for a fixed
    /// (password, salt, modulus). Pin it against the authoritative Proton SRP
    /// vector to prove our delegation computes the canonical value and uses
    /// hash version 4 — the same V4 hashing the working login path relies on.
    #[test]
    fn srp_verifier_is_deterministic_for_fixed_salt() {
        let password = "123";
        let salt = "SzHkg+YYA/eN1A==";
        let expected_verifier = "j2o8z9G+Xm5t07Y6D7rauq3bNi6v0ZqnM1nWuZHS8PgtQOl4Xgh8LjuzulhX1izaOqeIoW221Z/LDVkrUZzxAXwFdi5LfxMN+RHPJCg0Uk5OcigQHsO1xTMuk3hvoIXO7yIXXs2oCqpBwKNfuhMNjcwVlgjyh5ZC4FzhSV2lwlP7KE1me/USAOfq4FbW7KtDtvxX8fk6hezWIz9X8/bcAHwQkHobqOVTCE81Lg+WL7s4sMed72YHwx5p6S/YGm558zrZmeETv6PuS4MRkQ8vPRrIvmzPEQDUiOXCaqfLkGvBFeCbBjNtBM8AlbWcW8XE+gcb/GwWH8cHinzd4ddh4A==";

        let verifier = proton_srp::SRPAuth::generate_verifier_with_pgp(
            password,
            Some(salt),
            TEST_SIGNED_MODULUS,
        )
        .unwrap();
        let b64 = proton_srp::SRPVerifierB64::from(verifier);

        assert_eq!(b64.verifier, expected_verifier, "verifier g^x mod N");
        assert_eq!(b64.salt, salt, "salt is echoed unchanged");
        assert_eq!(u8::from(b64.version), 4, "Proton SRP hash version is 4");
    }

    /// `get_srp_verifier` binds the configured `ModulusID`, reports version 4,
    /// and produces fresh, decodable salt/verifier bytes on each call. Without
    /// a configured modulus it must fail loudly rather than fabricate one.
    #[tokio::test]
    async fn get_srp_verifier_structure_and_modulus_binding() {
        use base64::Engine as _;

        // No modulus configured → explicit SRP error, never a fabricated value.
        let bare = RpgpCrypto::new();
        assert!(matches!(
            bare.get_srp_verifier("pw").await,
            Err(CryptoError::Srp(_))
        ));

        let crypto = RpgpCrypto::new().with_srp_modulus("modulus-id-xyz", TEST_SIGNED_MODULUS);

        let v1 = crypto.get_srp_verifier("correct horse").await.unwrap();
        assert_eq!(v1.modulus_id, "modulus-id-xyz", "ModulusID is echoed back");
        assert_eq!(v1.version, 4, "registration uses SRP hash version 4");

        // Salt and verifier are valid base64 of the expected SRP byte lengths.
        let salt_bytes = base64::engine::general_purpose::STANDARD
            .decode(&v1.salt)
            .unwrap();
        assert_eq!(salt_bytes.len(), proton_srp::SALT_LEN_BYTES);
        let verifier_bytes = base64::engine::general_purpose::STANDARD
            .decode(&v1.verifier)
            .unwrap();
        assert_eq!(verifier_bytes.len(), proton_srp::SRP_LEN_BYTES);

        // A second call draws a fresh random salt, so the verifier differs.
        let v2 = crypto.get_srp_verifier("correct horse").await.unwrap();
        assert_ne!(v1.salt, v2.salt, "each verifier uses a fresh CSPRNG salt");
        assert_ne!(v1.verifier, v2.verifier, "fresh salt → distinct verifier");
    }

    // ── SKESK (password-encrypted session key) ───────────────────────────────

    /// Round-trip: encrypt a session key under a password (v4 SKESK), then
    /// recover it by parsing the packet and running S2K with the same
    /// password. Proves the SKESK we emit is self-consistent and decryptable.
    #[tokio::test]
    async fn session_key_password_roundtrip() {
        let crypto = RpgpCrypto::new();
        let password = "s3ssion-pa55phrase";
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        assert_eq!(session_key.data.len(), 32, "AES-256 session key");

        let skesk = crypto
            .encrypt_session_key_with_password(&session_key, password)
            .await
            .unwrap();
        assert!(!skesk.is_empty());

        // The emitted bytes parse as a single v4 SKESK packet with an
        // Iterated+Salted (type 3) S2K over SHA-256 and AES-256.
        let parser = PacketParser::new(std::io::BufReader::new(skesk.as_slice()));
        let mut saw_skesk = false;
        for packet in parser {
            if let pgp::packet::Packet::SymKeyEncryptedSessionKey(sk) = packet.unwrap() {
                saw_skesk = true;
                let s2k = sk.s2k().unwrap();
                assert_eq!(s2k.id(), 3, "Iterated+Salted S2K (type 3)");
                assert!(s2k.uses_salt(), "S2K is salted");
                assert_eq!(
                    sk.sym_algorithm(),
                    Some(SymmetricKeyAlgorithm::AES256),
                    "wrapping cipher is AES-256"
                );
            }
        }
        assert!(saw_skesk, "output contains exactly one SKESK packet");

        let recovered = RpgpCrypto::decrypt_session_key_with_password(&skesk, password).unwrap();
        assert_eq!(
            recovered.data, session_key.data,
            "recovered session key equals the original"
        );
        assert_eq!(recovered.cipher_algorithm, session_key.cipher_algorithm);

        // A wrong password must not recover the original key.
        let wrong = RpgpCrypto::decrypt_session_key_with_password(&skesk, "not-the-password");
        match wrong {
            Err(_) => {}
            Ok(other) => assert_ne!(
                other.data, session_key.data,
                "wrong password must not yield the original key"
            ),
        }
    }

    /// The SKESK round-trips through the ASCII-armor path too: Proton delivers
    /// `PGPMessage` fields armored, so `to_binary_pgp` must dearmor before the
    /// packet parser sees the SKESK.
    #[tokio::test]
    async fn session_key_password_roundtrip_armored() {
        let crypto = RpgpCrypto::new();
        let password = "armored-skesk-pw";
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let skesk = crypto
            .encrypt_session_key_with_password(&session_key, password)
            .await
            .unwrap();
        let armored = armor(&skesk, ArmorKind::Message);
        assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));

        let binary = RpgpCrypto::to_binary_pgp(armored.as_bytes()).unwrap();
        let recovered = RpgpCrypto::decrypt_session_key_with_password(&binary, password).unwrap();
        assert_eq!(recovered.data, session_key.data);
    }

    // ── SEIPDv2/AEAD rejection guard (ADR-0006) ──────────────────────────────

    /// A bare SEIPDv2 (AEAD) packet must be rejected explicitly with
    /// `CryptoError::AeadNotSupported`, not merely fail with some incidental
    /// parse/mismatch error from deep inside rpgp.
    #[tokio::test]
    async fn decrypt_rejects_seipdv2_explicitly() {
        use pgp::crypto::aead::{AeadAlgorithm as PgpAeadAlgorithm, ChunkSize};

        let crypto = RpgpCrypto::new();
        let raw_key = vec![0x42u8; 32];

        let seipd = SymEncryptedProtectedData::encrypt_seipdv2(
            rand::thread_rng(),
            SymmetricKeyAlgorithm::AES256,
            PgpAeadAlgorithm::Gcm,
            ChunkSize::default(),
            &raw_key,
            b"top secret",
        )
        .unwrap();
        let mut binary = Vec::new();
        seipd.to_writer_with_header(&mut binary).unwrap();

        let session_key = SessionKey {
            data: Zeroizing::new(raw_key),
            cipher_algorithm: 9,
            aead: AeadAlgorithm::Gcm,
        };

        let result = crypto.decrypt_and_verify(&binary, &session_key, &[]).await;
        assert!(
            matches!(result, Err(CryptoError::AeadNotSupported)),
            "expected AeadNotSupported, got {result:?}"
        );
    }

    // ── Debug redaction (no secrets in `{:?}` output) ────────────────────────

    #[tokio::test]
    async fn private_key_debug_redacts_armored_and_passphrase() {
        let crypto = RpgpCrypto::new();
        let (priv_key, _pub_armored) = crypto
            .generate_key("super-secret-passphrase", EncryptOptions::default())
            .await
            .unwrap();

        let debug_output = format!("{priv_key:?}");
        assert!(
            !debug_output.contains("super-secret-passphrase"),
            "Debug output must not leak the passphrase: {debug_output}"
        );
        assert!(
            !debug_output.contains("PRIVATE KEY"),
            "Debug output must not leak the armored private key: {debug_output}"
        );
        assert!(
            debug_output.contains(&priv_key.fingerprint_hex),
            "Debug output should still show the (non-secret) fingerprint"
        );
    }

    #[tokio::test]
    async fn session_key_debug_redacts_raw_bytes() {
        let crypto = RpgpCrypto::new();
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let debug_output = format!("{session_key:?}");
        let hex_bytes = hex::encode(&*session_key.data);
        assert!(
            !debug_output.contains(&hex_bytes),
            "Debug output must not leak the raw session key bytes: {debug_output}"
        );
        assert!(
            debug_output.contains("redacted"),
            "Debug output should indicate redaction: {debug_output}"
        );
    }
}
