//! Account / Identity supporting subdomain.
//!
//! The SDK does not model users or sessions — the host supplies a
//! [`ProtonDriveAccount`]. Mirrors `client/js/src/interface/account.ts`.

use async_trait::async_trait;
use proton_drive_crypto::{PrivateKey, PublicKey};

use crate::error::Result;

/// Active account context the host hands to the SDK.
#[async_trait]
pub trait ProtonDriveAccount: Send + Sync {
    /// Stable user identifier from the Account API.
    fn user_id(&self) -> &str;

    /// Primary email address tied to the active account.
    fn primary_email(&self) -> &str;

    /// Resolve an address's private key. Used to decrypt content addressed
    /// to that address.
    async fn address_private_key(&self, email: &str) -> Result<PrivateKey>;

    /// Resolve **all** public keys for an address (current + rotated-out), for
    /// signature verification. Mirrors JS `account.getPublicKeys(email)`. A
    /// revision can be signed by a key that has since been replaced, so the
    /// verifier must consider the address's whole key history, not just the
    /// primary key's public portion.
    async fn address_public_keys(&self, email: &str) -> Result<Vec<PublicKey>>;

    /// Resolve an address's stable ID (the Proton `AddressID`, not the email).
    /// Block-upload and revision endpoints key on this ID.
    async fn address_id(&self, email: &str) -> Result<String>;

    /// Fetch the user's salted key password (for SRP and key decryption).
    async fn key_password(&self) -> Result<String>;
}

/// Identity that produced a node or signature.
/// Mirrors JS `Author` / `AnonymousUser`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Author {
    User {
        email: String,
        display_name: Option<String>,
    },
    Anonymous,
    Unverified {
        email: String,
        reason: String,
    },
}
