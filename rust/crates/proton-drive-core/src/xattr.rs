//! Shared decryption + parsing of a file revision's encrypted extended
//! attributes (`XAttr`). Ports the read side of
//! `client/js/src/internal/nodes/extendedAttributes.ts`
//! (`parseFileExtendedAttributes`, `parseSize`, `parseDigests`,
//! `parseModificationTime`).
//!
//! XAttr is an armored PGP message: encrypted to the file's node key, signed by
//! the address key. Every step here is **best-effort** — an undecryptable,
//! non-UTF-8, or unparseable XAttr yields `None`/empty, never an error. This
//! mirrors JS, where a failed XAttr parse is caught and the node is still
//! returned with whatever else decrypted (`parseFileExtendedAttributes`'s
//! `try { … } catch { return {} }`), and cs `DtoToMetadataConverter` recording
//! an `ExtendedAttributesDeserializationError` against the node while still
//! returning everything else.
//!
//! Shared by the listing/fetch path (populating [`crate::nodes::Revision`]) and
//! the download path ([`crate::download::FileDownloader`]'s post-download
//! cross-check and pre-download progress total), so all callers read the same
//! bytes the same way.

use std::sync::Arc;
use std::time::SystemTime;

use proton_drive_crypto::{OpenPgpCrypto, PrivateKey};

/// Outcome of best-effort `Common.ModificationTime` extraction from a decrypted
/// XAttr document — mirrors cs's `Result<DateTime, ProtonDriveError>?` on
/// `CommonExtendedAttributes.ModificationTime`
/// (`reference/client/cs/src/Proton.Drive.Sdk/Api/Files/CommonExtendedAttributes.cs`):
/// absent, present-and-valid, or present-but-unparseable. The last case is a
/// per-node degradation surfaced to the caller, never a failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XAttrModificationTime {
    /// The parsed claimed modification time, when present and valid.
    pub time: Option<SystemTime>,
    /// Set when `Common.ModificationTime` was present but not parseable into a
    /// time (wrong JSON type, or a string in no accepted date format). Digits
    /// are redacted so the shape can be diagnosed without leaking the exact
    /// claimed timestamp into logs.
    pub error: Option<String>,
}

/// Decrypt a revision's armored `XAttr` blob to its plaintext JSON value.
///
/// Best-effort: if undecryptable, not valid UTF-8, or not valid JSON, warns and
/// returns `None` (JS `parseFileExtendedAttributes` falls back to `{}`). `node_id`
/// is used only for log context.
///
/// XAttr is an armored PGP message (`armoredExtendedAttributes`): encrypted to
/// the node key, signed by the address key. Decrypt the session key with the
/// node key, then the message body; verification is best-effort here (empty
/// keys → no signature check), mirroring JS where a failed XAttr decrypt is
/// non-fatal.
pub async fn decrypt_xattr_json(
    crypto: &Arc<dyn OpenPgpCrypto>,
    node_private_key: &PrivateKey,
    node_id: &str,
    xattr_armored: &str,
) -> Option<serde_json::Value> {
    let xattr_bytes = xattr_armored.as_bytes();
    let session_key = match crypto
        .decrypt_session_key(xattr_bytes, std::slice::from_ref(node_private_key))
        .await
    {
        Ok(sk) => sk,
        Err(e) => {
            tracing::warn!(
                node_id = %node_id,
                "XAttr session-key decrypt failed: {e} — skipping"
            );
            return None;
        }
    };

    let plaintext = match crypto
        .decrypt_and_verify(xattr_bytes, &session_key, &[])
        .await
    {
        Ok((pt, _)) => pt,
        Err(e) => {
            tracing::warn!(
                node_id = %node_id,
                "XAttr decrypt failed: {e} — skipping"
            );
            return None;
        }
    };

    let json_str = match std::str::from_utf8(&plaintext) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                node_id = %node_id,
                "XAttr plaintext not UTF-8: {e}"
            );
            return None;
        }
    };

    match serde_json::from_str(json_str) {
        Ok(v) => Some(v),
        Err(e) => {
            // Show what was actually in the JSON (digits redacted, matching cs
            // `Iso8601DateTimeResultJsonConverter`'s redaction) rather than just
            // the serde_json parse error — that error alone doesn't say what
            // shape the payload had.
            tracing::warn!(
                node_id = %node_id,
                "XAttr JSON parse failed: {e}; payload was: {}",
                redact_digits(json_str)
            );
            None
        }
    }
}

/// Extract `Common.Digests.SHA1` from a decrypted XAttr document.
///
/// Mirrors JS `parseDigests` (`extendedAttributes.ts`): returns the SHA1 string
/// when present and a JSON string, else `None`. First-party writers emit
/// 40-hex-lowercase (this SDK's uploader does `hex::encode(sha1)`); the value is
/// returned verbatim rather than re-validated, matching JS's leniency.
pub fn content_sha1(xattr: &serde_json::Value) -> Option<String> {
    xattr
        .get("Common")
        .and_then(|c| c.get("Digests"))
        .and_then(|d| d.get("SHA1"))
        .and_then(|s| s.as_str())
        .map(str::to_owned)
}

/// Extract `Common.Size` (the claimed plaintext byte length) from a decrypted
/// XAttr document. Mirrors JS `parseSize`: returns the value only when present
/// and a JSON number.
pub fn size(xattr: &serde_json::Value) -> Option<u64> {
    xattr
        .get("Common")
        .and_then(|c| c.get("Size"))
        .and_then(serde_json::Value::as_u64)
}

/// Extract `Common.ModificationTime` from a decrypted XAttr document.
///
/// `ModificationTime` is a JSON *string* on the wire (`dateToIsoString` —
/// `extendedAttributes.ts`), never a number. Mirrors JS `parseModificationTime`:
/// an absent/null field yields the default (no time, no error); a present string
/// that parses yields the time; a present string that does not parse, or a
/// non-string value, yields a redacted error while still leaving `time` `None`
/// (a per-node degradation, never a failure).
pub fn modification_time(xattr: &serde_json::Value) -> XAttrModificationTime {
    match xattr.get("Common").and_then(|c| c.get("ModificationTime")) {
        None | Some(serde_json::Value::Null) => XAttrModificationTime::default(),
        Some(serde_json::Value::String(raw)) => match parse_modification_time(raw) {
            Some(time) => XAttrModificationTime {
                time: Some(time),
                error: None,
            },
            None => XAttrModificationTime {
                time: None,
                error: Some(format!(
                    "XAttr ModificationTime \"{}\" is not a recognized date format",
                    redact_digits(raw)
                )),
            },
        },
        Some(other) => XAttrModificationTime {
            time: None,
            error: Some(format!(
                "XAttr ModificationTime has unexpected JSON type (expected string): {}",
                redact_digits(&other.to_string())
            )),
        },
    }
}

/// Redact ASCII digits from a string for safe inclusion in logs/error text —
/// mirrors cs `Iso8601DateTimeResultJsonConverter`'s `redactedValue`
/// (`char.IsDigit(c) ? '#' : c`): shows the *shape* of what was actually in the
/// JSON without leaking the exact claimed timestamp.
fn redact_digits(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect()
}

/// Parse an XAttr `Common.ModificationTime` string into a `SystemTime`.
///
/// Accepts the format set upstream both writes and reads:
/// - JS `Date.prototype.toISOString()` (`extendedAttributes.ts`
///   `dateToIsoString`) — always UTC, always exactly 3 fractional digits:
///   `YYYY-MM-DDTHH:MM:SS.sssZ`.
/// - C# round-trip (`"O"`) format
///   (`Iso8601DateTimeResultJsonConverter.Write`) — always UTC, always exactly
///   7 fractional digits: `YYYY-MM-DDTHH:MM:SS.fffffffZ`.
/// - The general RFC 3339 shape cs's reader also accepts (`TryGetDateTimeOffset`
///   plus its `DateTimeOffset.TryParse` fallback): any fractional-second digit
///   count from 0 to 9, and either a `Z` suffix or a numeric `+HH:MM`/`-HH:MM`
///   offset in place of `Z` — covering values written by other first-party
///   clients (desktop/mobile), not just this SDK's own writer.
///
/// Returns `None` — not an error — for anything else. The inverse of
/// `upload::system_time_to_iso8601`'s `civil_from_days`.
fn parse_modification_time(raw: &str) -> Option<SystemTime> {
    let bytes = raw.as_bytes();
    // Shortest valid form: "YYYY-MM-DDTHH:MM:SS" + "Z" == 20 bytes.
    if bytes.len() < 20 {
        return None;
    }

    let digit = |i: usize| -> Option<i64> {
        let c = *bytes.get(i)?;
        if c.is_ascii_digit() {
            Some((c - b'0') as i64)
        } else {
            None
        }
    };
    let two = |i: usize| -> Option<i64> { Some(digit(i)? * 10 + digit(i + 1)?) };
    let four = |i: usize| -> Option<i64> {
        Some(digit(i)? * 1000 + digit(i + 1)? * 100 + digit(i + 2)? * 10 + digit(i + 3)?)
    };

    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let year = four(0)?;
    let month = two(5)?;
    let day = two(8)?;

    let t = bytes.get(10)?;
    if *t != b'T' && *t != b't' {
        return None;
    }
    if bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') {
        return None;
    }
    let hour = two(11)?;
    let minute = two(14)?;
    let second = two(17)?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }

    let mut cursor = 19usize;
    let mut nanos: i64 = 0;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let frac_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        let frac_len = cursor - frac_start;
        if !(1..=9).contains(&frac_len) {
            return None;
        }
        let mut value: i64 = 0;
        for i in frac_start..cursor {
            value = value * 10 + digit(i)?;
        }
        let scale = 10i64.pow(9 - frac_len as u32);
        nanos = value * scale;
    }

    let offset_minutes: i64 = match bytes.get(cursor) {
        Some(b'Z') | Some(b'z') => {
            cursor += 1;
            0
        }
        Some(b'+') | Some(b'-') => {
            let sign = if bytes[cursor] == b'+' { 1 } else { -1 };
            let offset_hour = two(cursor + 1)?;
            if bytes.get(cursor + 3) != Some(&b':') {
                return None;
            }
            let offset_minute = two(cursor + 4)?;
            cursor += 6;
            sign * (offset_hour * 60 + offset_minute)
        }
        _ => return None,
    };

    // Trailing garbage after a well-formed timestamp+offset is not tolerated.
    if cursor != bytes.len() {
        return None;
    }

    // days_from_civil (Howard Hinnant, http://howardhinnant.github.io/date_algorithms.html)
    // — the inverse of `upload::system_time_to_iso8601`'s `civil_from_days`.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (month + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era * 146_097 + doe - 719_468;

    let seconds_of_day = hour * 3_600 + minute * 60 + second;
    let total_seconds = days_since_epoch * 86_400 + seconds_of_day - offset_minutes * 60;

    // `std::time::SystemTime`'s `Duration`-based API cannot represent an instant
    // before `UNIX_EPOCH` on all platforms; treat as unparseable rather than
    // panicking or silently clamping to the epoch.
    if total_seconds < 0 {
        return None;
    }

    Some(
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(total_seconds as u64)
            + std::time::Duration::from_nanos(nanos as u64),
    )
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn xattr_value(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn content_sha1_reads_common_digests_sha1() {
        let v = xattr_value(
            r#"{"Common":{"Size":11,"Digests":{"SHA1":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}}}"#,
        );
        assert_eq!(
            content_sha1(&v).as_deref(),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
    }

    #[test]
    fn content_sha1_missing_digests_is_none() {
        let v = xattr_value(r#"{"Common":{"Size":11}}"#);
        assert_eq!(content_sha1(&v), None);
    }

    #[test]
    fn content_sha1_missing_common_is_none() {
        let v = xattr_value(r#"{"Location":{"Latitude":1.0}}"#);
        assert_eq!(content_sha1(&v), None);
    }

    #[test]
    fn content_sha1_non_string_is_none() {
        // Mirrors JS `parseDigests` rejecting a non-string SHA1.
        let v = xattr_value(r#"{"Common":{"Digests":{"SHA1":12345}}}"#);
        assert_eq!(content_sha1(&v), None);
    }

    #[test]
    fn size_reads_common_size() {
        let v = xattr_value(r#"{"Common":{"Size":4096}}"#);
        assert_eq!(size(&v), Some(4096));
    }

    #[test]
    fn size_non_number_is_none() {
        let v = xattr_value(r#"{"Common":{"Size":"4096"}}"#);
        assert_eq!(size(&v), None);
    }

    #[test]
    fn modification_time_absent_is_empty() {
        let v = xattr_value(r#"{"Common":{"Size":1}}"#);
        assert_eq!(modification_time(&v), XAttrModificationTime::default());
    }

    #[test]
    fn modification_time_null_is_empty() {
        let v = xattr_value(r#"{"Common":{"ModificationTime":null}}"#);
        assert_eq!(modification_time(&v), XAttrModificationTime::default());
    }

    #[test]
    fn modification_time_js_isostring_parses() {
        // JS `Date(0).toISOString()` — epoch, 3 fractional digits.
        let v = xattr_value(r#"{"Common":{"ModificationTime":"1970-01-01T00:00:00.000Z"}}"#);
        let got = modification_time(&v);
        assert_eq!(got.time, Some(std::time::UNIX_EPOCH));
        assert_eq!(got.error, None);
    }

    #[test]
    fn modification_time_cs_roundtrip_seven_fraction_digits_parses() {
        // C# "O" format — 7 fractional digits.
        let v = xattr_value(r#"{"Common":{"ModificationTime":"2021-01-01T00:00:00.0000000Z"}}"#);
        let got = modification_time(&v);
        let expected = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_609_459_200);
        assert_eq!(got.time, Some(expected));
        assert_eq!(got.error, None);
    }

    #[test]
    fn modification_time_numeric_offset_parses() {
        // RFC 3339 with a +HH:MM offset instead of Z (other first-party clients).
        let v = xattr_value(r#"{"Common":{"ModificationTime":"2021-01-01T01:00:00+01:00"}}"#);
        let got = modification_time(&v);
        let expected = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_609_459_200);
        assert_eq!(got.time, Some(expected));
        assert_eq!(got.error, None);
    }

    #[test]
    fn modification_time_unparseable_string_yields_redacted_error() {
        let v = xattr_value(r#"{"Common":{"ModificationTime":"not-a-date-2020"}}"#);
        let got = modification_time(&v);
        assert_eq!(got.time, None);
        let err = got.error.expect("unparseable time should record an error");
        // Digits redacted to '#'.
        assert!(err.contains("not-a-date-####"), "got: {err}");
    }

    #[test]
    fn modification_time_wrong_type_yields_error() {
        let v = xattr_value(r#"{"Common":{"ModificationTime":1609459200}}"#);
        let got = modification_time(&v);
        assert_eq!(got.time, None);
        assert!(got.error.is_some());
    }

    #[test]
    fn modification_time_before_epoch_is_unparseable() {
        // SystemTime's Duration API can't represent pre-epoch; treated as
        // unparseable rather than clamped.
        let v = xattr_value(r#"{"Common":{"ModificationTime":"1960-01-01T00:00:00.000Z"}}"#);
        let got = modification_time(&v);
        assert_eq!(got.time, None);
        assert!(got.error.is_some());
    }

    /// Accepted-format matrix for the private [`parse_modification_time`],
    /// exercised directly (no crypto/HTTP) — the parser is the same one both
    /// the listing/fetch and download paths reach through
    /// [`modification_time`].
    mod parse_modification_time_tests {
        use super::super::parse_modification_time;
        use std::time::{Duration, UNIX_EPOCH};

        // 1_700_000_000s since epoch == 2023-11-14T22:13:20.000Z (same constant
        // `upload::tests::xattr_json_with_mtime` uses for the writer side).
        const EPOCH_SECS: u64 = 1_700_000_000;

        #[test]
        fn accepts_js_millisecond_format() {
            assert_eq!(
                parse_modification_time("2023-11-14T22:13:20.000Z"),
                Some(UNIX_EPOCH + Duration::from_secs(EPOCH_SECS))
            );
        }

        #[test]
        fn accepts_no_fractional_seconds() {
            assert_eq!(
                parse_modification_time("2023-11-14T22:13:20Z"),
                Some(UNIX_EPOCH + Duration::from_secs(EPOCH_SECS))
            );
        }

        #[test]
        fn accepts_cs_seven_digit_round_trip_format() {
            assert_eq!(
                parse_modification_time("2023-11-14T22:13:20.1234567Z"),
                Some(
                    UNIX_EPOCH
                        + Duration::from_secs(EPOCH_SECS)
                        + Duration::from_nanos(123_456_700)
                )
            );
        }

        #[test]
        fn accepts_positive_numeric_offset() {
            // 23:13:20+01:00 == 22:13:20Z.
            assert_eq!(
                parse_modification_time("2023-11-14T23:13:20+01:00"),
                Some(UNIX_EPOCH + Duration::from_secs(EPOCH_SECS))
            );
        }

        #[test]
        fn accepts_negative_numeric_offset() {
            // 21:13:20-01:00 == 22:13:20Z.
            assert_eq!(
                parse_modification_time("2023-11-14T21:13:20-01:00"),
                Some(UNIX_EPOCH + Duration::from_secs(EPOCH_SECS))
            );
        }

        #[test]
        fn rejects_empty_and_truncated_strings() {
            assert_eq!(parse_modification_time(""), None);
            assert_eq!(parse_modification_time("2023-11-14"), None);
        }

        #[test]
        fn rejects_non_date_garbage() {
            assert_eq!(parse_modification_time("not-a-date-at-all!!"), None);
        }

        #[test]
        fn rejects_out_of_range_components() {
            assert_eq!(parse_modification_time("2023-13-14T22:13:20Z"), None); // month 13
            assert_eq!(parse_modification_time("2023-11-14T25:13:20Z"), None); // hour 25
        }

        #[test]
        fn rejects_missing_offset_or_z() {
            assert_eq!(parse_modification_time("2023-11-14T22:13:20"), None);
        }
    }
}
