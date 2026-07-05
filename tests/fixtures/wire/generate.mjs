#!/usr/bin/env node
/**
 * generate.mjs — one-shot fixture generator for wire-format validation tests.
 *
 * Generates:
 *   key_pub.asc / key_priv.asc          — Ed25519+X25519 keypair (empty passphrase)
 *   signer_pub.asc / signer_priv.asc    — Ed25519 signing keypair (empty passphrase)
 *   seipdv1_signed.plaintext.bin        — 256-byte deterministic plaintext
 *   seipdv1_signed.bin                  — OpenPGP.js SEIPDv1 encrypted+signed message
 *   seipdv1_signed.meta.json            — metadata (fingerprints, sha256 of plaintext)
 *   seipdv1_tampered.bin                — seipdv1_signed.bin with one body byte flipped
 *   seipdv1_wrong_signer.bin            — re-signed with a throwaway key
 *   seipdv1_truncated.bin               — seipdv1_signed.bin cut off mid-SEIPD-body
 *   seipdv1_wrong_recipient.bin         — encrypted to a throwaway key, NOT key_pub.asc
 *
 * Usage:
 *   npm i openpgp          # install once (not tracked in package.json)
 *   node generate.mjs
 *
 * Requires: Node >= 18, openpgp v6+
 *
 * KEY STABILITY: if `key_pub.asc`/`key_priv.asc`/`signer_pub.asc`/
 * `signer_priv.asc` already exist in this directory, they are REUSED as-is
 * rather than regenerated. Only the derived `.bin`/`.meta.json` fixtures are
 * rewritten. This keeps the primary keypairs stable across regenerations
 * (no silent key rotation) and, incidentally, makes the tamper-offset
 * computation below reproducible run to run. Delete the `.asc` files first
 * if you deliberately want a fresh keypair.
 *
 * WARNING: Keys produced here are TEST-ONLY. Never use in production.
 *          Empty passphrases are intentional for test simplicity.
 */

import { createHash, createHmac } from 'node:crypto';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ── dependency guard ──────────────────────────────────────────────────────────
let openpgp;
try {
  openpgp = await import('openpgp');
} catch {
  console.error(
    '\nERROR: openpgp npm package is not installed.\n' +
    'Run:  npm i openpgp\n' +
    'Then re-run:  node generate.mjs\n'
  );
  process.exit(1);
}

const OUT_DIR = dirname(fileURLToPath(import.meta.url));
const out = (name) => join(OUT_DIR, name);

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Deterministic pseudo-random 256 bytes seeded from a fixed string.
 * Uses HMAC-SHA256 in counter mode so it is reproducible across platforms
 * without depending on any specific RNG implementation.
 */
function deterministicPlaintext(seedString, length = 256) {
  const result = Buffer.alloc(length);
  let offset = 0;
  let counter = 0;
  while (offset < length) {
    const chunk = createHmac('sha256', seedString)
      .update(Buffer.from([counter]))
      .digest();
    const toCopy = Math.min(chunk.length, length - offset);
    chunk.copy(result, offset, 0, toCopy);
    offset += toCopy;
    counter++;
  }
  return result;
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Load an existing armored keypair from disk if both halves are present,
 * otherwise generate a fresh one and write it out. Returns
 * `{ publicKey, privateKey, reused }` (armored strings).
 */
async function loadOrGenerateKey(pubPath, privPath, genOpts) {
  if (existsSync(pubPath) && existsSync(privPath)) {
    return {
      publicKey: readFileSync(pubPath, 'utf8'),
      privateKey: readFileSync(privPath, 'utf8'),
      reused: true,
    };
  }
  const key = await openpgp.generateKey(genOpts);
  writeFileSync(pubPath, key.publicKey, 'utf8');
  writeFileSync(privPath, key.privateKey, 'utf8');
  return { publicKey: key.publicKey, privateKey: key.privateKey, reused: false };
}

/**
 * Minimal RFC 4880 packet-header walker. Decodes each packet's tag and body
 * length from its actual header encoding (new-format and old-format) rather
 * than scanning the byte stream for a tag value that merely looks right.
 *
 * This replaces a previous heuristic that scanned for the first `0xD2`
 * (new-format tag 18, SEIPD) or `0xA4..0xA7` (old-format tag 9) byte in the
 * whole buffer: a PKESK packet's own body is MPI-encoded key material with
 * essentially random bytes, so on a freshly generated keypair that scan
 * could land inside the PKESK instead of the SEIPD packet purely by chance,
 * corrupting the wrong packet and breaking `wire_tampered_ciphertext_is_rejected`.
 * Walking real packet-length headers from the start never confuses packet
 * *contents* for a packet *boundary*.
 *
 * Returns an array of `{ tag, headerLength, bodyStart, bodyLength }`.
 */
function parsePackets(buf) {
  const packets = [];
  let offset = 0;
  while (offset < buf.length) {
    const first = buf[offset];
    if ((first & 0x80) === 0) {
      throw new Error(`invalid OpenPGP packet header at offset ${offset}: 0x${first.toString(16)}`);
    }
    const newFormat = (first & 0x40) !== 0;
    let tag;
    let headerLength;
    let bodyLength;
    if (newFormat) {
      tag = first & 0x3f;
      const len0 = buf[offset + 1];
      if (len0 < 192) {
        bodyLength = len0;
        headerLength = 2;
      } else if (len0 < 224) {
        const len1 = buf[offset + 2];
        bodyLength = (len0 - 192) * 256 + len1 + 192;
        headerLength = 3;
      } else if (len0 === 255) {
        bodyLength = buf.readUInt32BE(offset + 2);
        headerLength = 6;
      } else {
        // Partial Body Length (streaming packets) — openpgp.js's
        // non-streaming `format: 'binary'` output does not emit these for
        // our small deterministic fixtures.
        throw new Error(`partial-body-length packet at offset ${offset} is not supported`);
      }
    } else {
      tag = (first >> 2) & 0x0f;
      const lengthType = first & 0x03;
      if (lengthType === 0) {
        bodyLength = buf[offset + 1];
        headerLength = 2;
      } else if (lengthType === 1) {
        bodyLength = buf.readUInt16BE(offset + 1);
        headerLength = 3;
      } else if (lengthType === 2) {
        bodyLength = buf.readUInt32BE(offset + 1);
        headerLength = 5;
      } else {
        throw new Error(`indeterminate-length old-format packet at offset ${offset} is not supported`);
      }
    }
    const bodyStart = offset + headerLength;
    packets.push({ tag, headerLength, bodyStart, bodyLength });
    offset = bodyStart + bodyLength;
  }
  return packets;
}

/** Find the Symmetrically Encrypted Integrity Protected Data packet (tag 18). */
function findSeipdPacket(buf) {
  const packets = parsePackets(buf);
  const seipd = packets.find((p) => p.tag === 18);
  if (!seipd) {
    throw new Error('no SEIPD (tag 18) packet found in message — cannot locate body to tamper/truncate');
  }
  return seipd;
}

// ── generate/reuse keypairs ────────────────────────────────────────────────────

const encKeyGenOpts = {
  type: 'curve25519',
  userIDs: [{ name: 'Drive Test Key', email: 'test-enc@example.invalid' }],
  format: 'armored',
  config: { preferredHashAlgorithm: openpgp.enums.hash.sha256 },
};
const encKey = await loadOrGenerateKey(out('key_pub.asc'), out('key_priv.asc'), encKeyGenOpts);
console.log(
  encKey.reused
    ? 'Reusing committed encryption keypair (key_pub.asc / key_priv.asc).'
    : 'Generated new Ed25519+X25519 encryption keypair (key_pub.asc / key_priv.asc).'
);

const signerKeyGenOpts = {
  type: 'curve25519',
  userIDs: [{ name: 'Drive Test Signer', email: 'test-signer@example.invalid' }],
  format: 'armored',
  config: { preferredHashAlgorithm: openpgp.enums.hash.sha256 },
};
const signerKey = await loadOrGenerateKey(out('signer_pub.asc'), out('signer_priv.asc'), signerKeyGenOpts);
console.log(
  signerKey.reused
    ? 'Reusing committed signing keypair (signer_pub.asc / signer_priv.asc).'
    : 'Generated new Ed25519 signing keypair (signer_pub.asc / signer_priv.asc).'
);

// ── deterministic plaintext ───────────────────────────────────────────────────

const SEED = 'proton-drive-sdk-wire-format-test-fixture-v1';
const plaintext = deterministicPlaintext(SEED, 256);
writeFileSync(out('seipdv1_signed.plaintext.bin'), plaintext);
console.log('  Written: seipdv1_signed.plaintext.bin (256 bytes, seed: ' + SEED + ')');

// ── encrypt + sign ────────────────────────────────────────────────────────────

console.log('Encrypting and signing…');
const encPublicKey = await openpgp.readKey({ armoredKey: encKey.publicKey });
const signerPrivateKey = await openpgp.readPrivateKey({ armoredKey: signerKey.privateKey });

const encrypted = await openpgp.encrypt({
  message: await openpgp.createMessage({ binary: plaintext }),
  encryptionKeys: encPublicKey,
  signingKeys: signerPrivateKey,
  config: {
    preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed,
    aeadProtect: false,
    // Force SEIPDv1 — do not emit SEIPDv2 AEAD packets.
    allowInsecureDecryptionWithSigningKeys: false,
  },
  format: 'binary',
});

const ciphertextBuf = Buffer.from(encrypted);
writeFileSync(out('seipdv1_signed.bin'), ciphertextBuf);
console.log('  Written: seipdv1_signed.bin (' + ciphertextBuf.length + ' bytes)');

// ── metadata ──────────────────────────────────────────────────────────────────

// Extract fingerprints from the armored keys (openpgp uses lowercase hex).
const encParsed = await openpgp.readKey({ armoredKey: encKey.publicKey });
const signerParsed = await openpgp.readKey({ armoredKey: signerKey.publicKey });

const meta = {
  generator: 'generate.mjs (openpgp.js v6, SEIPDv1)',
  generated_at: new Date().toISOString(),
  plaintext_seed: SEED,
  plaintext_length: plaintext.length,
  plaintext_sha256: sha256hex(plaintext),
  encryption_key_fingerprint: encParsed.getFingerprint(),
  signer_key_fingerprint: signerParsed.getFingerprint(),
  cipher_algorithm: 'AES-256',
  compression: 'uncompressed',
  aead: false,
};
writeFileSync(out('seipdv1_signed.meta.json'), JSON.stringify(meta, null, 2) + '\n', 'utf8');
console.log('  Written: seipdv1_signed.meta.json');
console.log('  Plaintext SHA-256:', meta.plaintext_sha256);

// ── tampered ciphertext ───────────────────────────────────────────────────────
//
// Locate the SEIPD packet by walking real packet headers (see `parsePackets`
// above), then flip a byte well inside its body — clear of the packet
// header and the 1-byte SEIPD version field.

const tampered = Buffer.from(ciphertextBuf);
const seipdForTamper = findSeipdPacket(tampered);
const TAMPER_OFFSET = seipdForTamper.bodyStart + 32;
if (TAMPER_OFFSET >= seipdForTamper.bodyStart + seipdForTamper.bodyLength) {
  console.error('ERROR: SEIPD body too short to place tamper byte safely at +32');
  process.exit(1);
}
const original = tampered[TAMPER_OFFSET];
tampered[TAMPER_OFFSET] = original ^ 0xff;
console.log(
  `  Tampered byte at offset ${TAMPER_OFFSET} (SEIPD body start ${seipdForTamper.bodyStart}): ` +
  `0x${original.toString(16).padStart(2, '0')} -> 0x${tampered[TAMPER_OFFSET].toString(16).padStart(2, '0')}`
);
writeFileSync(out('seipdv1_tampered.bin'), tampered);
console.log('  Written: seipdv1_tampered.bin');

// ── truncated ciphertext ──────────────────────────────────────────────────────
//
// Simulate a network interruption / short read: cut the message off partway
// through the SEIPD body (well past the PKESK packet, so session-key
// extraction still succeeds — only the final decrypt+verify step must fail).

const seipdForTruncate = findSeipdPacket(ciphertextBuf);
const TRUNCATE_AT = seipdForTruncate.bodyStart + Math.floor(seipdForTruncate.bodyLength / 2);
const truncated = ciphertextBuf.subarray(0, TRUNCATE_AT);
writeFileSync(out('seipdv1_truncated.bin'), truncated);
console.log(
  `  Written: seipdv1_truncated.bin (${truncated.length} of ${ciphertextBuf.length} bytes, ` +
  `cut mid-SEIPD-body at offset ${TRUNCATE_AT})`
);

// ── wrong signer ──────────────────────────────────────────────────────────────

console.log('Generating throwaway signer (wrong-signer fixture)…');
const throwawayKey = await openpgp.generateKey({
  type: 'curve25519',
  userIDs: [{ name: 'Drive Throwaway Signer', email: 'throwaway@example.invalid' }],
  format: 'armored',
  config: {
    preferredHashAlgorithm: openpgp.enums.hash.sha256,
  },
});

const throwawayPrivKey = await openpgp.readPrivateKey({ armoredKey: throwawayKey.privateKey });

const wrongSigned = await openpgp.encrypt({
  message: await openpgp.createMessage({ binary: plaintext }),
  encryptionKeys: encPublicKey,
  signingKeys: throwawayPrivKey,
  config: {
    preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed,
    aeadProtect: false,
  },
  format: 'binary',
});

writeFileSync(out('seipdv1_wrong_signer.bin'), Buffer.from(wrongSigned));
console.log('  Written: seipdv1_wrong_signer.bin (signed by throwaway key NOT in signer_pub.asc)');
console.log('  Throwaway signer fingerprint:', (await openpgp.readKey({ armoredKey: throwawayKey.publicKey })).getFingerprint());

// ── wrong recipient ───────────────────────────────────────────────────────────
//
// Encrypt to a DIFFERENT, throwaway encryption key instead of key_pub.asc —
// simulates a parent-key-resolution bug that unlocks the wrong node/share
// key: key_priv.asc has no PKESK to itself in this message, so session-key
// extraction must fail cleanly, not silently produce garbage or panic.

console.log('Generating throwaway recipient (wrong-recipient fixture)…');
const throwawayRecipientKey = await openpgp.generateKey({
  type: 'curve25519',
  userIDs: [{ name: 'Drive Throwaway Recipient', email: 'throwaway-recipient@example.invalid' }],
  format: 'armored',
  config: {
    preferredHashAlgorithm: openpgp.enums.hash.sha256,
  },
});
const throwawayRecipientPub = await openpgp.readKey({ armoredKey: throwawayRecipientKey.publicKey });

const wrongRecipient = await openpgp.encrypt({
  message: await openpgp.createMessage({ binary: plaintext }),
  encryptionKeys: throwawayRecipientPub,
  signingKeys: signerPrivateKey,
  config: {
    preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed,
    aeadProtect: false,
    allowInsecureDecryptionWithSigningKeys: false,
  },
  format: 'binary',
});

writeFileSync(out('seipdv1_wrong_recipient.bin'), Buffer.from(wrongRecipient));
console.log('  Written: seipdv1_wrong_recipient.bin (encrypted to a throwaway key, NOT key_pub.asc)');
console.log('  Throwaway recipient fingerprint:', throwawayRecipientPub.getFingerprint());

// ── compressed + signed (ExtendedAttributes-shaped payload) ──────────────────
//
// The JS SDK sets `compress: true` when encrypting ExtendedAttributes
// (reference/client/js/src/crypto/driveCrypto.ts:556 `encryptExtendedAttributes`
// -> openPGPCrypto.ts:124-132 `encryptAndSignArmored`, which forwards
// `compress: options.compress || false` to the host-injected CryptoProxy).
// That means real XAttr blobs from any first-party client arrive as a
// SEIPD whose inner plaintext is an OpenPGP-compressed packet wrapping the
// signed literal. This fixture reproduces that shape (ZIP — RFC 4880 §9.3's
// mandatory-to-implement algorithm, chosen here for interop since the exact
// algorithm CryptoProxy selects lives in the host-injected @proton/crypto
// package, not vendored under reference/) so the Rust decrypt path can be
// proven to decompress before verifying (see proton-drive-crypto finalize_decrypted).

console.log('Encrypting and signing a compressed payload (XAttr-shaped)…');
const compressedSigned = await openpgp.encrypt({
  message: await openpgp.createMessage({ binary: plaintext }),
  encryptionKeys: encPublicKey,
  signingKeys: signerPrivateKey,
  config: {
    preferredCompressionAlgorithm: openpgp.enums.compression.zip,
    aeadProtect: false,
    allowInsecureDecryptionWithSigningKeys: false,
  },
  format: 'binary',
});

const compressedSignedBuf = Buffer.from(compressedSigned);
writeFileSync(out('seipdv1_signed_compressed.bin'), compressedSignedBuf);
console.log('  Written: seipdv1_signed_compressed.bin (' + compressedSignedBuf.length + ' bytes)');

const compressedMeta = {
  generator: 'generate.mjs (openpgp.js v6, SEIPDv1, ZIP-compressed)',
  generated_at: new Date().toISOString(),
  plaintext_seed: SEED,
  plaintext_length: plaintext.length,
  plaintext_sha256: sha256hex(plaintext),
  encryption_key_fingerprint: encParsed.getFingerprint(),
  signer_key_fingerprint: signerParsed.getFingerprint(),
  cipher_algorithm: 'AES-256',
  compression: 'zip',
  aead: false,
};
writeFileSync(out('seipdv1_signed_compressed.meta.json'), JSON.stringify(compressedMeta, null, 2) + '\n', 'utf8');
console.log('  Written: seipdv1_signed_compressed.meta.json');

// ── done ──────────────────────────────────────────────────────────────────────

console.log('\nAll fixtures written successfully.');
console.log('REMINDER: These keys use EMPTY passphrases and are TEST-ONLY.');
console.log('          Never use them for any real purpose.');
