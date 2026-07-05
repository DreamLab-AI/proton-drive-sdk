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
 *
 * Usage:
 *   npm i openpgp          # install once (not tracked in package.json)
 *   node generate.mjs
 *
 * Requires: Node >= 18, openpgp v6+
 *
 * WARNING: Keys produced here are TEST-ONLY. Never use in production.
 *          Empty passphrases are intentional for test simplicity.
 */

import { createHash, createHmac } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';
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

// ── generate keypairs ─────────────────────────────────────────────────────────

console.log('Generating Ed25519+X25519 encryption keypair…');
const encKey = await openpgp.generateKey({
  type: 'curve25519',
  userIDs: [{ name: 'Drive Test Key', email: 'test-enc@example.invalid' }],
  format: 'armored',
  config: {
    preferredHashAlgorithm: openpgp.enums.hash.sha256,
  },
});

writeFileSync(out('key_pub.asc'), encKey.publicKey, 'utf8');
writeFileSync(out('key_priv.asc'), encKey.privateKey, 'utf8');
console.log('  Written: key_pub.asc, key_priv.asc');

console.log('Generating Ed25519 signing keypair…');
const signerKey = await openpgp.generateKey({
  type: 'curve25519',
  userIDs: [{ name: 'Drive Test Signer', email: 'test-signer@example.invalid' }],
  format: 'armored',
  config: {
    preferredHashAlgorithm: openpgp.enums.hash.sha256,
  },
});

writeFileSync(out('signer_pub.asc'), signerKey.publicKey, 'utf8');
writeFileSync(out('signer_priv.asc'), signerKey.privateKey, 'utf8');
console.log('  Written: signer_pub.asc, signer_priv.asc');

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
// Find the SEIPD packet body and flip one byte deep inside it (offset >= 30
// from the SEIPD tag byte, well clear of packet headers/version fields).
//
// OpenPGP binary structure: packets are prefixed with a tag byte and length.
// We scan forward until we find the SEIPD tag (tag 18, 0xD2 new-format or
// old-format 0xC9/0xCA/0xCB/0xCC with content-tag 9).
// Once found, we skip the packet header bytes and flip a byte at +32.

const tampered = Buffer.from(ciphertextBuf);

// Find the SEIPD packet: new-format tag 18 = 0xC0 | 18 = 0xD2
// Old-format tag for SEIPD body = tag 9, old-format = 0x80 | (9 << 2) = 0xA4/0xA5/0xA6/0xA7
let seipdOffset = -1;
for (let i = 0; i < tampered.length - 10; i++) {
  const b = tampered[i];
  // New-format packet tag 18 (SEIPDv1 / SEIPDv2)
  if (b === 0xD2) {
    seipdOffset = i;
    break;
  }
  // Old-format packet tag bits[7:6]=10, tag bits[5:2]=9 => 0xA4..0xA7
  if ((b & 0xFC) === 0xA4) {
    seipdOffset = i;
    break;
  }
}

if (seipdOffset < 0) {
  // Fallback: flip something beyond byte 30 which is always within SEIPD body
  // for any realistic ciphertext. Not ideal but prevents silent failure.
  console.warn('  WARNING: could not locate SEIPD tag byte; using heuristic offset 40');
  seipdOffset = 8; // will be bumped by +32 below
}

// Skip the packet header (tag byte + length bytes) and then skip the version
// byte of SEIPD (1 byte). Flip a byte at header+32 to land well inside body.
const FLIP_OFFSET = seipdOffset + 32;
if (FLIP_OFFSET >= tampered.length) {
  console.error('ERROR: ciphertext too short to place tamper byte safely');
  process.exit(1);
}
const original = tampered[FLIP_OFFSET];
tampered[FLIP_OFFSET] = original ^ 0xFF;
console.log(`  Tampered byte at offset ${FLIP_OFFSET}: 0x${original.toString(16).padStart(2,'0')} -> 0x${tampered[FLIP_OFFSET].toString(16).padStart(2,'0')}`);
writeFileSync(out('seipdv1_tampered.bin'), tampered);
console.log('  Written: seipdv1_tampered.bin');

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

// ── compressed + signed (ExtendedAttributes-shaped payload) ──────────────────
//
// The JS SDK sets `compress: true` when encrypting ExtendedAttributes
// (reference/js/sdk/src/crypto/driveCrypto.ts:556 `encryptExtendedAttributes`
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
