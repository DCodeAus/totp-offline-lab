// ===================================================================
// totp.js: the maths behind six-digit authenticator codes (TOTP)
//
// What it does: turns a shared secret and the current time into a code,
// exactly as RFC 6238 (TOTP) and RFC 4226 (HOTP) describe.
// What you need: a browser on https or localhost, or Node.js 20+.
// Both provide the Web Crypto API (crypto.subtle) used for HMAC-SHA1.
// How to check it: run `node test.mjs` in this folder. It compares the
// output with the official test values printed in RFC 6238.
//
// Nothing here touches the network, the page or storage. It's plain
// maths, which is why authenticator apps work without internet.
// ===================================================================

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Secrets are shared as Base32 text (A–Z and 2–7) because it's easy to
// type and has no look-alike characters such as 0/O or 1/l.
export function base32Encode(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/[\s=-]/g, "");
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error("A Base32 secret can only contain the letters A to Z and the digits 2 to 7.");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

// A fresh 160-bit (20-byte) secret, the size RFC 4226 recommends.
// crypto.getRandomValues is a cryptographically secure random source.
// Math.random is not, and is never used here.
export function randomSecret(byteLength = 20) {
  return globalThis.crypto.getRandomValues(new Uint8Array(byteLength));
}

// Step 2: time -> counter. Count how many 30-second steps have passed
// since 1 January 1970 (Unix time), rounding down.
export function timeToCounter(unixSeconds, period = 30) {
  return Math.floor(unixSeconds / period);
}

// The counter is fed to HMAC as 8 bytes, most significant first.
// JavaScript bit operations only handle 32 bits, so write the high and
// low halves separately.
export function counterBytes(counter) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  return new Uint8Array(buf);
}

// Step 3: HMAC-SHA1 of the counter, keyed with the secret. 20 bytes out.
// SHA-1 collision attacks don't affect HMAC-SHA1, so it's still sound for TOTP.
export async function hmacSha1(keyBytes, messageBytes) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error("NO_WEBCRYPTO");
  const key = await subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", key, messageBytes));
}

// Step 4: dynamic truncation. The last 4 bits of the HMAC choose where to
// read 4 bytes from. The top bit is cleared so the number is never negative.
// Step 5: keep the last 6 (or 8) decimal digits, padding with leading zeros.
export function truncate(hmac, digits = 6) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  const code = String(binary % 10 ** digits).padStart(digits, "0");
  return { offset, binary, code };
}

// All five steps together. Returns every intermediate value so the page
// can show its working.
export async function totp(keyBytes, unixSeconds, { period = 30, digits = 6 } = {}) {
  const counter = timeToCounter(unixSeconds, period);
  const message = counterBytes(counter);
  const hmac = await hmacSha1(keyBytes, message);
  return { counter, message, hmac, ...truncate(hmac, digits) };
}

// Official test values from RFC 6238, Appendix B (SHA-1 rows).
// Seed is the ASCII text "12345678901234567890". Codes are 8 digits.
export const RFC6238_SEED = "12345678901234567890";
export const RFC6238_SHA1 = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

export async function rfcSelfTest() {
  const key = new TextEncoder().encode(RFC6238_SEED);
  const rows = [];
  for (const [time, expected] of RFC6238_SHA1) {
    const { code, counter } = await totp(key, time, { digits: 8 });
    rows.push({ time, counter, expected, got: code, pass: code === expected });
  }
  return rows;
}

export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
