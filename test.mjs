// Checks totp.js against the official RFC 6238 (TOTP) and RFC 4226 (HOTP) test values.
// Run it from this folder with:  node test.mjs   (needs Node.js 20 or newer)
// Every line should say PASS. If any says FAIL, don't publish the page.
import { rfcSelfTest, hotp, RFC4226_HOTP, RFC6238_SEED, base32Encode, base32Decode, randomSecret, counterBytes, toHex } from "./totp.js";

let ok = true;
for (const r of await rfcSelfTest()) {
  console.log(`${r.pass ? "PASS" : "FAIL"}  time ${String(r.time).padStart(11)}  expected ${r.expected}  got ${r.got}`);
  ok &&= r.pass;
}

// HOTP: RFC 4226 counters 0 to 9
const seed = new TextEncoder().encode(RFC6238_SEED);
for (let c = 0; c < RFC4226_HOTP.length; c++) {
  const got = (await hotp(seed, c)).code, pass = got === RFC4226_HOTP[c];
  console.log(`${pass ? "PASS" : "FAIL"}  HOTP counter ${c}  expected ${RFC4226_HOTP[c]}  got ${got}`);
  ok &&= pass;
}

// Base32 should round-trip, and bad characters should be rejected
const s = randomSecret();
const rt = toHex(base32Decode(base32Encode(s))) === toHex(s);
console.log(`${rt ? "PASS" : "FAIL"}  Base32 round trip`);
let rejected = false;
try { base32Decode("ABC1!"); } catch { rejected = true; }
console.log(`${rejected ? "PASS" : "FAIL"}  Base32 rejects invalid characters`);
// The counter for the year-2603 RFC row needs more than 32 bits
const big = toHex(counterBytes(Math.floor(20000000000 / 30))) === "0000000027bc86aa";
console.log(`${big ? "PASS" : "FAIL"}  64-bit counter encoding`);
ok &&= rt && rejected && big;

console.log(ok ? "\nAll checks passed." : "\nSome checks FAILED.");
process.exit(ok ? 0 : 1);
