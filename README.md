# Offline Code Lab

An interactive page that explains how six-digit authenticator codes work without internet. These are the codes from apps like Google Authenticator, known as TOTP (RFC 6238).

**Live page:** https://dcodeaus.github.io/totp-offline-lab/

## What's on the page

- **3D model.** A demo phone and a demo server with no connection between them, each holding the same secret (the gold keys) and reading the same clock. Both show the same code. Drag to rotate, and click any part to learn what it does.
- **Clock slider.** Put the phone's clock out by up to two minutes and watch the server accept the code, then reject it.
- **The working.** The five steps that turn a secret and the time into a code, with the real values updating every 30 seconds.
- **Proof.** The page checks its own maths against the official RFC 6238 test values, live in your browser.
- **Try it with your real app.** Scan a throwaway demo QR code with Google Authenticator (or any authenticator app), turn on aeroplane mode, and watch your phone keep matching the page.
- **Log in to the demo server.** Reuse a code and it's refused. Guess at random with and without a rate limit to see why limits matter.
- **HOTP vs TOTP.** The older button-press version, and how its counters drift out of step.
- **Phishing walkthrough.** Step by step: how a fake site passes on your six-digit code, and why a passkey can't be tricked the same way.
- **Plain-English notes** on what these codes protect against, what they don't, and what a server must do.

It's an educational demo. It isn't affiliated with Google or any authenticator app.

## Running it on your own computer

You need Python 3, which comes with macOS. If you double-click `index.html`, the codes won't calculate, because browsers only allow their cryptography tools on `https://` or `localhost` pages. Run a tiny local web server instead:

1. Open Terminal.
2. Go to this folder: `cd path/to/totp-offline-lab`
3. Start the server: `python3 -m http.server 8000`
4. Open http://localhost:8000 in your browser.
5. Press `Ctrl+C` in Terminal when you're finished.

## Checking the maths

If you have Node.js 20 or newer, run:

```
node test.mjs
```

It runs the same RFC 6238 (TOTP) test values as the page, the RFC 4226 (HOTP) test values, and a few extra checks. Every line should say PASS.

## What each file does

| File | What it's for |
| --- | --- |
| `index.html` | The page: headings, text and layout. |
| `style.css` | Colours, fonts and layout, with light and dark themes. |
| `totp.js` | The TOTP maths on its own, with comments explaining each step. No page, network or storage code. |
| `app.js` | Shows the codes and the working, runs the demos (QR code, demo login, HOTP, phishing steps) and builds the 3D scene. To change the wording on the cards, edit `PARTS` near the top. The phishing steps are in `PHISH`. |
| `test.mjs` | Checks `totp.js` against RFC 6238 from Terminal. |
| `vendor/three.module.min.js` | three.js 0.170.0, the 3D library, copied in unchanged. |
| `vendor/three-LICENSE.txt` | three.js's MIT licence. |
| `vendor/qrcode.mjs` | qrcode-generator 2.0.4, which works out the QR code's squares. Copied in unchanged. Its MIT licence is at the top of the file. |
| `.nojekyll` | Tells GitHub Pages to serve the files as they are. |

## Security

- **No secret input.** The page never asks for a real secret or QR code. The only text box takes a six-digit demo code, accepts digits only, and is never stored or sent. Demo secrets come from `crypto.getRandomValues`, stay in memory only and vanish when the tab closes. `Math.random` isn't used anywhere.
- **Standard cryptography.** HMAC-SHA1 runs in the browser's built-in Web Crypto API, not hand-written code.
- **Nothing loads from other websites.** three.js and the QR library are copied into `vendor/`. The page draws the QR code onto a canvas itself, so no HTML is built from text. There are no trackers, analytics, web fonts, cookies or storage.
- **A Content Security Policy** in `index.html` only lets the browser run scripts and styles from this site. Inline scripts, network connections, forms and plugins are blocked.
- **No unsafe code patterns.** All text is written with `textContent`, never `innerHTML` or `eval`.
- **Known vulnerabilities:** none known in the GitHub advisory database for three.js 0.170.0 or qrcode-generator 2.0.4. The two issues listed for three.js (CVE-2022-0177, CVE-2020-28496) only affect versions below 0.137.0. qrcode-generator has none listed.
- **Limit:** GitHub Pages can't send security headers, so the page can't stop other sites from framing it. It has no login or real data, so there's nothing to gain from that.

- **The demo QR code is throwaway.** It's made in the browser each visit and protects nothing. The page tells people to delete it from their app afterwards.

### Checking the library files haven't been changed

The SHA-384 hashes should be:

```
vendor/three.module.min.js  sha384-IDC7sAMAIMB/TZ6dgKKPPAKZ2bXXXP8+FBMBC8cU319eBhKITx+PaalhfDkDNH28
vendor/qrcode.mjs           sha384-xHtsZTi0cOhTiha4kloGDUR5e5A8ixkKsF1Mmpqq3tkDpAhkA4YOKIDua/Tc0Ecd
```

Check them in Terminal from this folder:

```
for f in vendor/three.module.min.js vendor/qrcode.mjs; do echo "$f sha384-$(openssl dgst -sha384 -binary $f | openssl base64 -A)"; done
```
