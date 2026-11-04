# Offline Code Lab

An interactive page that explains how six-digit authenticator codes work without internet. These are the codes from apps like Google Authenticator, known as TOTP (RFC 6238).

**Live page:** https://dcodeaus.github.io/totp-offline-lab/

## What's on the page

- **3D model.** A demo phone and a demo server with no connection between them, each holding the same secret (the gold keys) and reading the same clock. Both show the same code. Drag to rotate, and click any part to learn what it does.
- **Clock slider.** Put the phone's clock out by up to two minutes and watch the server accept the code, then reject it.
- **The working.** The five steps that turn a secret and the time into a code, with the real values updating every 30 seconds.
- **Proof.** The page checks its own maths against the official RFC 6238 test values, live in your browser.
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

It runs the same RFC 6238 test values as the page, plus a few extra checks. Every line should say PASS.

## What each file does

| File | What it's for |
| --- | --- |
| `index.html` | The page: headings, text and layout. |
| `style.css` | Colours, fonts and layout, with light and dark themes. |
| `totp.js` | The TOTP maths on its own, with comments explaining each step. No page, network or storage code. |
| `app.js` | Shows the codes and the working, and builds the 3D scene. To change the wording on the cards, edit `PARTS` near the top. |
| `test.mjs` | Checks `totp.js` against RFC 6238 from Terminal. |
| `vendor/three.module.min.js` | three.js 0.170.0, the 3D library, copied in unchanged. |
| `vendor/three-LICENSE.txt` | three.js's MIT licence. |
| `.nojekyll` | Tells GitHub Pages to serve the files as they are. |

## Security

- **No secret input.** The page never asks for a real secret or QR code. Demo secrets come from `crypto.getRandomValues`, stay in memory only and vanish when the tab closes. `Math.random` isn't used anywhere.
- **Standard cryptography.** HMAC-SHA1 runs in the browser's built-in Web Crypto API, not hand-written code.
- **Nothing loads from other websites.** three.js is copied into `vendor/`. There are no trackers, analytics, web fonts, cookies or storage.
- **A Content Security Policy** in `index.html` only lets the browser run scripts and styles from this site. Inline scripts, network connections, forms and plugins are blocked.
- **No unsafe code patterns.** All text is written with `textContent`, never `innerHTML` or `eval`.
- **Known vulnerabilities:** none known for three.js 0.170.0 in the GitHub advisory database. The two listed issues (CVE-2022-0177, CVE-2020-28496) only affect versions below 0.137.0.
- **Limit:** GitHub Pages can't send security headers, so the page can't stop other sites from framing it. It has no login or real data, so there's nothing to gain from that.

### Checking the three.js file hasn't been changed

The SHA-384 hash of `vendor/three.module.min.js` should be:

```
sha384-IDC7sAMAIMB/TZ6dgKKPPAKZ2bXXXP8+FBMBC8cU319eBhKITx+PaalhfDkDNH28
```

Check it in Terminal from this folder:

```
echo "sha384-$(openssl dgst -sha384 -binary vendor/three.module.min.js | openssl base64 -A)"
```
