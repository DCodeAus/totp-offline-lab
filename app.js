// ===================================================================
// Offline Code Lab: page code
// How it fits together, for anyone picking this up later:
//   1. totp.js does the maths. This file only displays it.
//   2. PARTS holds the text for each clickable part of the 3D model.
//   3. The live codes, the five-step working, the RFC check and the QR
//      text are plain web page code and work even if 3D fails to load.
//   4. init3D() builds the phone, server, clock and keys with three.js.
// Security: demo secrets come from crypto.getRandomValues and live only
// in memory. Text is only written with textContent (no innerHTML, no
// eval). Nothing is stored and nothing is sent anywhere.
// ===================================================================
import * as T from "./totp.js";

const THREE_URL = document.querySelector('meta[name="three-src"]')?.content || "./vendor/three.module.min.js";
const $ = (id) => document.getElementById(id);
const PERIOD = 30;

const PARTS = {
  phone: { title: "The authenticator app", body: "At setup it scanned the QR code and saved the secret in the phone's protected storage. From then on it only needs the secret and the phone's clock. Every 30 seconds it runs the five steps below and shows the result. It never sends anything.", tip: "Move the clock slider to see what happens when the phone's time drifts." },
  server: { title: "The website's server", body: "It saved the same secret when you set up two-factor login. When you type a code, it works out its own codes for the previous, current and next 30-second steps and checks whether yours matches one. It should also refuse a code that's already been used, and limit how many guesses you get.", tip: "The window of plus or minus one step allows for small clock differences and slow typing." },
  clock: { title: "The shared clock", body: "Both sides count Unix time, the seconds since 1 January 1970 in UTC, and divide by 30. Time zones don't matter. The only thing that can break it is a clock that's wrong, which is why phones should set their time automatically.", tip: "The lit segments count the seconds in the current 30-second step." },
  secret: { title: "The shared secret", body: "A random 160-bit value made by the website at setup and shown once as a QR code. Both sides keep a copy. Anyone else who gets it can make your codes forever, so treat the QR code like a password.", tip: "Click New demo secret to make a different one. Every code changes." },
  gap: { title: "No connection needed", body: "After setup, nothing travels between the phone and the server. The code only proves that whoever typed it holds the secret right now. That's why it works in aeroplane mode, and why there's no message for a SIM-swap attacker to intercept.", tip: "It isn't phishing-proof: a fake site can still pass on a code you type into it." },
};
const PART_ORDER = ["secret", "clock", "phone", "server", "gap"];

const state = {
  secret: T.randomSecret(), skew: 0, paused: false, pausedAt: 0,
  phone: null, server: null, verdict: { ok: true, text: "Accepted" }, selected: "secret",
  gen: 0, lastKey: "", noCrypto: !(globalThis.crypto && globalThis.crypto.subtle),
};
const nowSec = () => (state.paused ? state.pausedAt : Date.now() / 1000);
const hooks = { onSelect() {}, onCodes() {} };
const group3 = (c) => c.slice(0, 3) + " " + c.slice(3);

// ---------- Selection card and part chips ----------
for (const k of PART_ORDER) {
  const b = document.createElement("button");
  b.type = "button"; b.dataset.part = k; b.textContent = PARTS[k].title;
  b.addEventListener("click", () => selectPart(k));
  $("chips").append(b);
}
function selectPart(k) {
  state.selected = k;
  $("card-title").textContent = PARTS[k].title;
  $("card-body").textContent = PARTS[k].body;
  $("card-tip").textContent = PARTS[k].tip;
  for (const b of $("chips").children) b.setAttribute("aria-pressed", String(b.dataset.part === k));
  hooks.onSelect();
}
selectPart("secret");

// ---------- The five-step working ----------
const hexCells = [];
for (let i = 0; i < 20; i++) {
  const s = document.createElement("span");
  const idx = document.createElement("small"); idx.textContent = String(i);
  s.append(idx, document.createTextNode("··"));
  $("p-hmac").append(s); hexCells.push(s);
}
const bytesSpaced = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join(" ");

function renderSecret() {
  const b32 = T.base32Encode(state.secret);
  $("p-b32").textContent = b32.match(/.{1,4}/g).join(" ");
  $("p-key").textContent = bytesSpaced(state.secret);
  $("uri").textContent = `otpauth://totp/Offline%20Code%20Lab:learner?secret=${b32}&issuer=Offline%20Code%20Lab&algorithm=SHA1&digits=6&period=30`;
}

function renderPipeline(r, t) {
  const tp = t + state.skew;
  $("p-unix").textContent = `${Math.floor(tp)}${state.skew ? `  (real time ${state.skew > 0 ? "+" : "−"} ${Math.abs(state.skew)} s)` : ""}`;
  if (!r) return;
  $("p-counter").textContent = `${r.counter}  (hex ${r.counter.toString(16)})`;
  $("p-msg").textContent = bytesSpaced(r.message);
  r.hmac.forEach((b, i) => {
    hexCells[i].lastChild.textContent = b.toString(16).padStart(2, "0");
    hexCells[i].classList.toggle("pick", i >= r.offset && i < r.offset + 4);
    hexCells[i].classList.toggle("off", i === 19);
  });
  const last = r.hmac[19];
  const four = r.hmac.slice(r.offset, r.offset + 4);
  $("p-offset").textContent = `last byte 0x${last.toString(16).padStart(2, "0")} → final 4 bits = ${r.offset}`;
  $("p-four").textContent = `${bytesSpaced(four)}  (bytes ${r.offset} to ${r.offset + 3})`;
  $("p-bin").textContent = `0x${r.binary.toString(16).padStart(8, "0")} = ${r.binary.toLocaleString("en")}`;
  $("p-mod").textContent = `${r.binary.toLocaleString("en")} mod 1,000,000 = ${Number(r.code).toLocaleString("en")}`;
  $("p-code").textContent = group3(r.code);
}

// ---------- Live codes: phone (with clock offset) vs server (true time) ----------
async function recompute(force) {
  if (state.noCrypto) return;
  const t = nowSec();
  const cP = T.timeToCounter(t + state.skew, PERIOD), cS = T.timeToCounter(t, PERIOD);
  const key = `${cP}|${cS}`;
  if (!force && key === state.lastKey) return;
  state.lastKey = key;
  const gen = ++state.gen;
  const phone = await T.totp(state.secret, cP * PERIOD);
  const window3 = await Promise.all([-1, 0, 1].map((d) => T.totp(state.secret, (cS + d) * PERIOD)));
  if (gen !== state.gen) return; // a newer calculation has started; drop this one
  state.phone = phone;
  state.server = { prev: window3[0].code, now: window3[1].code, next: window3[2].code };
  const hit = [-1, 0, 1].find((d, i) => window3[i].code === phone.code);
  if (hit === 0) state.verdict = { ok: true, text: "Accepted" };
  else if (hit === -1) state.verdict = { ok: true, text: "Accepted · phone one step behind" };
  else if (hit === 1) state.verdict = { ok: true, text: "Accepted · phone one step ahead" };
  else state.verdict = { ok: false, text: `Rejected · phone clock ${Math.abs(cP - cS)} steps off` };
  $("c-phone").textContent = group3(phone.code);
  $("c-server").textContent = group3(state.server.now);
  const v = $("verdict");
  v.textContent = state.verdict.text;
  v.className = "pill " + (state.verdict.ok ? "ok" : "bad");
  renderPipeline(phone, t);
  for (const id of ["c-phone", "p-code"]) { const n = $(id); n.classList.remove("flash"); void n.offsetWidth; n.classList.add("flash"); }
  hooks.onCodes();
}

let lastWhole = -1;
function tickUi() {
  const t = nowSec();
  const left = PERIOD - (((t % PERIOD) + PERIOD) % PERIOD);
  $("timebar-fill").style.transform = `scaleX(${(left / PERIOD).toFixed(4)})`;
  const whole = Math.floor(t);
  if (whole !== lastWhole) {
    lastWhole = whole;
    $("c-left").textContent = state.paused ? `Clock paused · ${Math.ceil(left)} s left in this step` : `New code in ${Math.ceil(left)} s`;
    renderPipeline(state.phone, t);
  }
  recompute(false);
  requestAnimationFrame(tickUi);
}

$("skew").addEventListener("input", (e) => {
  state.skew = Number(e.target.value);
  $("skew-out").textContent = `${state.skew > 0 ? "+" : ""}${state.skew} s`;
  recompute(true);
});
$("pause").addEventListener("change", (e) => {
  state.paused = e.target.checked;
  if (state.paused) state.pausedAt = Date.now() / 1000;
  lastWhole = -1;
});
$("new-secret").addEventListener("click", () => { state.secret = T.randomSecret(); renderSecret(); recompute(true); });

// ---------- RFC 6238 check ----------
async function runRfc() {
  const body = $("rfc-rows");
  body.replaceChildren();
  if (state.noCrypto) return;
  for (const r of await T.rfcSelfTest()) {
    const tr = document.createElement("tr");
    for (const [txt, cls] of [[String(r.time), ""], [r.expected, ""], [r.got, ""], [r.pass ? "Pass" : "Fail", r.pass ? "pass" : "fail"]]) {
      const td = document.createElement("td"); td.textContent = txt; if (cls) td.className = cls; tr.append(td);
    }
    body.append(tr);
  }
}
$("rfc-run").addEventListener("click", runRfc);

renderSecret();
if (state.noCrypto) {
  $("crypto-missing").hidden = false;
  $("verdict").textContent = "Can't calculate";
  $("verdict").className = "pill bad";
}
runRfc();
requestAnimationFrame(tickUi);

// ---------- 3D ----------
let THREE = null;
try { THREE = await import(THREE_URL); } catch (err) { THREE = null; }
if (!THREE) showFallback("The 3D model couldn't load. Everything else on the page still works.");
else init3D();

function showFallback(msg) { const f = $("fallback"); f.textContent = msg; f.hidden = false; $("scene").hidden = true; }

function init3D() {
  const stage = $("stage"), canvas = $("scene"), labelsBox = $("labels");
  let renderer;
  try { renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: "low-power" }); }
  catch (e) { return showFallback("Your browser couldn't start WebGL, so the 3D model is off. Everything else on the page still works."); }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(0x000000, 0);
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 100);
  scene.add(new THREE.HemisphereLight(0xeef2ff, 0x2a3045, 1.4));
  const key = new THREE.DirectionalLight(0xffffff, 2.2); key.position.set(4, 7, 9); scene.add(key);
  const rim = new THREE.DirectionalLight(0x9fb4ff, 0.9); rim.position.set(-6, -2, -6); scene.add(rim);

  const pickables = [], registry = {};
  const reg = (k, m) => { m.userData.key = k; pickables.push(m); (registry[k] ||= []).push(m); };
  const mat = (color, o = {}) => new THREE.MeshStandardMaterial({ color, roughness: 0.5, metalness: 0.1, ...o });
  const MONO = '600 {s}px ui-monospace, "SF Mono", Menlo, Consolas, monospace';
  const font = (s) => MONO.replace("{s}", s);

  // Canvas-drawn screens: the code is painted onto a texture
  function screen(w, h, pxW, pxH) {
    const c = document.createElement("canvas"); c.width = pxW; c.height = pxH;
    const tex = new THREE.CanvasTexture(c); tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = 4;
    const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ map: tex, toneMapped: false }));
    return { mesh: m, ctx: c.getContext("2d"), tex, w: pxW, h: pxH };
  }

  // Demo phone: rounded slab with a screen
  const phone = new THREE.Group(); phone.position.set(-3.3, 0, 0); scene.add(phone);
  {
    const s = new THREE.Shape(), W = 1.6, H = 3.1, r = 0.22;
    s.moveTo(-W / 2 + r, -H / 2); s.lineTo(W / 2 - r, -H / 2); s.quadraticCurveTo(W / 2, -H / 2, W / 2, -H / 2 + r);
    s.lineTo(W / 2, H / 2 - r); s.quadraticCurveTo(W / 2, H / 2, W / 2 - r, H / 2); s.lineTo(-W / 2 + r, H / 2);
    s.quadraticCurveTo(-W / 2, H / 2, -W / 2, H / 2 - r); s.lineTo(-W / 2, -H / 2 + r); s.quadraticCurveTo(-W / 2, -H / 2, -W / 2 + r, -H / 2);
    const g = new THREE.ExtrudeGeometry(s, { depth: 0.16, bevelEnabled: true, bevelSize: 0.04, bevelThickness: 0.04, bevelSegments: 3 });
    g.translate(0, 0, -0.08);
    const body = new THREE.Mesh(g, mat(0x2b3150, { roughness: 0.35, metalness: 0.4 }));
    phone.add(body); reg("phone", body);
  }
  const phoneScreen = screen(1.38, 2.8, 276, 560);
  phoneScreen.mesh.position.z = 0.13; phone.add(phoneScreen.mesh); reg("phone", phoneScreen.mesh);

  // Demo server: rack box with slots, LEDs and a front display
  const server = new THREE.Group(); server.position.set(3.3, -0.1, 0); scene.add(server);
  {
    const body = new THREE.Mesh(new THREE.BoxGeometry(2.3, 2.9, 1.4), mat(0x323852, { roughness: 0.55, metalness: 0.3 }));
    server.add(body); reg("server", body);
    for (const y of [-0.55, -0.95, -1.3]) {
      const slot = new THREE.Mesh(new THREE.BoxGeometry(2.0, 0.05, 0.02), mat(0x1b1f33));
      slot.position.set(0, y, 0.71); server.add(slot); reg("server", slot);
    }
    for (let i = 0; i < 4; i++) {
      const led = new THREE.Mesh(new THREE.SphereGeometry(0.045, 12, 8), new THREE.MeshBasicMaterial({ color: i % 2 ? 0x4fc58b : 0x8098ff }));
      led.position.set(-0.85 + i * 0.18, -0.75, 0.72); server.add(led);
    }
  }
  const serverScreen = screen(2.0, 1.35, 400, 270);
  serverScreen.mesh.position.set(0, 0.55, 0.711); server.add(serverScreen.mesh); reg("server", serverScreen.mesh);

  // Shared clock: 30 segments, one per second of the current step
  const clock = new THREE.Group(); clock.position.set(0, 2.15, 0); scene.add(clock);
  const segs = [];
  const segOn = new THREE.MeshStandardMaterial({ color: 0xf0a83c, emissive: 0xf0a83c, emissiveIntensity: 0.9, roughness: 0.4 });
  const segOff = mat(0x4a4f66);
  for (let i = 0; i < PERIOD; i++) {
    const a = Math.PI / 2 - (i / PERIOD) * Math.PI * 2;
    const m = new THREE.Mesh(new THREE.BoxGeometry(0.2, 0.07, 0.09), segOff);
    m.position.set(Math.cos(a) * 1.0, Math.sin(a) * 1.0, 0); m.rotation.z = a + Math.PI / 2;
    clock.add(m); segs.push(m); reg("clock", m);
  }
  const clockFace = screen(1.5, 1.5, 256, 256);
  clock.add(clockFace.mesh); reg("clock", clockFace.mesh);

  // Same secret: two identical keys
  function makeKey() {
    const g = new THREE.Group(), m = mat(0xd4a23a, { metalness: 0.7, roughness: 0.3 });
    const bow = new THREE.Mesh(new THREE.TorusGeometry(0.2, 0.07, 12, 28), m); bow.position.x = -0.42;
    const shaft = new THREE.Mesh(new THREE.BoxGeometry(0.66, 0.09, 0.09), m); shaft.position.x = 0.1;
    const t1 = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.17, 0.09), m); t1.position.set(0.3, -0.12, 0);
    const t2 = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.12, 0.09), m); t2.position.set(0.4, -0.1, 0);
    for (const p of [bow, shaft, t1, t2]) { g.add(p); reg("secret", p); }
    return g;
  }
  const keys = [makeKey(), makeKey()];
  keys[0].position.set(-3.3, 2.35, 0); keys[1].position.set(3.3, 2.35, 0);
  keys.forEach((k) => scene.add(k));

  // Dashed lines: inputs flowing in, and the missing link between devices
  function dashed(points, color, dash = 0.12, gap = 0.1) {
    const g = new THREE.BufferGeometry().setFromPoints(points.map((p) => new THREE.Vector3(...p)));
    const l = new THREE.Line(g, new THREE.LineDashedMaterial({ color, dashSize: dash, gapSize: gap }));
    l.computeLineDistances(); scene.add(l); return l;
  }
  dashed([[-3.3, 2.05, 0], [-3.3, 1.65, 0]], 0x8098ff); dashed([[3.3, 2.05, 0], [3.3, 1.45, 0]], 0x8098ff);
  dashed([[-1.0, 2.15, 0], [-2.4, 1.6, 0]], 0xf0a83c); dashed([[1.0, 2.15, 0], [2.1, 1.45, 0]], 0xf0a83c);
  dashed([[-2.35, -0.3, 0], [2.0, -0.3, 0]], 0x8a90a8, 0.16, 0.16);
  const gap = new THREE.Group(); gap.position.set(-0.15, -0.3, 0); scene.add(gap);
  for (const r of [Math.PI / 4, -Math.PI / 4]) {
    const b = new THREE.Mesh(new THREE.BoxGeometry(0.5, 0.09, 0.09), mat(0xf37466, { roughness: 0.4 }));
    b.rotation.z = r; gap.add(b); reg("gap", b);
  }
  const gapHit = new THREE.Mesh(new THREE.BoxGeometry(4.2, 0.4, 0.3), new THREE.MeshBasicMaterial({ visible: false }));
  gapHit.position.set(-0.15, -0.3, 0); scene.add(gapHit); gapHit.userData.key = "gap"; pickables.push(gapHit);

  // Screen painting
  function paintPhone() {
    const { ctx, w, h } = phoneScreen;
    ctx.fillStyle = "#0d1122"; ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = "#8a93b8"; ctx.font = font(15); ctx.textAlign = "center";
    ctx.fillText("DEMO PHONE", w / 2, 40);
    ctx.fillText("Offline Code Lab", w / 2, 64);
    ctx.fillStyle = "#f0a83c"; ctx.font = font(54);
    const code = state.phone ? state.phone.code : "------";
    ctx.fillText(code.slice(0, 3), w / 2, 250); ctx.fillText(code.slice(3), w / 2, 312);
    const t = nowSec() + state.skew, left = PERIOD - (((t % PERIOD) + PERIOD) % PERIOD);
    ctx.strokeStyle = "#2a3150"; ctx.lineWidth = 8; ctx.beginPath(); ctx.arc(w / 2, 410, 34, 0, Math.PI * 2); ctx.stroke();
    ctx.strokeStyle = "#f0a83c"; ctx.beginPath(); ctx.arc(w / 2, 410, 34, -Math.PI / 2, -Math.PI / 2 + (left / PERIOD) * Math.PI * 2); ctx.stroke();
    ctx.fillStyle = "#c9cfe6"; ctx.font = font(18); ctx.fillText(String(Math.ceil(left)), w / 2, 417);
    ctx.fillStyle = state.skew ? "#f37466" : "#8a93b8"; ctx.font = font(15);
    ctx.fillText(state.skew ? `clock ${state.skew > 0 ? "+" : "−"}${Math.abs(state.skew)} s` : "clock correct", w / 2, 500);
    ctx.fillStyle = "#8a93b8"; ctx.fillText("no network", w / 2, 528);
    phoneScreen.tex.needsUpdate = true;
  }
  function paintServer() {
    const { ctx, w, h } = serverScreen;
    ctx.fillStyle = "#0d1122"; ctx.fillRect(0, 0, w, h);
    ctx.textAlign = "left"; ctx.fillStyle = "#8a93b8"; ctx.font = font(15);
    ctx.fillText("DEMO SERVER · accepts", 20, 32);
    const s = state.server || { prev: "------", now: "------", next: "------" };
    const match = state.phone && state.phone.code;
    [["prev", s.prev], ["now ", s.now], ["next", s.next]].forEach(([lab, code], i) => {
      const y = 82 + i * 52;
      ctx.fillStyle = "#8a93b8"; ctx.font = font(16); ctx.fillText(lab, 24, y);
      ctx.fillStyle = code === match ? "#4fc58b" : i === 1 ? "#8098ff" : "#59607d"; ctx.font = font(36);
      ctx.fillText(group3(code), 100, y + 4);
    });
    ctx.fillStyle = state.verdict.ok ? "#4fc58b" : "#f37466"; ctx.font = font(17);
    ctx.fillText(state.verdict.ok ? "MATCH" : "NO MATCH", 20, 250);
    serverScreen.tex.needsUpdate = true;
  }
  function paintClock(left) {
    const { ctx, w, h } = clockFace;
    ctx.clearRect(0, 0, w, h);
    ctx.textAlign = "center"; ctx.fillStyle = "#f0a83c"; ctx.font = font(64); ctx.fillText(String(Math.ceil(left)), w / 2, 140);
    ctx.fillStyle = "#9aa2bc"; ctx.font = font(18); ctx.fillText("seconds left", w / 2, 176);
    clockFace.tex.needsUpdate = true;
  }
  hooks.onCodes = () => { paintPhone(); paintServer(); };

  // Labels
  const tags = {};
  const mk = (k, text, cls) => { const t = document.createElement("div"); t.className = "tag " + (cls || ""); t.textContent = text; labelsBox.append(t); tags[k] = t; };
  mk("phone", "Demo phone"); mk("server", "Demo server"); mk("clock", "Shared clock", "time");
  mk("k1", "Same secret", "secret"); mk("k2", "Same secret", "secret"); mk("gap", "No connection", "bad");
  const anchors = { phone: [-3.3, -1.95, 0], server: [3.3, -1.95, 0], clock: [0, 3.45, 0], k1: [-3.3, 2.85, 0], k2: [3.3, 2.85, 0], gap: [-0.15, -0.7, 0] };

  // Camera orbit
  const target = new THREE.Vector3(0, 0.55, 0);
  const cam = { theta: 0.22, phi: 0.1 };
  let baseR = 12;
  function resize() {
    const w = stage.clientWidth, h = stage.clientHeight; if (!w || !h) return;
    renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix();
    const v = THREE.MathUtils.degToRad(camera.fov), hf = 2 * Math.atan(Math.tan(v / 2) * camera.aspect);
    baseR = 1.05 * Math.max(5.2 / Math.tan(hf / 2), 3.4 / Math.tan(v / 2));
  }
  new ResizeObserver(resize).observe(stage); resize();
  $("reset-view").addEventListener("click", () => { cam.theta = 0.22; cam.phi = 0.1; });
  canvas.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft") cam.theta -= 0.1; else if (e.key === "ArrowRight") cam.theta += 0.1;
    else if (e.key === "ArrowUp") cam.phi = Math.min(1.1, cam.phi + 0.08); else if (e.key === "ArrowDown") cam.phi = Math.max(-0.6, cam.phi - 0.08);
    else return;
    e.preventDefault();
  });

  // Picking
  const ray = new THREE.Raycaster(), ndc = new THREE.Vector2();
  let hovered = null, drag = null;
  function pickAt(x, y) {
    const r = canvas.getBoundingClientRect();
    ndc.set(((x - r.left) / r.width) * 2 - 1, -((y - r.top) / r.height) * 2 + 1);
    ray.setFromCamera(ndc, camera);
    const hit = ray.intersectObjects(pickables, false)[0];
    return hit ? hit.object.userData.key : null;
  }
  canvas.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY, moved: 0 }; try { canvas.setPointerCapture(e.pointerId); } catch (_) {} });
  canvas.addEventListener("pointermove", (e) => {
    if (drag) {
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      drag.moved += Math.abs(dx) + Math.abs(dy); drag.x = e.clientX; drag.y = e.clientY;
      cam.theta -= dx * 0.008;
      if (e.pointerType === "mouse") cam.phi = Math.max(-0.6, Math.min(1.1, cam.phi + dy * 0.006));
    } else if (e.pointerType === "mouse") {
      hovered = pickAt(e.clientX, e.clientY); canvas.classList.toggle("hovering", !!hovered);
    }
  });
  canvas.addEventListener("pointerup", (e) => { if (drag && drag.moved < 6) { const k = pickAt(e.clientX, e.clientY); if (k) selectPart(k); } drag = null; });
  canvas.addEventListener("pointercancel", () => { drag = null; });
  canvas.addEventListener("pointerleave", () => { hovered = null; canvas.classList.remove("hovering"); });

  const tmp = new THREE.Vector3();
  let lastSecond = -1, prev = performance.now();
  function frame(now) {
    const dt = Math.min(0.05, (now - prev) / 1000); prev = now;
    if (!reduceMotion) keys.forEach((k) => { k.rotation.y += dt * 0.8; });

    const t = nowSec(), into = ((t % PERIOD) + PERIOD) % PERIOD, left = PERIOD - into;
    const sec = Math.floor(t);
    if (sec !== lastSecond) {
      lastSecond = sec;
      segs.forEach((m, i) => { m.material = i < Math.floor(into) + 1 ? segOn : segOff; });
      paintClock(left); paintPhone(); paintServer();
    }

    // Highlight the selected part (warm glow) and the hovered part (soft glow)
    for (const [k, ms] of Object.entries(registry)) {
      const e = k === state.selected ? 0x3a3320 : k === hovered ? 0x22263a : 0x000000;
      for (const m of ms) if (m.material.emissive && m.material !== segOn) m.material.emissive.setHex(e);
    }

    const r = baseR;
    camera.position.set(target.x + r * Math.sin(cam.theta) * Math.cos(cam.phi), target.y + r * Math.sin(cam.phi), target.z + r * Math.cos(cam.theta) * Math.cos(cam.phi));
    camera.lookAt(target);

    for (const [k, p] of Object.entries(anchors)) {
      tmp.set(...p).project(camera);
      const tg = tags[k];
      if (tmp.z > 1) { tg.style.display = "none"; continue; }
      tg.style.display = "";
      const x = (tmp.x + 1) / 2 * stage.clientWidth, y = (1 - tmp.y) / 2 * stage.clientHeight;
      tg.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px) translate(-50%, -50%)`;
    }
    renderer.render(scene, camera);
    requestAnimationFrame(frame);
  }
  hooks.onSelect = () => {};
  requestAnimationFrame(frame);
}
