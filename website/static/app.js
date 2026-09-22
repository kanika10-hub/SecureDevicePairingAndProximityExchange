/* Live Crypto Visualizer — WebSocket client + step renderer */

// ── Step metadata ────────────────────────────────────────────────────────────

const STEP_META = {
  x25519_keygen:    { icon: "🔑", type: "key",      valueColor: { pub_hex: "col-blue" } },
  mlkem_keygen:     { icon: "🔑", type: "key",      valueColor: { pub_hex: "col-blue" } },
  qr_display:       { icon: "📱", type: "qr",       valueColor: { x25519_pub_hex: "col-blue" } },
  qr_scan:          { icon: "📷", type: "qr",       valueColor: { x25519_pub_hex: "col-blue" } },
  x25519_dh:        { icon: "🔀", type: "dh",       valueColor: { peer_pub_hex: "col-blue", shared_secret_hex: "col-purple" } },
  mlkem_encap:      { icon: "📦", type: "dh",       valueColor: { ciphertext_hex: "col-orange", pq_secret_hex: "col-purple" } },
  mlkem_decap:      { icon: "📦", type: "dh",       valueColor: { ciphertext_hex: "col-orange", pq_secret_hex: "col-purple" } },
  hkdf_combine:     { icon: "⚗️",  type: "kdf",      valueColor: { classical_hex: "col-purple", pq_hex: "col-purple", session_key_hex: "col-blue" } },
  ascon_encrypt:    { icon: "🔒", type: "encrypt",   valueColor: { plaintext: "col-green", plaintext_preview: "col-green", key_hex: "col-blue", nonce_hex: "col-text", ciphertext_hex: "col-orange" } },
  ascon_decrypt:    { icon: "🔓", type: "decrypt",   valueColor: { ciphertext_hex: "col-orange", key_hex: "col-blue", nonce_hex: "col-text", plaintext: "col-green", plaintext_preview: "col-green" } },
  ephemeral_keygen: { icon: "✨", type: "key",      valueColor: { x25519_pub_hex: "col-blue", mlkem_pub_hex: "col-blue" } },
  mac_compute:      { icon: "🖊️", type: "mac",      valueColor: { long_term_key_hex: "col-purple", mac_hex: "col-blue" } },
  mac_verify:       { icon: "✅", type: "mac",      valueColor: { expected_mac_hex: "col-blue", received_mac_hex: "col-blue" } },
  session_key:      { icon: "⚗️",  type: "kdf",      valueColor: { x25519_shared_hex: "col-purple", pq_secret_hex: "col-purple", session_key_hex: "col-blue" } },
  pairing_done:     { icon: "🤝", type: "done",     valueColor: { fingerprint: "col-green" } },
  reconnect_done:   { icon: "🔄", type: "done",     valueColor: { session_key_hex: "col-green" } },
  stranger_identity:{ icon: "👾", type: "stranger",  valueColor: { x25519_pub_hex: "col-red" } },
  stranger_mac:     { icon: "⚠️",  type: "stranger",  valueColor: { fake_mac_hex: "col-red", random_key_hex: "col-red" } },
  trust_check_fail: { icon: "🚫", type: "reject",    valueColor: { result: "col-red", action: "col-red" } },
  stranger_rejected:{ icon: "⛔", type: "reject",    valueColor: { result: "col-red" } },
  scenario_header:  { icon: "📋", type: "info",     valueColor: {} },
};

const DEFAULT_META = { icon: "ℹ️", type: "text", valueColor: {} };

// ── DOM refs ──────────────────────────────────────────────────────────────────

const feedA        = document.getElementById("feed-a");
const feedB        = document.getElementById("feed-b");
const statusA      = document.getElementById("status-a");
const statusB      = document.getElementById("status-b");
const qrArea       = document.getElementById("qr-area");
const btnPair      = document.getElementById("btn-pair");
const btnReconnect = document.getElementById("btn-reconnect");
const btnStranger  = document.getElementById("btn-stranger");
const btnSend      = document.getElementById("btn-send");
const msgInput     = document.getElementById("msg-input");
const banner       = document.getElementById("paired-banner");
const bannerIcon   = document.getElementById("banner-icon");
const bannerTitle  = document.getElementById("banner-title");
const bannerSub    = document.getElementById("banner-sub");

// ── State ─────────────────────────────────────────────────────────────────────

let pairedDone = false;

// ── Render helpers ────────────────────────────────────────────────────────────

function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function renderValue(key, val, colorMap) {
  const cls = colorMap[key] || "col-text";
  const display = (typeof val === "boolean")
    ? (val ? "✅ verified" : "❌ FAILED")
    : escHtml(String(val));
  return `<div class="val-row">
      <span class="val-key">${escHtml(key)}</span>
      <span class="val-val ${cls}">${display}</span>
    </div>`;
}

function buildCard(event) {
  const meta    = STEP_META[event.step] || DEFAULT_META;
  const data    = event.data || {};
  const cmap    = meta.valueColor || {};
  const stepNum = event.step_num;
  const uses    = event.uses_from || [];

  const numHtml = (stepNum != null)
    ? `<span class="step-num">Step ${stepNum}</span>`
    : "";

  let depsHtml = "";
  if (uses.length) {
    const devName = d => d === "device-a" ? "Device A" : "Device B";
    const rows = uses.map(dep =>
      `<div class="dep-badge">↑ Step ${dep.step_num} (${devName(dep.device)}) — ${escHtml(dep.field)}</div>`
    ).join("");
    depsHtml = `<div class="card-deps">${rows}</div>`;
  }

  const descHtml = `<div class="card-desc">${escHtml(event.description)}</div>`;
  const eqHtml   = data.equation
    ? `<div class="card-equation">${escHtml(data.equation)}</div>`
    : "";
  const valsHtml = Object.entries(data)
    .filter(([k]) => k !== "equation")
    .map(([k, v]) => renderValue(k, v, cmap))
    .join("");

  return `<div class="step-card type-${meta.type} expanded">
      <div class="card-header">
        ${numHtml}
        <span class="card-icon">${meta.icon}</span>
        <span class="card-label">${escHtml(event.label)}</span>
        <span class="chevron">▶</span>
      </div>
      <div class="card-body">
        ${depsHtml}
        ${descHtml}
        ${eqHtml}
        ${valsHtml.length ? `<div class="card-values">${valsHtml}</div>` : ""}
      </div>
    </div>`;
}

function appendCard(feed, event) {
  feed.insertAdjacentHTML("beforeend", buildCard(event));
  const card = feed.lastElementChild;
  card.querySelector(".card-header").addEventListener("click", () => {
    card.classList.toggle("expanded");
  });
  card.scrollIntoView({ behavior: "smooth", block: "end" });
}

// ── Banner helper ─────────────────────────────────────────────────────────────

function showBanner(icon, title, sub, color) {
  bannerIcon.textContent  = icon;
  bannerTitle.textContent = title;
  bannerSub.textContent   = sub;
  banner.className = "paired-banner show" + (color === "red" ? " banner-red" : "");
}

// ── QR loading ────────────────────────────────────────────────────────────────

async function loadQr() {
  try {
    const res  = await fetch("/qr");
    const data = await res.json();
    qrArea.innerHTML = `
      <div>
        <img class="qr-img" src="${data.qr_image}" alt="QR code for Device A">
        <p class="qr-caption">device-a public keys encoded</p>
      </div>`;
    btnPair.disabled = false;
  } catch (e) {
    qrArea.innerHTML = `<span style="color:var(--red);font-size:11px">QR load failed: ${e.message}</span>`;
  }
}

// ── WebSocket setup ───────────────────────────────────────────────────────────

function connectDevice(device) {
  const host = location.host;
  const ws   = new WebSocket(`ws://${host}/ws/${device}`);
  const feed = device === "device-a" ? feedA : feedB;
  const stat = device === "device-a" ? statusA : statusB;

  ws.onopen = () => {
    stat.textContent = "● connected";
    stat.classList.add("connected");
  };

  ws.onclose = () => {
    stat.textContent = "disconnected";
    stat.classList.remove("connected");
    setTimeout(() => connectDevice(device), 2000);
  };

  ws.onmessage = (e) => {
    const event = JSON.parse(e.data);

    // Broadcast events — each handler adds only to its own feed
    if (event.step === "pairing_done") {
      appendCard(feed, event);
      if (device === "device-a") {
        showBanner("✅", "Devices Paired", event.data.fingerprint, "green");
        pairedDone            = true;
        btnSend.disabled      = false;
        msgInput.disabled     = false;
        btnReconnect.disabled = false;
        btnStranger.disabled  = false;
      }
      return;
    }

    if (event.step === "reconnect_done") {
      appendCard(feed, event);
      if (device === "device-a") {
        const ok = event.data.keys_match;
        showBanner("🔄", "Reconnection Successful",
          ok ? "Fresh session key — forward secrecy ✓" : "Key mismatch!",
          ok ? "green" : "red");
      }
      return;
    }

    if (event.step === "stranger_rejected") {
      appendCard(feed, event);
      if (device === "device-a") {
        showBanner("⛔", "Stranger Rejected",
          "Unknown device blocked — only paired devices may connect", "red");
      }
      return;
    }

    appendCard(feed, event);
  };

  ws.onerror = () => { stat.textContent = "error"; };

  return ws;
}

// ── Button handlers ───────────────────────────────────────────────────────────

btnPair.addEventListener("click", async () => {
  btnPair.disabled      = true;
  btnReconnect.disabled = true;
  btnStranger.disabled  = true;
  feedA.innerHTML       = "";
  feedB.innerHTML       = "";
  banner.className      = "paired-banner";
  pairedDone            = false;
  btnSend.disabled      = true;
  msgInput.disabled     = true;
  await fetch("/pair/start", { method: "POST" });
});

btnReconnect.addEventListener("click", async () => {
  feedA.innerHTML  = "";
  feedB.innerHTML  = "";
  banner.className = "paired-banner";
  await fetch("/reconnect", { method: "POST" });
});

btnStranger.addEventListener("click", async () => {
  feedA.innerHTML  = "";
  feedB.innerHTML  = "";
  banner.className = "paired-banner";
  await fetch("/stranger", { method: "POST" });
});

btnSend.addEventListener("click", async () => {
  const text = msgInput.value.trim();
  if (!text) return;
  btnSend.disabled = true;
  feedA.innerHTML  = "";
  feedB.innerHTML  = "";
  await fetch("/message", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  setTimeout(() => { btnSend.disabled = false; }, 2000);
});

msgInput.addEventListener("keydown", e => { if (e.key === "Enter") btnSend.click(); });

// ── Device label update ───────────────────────────────────────────────────────

function updateDeviceLabel(panel, value) {
  const badge = document.getElementById(`badge-${panel}`);
  if (badge) badge.textContent = value;
}

// ── Boot ──────────────────────────────────────────────────────────────────────

connectDevice("device-a");
connectDevice("device-b");
loadQr();
