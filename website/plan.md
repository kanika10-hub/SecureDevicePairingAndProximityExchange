# Crypto Visualizer Website — Phase-wise Plan

## What this is

A browser-based interactive demo that runs the real cryptography from this project
and animates every step of the math live — key generation, hybrid X25519 + ML-KEM-768
key exchange, HKDF combination, ASCON-128a encryption and decryption — with real
computed hex values shown at each stage, not hardcoded examples.

Two panels side by side (Device A / Device B). Scan a QR code to pair. Type a message
and watch it get encrypted on one side, travel across, and decrypt on the other — step
by step, with smooth animated transitions between each stage.

---

## Architecture

```
website/
├── plan.md                  ← this file
├── server.py                ← FastAPI + WebSocket backend (wraps core/, pairing/, proximity/)
├── requirements.txt         ← fastapi, uvicorn, websockets (added on top of project deps)
└── static/
    ├── index.html           ← single page, two-panel layout
    ├── style.css            ← animations, transitions, color coding
    └── app.js               ← WebSocket client, step renderer, animation controller
```

**Backend:** Python (FastAPI + WebSockets) — reuses the existing `core/`, `pairing/`,
and `proximity/` modules directly. Each crypto step emits a WebSocket event with the
real intermediate values (hex keys, ciphertext, nonce, etc.) so the frontend can
render them live.

**Frontend:** Vanilla HTML + CSS + JavaScript (no framework). MathJax for rendering
equations. CSS transitions for smooth step-to-step animations. Two panels stay in sync
via the same WebSocket connection.

**No simulation:** every number shown on screen is the real output of the actual
crypto code in this repo.

---

## Phase 1 — Backend WebSocket Server

**Goal:** Python server that wraps the crypto and streams step-by-step events.

Tasks:
- Add `fastapi` and `uvicorn` to a `website/requirements.txt`
- `server.py` with these WebSocket endpoints:
  - `/ws/device-a` and `/ws/device-b` — one connection per panel
  - `GET /qr` — generates a QR code from Device A's identity, returns base64 PNG
- On pairing, emit one WebSocket event per crypto step:
  - `x25519_keygen`  → `{ priv_hex, pub_hex }`
  - `mlkem_keygen`   → `{ pub_hex (truncated) }`
  - `x25519_dh`      → `{ peer_pub_hex, shared_secret_hex }`
  - `mlkem_encap`    → `{ ciphertext_hex, pq_secret_hex }`
  - `hkdf_combine`   → `{ classical_hex, pq_hex, session_key_hex }`
  - `pairing_done`   → `{ fingerprint }`
- On message send, emit:
  - `ascon_encrypt`  → `{ plaintext, key_hex, nonce_hex, ciphertext_hex }`
  - `ascon_decrypt`  → `{ ciphertext_hex, nonce_hex, plaintext }`

Deliverable: `python website/server.py` starts a server, WebSocket events flow
when the pairing and message flows are triggered via HTTP POST.

---

## Phase 2 — Frontend Shell

**Goal:** A working two-panel page that connects to the backend and displays raw events.

Tasks:
- `index.html` — two side-by-side panels labeled "Device A" and "Device B"
- Each panel has three sections:
  - **QR / Status bar** at the top
  - **Crypto steps feed** in the middle (scrollable)
  - **Message box** at the bottom
- `app.js` — opens WebSocket connections to `/ws/device-a` and `/ws/device-b`,
  receives events, and appends raw JSON to the steps feed
- Basic `style.css` — dark background, monospace font for hex values, two columns

Deliverable: Open `http://localhost:8000` and see both panels live-updating as
events arrive from the backend.

---

## Phase 3 — QR Pairing Flow

**Goal:** Display the real QR code and animate the pairing handshake across both panels.

Tasks:
- On page load, Device A panel fetches `/qr` and displays the QR image
- Device B panel shows a "Scan QR" button — clicking it sends a POST to `/pair/start`
  which triggers the full pairing handshake in the backend
- As each step event arrives, the steps feed renders a styled card per step:
  - Step card shows: step name, a one-line plain-English description, and the hex value
  - Cards appear one by one with a fade-in + slide-up animation (CSS `@keyframes`)
  - Active step card is highlighted; completed steps dim slightly
- Final card shows the **safety number** (fingerprint) on both sides with a
  green "PAIRED" badge and a checkmark animation

Color coding used throughout:
  - Blue  = key material (public/private keys)
  - Orange = ciphertext / encrypted data
  - Green  = plaintext / decrypted data
  - Purple = derived values (shared secrets, session key)

Deliverable: Open the page, click "Scan QR", watch all pairing steps animate
across both panels ending with matching safety numbers.

---

## Phase 4 — Crypto Step Animations (the math)

**Goal:** Each step card shows the actual equation being computed, not just the result.

Tasks:
For each step, show a three-part animated sequence:

  **X25519 key generation**
    - Equation: `pub = priv · G`  (scalar × base point)
    - Show: private scalar (hex) → multiply arrow → base point G → public key (hex)

  **X25519 Diffie-Hellman**
    - Equation: `shared = my_priv · peer_pub`
    - Show: two keys feed into a multiply node → shared secret emerges

  **ML-KEM-768 encapsulation**
    - Equation: `(ciphertext, secret) = Encaps(peer_pub)`
    - Show: peer's public key → lattice encapsulation box → ciphertext + PQ secret

  **HKDF combination**
    - Equation: `session_key = HKDF-SHA256(X25519_secret ∥ ML-KEM_secret)`
    - Show: two secret blobs being concatenated → fed into HKDF funnel → 128-bit key out

  **ASCON-128a encryption**
    - Equation: `ciphertext = ASCON(key, nonce, plaintext)`
    - Show: plaintext block → nonce injected → ASCON state permutation (visualized as
      a 5×64-bit grid animating) → ciphertext block out

  **ASCON-128a decryption**
    - Same in reverse: ciphertext → ASCON → plaintext revealed with a green flash

Animation mechanics:
- Each equation renders using MathJax
- Hex values are typed out character by character (typewriter effect, ~8ms/char)
- Arrows between nodes draw with a CSS stroke animation
- "Active" step pulses with a blue border glow; completed steps stay visible but shrink
  to a compact summary line so the feed doesn't overflow

Deliverable: The pairing flow looks like a live crypto textbook being filled in.

---

## Phase 5 — Message Send Flow

**Goal:** User types a message, sends it, and watches the full encrypt → transmit → decrypt
pipeline animate across both panels in sync.

Tasks:
- Message input box at the bottom of Device A's panel
- "Send" button → POST `/message` with `{ "text": "..." }`
- Backend runs the proximity protocol (ephemeral handshake + ASCON encryption) and
  emits the steps as WebSocket events — same step-card system as Phase 4
- Timeline of events shown:
  1. Device A: ephemeral X25519 + ML-KEM keypair generated
  2. Device A: INITIATE message built (with MAC)
  3. Device B: receives INITIATE, verifies MAC, generates response
  4. Device B: RESPONSE sent (ephemeral pub + KEM ciphertext + MAC)
  5. Device A: decapsulates, combines → fresh session key
  6. Device A: ASCON encrypts the message → ciphertext shown
  7. Device B: ASCON decrypts → plaintext revealed
- The message text appears on Device B's panel character by character after decryption
- A timeline bar above both panels shows which side is "active" at each step

Deliverable: Full end-to-end message demo with every crypto step visible, all real values.

---

## Phase 6 — Polish and Controls

**Goal:** Make it smooth enough to show a teacher or demo in a presentation.

Tasks:
- **Step speed control** — a slider: Slow / Normal / Fast (controls animation timing)
- **Pause / Resume** — spacebar or button pauses after any step so you can explain it
- **Replay** — replay button re-runs the last flow from the beginning with new keys
- **Tooltips** — hover on any hex value shows a plain-English tooltip:
  e.g. hover on session key → "This 128-bit key is used by ASCON to encrypt all
  messages in this session. It is derived from both the X25519 and ML-KEM secrets,
  so breaking one algorithm alone is not enough to compromise it."
- **Mobile QR display** — if window width < 768px, show only the QR code fullscreen
  for easy phone scanning
- **Step labels** — each step card has a "Why this step?" toggle that expands a
  one-paragraph explanation of why this step exists in the protocol
- **Export** — "Copy session transcript" button copies all step values as JSON,
  useful for pasting into a report

---

## Definition of Done

- [ ] Phase 1: Backend emits all crypto step events over WebSocket with real hex values
- [ ] Phase 2: Both panels update live in the browser
- [ ] Phase 3: QR pairing animates end-to-end, safety numbers shown and match
- [ ] Phase 4: Every crypto step shows the equation + real computed values + animation
- [ ] Phase 5: Full message send/receive flow animated across both panels
- [ ] Phase 6: Pause/replay/speed controls work; tooltips explain each value

---

## How to run (once built)

```bash
cd website
pip install -r requirements.txt
python server.py
# open http://localhost:8000 in browser
```
