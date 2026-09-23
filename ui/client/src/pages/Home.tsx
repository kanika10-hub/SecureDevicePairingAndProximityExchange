import { useEffect, useRef, useState } from "react";
import {
  Activity,
  Check,
  ChevronDown,
  ChevronRight,
  CircleDot,
  KeyRound,
  Laptop,
  LockKeyhole,
  RadioTower,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Tablet,
  UserRoundX,
  Watch,
  X,
  Zap,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

type Scenario = "pair" | "reconnect" | "stranger";
type Phase = "ready" | "negotiating" | "success" | "rejected";
type WsStatus = "connecting" | "connected" | "disconnected";

type UsesFrom = { step_num: number; device: string; label: string; field: string };
type StepEvent = {
  step: string;
  step_num: number | null;
  label: string;
  description: string;
  data: Record<string, unknown>;
  uses_from: UsesFrom[];
};
type Banner = { tone: "success" | "danger" | "info"; title: string; detail: string; icon: typeof Check };
type QueueItem = { setter: React.Dispatch<React.SetStateAction<StepEvent[]>>; event: StepEvent };

// ── Step metadata ──────────────────────────────────────────────────────────────

const STEP_TYPE: Record<string, string> = {
  x25519_keygen: "key", mlkem_keygen: "key", ephemeral_keygen: "key",
  x25519_dh: "dh", mlkem_encap: "dh", mlkem_decap: "dh",
  hkdf_combine: "kdf", session_key: "kdf",
  ascon_encrypt: "encrypt", ascon_decrypt: "decrypt",
  qr_display: "qr", qr_scan: "qr",
  mac_compute: "mac", mac_verify: "mac",
  pairing_done: "done", reconnect_done: "done",
  stranger_identity: "stranger", stranger_mac: "stranger",
  trust_check_fail: "reject", stranger_rejected: "reject",
  scenario_header: "info",
};

const STEP_ICON: Record<string, string> = {
  x25519_keygen: "🔑", mlkem_keygen: "🔑", ephemeral_keygen: "✨",
  x25519_dh: "🔀", mlkem_encap: "📦", mlkem_decap: "📦",
  hkdf_combine: "⚗️", session_key: "⚗️",
  ascon_encrypt: "🔒", ascon_decrypt: "🔓",
  qr_display: "📱", qr_scan: "📷",
  mac_compute: "✍️", mac_verify: "✅",
  pairing_done: "🤝", reconnect_done: "🔄",
  stranger_identity: "👾", stranger_mac: "⚠️",
  trust_check_fail: "🚫", stranger_rejected: "⛔",
  scenario_header: "📋",
};

const TYPE_ACCENT: Record<string, string> = {
  key: "var(--cyan)", dh: "var(--violet)", kdf: "var(--violet)",
  encrypt: "var(--amber)", decrypt: "var(--lime)",
  qr: "var(--cyan)", mac: "var(--cyan)",
  done: "var(--lime)", stranger: "var(--red)", reject: "var(--red)",
  info: "var(--amber)",
};

const DEVICE_OPTIONS = [
  { label: "💻 Laptop", icon: <Laptop size={20} strokeWidth={1.7} /> },
  { label: "📱 Phone",  icon: <Smartphone size={20} strokeWidth={1.7} /> },
  { label: "📊 Tablet", icon: <Tablet size={20} strokeWidth={1.7} /> },
  { label: "⌚ Watch",  icon: <Watch size={20} strokeWidth={1.7} /> },
];

// ── StepCard ───────────────────────────────────────────────────────────────────

function StepCard({ event }: { event: StepEvent }) {
  const [open, setOpen] = useState(true);
  const type   = STEP_TYPE[event.step] ?? "text";
  const accent = TYPE_ACCENT[type] ?? "rgba(255,255,255,.25)";
  const icon   = STEP_ICON[event.step] ?? "ℹ️";

  return (
    <div style={{
      borderRadius: "9px", border: "1px solid rgba(255,255,255,.09)",
      borderLeft: `3px solid ${accent}`,
      background: "rgba(14,19,26,.8)", overflow: "hidden",
      animation: "slide-in .3s cubic-bezier(.22,.68,0,1.2) both",
      marginBottom: "5px", flexShrink: 0,
    }}>
      <div
        onClick={() => setOpen(v => !v)}
        style={{ display: "flex", alignItems: "center", gap: "7px", padding: "7px 10px", cursor: "pointer", userSelect: "none" }}
      >
        {event.step_num != null && (
          <span style={{
            fontSize: "9px", fontFamily: "'Space Mono', monospace", color: "var(--muted)",
            background: "rgba(0,0,0,.35)", border: "1px solid rgba(255,255,255,.1)",
            borderRadius: "4px", padding: "1px 6px", flexShrink: 0, minWidth: "46px", textAlign: "center",
          }}>
            Step {event.step_num}
          </span>
        )}
        <span style={{ fontSize: "13px", flexShrink: 0 }}>{icon}</span>
        <span style={{ fontSize: "11px", fontWeight: 700, color: "#e8efeb", flex: 1, letterSpacing: "-.01em" }}>
          {event.label}
        </span>
        <span style={{
          fontSize: "8px", color: "var(--muted)", flexShrink: 0,
          transition: "transform .18s", transform: open ? "rotate(90deg)" : "none",
        }}>▶</span>
      </div>

      {open && (
        <div style={{ borderTop: "1px solid rgba(255,255,255,.07)" }}>
          {event.uses_from?.length > 0 && (
            <div style={{
              padding: "5px 10px", display: "flex", flexDirection: "column", gap: "2px",
              background: "rgba(90,216,232,.04)", borderBottom: "1px solid rgba(255,255,255,.07)",
            }}>
              {event.uses_from.map((dep, i) => (
                <div key={i} style={{ fontSize: "9px", color: "var(--cyan)", fontFamily: "'Space Mono', monospace" }}>
                  ↑ Step {dep.step_num} ({dep.device === "device-a" ? "Device A" : "Device B"}) — {dep.field}
                </div>
              ))}
            </div>
          )}
          <div style={{
            padding: "6px 10px", fontSize: "10px", color: "var(--muted)", lineHeight: 1.55,
            borderBottom: "1px solid rgba(255,255,255,.07)",
          }}>
            {event.description}
          </div>
          {event.data?.equation && (
            <div style={{
              padding: "5px 10px", fontFamily: "'Space Mono', monospace", fontSize: "9.5px",
              color: "var(--amber)", background: "rgba(242,187,103,.05)",
              borderBottom: "1px solid rgba(255,255,255,.07)",
            }}>
              {String(event.data.equation)}
            </div>
          )}
          <div style={{ padding: "7px 10px", display: "flex", flexDirection: "column", gap: "4px" }}>
            {Object.entries(event.data)
              .filter(([k]) => k !== "equation")
              .map(([k, v]) => (
                <div key={k} style={{ display: "flex", gap: "8px", alignItems: "flex-start" }}>
                  <span style={{
                    fontSize: "9px", color: "#5c686e", fontFamily: "'Space Mono', monospace",
                    flexShrink: 0, paddingTop: "1px", minWidth: "96px",
                  }}>{k}</span>
                  <span style={{
                    fontFamily: "'Space Mono', monospace", fontSize: "9px",
                    wordBreak: "break-all", lineHeight: 1.5,
                    color: typeof v === "boolean"
                      ? (v ? "var(--lime)" : "var(--red)")
                      : k.includes("key") || k.includes("pub") ? "var(--cyan)"
                      : k.includes("cipher") || k.includes("nonce") ? "var(--amber)"
                      : k.includes("secret") || k.includes("pq") ? "var(--violet)"
                      : k.includes("plain") ? "var(--lime)"
                      : "var(--muted)",
                  }}>
                    {typeof v === "boolean" ? (v ? "✅ verified" : "❌ FAILED") : String(v)}
                  </span>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── DevicePanel ────────────────────────────────────────────────────────────────

function DevicePanel({
  side, label, steps, status, qrImage, onLabelChange, pairedDone,
}: {
  side: "left" | "right"; label: string; steps: StepEvent[];
  status: WsStatus; qrImage?: string;
  onLabelChange: (l: string) => void; pairedDone: boolean;
}) {
  const feedRef = useRef<HTMLDivElement>(null);
  const isLeft  = side === "left";
  const option  = DEVICE_OPTIONS.find(d => d.label === label) ?? DEVICE_OPTIONS[0];

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [steps]);

  return (
    <article
      className={`endpoint-card ${side}`}
      style={{ display: "flex", flexDirection: "column", minHeight: "420px" }}
    >
      <div className="card-topline">
        <div className={`device-orb ${isLeft ? "orb-blue" : "orb-lime"}`}>{option.icon}</div>
        <div className="device-meta">
          <span className="eyebrow">{isLeft ? "ORIGIN DEVICE" : "TARGET DEVICE"}</span>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <h2 style={{ margin: 0 }}>{label.slice(2)}</h2>
            <select
              value={label}
              onChange={e => onLabelChange(e.target.value)}
              style={{
                background: "rgba(255,255,255,.06)", border: "1px solid rgba(255,255,255,.12)",
                borderRadius: "5px", color: "var(--muted)", fontSize: "10px",
                padding: "2px 6px", cursor: "pointer", outline: "none",
              }}
            >
              {DEVICE_OPTIONS.map(d => (
                <option key={d.label} value={d.label}>{d.label}</option>
              ))}
            </select>
          </div>
        </div>
        <span className={`presence ${status !== "connected" ? "offline" : ""}`}>
          <span className="presence-dot" />
          {status}
        </span>
      </div>

      {isLeft && qrImage && (
        <div style={{
          display: "flex", flexDirection: "column", alignItems: "center",
          padding: "12px 14px", borderTop: "1px solid rgba(255,255,255,.07)",
          borderBottom: "1px solid rgba(255,255,255,.07)",
        }}>
          <img
            src={qrImage} alt="Device A QR"
            style={{ width: 110, height: 110, borderRadius: "8px", border: "1px solid rgba(255,255,255,.1)" }}
          />
          <span style={{ fontSize: "9px", color: "var(--muted)", fontFamily: "'Space Mono', monospace", marginTop: "5px" }}>
            device-a public keys encoded
          </span>
        </div>
      )}

      <div
        ref={feedRef}
        style={{
          flex: 1, overflowY: "auto", padding: "10px",
          display: "flex", flexDirection: "column",
          scrollbarWidth: "thin", scrollbarColor: "rgba(255,255,255,.08) transparent",
        }}
      >
        {steps.length === 0 ? (
          <div style={{
            flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
            color: "var(--faint)", fontSize: "9px", fontFamily: "'Space Mono', monospace",
            letterSpacing: ".1em", textTransform: "uppercase",
          }}>
            waiting for steps…
          </div>
        ) : (
          steps.map((evt, i) => <StepCard key={i} event={evt} />)
        )}
      </div>

      {pairedDone && (
        <div className="fingerprint-row" style={{ padding: "10px 14px" }}>
          <span className="fingerprint-label">status</span>
          <span className="fingerprint cyan">paired ✓</span>
        </div>
      )}
    </article>
  );
}

// ── Wire ───────────────────────────────────────────────────────────────────────

function Wire({ phase, stranger }: { phase: Phase; stranger: boolean }) {
  const matched  = phase === "success" && !stranger;
  const rejected = phase === "rejected";
  return (
    <div className={`wire-zone ${matched ? "matched" : ""} ${rejected ? "rejected" : ""}`}>
      <div className="wire-label top">network</div>
      <div className="wire-core">
        <div className="wire-glow" />
        <div className="wire-line" />
        <div className="wire-node node-top"><span /></div>
        <div className="wire-node node-bottom"><span /></div>
        {matched  && <div className="match-mark"><Check size={13} /></div>}
        {rejected && <div className="match-mark reject-mark"><X size={13} /></div>}
      </div>
      <div className="wire-label bottom">encrypted</div>
      <span className="wire-status">
        {matched ? "key match" : rejected ? "access denied" : phase === "negotiating" ? "negotiating" : "standby"}
      </span>
    </div>
  );
}

// ── Home ───────────────────────────────────────────────────────────────────────

export default function Home() {
  const [stepsA,  setStepsA]  = useState<StepEvent[]>([]);
  const [stepsB,  setStepsB]  = useState<StepEvent[]>([]);
  const [statusA, setStatusA] = useState<WsStatus>("connecting");
  const [statusB, setStatusB] = useState<WsStatus>("connecting");
  const [phase,       setPhase]       = useState<Phase>("ready");
  const [scenario,    setScenario]    = useState<Scenario>("pair");
  const [pairedDone,  setPairedDone]  = useState(false);
  const [banner,      setBanner]      = useState<Banner>({ tone: "info", title: "Ready to pair", detail: "Select a scenario and press run", icon: KeyRound });
  const [accountOpen, setAccountOpen] = useState(false);
  const [stepByStep,  setStepByStep]  = useState(false);
  const [pendingCount,setPendingCount]= useState(0);
  const [qrImage,     setQrImage]     = useState("");
  const [labelA,      setLabelA]      = useState("💻 Laptop");
  const [labelB,      setLabelB]      = useState("📱 Phone");
  const [msgText,     setMsgText]     = useState("");

  // Stable refs used inside WebSocket callbacks
  const stepByStepRef   = useRef(false);
  const pendingQueue    = useRef<QueueItem[]>([]);
  const currentLabelA   = useRef("💻 Laptop");
  const currentLabelB   = useRef("📱 Phone");

  // Keep refs in sync
  useEffect(() => { stepByStepRef.current = stepByStep; }, [stepByStep]);
  useEffect(() => { currentLabelA.current = labelA; }, [labelA]);
  useEffect(() => { currentLabelB.current = labelB; }, [labelB]);

  const stranger    = scenario === "stranger";
  const statusLabel = phase === "negotiating" ? "session negotiating"
    : phase === "rejected" ? "access denied"
    : pairedDone ? (scenario === "reconnect" ? "session reconnected" : "session secure")
    : "standby";

  // ── Apply a real event to state ────────────────────────────────────────────
  // Assigned fresh each render so it always closes over current state setters.
  const applyEventRef = useRef<(setter: React.Dispatch<React.SetStateAction<StepEvent[]>>, event: StepEvent) => void>(null!);
  applyEventRef.current = (setter, event) => {
    setter(prev => [...prev, event]);
    if (event.step === "pairing_done") {
      setPairedDone(true); setPhase("success");
      setBanner({ tone: "success", title: "Pairing complete", detail: `Fingerprint: ${String(event.data.fingerprint ?? "")}`, icon: Check });
    } else if (event.step === "reconnect_done") {
      const ok = event.data.keys_match as boolean;
      setPhase("success");
      setBanner({ tone: ok ? "success" : "danger", title: ok ? "Session reconnected" : "Key mismatch!", detail: ok ? "Trusted session resumed · key match confirmed" : "Keys did not match", icon: RefreshCw });
    } else if (event.step === "stranger_rejected") {
      setPhase("rejected");
      setBanner({ tone: "danger", title: "Stranger rejected", detail: "Unknown device blocked — only paired devices may connect", icon: UserRoundX });
    } else {
      setPhase(p => p === "negotiating" || p === "success" ? p : "negotiating");
    }
  };

  // ── WebSocket connections (run once) ───────────────────────────────────────
  useEffect(() => {
    let alive = true;

    function makeWs(device: string, setter: React.Dispatch<React.SetStateAction<StepEvent[]>>, setStatus: React.Dispatch<React.SetStateAction<WsStatus>>) {
      const ws = new WebSocket(`ws://${location.host}/ws/${device}`);
      ws.onopen  = () => { if (alive) setStatus("connected"); };
      ws.onerror = () => { if (alive) setStatus("disconnected"); };
      ws.onclose = () => {
        if (alive) {
          setStatus("disconnected");
          setTimeout(() => { if (alive) makeWs(device, setter, setStatus); }, 2000);
        }
      };
      ws.onmessage = (e) => {
        if (!alive) return;
        const event: StepEvent = JSON.parse(e.data);
        if (stepByStepRef.current) {
          pendingQueue.current.push({ setter, event });
          setPendingCount(n => n + 1);
        } else {
          applyEventRef.current(setter, event);
        }
      };
      return ws;
    }

    const wsA = makeWs("device-a", setStepsA, setStatusA);
    const wsB = makeWs("device-b", setStepsB, setStatusB);
    return () => { alive = false; wsA.close(); wsB.close(); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── QR loading ─────────────────────────────────────────────────────────────
  async function loadQr() {
    try {
      const res  = await fetch("/qr");
      const data = await res.json();
      setQrImage(data.qr_image);
    } catch {}
  }
  useEffect(() => { loadQr(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Queue helpers ──────────────────────────────────────────────────────────
  function clearQueue() {
    pendingQueue.current = [];
    setPendingCount(0);
  }

  function advanceStep() {
    if (!pendingQueue.current.length) return;
    const { setter, event } = pendingQueue.current.shift()!;
    applyEventRef.current(setter, event);
    setPendingCount(pendingQueue.current.length);
  }

  function toggleStepByStep() {
    const next = !stepByStep;
    setStepByStep(next);
    stepByStepRef.current = next;
    if (!next) {
      while (pendingQueue.current.length) {
        const { setter, event } = pendingQueue.current.shift()!;
        applyEventRef.current(setter, event);
      }
      setPendingCount(0);
    }
  }

  // ── Device change ──────────────────────────────────────────────────────────
  async function changeDevice(panel: "a" | "b", newLabel: string) {
    setStepsA([]); setStepsB([]);
    clearQueue();
    setBanner({ tone: "info", title: "Switching device…", detail: "Checking for previously paired state", icon: KeyRound });

    const fromKey = `${currentLabelA.current}:${currentLabelB.current}`;
    if (panel === "a") { setLabelA(newLabel); currentLabelA.current = newLabel; }
    else               { setLabelB(newLabel); currentLabelB.current = newLabel; }
    const toKey = `${currentLabelA.current}:${currentLabelB.current}`;

    const res  = await fetch("/switch-device", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ from_key: fromKey, to_key: toKey }) });
    const data = await res.json();

    if (data.paired) {
      setPairedDone(true); setPhase("success");
      setBanner({ tone: "success", title: "Device restored", detail: "Previously paired — reconnect or send a message", icon: Check });
    } else {
      setPairedDone(false); setPhase("ready");
      setBanner({ tone: "info", title: "New device selected", detail: "Pair this device to begin", icon: KeyRound });
    }
    await loadQr();
  }

  // ── Scenario run ───────────────────────────────────────────────────────────
  async function runScenario() {
    setStepsA([]); setStepsB([]);
    clearQueue();
    setPhase("negotiating");
    setBanner({ tone: "info", title: "Comparing fingerprints…", detail: "Both devices are deriving a shared session key", icon: KeyRound });

    if (scenario === "pair") {
      setPairedDone(false);
      await fetch("/pair/start", { method: "POST" });
    } else if (scenario === "reconnect") {
      if (!pairedDone) return;
      await fetch("/reconnect", { method: "POST" });
    } else {
      if (!pairedDone) return;
      await fetch("/stranger", { method: "POST" });
    }
  }

  // ── Send message ───────────────────────────────────────────────────────────
  async function sendMessage() {
    if (!msgText.trim() || !pairedDone) return;
    setStepsA([]); setStepsB([]);
    clearQueue();
    setPhase("negotiating");
    await fetch("/message", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: msgText }) });
  }

  // ── Derived event log (last 2 steps across both feeds) ─────────────────────
  const recentEvents = [...stepsA, ...stepsB]
    .filter(e => e.step_num != null)
    .sort((a, b) => (a.step_num ?? 0) - (b.step_num ?? 0))
    .slice(-2);

  return (
    <main className="console-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      {/* ── Header ── */}
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><ShieldCheck size={18} strokeWidth={1.8} /></div>
          <div>
            <div className="brand-name">CIPHER<span>/</span>LINK</div>
            <div className="brand-caption">secure session console</div>
          </div>
        </div>
        <div className="topbar-right">
          <div className="live-indicator"><span className="live-dot" /> relay online</div>
          <button className="avatar-button" onClick={() => setAccountOpen(v => !v)}>AR</button>
          {accountOpen && (
            <div className="account-popover">
              <span>operator</span><strong>Alex Rivera</strong><small>local-only mode</small>
            </div>
          )}
        </div>
      </header>

      {/* ── Hero ── */}
      <section className="hero-intro">
        <div>
          <div className="section-kicker"><span className="kicker-line" /> session / 0042</div>
          <h1>Pair with confidence<span>.</span></h1>
          <p>Compare device fingerprints before a secure channel opens.</p>
        </div>
        <div className={`hero-status ${phase === "rejected" ? "status-danger" : phase === "negotiating" ? "status-syncing" : ""}`}>
          <CircleDot size={15} />
          <div><span>current state</span><strong>{statusLabel}</strong></div>
          <ChevronDown size={15} />
        </div>
      </section>

      {/* ── Scenario bar ── */}
      <section className="scenario-bar">
        <div className="scenario-tabs">
          {(["pair", "reconnect", "stranger"] as Scenario[]).map(s => (
            <button
              key={s}
              className={`scenario-tab ${scenario === s ? "active" : ""}`}
              onClick={() => setScenario(s)}
            >
              {s === "pair" ? <Zap size={14} /> : s === "reconnect" ? <RefreshCw size={14} /> : <UserRoundX size={14} />}
              <span>{s === "pair" ? "Pair new device" : s === "reconnect" ? "Reconnect previous" : "Block unknown"}</span>
            </button>
          ))}
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          {/* Step-by-step toggle */}
          <button
            onClick={toggleStepByStep}
            style={{
              display: "flex", alignItems: "center", gap: "6px",
              border: `1px solid ${stepByStep ? "rgba(90,216,232,.55)" : "rgba(255,255,255,.12)"}`,
              borderRadius: "7px", padding: "9px 13px",
              color: stepByStep ? "var(--cyan)" : "var(--muted)",
              background: stepByStep ? "rgba(90,216,232,.1)" : "rgba(255,255,255,.04)",
              cursor: "pointer", fontSize: "11px", fontWeight: 600, transition: "all .15s ease",
            }}
          >
            {stepByStep ? "⏸ Step-by-Step" : "⏭ Auto"}
          </button>

          {stepByStep && (
            <button
              onClick={advanceStep}
              disabled={pendingCount === 0}
              style={{
                display: "flex", alignItems: "center", gap: "6px",
                border: "1px solid rgba(180,243,106,.42)", borderRadius: "7px",
                padding: "9px 13px", color: "#dff6d4",
                background: "rgba(180,243,106,.12)", cursor: "pointer",
                fontSize: "11px", fontWeight: 700,
                opacity: pendingCount === 0 ? .35 : 1, transition: "all .15s ease",
              }}
            >
              <ChevronRight size={14} />
              Next Step
              {pendingCount > 0 && (
                <span style={{ background: "rgba(0,0,0,.3)", borderRadius: "8px", padding: "0 5px", fontSize: "10px" }}>
                  {pendingCount}
                </span>
              )}
            </button>
          )}

          <button
            className={`run-button ${stranger ? "danger-button" : ""}`}
            onClick={runScenario}
            disabled={scenario !== "pair" && !pairedDone}
            style={{ opacity: scenario !== "pair" && !pairedDone ? .4 : 1 }}
          >
            {stranger ? <UserRoundX size={15} /> : scenario === "reconnect" ? <RefreshCw size={15} /> : <RadioTower size={15} />}
            {scenario === "pair" ? "Start pairing" : scenario === "reconnect" ? "Reconnect" : "Block device"}
          </button>
        </div>
      </section>

      {/* ── Connection grid ── */}
      <section className="connection-grid">
        <DevicePanel
          side="left" label={labelA} steps={stepsA} status={statusA}
          qrImage={qrImage} pairedDone={pairedDone}
          onLabelChange={l => changeDevice("a", l)}
        />
        <Wire phase={phase} stranger={stranger} />
        <DevicePanel
          side="right" label={labelB} steps={stepsB} status={statusB}
          pairedDone={pairedDone}
          onLabelChange={l => changeDevice("b", l)}
        />
      </section>

      {/* ── Lower grid ── */}
      <section className="lower-grid">
        <div className="event-card">
          <div className="panel-heading">
            <span><Activity size={15} /> exchange log</span>
            <span className="live-tag">live</span>
          </div>
          <div className="event-list">
            {recentEvents.length === 0 ? (
              <>
                <div className="event-row">
                  <span className="event-time">——</span>
                  <span className="event-dot cyan-dot" />
                  <span>relay heartbeat</span>
                  <b>ok</b>
                </div>
                <div className="event-row">
                  <span className="event-time">——</span>
                  <span className="event-dot cyan-dot" />
                  <span>waiting for scenario</span>
                  <b>—</b>
                </div>
              </>
            ) : recentEvents.map((evt, i) => {
              const t = STEP_TYPE[evt.step] ?? "text";
              const isWarn = t === "reject" || t === "stranger";
              return (
                <div className="event-row" key={i}>
                  <span className="event-time">step {evt.step_num}</span>
                  <span className={`event-dot ${isWarn ? "red-dot" : t === "done" || t === "decrypt" ? "lime-dot" : "cyan-dot"}`} />
                  <span>{evt.label}</span>
                  <b className={isWarn ? "danger-text" : ""}>{isWarn ? "warn" : "ok"}</b>
                </div>
              );
            })}
          </div>
        </div>

        {/* Send encrypted message */}
        <div className="metric-card">
          <div className="panel-heading">
            <span><LockKeyhole size={15} /> send encrypted</span>
            <span className="tiny-label">ASCON-128a</span>
          </div>
          <div style={{ display: "flex", gap: "8px", marginTop: "14px" }}>
            <input
              value={msgText}
              onChange={e => setMsgText(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") sendMessage(); }}
              disabled={!pairedDone}
              placeholder={pairedDone ? "Type a message to encrypt…" : "Pair devices first…"}
              style={{
                flex: 1, padding: "8px 12px", borderRadius: "7px",
                border: "1px solid rgba(255,255,255,.1)",
                background: "rgba(255,255,255,.05)", color: "var(--foreground)",
                fontSize: "12px", outline: "none",
                opacity: pairedDone ? 1 : .4, transition: "opacity .15s",
              }}
            />
            <button
              onClick={sendMessage}
              disabled={!pairedDone || !msgText.trim()}
              style={{
                padding: "8px 14px", borderRadius: "7px",
                border: "1px solid rgba(180,243,106,.38)",
                background: "rgba(180,243,106,.12)", color: "#dff6d4",
                cursor: pairedDone && msgText.trim() ? "pointer" : "not-allowed",
                fontSize: "11px", fontWeight: 700,
                opacity: pairedDone && msgText.trim() ? 1 : .35,
                transition: "opacity .15s",
              }}
            >
              Send
            </button>
          </div>
        </div>
      </section>

      {/* ── Floating banner ── */}
      <div
        className={`floating-banner ${banner.tone === "danger" ? "danger" : banner.tone === "info" ? "is-negotiating" : ""}`}
        role="status"
      >
        <div className="banner-icon"><banner.icon size={17} /></div>
        <div className="banner-copy">
          <strong>{banner.title}</strong>
          <span>{banner.detail}</span>
        </div>
        <span className="banner-mark">
          {banner.tone === "success" ? "verified" : banner.tone === "danger" ? "stopped" : "…"}
        </span>
      </div>
    </main>
  );
}
