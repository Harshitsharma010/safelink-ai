import { useState, useEffect, useRef } from "react";
import "./App.css";

const API = "https://safelink-ai-s4fy.onrender.com";

function ScoreRing({ score, color }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const colorMap = { green: "#22c55e", amber: "#f59e0b", red: "#ef4444" };
  const stroke = colorMap[color] || "#888";

  return (
    <svg width="140" height="140" viewBox="0 0 140 140" className="score-ring">
      <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
      <circle
        cx="70" cy="70" r={r}
        fill="none"
        stroke={stroke}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={circ}
        strokeDashoffset={offset}
        transform="rotate(-90 70 70)"
        style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1), stroke 0.4s" }}
      />
      <text x="70" y="62" textAnchor="middle" className="ring-score" fill={stroke}>{score}</text>
      <text x="70" y="82" textAnchor="middle" className="ring-label" fill="rgba(255,255,255,0.45)">/ 100</text>
    </svg>
  );
}

function SignalBadge({ signal }) {
  const sev = signal.severity;
  const icons = { high: "▲", medium: "◆", low: "●", safe: "✓", info: "ℹ" };
  return (
    <div className={`signal signal--${sev}`}>
      <span className="signal-icon">{icons[sev] || "●"}</span>
      <div>
        <div className="signal-label">{signal.label}</div>
        <div className="signal-detail">{signal.detail}</div>
      </div>
    </div>
  );
}

function HistoryItem({ item, onClick }) {
  const colorMap = { green: "#22c55e", amber: "#f59e0b", red: "#ef4444" };
  return (
    <button className="history-item" onClick={() => onClick(item)}>
      <span className="history-dot" style={{ background: colorMap[item.color] }} />
      <span className="history-input">{item.input.substring(0, 50)}{item.input.length > 50 ? "…" : ""}</span>
      <span className="history-score" style={{ color: colorMap[item.color] }}>{item.score}</span>
    </button>
  );
}

function LoadingPulse() {
  return (
    <div className="loading-wrap">
      <div className="loading-scanner">
        <div className="scanner-beam" />
        <div className="scanner-grid">
          {Array.from({ length: 16 }).map((_, i) => (
            <div key={i} className="scanner-cell" style={{ animationDelay: `${(i * 0.07).toFixed(2)}s` }} />
          ))}
        </div>
      </div>
      <p className="loading-text">Analyzing threat signature…</p>
    </div>
  );
}

export default function App() {
  const [input, setInput] = useState("");
  const [apiKey, setApiKey] = useState(() => localStorage.getItem("sl_apikey") || "");
  const [showApiKey, setShowApiKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [history, setHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem("sl_history") || "[]"); } catch { return []; }
  });
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem("sl_dark") !== "false");
  const [showHistory, setShowHistory] = useState(false);
  const textareaRef = useRef(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", darkMode ? "dark" : "light");
    localStorage.setItem("sl_dark", darkMode);
  }, [darkMode]);

  useEffect(() => {
    if (apiKey) localStorage.setItem("sl_apikey", apiKey);
  }, [apiKey]);

  const analyze = async () => {
    if (!input.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);

    try {
      // Retry up to 3x — handles Render free tier cold starts
      let res, text;
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          res = await fetch(`${API}/api/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ input: input.trim(), apiKey: apiKey || undefined })
          });
          text = await res.text();
          if (text && !text.startsWith("<")) break;
          if (attempt < 3) {
            setError(`Server waking up… retrying (${attempt}/3)`);
            await new Promise(r => setTimeout(r, 5000));
          }
        } catch (fetchErr) {
          if (attempt === 3) throw fetchErr;
          await new Promise(r => setTimeout(r, 3000));
        }
      }
      if (!text || text.startsWith("<")) {
        throw new Error("Server is starting — please wait 30 seconds and try again");
      }
      let data;
      try { data = JSON.parse(text); } catch {
        throw new Error("Bad response from server. Try again in a moment.");
      }
      if (!res.ok) throw new Error(data.error || "Analysis failed");

      setResult(data);
      const newHistory = [data, ...history.filter(h => h.input !== data.input)].slice(0, 20);
      setHistory(newHistory);
      localStorage.setItem("sl_history", JSON.stringify(newHistory));
    } catch (e) {
      setError(e.message || "Could not reach the analysis server. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) analyze();
  };

  const loadHistory = (item) => {
    setInput(item.input);
    setResult(item);
    setShowHistory(false);
  };

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("sl_history");
  };

  const labelEmoji = { Safe: "✓", Suspicious: "!", Dangerous: "✕" };

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-brand">
          <div className="logo-mark">
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
              <path d="M14 2L4 7v8c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V7L14 2z" fill="currentColor" opacity="0.15" />
              <path d="M14 2L4 7v8c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V7L14 2z" stroke="currentColor" strokeWidth="1.5" fill="none" />
              <path d="M10 14l3 3 5-5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <span className="brand-name">SafeLink <em>AI</em></span>
        </div>
        <div className="header-actions">
          <button className="icon-btn" onClick={() => setShowHistory(!showHistory)} title="Scan history">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.2" />
              <path d="M8 5v3.5l2 2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
            </svg>
            {history.length > 0 && <span className="badge">{history.length}</span>}
          </button>
          <button className="icon-btn" onClick={() => setDarkMode(!darkMode)} title="Toggle theme">
            {darkMode
              ? <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="3" fill="currentColor" /><path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.2 3.2l1.1 1.1M11.7 11.7l1.1 1.1M3.2 12.8l1.1-1.1M11.7 4.3l1.1-1.1" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" /></svg>
              : <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M13.5 9A6 6 0 017 2.5a6 6 0 100 11 6 6 0 006.5-4.5z" stroke="currentColor" strokeWidth="1.2" fill="none" /></svg>
            }
          </button>
        </div>
      </header>

      {/* History Panel */}
      {showHistory && (
        <div className="history-panel">
          <div className="history-header">
            <span>Recent scans</span>
            {history.length > 0 && <button className="text-btn" onClick={clearHistory}>Clear all</button>}
          </div>
          {history.length === 0
            ? <p className="history-empty">No scans yet.</p>
            : history.map((item, i) => <HistoryItem key={i} item={item} onClick={loadHistory} />)
          }
        </div>
      )}

      {/* Main Content */}
      <main className="main">
        <div className="hero">
          <h1>Detect phishing<br /><span className="hero-accent">before it's too late</span></h1>
          <p className="hero-sub">Paste any URL or suspicious message. Our AI analyzes it in seconds.</p>
        </div>

        {/* Input Card */}
        <div className="card input-card">
          <label className="input-label">URL or message to analyze</label>
          <textarea
            ref={textareaRef}
            className="input-box"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKey}
            placeholder="https://paypal-secure-login.xyz/verify?account=...&#10;or paste a suspicious email/SMS message"
            rows={4}
            maxLength={2000}
          />
          <div className="input-footer">
            <span className="char-count">{input.length}/2000 · Ctrl+Enter to scan</span>
            <button
              className={`scan-btn ${loading ? "scan-btn--loading" : ""}`}
              onClick={analyze}
              disabled={loading || !input.trim()}
            >
              {loading ? (
                <><span className="spinner" />Scanning…</>
              ) : (
                <><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1L1 4v4c0 3 2.5 5.7 6 6.5C10.5 13.7 13 11 13 8V4L7 1z" stroke="currentColor" strokeWidth="1.2" fill="none" /><path d="M4.5 7l2 2 3-3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" /></svg>Analyze</>
              )}
            </button>
          </div>

        </div>

        {/* Error */}
        {error && (
          <div className="error-banner">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.2" /><path d="M8 5v3M8 10.5v.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && <LoadingPulse />}

        {/* Result */}
        {result && !loading && (
          <div className={`result-card result-card--${result.color}`}>
            {/* Score */}
            <div className="result-header">
              <ScoreRing score={result.score} color={result.color} />
              <div className="result-meta">
                <div className={`result-label result-label--${result.color}`}>
                  <span className="label-icon">{labelEmoji[result.label]}</span>
                  {result.label}
                </div>
                <div className="result-input-display">
                  <span className="result-input-text">{result.input.substring(0, 80)}{result.input.length > 80 ? "…" : ""}</span>
                </div>
                <div className="result-type">{result.isUrl ? "URL Analysis" : "Message Analysis"}</div>
              </div>
            </div>

            {/* AI Explanation */}
            {result.aiExplanation && (
              <div className="ai-explanation">
                <div className="ai-badge">
                  <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="5" stroke="currentColor" strokeWidth="1" /><path d="M4 6.5c.3.8 1 1.5 2 1.5s1.7-.7 2-1.5M4.5 4.5h.01M7.5 4.5h.01" stroke="currentColor" strokeWidth="1" strokeLinecap="round" /></svg>
                  Claude AI
                </div>
                <p className="ai-text">{result.aiExplanation}</p>
              </div>
            )}

            {/* Signals */}
            <div className="signals-section">
              <h3 className="signals-title">Detection signals ({result.signals.length})</h3>
              <div className="signals-list">
                {result.signals.map((s, i) => <SignalBadge key={i} signal={s} />)}
              </div>
            </div>

            {/* Score bar */}
            <div className="score-bar-wrap">
              <div className="score-bar-track">
                <div
                  className={`score-bar-fill score-bar-fill--${result.color}`}
                  style={{ width: `${result.score}%` }}
                />
                <div className="score-bar-labels">
                  <span>Safe</span><span>Suspicious</span><span>Dangerous</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Sample URLs */}
        {!result && !loading && (
          <div className="samples">
            <p className="samples-title">Try an example</p>
            <div className="samples-grid">
              {[
                { label: "Phishing URL", value: "http://paypal-account-verify.tk/login?user=target@gmail.com" },
                { label: "Safe URL", value: "https://github.com/anthropics/claude" },
                { label: "Suspicious message", value: "URGENT: Your account is suspended! Click here immediately to verify: http://bit.ly/3xyzABC" },
                { label: "IP-based URL", value: "http://192.168.1.1/bank/login/verify" },
              ].map((s, i) => (
                <button key={i} className="sample-btn" onClick={() => setInput(s.value)}>
                  <span className="sample-label">{s.label}</span>
                  <span className="sample-value">{s.value.substring(0, 45)}…</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </main>

      <footer className="footer">
        SafeLink AI · Built by Harshit Sharma · Real-time phishing detection with explainable scoring
      </footer>
    </div>
  );
}
