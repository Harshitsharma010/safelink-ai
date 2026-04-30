# 🔒 SafeLink AI — Phishing Detection Web App

Detect whether a URL or message is **Safe**, **Suspicious**, or **Dangerous** using rule-based analysis + optional Claude AI explanations.

---

## 📁 Project Structure

```
safelink-ai/
├── backend/
│   ├── server.js        # Express API — scoring engine + Claude integration
│   └── package.json
├── frontend/
│   ├── public/
│   │   └── index.html
│   └── src/
│       ├── App.js       # Main React component
│       ├── App.css      # All styles (dark/light mode)
│       └── index.js     # React entry point
├── package.json         # Root scripts (optional)
└── README.md
```

---

## 🚀 Quick Start (Two Terminals)

### Prerequisites
- **Node.js 18+** installed → [nodejs.org](https://nodejs.org)

### Terminal 1 — Backend

```bash
cd safelink-ai/backend
npm install
node server.js
```

You'll see:
```
🔒 SafeLink AI Backend running at http://localhost:3001
   POST /api/analyze  — analyze URLs and messages
   GET  /health       — health check
```

### Terminal 2 — Frontend

```bash
cd safelink-ai/frontend
npm install
npm start
```

Browser opens at **http://localhost:3000** automatically.

---

## 🔑 Optional: Claude AI Explanations

To get plain-English AI explanations powered by Claude:

1. Get a free API key at [console.anthropic.com](https://console.anthropic.com)
2. In the app, click **"Claude API key (optional)"** at the bottom of the input card
3. Paste your key (starts with `sk-ant-...`)

Your key is saved locally in `localStorage` — it's never sent anywhere except the Anthropic API.

---

## ✨ Features

| Feature | Details |
|---|---|
| **URL Analysis** | HTTPS check, URL length, subdomain count, suspicious keywords, TLD, IP detection, URL shorteners |
| **Message Analysis** | Urgency language, sensitive info requests, embedded links, capitalization patterns |
| **Risk Score** | 0–100 score with animated ring visualization |
| **Labels** | Safe (0–25) · Suspicious (26–60) · Dangerous (61–100) |
| **Signal Breakdown** | Every detection signal explained in plain English |
| **AI Explanation** | Optional Claude-powered 2–3 sentence summary |
| **Scan History** | Last 20 scans saved locally, clickable to reload |
| **Dark / Light Mode** | Toggle in header, preference saved |
| **Sample URLs** | One-click examples to demo the tool |

---

## 🔌 API Reference

### `POST /api/analyze`

**Request body:**
```json
{
  "input": "http://paypal-verify.tk/login",
  "apiKey": "sk-ant-..."  // optional
}
```

**Response:**
```json
{
  "input": "http://paypal-verify.tk/login",
  "score": 73,
  "label": "Dangerous",
  "color": "red",
  "isUrl": true,
  "signals": [
    {
      "label": "No HTTPS",
      "severity": "high",
      "detail": "Uses plain HTTP — data is not encrypted."
    },
    {
      "label": "Suspicious TLD (.tk)",
      "severity": "high",
      "detail": "The \".tk\" TLD is frequently associated with free hosting and phishing domains."
    }
  ],
  "aiExplanation": "This URL shows multiple high-severity phishing indicators...",
  "timestamp": "2025-01-15T12:00:00.000Z"
}
```

### `GET /health`
```json
{ "status": "ok", "service": "SafeLink AI" }
```

---

## 🧠 How Scoring Works

| Signal | Points |
|---|---|
| No HTTPS | +20 |
| URL length > 100 chars | +8–15 |
| IP address as hostname | +30 |
| @ symbol in URL | +25 |
| Suspicious TLD (.tk, .xyz, etc.) | +20 |
| 3+ subdomains | +10 per extra level |
| URL shortener | +15 |
| Suspicious keywords in URL/text | +8 per keyword (max 35) |
| Urgency language (messages) | +15 per phrase |
| Sensitive info requests | +20 per item |
| 2+ hyphens in domain | +8 |
| Hex encoding in URL | +10 |

**Score thresholds:**
- **0–25** → ✓ Safe (green)
- **26–60** → ! Suspicious (amber)  
- **61–100** → ✕ Dangerous (red)

---

## 🛠 Troubleshooting

| Issue | Fix |
|---|---|
| "Could not reach server" | Make sure backend is running on port 3001 |
| Frontend won't start | Run `npm install` in the `frontend/` folder |
| AI explanation not showing | Check your API key is valid and starts with `sk-ant-` |
| Port 3001 already in use | `PORT=3002 node server.js` then update frontend proxy |

---

## 🗺 12-Hour Build Plan

| Hour | Task |
|---|---|
| 0–1 | Project setup, folder structure, dependencies |
| 1–3 | Backend scoring engine (`server.js`) |
| 3–5 | React UI — input, layout, basic result display |
| 5–7 | Score ring animation, signal cards, styling |
| 7–9 | Claude AI integration, dark mode, history |
| 9–10 | Sample URLs, error handling, polish |
| 10–11 | Testing with real phishing URLs |
| 11–12 | README, final cleanup, deploy-ready |

---

## 📦 Tech Stack

- **Frontend**: React 18, CSS Variables (no CSS framework)
- **Backend**: Node.js + Express
- **AI**: Anthropic Claude API (claude-haiku-4-5) — optional
- **Storage**: Browser `localStorage` (no database)
- **Fonts**: Syne (display) + IBM Plex Mono

---

Built as a rapid MVP. Not a substitute for professional security tools like VirusTotal, Google Safe Browsing, or enterprise email security gateways.
