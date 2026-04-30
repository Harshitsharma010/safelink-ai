const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");

const app = express();
app.use(cors());
app.use(express.json());

// ─── Rule-based phishing scoring ────────────────────────────────────────────

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "update", "bank", "secure", "account",
  "password", "confirm", "billing", "paypal", "amazon", "netflix",
  "apple", "microsoft", "google", "suspended", "urgent", "click",
  "free", "winner", "prize", "claim", "limited", "expire",
  "validate", "credential", "signin", "webscr", "ebayisapi"
];

const PHISHING_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click"];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link", "rb.gy", "is.gd"];

function analyzeInput(input) {
  const signals = [];
  let score = 0;

  const isUrl = /^https?:\/\//i.test(input) || /^www\./i.test(input) ||
    /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/.test(input);

  let url = input;
  let hostname = "";
  let pathname = "";
  let protocol = "";

  if (isUrl) {
    try {
      const raw = input.startsWith("http") ? input : "http://" + input;
      const parsed = new URL(raw);
      hostname = parsed.hostname.toLowerCase();
      pathname = parsed.pathname.toLowerCase();
      protocol = parsed.protocol;
      url = raw;
    } catch {
      hostname = input.toLowerCase();
    }

    // ── URL-specific checks ──────────────────────────────────────────────────

    // HTTPS check
    if (protocol && protocol !== "https:") {
      score += 20;
      signals.push({ label: "No HTTPS", severity: "high", detail: "Uses plain HTTP — data is not encrypted." });
    } else if (protocol === "https:") {
      signals.push({ label: "HTTPS present", severity: "safe", detail: "Connection is encrypted." });
    }

    // URL length
    if (url.length > 100) {
      const pts = url.length > 150 ? 15 : 8;
      score += pts;
      signals.push({ label: "Long URL", severity: "medium", detail: `URL is ${url.length} characters — unusually long URLs often hide the true destination.` });
    }

    // Subdomain count
    const parts = hostname.split(".");
    const subdomainCount = parts.length - 2;
    if (subdomainCount >= 3) {
      score += 10 * (subdomainCount - 2);
      signals.push({ label: `Excessive subdomains (${subdomainCount})`, severity: "medium", detail: `"${hostname}" has ${subdomainCount} subdomain levels — phishing sites use this to spoof legitimate domains.` });
    }

    // Dot count
    const dotCount = (hostname.match(/\./g) || []).length;
    if (dotCount > 3) {
      score += 8;
      signals.push({ label: `High dot count (${dotCount} dots)`, severity: "medium", detail: "Many dots in a domain often indicate a multi-level subdomain trick." });
    }

    // IP address as hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 30;
      signals.push({ label: "IP address as URL", severity: "high", detail: "Legitimate sites don't use raw IP addresses — this is a strong phishing signal." });
    }

    // URL shortener
    if (SHORTENERS.some(s => hostname.includes(s))) {
      score += 15;
      signals.push({ label: "URL shortener detected", severity: "medium", detail: "Shortened URLs mask the real destination — common in phishing campaigns." });
    }

    // Suspicious TLD
    const tldMatch = PHISHING_TLDS.find(t => hostname.endsWith(t));
    if (tldMatch) {
      score += 20;
      signals.push({ label: `Suspicious TLD (${tldMatch})`, severity: "high", detail: `The "${tldMatch}" TLD is frequently associated with free hosting and phishing domains.` });
    }

    // @ symbol in URL (credential harvesting trick)
    if (url.includes("@")) {
      score += 25;
      signals.push({ label: "@ symbol in URL", severity: "high", detail: "An @ in a URL causes browsers to ignore everything before it — a classic phishing trick." });
    }

    // Double slash redirect
    if (url.replace("://", "").includes("//")) {
      score += 12;
      signals.push({ label: "Double slash redirect", severity: "medium", detail: "Extra slashes can indicate redirect manipulation." });
    }

    // Hyphen count (e.g. paypal-secure-login.com)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      score += 8;
      signals.push({ label: `Many hyphens (${hyphenCount})`, severity: "low", detail: `"${hostname}" has ${hyphenCount} hyphens — phishing domains often hyphenate brand names to look legitimate.` });
    }

    // Hexadecimal encoding
    if (/%[0-9a-f]{2}/i.test(url)) {
      score += 10;
      signals.push({ label: "URL encoding detected", severity: "medium", detail: "Hex-encoded characters can be used to obfuscate malicious URLs." });
    }

    // Suspicious keywords in URL
    const urlLower = url.toLowerCase();
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(k => urlLower.includes(k));
    if (foundKeywords.length > 0) {
      score += Math.min(foundKeywords.length * 8, 35);
      signals.push({
        label: `Suspicious keywords (${foundKeywords.length})`,
        severity: foundKeywords.length >= 3 ? "high" : "medium",
        detail: `Found: "${foundKeywords.join('", "')}" — these words are common in phishing URLs.`
      });
    }

  } else {
    // ── Text/message analysis ────────────────────────────────────────────────
    signals.push({ label: "Message (non-URL) analysis", severity: "info", detail: "Analyzing this as a text message rather than a URL." });

    const textLower = input.toLowerCase();

    // Urgency phrases
    const urgencyPhrases = ["act now", "immediately", "urgent", "expires soon", "limited time", "24 hours", "account suspended", "verify now"];
    const foundUrgency = urgencyPhrases.filter(p => textLower.includes(p));
    if (foundUrgency.length > 0) {
      score += foundUrgency.length * 15;
      signals.push({ label: "Urgency language", severity: "high", detail: `Detected: "${foundUrgency.join('", "')}" — pressure tactics are a hallmark of phishing messages.` });
    }

    // Suspicious keywords in text
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(k => textLower.includes(k));
    if (foundKeywords.length > 0) {
      score += Math.min(foundKeywords.length * 6, 30);
      signals.push({ label: `Suspicious keywords (${foundKeywords.length})`, severity: "medium", detail: `Found: "${foundKeywords.slice(0, 5).join('", "')}"${foundKeywords.length > 5 ? '...' : ''}` });
    }

    // Links inside message
    const urlsInText = input.match(/https?:\/\/[^\s]+/gi) || [];
    if (urlsInText.length > 0) {
      score += 10;
      signals.push({ label: `Contains ${urlsInText.length} link(s)`, severity: "medium", detail: "Messages with embedded links require extra scrutiny." });

      const hasShortener = urlsInText.some(u => SHORTENERS.some(s => u.includes(s)));
      if (hasShortener) {
        score += 15;
        signals.push({ label: "Shortened link in message", severity: "high", detail: "The message contains a shortened URL — often used to hide phishing destinations." });
      }
    }

    // Requests for sensitive info
    const sensitiveRequests = ["social security", "ssn", "credit card", "bank account", "routing number", "password", "pin", "mother's maiden"];
    const foundSensitive = sensitiveRequests.filter(s => textLower.includes(s));
    if (foundSensitive.length > 0) {
      score += foundSensitive.length * 20;
      signals.push({ label: "Requests sensitive info", severity: "high", detail: `Asks for: "${foundSensitive.join('", "')}" — legitimate organizations don't request this via message.` });
    }

    // Grammar/typo proxies (all caps words)
    const allCapsWords = (input.match(/\b[A-Z]{4,}\b/g) || []);
    if (allCapsWords.length >= 2) {
      score += 8;
      signals.push({ label: "Unusual capitalization", severity: "low", detail: "Excessive capitalization is common in phishing messages to create alarm." });
    }
  }

  // Clamp score
  score = Math.min(score, 100);

  let label, color;
  if (score <= 25) { label = "Safe"; color = "green"; }
  else if (score <= 60) { label = "Suspicious"; color = "amber"; }
  else { label = "Dangerous"; color = "red"; }

  return { score, label, color, signals, isUrl, hostname };
}

// ─── Claude AI Explanation ───────────────────────────────────────────────────

async function getAIExplanation(input, analysis, apiKey) {
  if (!apiKey) return null;

  const prompt = `You are a cybersecurity expert. A user submitted this for phishing analysis:

INPUT: "${input.substring(0, 500)}"

ANALYSIS RESULTS:
- Risk Score: ${analysis.score}/100
- Label: ${analysis.label}
- Signals detected: ${analysis.signals.map(s => `${s.label}: ${s.detail}`).join(" | ")}

Write a concise 2-3 sentence plain-English explanation of WHY this is ${analysis.label.toLowerCase()}, what the user should do, and one specific thing to watch out for. Be direct and specific. No markdown.`;

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 200,
        messages: [{ role: "user", content: prompt }]
      })
    });

    if (!res.ok) return null;
    const data = await res.json();
    return data?.content?.[0]?.text || null;
  } catch {
    return null;
  }
}

// ─── Routes ─────────────────────────────────────────────────────────────────

app.get("/health", (req, res) => res.json({ status: "ok", service: "SafeLink AI" }));

app.post("/api/analyze", async (req, res) => {
  const { input, apiKey } = req.body;

  if (!input || typeof input !== "string" || input.trim().length === 0) {
    return res.status(400).json({ error: "Input is required." });
  }

  const trimmed = input.trim();
  if (trimmed.length > 2000) {
    return res.status(400).json({ error: "Input too long (max 2000 characters)." });
  }

  try {
    const analysis = analyzeInput(trimmed);
    const aiExplanation = await getAIExplanation(trimmed, analysis, apiKey);

    res.json({
      input: trimmed,
      score: analysis.score,
      label: analysis.label,
      color: analysis.color,
      signals: analysis.signals,
      isUrl: analysis.isUrl,
      aiExplanation,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Analysis failed. Please try again." });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n🔒 SafeLink AI Backend running at http://localhost:${PORT}`);
  console.log(`   POST /api/analyze  — analyze URLs and messages`);
  console.log(`   GET  /health       — health check\n`);
});
