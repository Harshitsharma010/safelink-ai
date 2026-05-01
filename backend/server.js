const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

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
  let protocol = "";

  if (isUrl) {
    try {
      const raw = input.startsWith("http") ? input : "http://" + input;
      const parsed = new URL(raw);
      hostname = parsed.hostname.toLowerCase();
      protocol = parsed.protocol;
      url = raw;
    } catch {
      hostname = input.toLowerCase();
    }

    if (protocol && protocol !== "https:") {
      score += 20;
      signals.push({ label: "No HTTPS", severity: "high", detail: "Uses plain HTTP — data is not encrypted." });
    } else if (protocol === "https:") {
      signals.push({ label: "HTTPS present", severity: "safe", detail: "Connection is encrypted." });
    }

    if (url.length > 100) {
      score += url.length > 150 ? 15 : 8;
      signals.push({ label: "Long URL", severity: "medium", detail: `URL is ${url.length} characters — unusually long URLs often hide the true destination.` });
    }

    const parts = hostname.split(".");
    const subdomainCount = parts.length - 2;
    if (subdomainCount >= 3) {
      score += 10 * (subdomainCount - 2);
      signals.push({ label: `Excessive subdomains (${subdomainCount})`, severity: "medium", detail: `"${hostname}" has ${subdomainCount} subdomain levels — phishing sites use this to spoof legitimate domains.` });
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 30;
      signals.push({ label: "IP address as URL", severity: "high", detail: "Legitimate sites don't use raw IP addresses — this is a strong phishing signal." });
    }

    if (SHORTENERS.some(s => hostname.includes(s))) {
      score += 15;
      signals.push({ label: "URL shortener detected", severity: "medium", detail: "Shortened URLs mask the real destination — common in phishing campaigns." });
    }

    const tldMatch = PHISHING_TLDS.find(t => hostname.endsWith(t));
    if (tldMatch) {
      score += 20;
      signals.push({ label: `Suspicious TLD (${tldMatch})`, severity: "high", detail: `The "${tldMatch}" TLD is frequently associated with phishing domains.` });
    }

    if (url.includes("@")) {
      score += 25;
      signals.push({ label: "@ symbol in URL", severity: "high", detail: "An @ in a URL causes browsers to ignore everything before it — a classic phishing trick." });
    }

    if (url.replace("://", "").includes("//")) {
      score += 12;
      signals.push({ label: "Double slash redirect", severity: "medium", detail: "Extra slashes can indicate redirect manipulation." });
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      score += 8;
      signals.push({ label: `Many hyphens (${hyphenCount})`, severity: "low", detail: `"${hostname}" has ${hyphenCount} hyphens — phishing domains hyphenate brand names to look legitimate.` });
    }

    if (/%[0-9a-f]{2}/i.test(url)) {
      score += 10;
      signals.push({ label: "URL encoding detected", severity: "medium", detail: "Hex-encoded characters can obfuscate malicious URLs." });
    }

    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(k => url.toLowerCase().includes(k));
    if (foundKeywords.length > 0) {
      score += Math.min(foundKeywords.length * 8, 35);
      signals.push({
        label: `Suspicious keywords (${foundKeywords.length})`,
        severity: foundKeywords.length >= 3 ? "high" : "medium",
        detail: `Found: "${foundKeywords.join('", "')}" — common in phishing URLs.`
      });
    }

  } else {
    signals.push({ label: "Message (non-URL) analysis", severity: "info", detail: "Analyzing as a text message rather than a URL." });
    const textLower = input.toLowerCase();

    const urgencyPhrases = ["act now", "immediately", "urgent", "expires soon", "limited time", "24 hours", "account suspended", "verify now"];
    const foundUrgency = urgencyPhrases.filter(p => textLower.includes(p));
    if (foundUrgency.length > 0) {
      score += foundUrgency.length * 15;
      signals.push({ label: "Urgency language", severity: "high", detail: `Detected: "${foundUrgency.join('", "')}" — pressure tactics are a hallmark of phishing.` });
    }

    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(k => textLower.includes(k));
    if (foundKeywords.length > 0) {
      score += Math.min(foundKeywords.length * 6, 30);
      signals.push({ label: `Suspicious keywords (${foundKeywords.length})`, severity: "medium", detail: `Found: "${foundKeywords.slice(0, 5).join('", "')}"` });
    }

    const urlsInText = input.match(/https?:\/\/[^\s]+/gi) || [];
    if (urlsInText.length > 0) {
      score += 10;
      signals.push({ label: `Contains ${urlsInText.length} link(s)`, severity: "medium", detail: "Messages with embedded links require extra scrutiny." });
      if (urlsInText.some(u => SHORTENERS.some(s => u.includes(s)))) {
        score += 15;
        signals.push({ label: "Shortened link in message", severity: "high", detail: "Contains a shortened URL — often used to hide phishing destinations." });
      }
    }

    const sensitiveRequests = ["social security", "ssn", "credit card", "bank account", "routing number", "password", "pin"];
    const foundSensitive = sensitiveRequests.filter(s => textLower.includes(s));
    if (foundSensitive.length > 0) {
      score += foundSensitive.length * 20;
      signals.push({ label: "Requests sensitive info", severity: "high", detail: `Asks for: "${foundSensitive.join('", "')}"` });
    }

    if ((input.match(/\b[A-Z]{4,}\b/g) || []).length >= 2) {
      score += 8;
      signals.push({ label: "Unusual capitalization", severity: "low", detail: "Excessive capitalization is common in phishing messages." });
    }
  }

  score = Math.min(score, 100);
  let label, color;
  if (score <= 25) { label = "Safe"; color = "green"; }
  else if (score <= 60) { label = "Suspicious"; color = "amber"; }
  else { label = "Dangerous"; color = "red"; }

  return { score, label, color, signals, isUrl, hostname };
}

async function getAIExplanation(input, analysis, apiKey) {
  if (!apiKey) return null;
  try {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 5000);
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      signal: controller.signal,
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 200,
        messages: [{ role: "user", content: `You are a cybersecurity expert. Analyze this phishing result and explain in 2-3 plain sentences why it is ${analysis.label.toLowerCase()} (score: ${analysis.score}/100). Signals: ${analysis.signals.map(s => s.label).join(", ")}. Input: "${input.substring(0, 200)}". No markdown.` }]
      })
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.content?.[0]?.text || null;
  } catch { return null; }
}

// Keep-alive so Render free tier doesn't sleep
setInterval(() => {
  fetch(`http://localhost:${process.env.PORT || 3001}/health`).catch(() => {});
}, 14 * 60 * 1000);

app.get("/", (req, res) => res.json({ status: "ok", service: "SafeLink AI" }));
app.get("/health", (req, res) => res.json({ status: "ok", service: "SafeLink AI" }));

app.post("/api/analyze", async (req, res) => {
  try {
    const { input, apiKey } = req.body;
    if (!input || typeof input !== "string" || !input.trim()) {
      return res.status(400).json({ error: "Input is required." });
    }
    const trimmed = input.trim().substring(0, 2000);
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
app.listen(PORT, () => console.log(`SafeLink AI running on port ${PORT}`));
