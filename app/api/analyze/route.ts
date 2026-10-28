import { NextResponse } from "next/server";
import type { AnalysisResult, ScanResult } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 30;

/* ---------- prompt ---------- */

function buildPrompt(scan: ScanResult): string {
  const lines: string[] = [
    `You are a senior application-security engineer. A scan of ${scan.url} produced these findings:`,
    "",
    "## AI Scraper Defense (robots.txt)",
    scan.robots.found
      ? scan.robots.bots.map((b) => `- ${b.name}: ${b.blocked ? "BLOCKED" : "ALLOWED"}`).join("\n")
      : `robots.txt not found (HTTP ${scan.robots.status ?? "error"}). All crawlers allowed by default.`,
    "",
    "## Security Headers",
    `HTTP ${scan.headers.status}`,
    ...scan.headers.items.map((h) => `- ${h.label}: ${h.present ? `present (${h.value})` : "MISSING"}`),
    "",
    "## Dev Leaks",
    ...scan.leaks.map((l) => `- ${l.path}: ${l.state} (HTTP ${l.status ?? "-"}) — ${l.note}`),
    "",
    "---",
    "Respond with ONLY valid JSON matching this schema (no markdown fences):",
    '{ "grade": "<A+ to F>", "summary": "<2-3 sentence plain-text explanation>", "language": "<config language, e.g. nginx | apache | next.config.js | robots.txt>", "code": "<remediation config snippet>" }',
    "",
    "Rules:",
    "- grade: A+ (excellent) through F (critical). Base it on the combination of header coverage, crawler blocking, and leak exposure.",
    "- summary: Mention what is good and what needs fixing. Be specific.",
    "- code: A single, ready-to-paste configuration snippet that fixes the most impactful issues found. Pick the most relevant language (nginx, .htaccess, next.config.js, vercel.json, robots.txt, etc.).",
    "- If everything looks secure, still provide a hardening snippet.",
  ];
  return lines.join("\n");
}

/* ---------- AI provider abstraction ---------- */

interface ChatResponse {
  text: string;
}

async function callGemini(prompt: string, apiKey: string, model: string): Promise<ChatResponse> {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 1024 },
    }),
    signal: AbortSignal.timeout(25_000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Gemini API error ${res.status}: ${body.slice(0, 200)}`);
  }
  const data = await res.json();
  const text: string | undefined = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error("Gemini returned an empty response.");
  return { text };
}

async function callOpenAI(prompt: string, apiKey: string, model: string): Promise<ChatResponse> {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: "You are a senior application-security engineer. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 1024,
    }),
    signal: AbortSignal.timeout(25_000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`OpenAI API error ${res.status}: ${body.slice(0, 200)}`);
  }
  const data = await res.json();
  const text: string | undefined = data?.choices?.[0]?.message?.content;
  if (!text) throw new Error("OpenAI returned an empty response.");
  return { text };
}

/* ---------- parse & validate ---------- */

function parseAnalysis(raw: string): AnalysisResult {
  // Strip markdown code fences if the model wraps its answer
  const cleaned = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    throw new Error("The AI returned invalid JSON. Please retry.");
  }
  const obj = parsed as Record<string, unknown>;
  const grade = String(obj.grade ?? "").trim();
  const summary = String(obj.summary ?? "").trim();
  const language = String(obj.language ?? "text").trim();
  const code = String(obj.code ?? "").trim();
  if (!grade || !summary) {
    throw new Error("The AI response is missing required fields (grade, summary).");
  }
  return { grade, summary, language, code };
}

/* ---------- handler ---------- */

export async function POST(req: Request) {
  try {
    const apiKey = process.env.AI_API_KEY;
    if (!apiKey || apiKey === "your-key-here") {
      return NextResponse.json(
        { error: "AI analysis is not configured. Set AI_API_KEY in .env.local." },
        { status: 503 },
      );
    }

    const scan: ScanResult | null = await req.json().catch(() => null);
    if (!scan?.url || !scan.robots || !scan.headers || !scan.leaks) {
      return NextResponse.json({ error: "Invalid scan payload." }, { status: 400 });
    }

    const provider = (process.env.AI_PROVIDER ?? "gemini").toLowerCase();
    const prompt = buildPrompt(scan);

    let response: ChatResponse;
    if (provider === "openai") {
      const model = process.env.AI_MODEL || "gpt-4o-mini";
      response = await callOpenAI(prompt, apiKey, model);
    } else {
      const model = process.env.AI_MODEL || "gemini-2.5-flash";
      response = await callGemini(prompt, apiKey, model);
    }

    const analysis = parseAnalysis(response.text);
    return NextResponse.json(analysis);
  } catch (e) {
    const message = e instanceof Error ? e.message : "Analysis failed unexpectedly.";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
