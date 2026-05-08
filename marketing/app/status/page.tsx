import type { Metadata } from "next";
import { Activity } from "lucide-react";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "Capability Status — CyberArmor.AI",
  description:
    "Honest, buyer-facing status of every CyberArmor.AI capability: what is production-deployed, what works in controlled pilots, what requires operator configuration to activate, and what is on the roadmap.",
};

// ─── Status definitions ────────────────────────────────────────────────────
type Status = "production" | "pilot" | "poc" | "roadmap";

const STATUS_META: Record<Status, { label: string; color: string; bg: string; description: string }> = {
  production: {
    label: "Production-deployed",
    color: "#22C55E",
    bg: "rgba(34,197,94,0.10)",
    description: "Running in hosted stack and supported",
  },
  pilot: {
    label: "Pilot-ready",
    color: "#00A3FF",
    bg: "rgba(0,163,255,0.10)",
    description: "Works in controlled deployment / design partner",
  },
  poc: {
    label: "Configurable",
    color: "#F59E0B",
    bg: "rgba(245,158,11,0.10)",
    description: "Implemented and tested; activate with API keys or operator configuration in SaaS or local deployment",
  },
  roadmap: {
    label: "Roadmap",
    color: "#6B7280",
    bg: "rgba(107,114,128,0.10)",
    description: "Not available yet",
  },
};

// ─── Capability rows ───────────────────────────────────────────────────────
interface Row {
  capability: string;
  status: Status;
  notes?: string;
}

interface Section {
  title: string;
  rows: Row[];
}

const sections: Section[] = [
  {
    title: "URL & Context Trust Gate",
    rows: [
      {
        capability: "POST /evaluate end-to-end verdict",
        status: "pilot",
        notes: "Heuristic-only mode runs without model downloads. 15-min local PoC available.",
      },
      {
        capability: "Canonicalisation, querystring redaction, homoglyph / punycode normalisation",
        status: "pilot",
        notes: "canonicalize.py",
      },
      {
        capability: "SSRF-guarded safe crawler",
        status: "pilot",
        notes: "Isolated egress required in production. See scripts/poc/README.md.",
      },
      {
        capability: "Heuristic detection ensemble",
        status: "pilot",
        notes: "Prompt injection, credential harvest, brand impersonation, zero-width stripping.",
      },
      {
        capability: "ML-based detection (DeBERTa, BERT NER, toxic-bert, BART zero-shot)",
        status: "poc",
        notes: "Set TRANSFORMERS_OFFLINE=0 and allow model download on first start.",
      },
      {
        capability: "Playwright detonation sandbox (port 8015)",
        status: "pilot",
        notes: "Runs in isolated Docker detonation network with no internal route.",
      },
      {
        capability: "Google Safe Browsing v4 reputation feed",
        status: "poc",
        notes: "Set SAFE_BROWSING_API_KEY to activate.",
      },
      {
        capability: "Microsoft SmartScreen / Defender Threat Intelligence feed",
        status: "poc",
        notes: "Set SMARTSCREEN_TENANT_ID / CLIENT_ID / CLIENT_SECRET.",
      },
      {
        capability: "VirusTotal v3 URL reputation feed",
        status: "poc",
        notes: "Set VIRUSTOTAL_API_KEY. Results cached for VIRUSTOTAL_CACHE_TTL_S seconds.",
      },
      {
        capability: "Tenant allow / block lists",
        status: "pilot",
        notes: "Via GET /policies?tenant_id=…&scope=url-trust-gate on policy service.",
      },
      {
        capability: "Evidence writes to audit service",
        status: "pilot",
        notes: "POST /events. Best-effort, non-blocking.",
      },
      {
        capability: "/health, /ready, /metrics, /pki/public-key endpoints",
        status: "pilot",
        notes: "/ready probes detection, policy, and audit before declaring ready. Prometheus text/plain; version=0.0.4.",
      },
      {
        capability: "LangChain URL Trust Gate hook",
        status: "pilot",
        notes: "sdks/python/cyberarmor/frameworks/langchain_url_trust_gate.py",
      },
      {
        capability: "LlamaIndex URL Trust Gate hook",
        status: "pilot",
        notes: "sdks/python/cyberarmor/frameworks/llamaindex.py",
      },
      {
        capability: "RASP Python hook",
        status: "pilot",
        notes: "rasp/python/cyberarmor_rasp_url_trust_gate.py",
      },
      {
        capability: "Browser extension hook",
        status: "pilot",
        notes: "extensions/chromium-shared/url_trust_gate.js",
      },
      {
        capability: "Endpoint agent hook",
        status: "pilot",
        notes: "agents/endpoint-agent/monitors/url_trust_gate.py",
      },
      {
        capability: "Enforced mTLS between services",
        status: "poc",
        notes: "Set CYBERARMOR_ENFORCE_MTLS=true and provision certs.",
      },
      {
        capability: "Redis-backed reputation cache (multi-replica)",
        status: "poc",
        notes: "In-process cache works for single-node. Redis required for multi-replica.",
      },
      {
        capability: "OpenAI / Anthropic tool-use URL field wrappers",
        status: "pilot",
        notes: "sdks/python/cyberarmor/frameworks/openai_url_trust_gate.py, anthropic_url_trust_gate.py — intercepts tool-call response objects before agent fetch.",
      },
      {
        capability: "Kubernetes NetworkPolicy for detonation worker",
        status: "roadmap",
        notes: "Compose isolation is in place. K8s NetworkPolicy not yet written.",
      },
      {
        capability: "Feedback-driven detection fine-tuning",
        status: "roadmap",
        notes: "Evidence and /feedback endpoint exist. Offline trainer not yet built.",
      },
    ],
  },
  {
    title: "Control Plane, Detection & Policy",
    rows: [
      {
        capability: "Policy evaluation engine (OPA-backed, Python fallback)",
        status: "production",
        notes: "services/policy/",
      },
      {
        capability: "Tenant-scoped policy rules, artifacts, API-key flows",
        status: "production",
      },
      {
        capability: "Detection service — prompt injection, sensitive data, toxicity",
        status: "production",
        notes: "services/detection/",
      },
      {
        capability: "AI provider routing and resolution",
        status: "production",
        notes: "services/response/",
      },
      {
        capability: "Agent identity registration and delegation chains",
        status: "production",
      },
      {
        capability: "Audit logs, telemetry, incidents, evidence capture",
        status: "production",
        notes: "services/audit/",
      },
      {
        capability: "Compliance engine (14 frameworks)",
        status: "pilot",
        notes: "Working API. Expanding coverage with design partners.",
      },
      {
        capability: "Production SIEM / SOAR integration workflows",
        status: "pilot",
        notes: "Splunk, Sentinel, QRadar, Elastic, Google SecOps, Syslog/CEF.",
      },
    ],
  },
  {
    title: "Consumer Surfaces",
    rows: [
      {
        capability: "Endpoint agent (Linux / macOS / Windows)",
        status: "pilot",
        notes: "agents/endpoint-agent/",
      },
      {
        capability: "Chromium browser extension",
        status: "pilot",
        notes: "extensions/chromium-shared/",
      },
      {
        capability: "VS Code extension",
        status: "pilot",
        notes: "extensions/vscode/",
      },
      {
        capability: "Office add-in (Word, Excel, PowerPoint, OneNote, Outlook)",
        status: "pilot",
        notes: "extensions/office/",
      },
      {
        capability: "Python RASP",
        status: "pilot",
        notes: "rasp/python/",
      },
      {
        capability: "Go RASP",
        status: "pilot",
        notes: "rasp/go/",
      },
      {
        capability: "Java RASP",
        status: "pilot",
        notes: "rasp/java/",
      },
      {
        capability: "Node.js RASP",
        status: "pilot",
        notes: "rasp/nodejs/",
      },
      {
        capability: "LangChain SDK wrapper",
        status: "pilot",
        notes: "sdks/python/cyberarmor/frameworks/",
      },
      {
        capability: "LlamaIndex SDK wrapper",
        status: "pilot",
        notes: "sdks/python/cyberarmor/frameworks/",
      },
      {
        capability: "macOS / Windows kernel sensors",
        status: "pilot",
        notes: "kernel/ — verify scope before claiming in demos.",
      },
      {
        capability: "OpenAI tool-use URL wrapper",
        status: "pilot",
        notes: "sdks/python/cyberarmor/frameworks/openai_url_trust_gate.py",
      },
      {
        capability: "Anthropic tool-use URL wrapper",
        status: "pilot",
        notes: "sdks/python/cyberarmor/frameworks/anthropic_url_trust_gate.py",
      },
    ],
  },
];

// ─── Components ────────────────────────────────────────────────────────────
function StatusBadge({ status }: { status: Status }) {
  const meta = STATUS_META[status];
  return (
    <span style={{
      display: "inline-block",
      padding: "3px 10px",
      borderRadius: 6,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: "0.04em",
      color: meta.color,
      background: meta.bg,
      whiteSpace: "nowrap",
    }}>
      {meta.label}
    </span>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────
export default function StatusPage() {
  return (
    <div style={{ backgroundColor: "#000000" }}>
      {/* Hero */}
      <section style={{ paddingTop: "10rem", paddingBottom: "4rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.08) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />
        <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.25 }} />
        <div className="container-wide" style={{ position: "relative", textAlign: "center" }}>
          <div className="label-tag" style={{ marginBottom: 20, display: "inline-flex" }}>
            <Activity size={12} /> Capability Status
          </div>
          <h1 className="section-headline" style={{
            fontSize: "clamp(2rem, 4vw, 3rem)",
            marginBottom: 20, maxWidth: 700, margin: "0 auto 20px",
          }}>
            What works today.<br />
            <span className="gradient-text-blue">Honest about the boundary.</span>
          </h1>
          <p style={{
            fontSize: "1.05rem", color: "#8892A4", lineHeight: 1.75,
            maxWidth: 600, margin: "0 auto 16px",
          }}>
            This is the authoritative, buyer-facing statement of what is
            production-deployed, what is pilot-ready, what runs as a local PoC,
            and what is on the roadmap.
          </p>
          <p style={{ fontSize: 12, color: "#4A5568", marginBottom: 0 }}>
            Last updated: May 2026
          </p>
        </div>
      </section>

      {/* Legend */}
      <section style={{ padding: "2rem 0 3rem", backgroundColor: "#050508" }}>
        <div className="container-wide">
          <div style={{
            display: "flex", gap: 12, flexWrap: "wrap", justifyContent: "center",
          }}>
            {(Object.entries(STATUS_META) as [Status, typeof STATUS_META[Status]][]).map(([, meta]) => (
              <div key={meta.label} style={{
                display: "flex", alignItems: "flex-start", gap: 12,
                background: "#0F1117",
                border: "1px solid #1E2335",
                borderRadius: 10,
                padding: "14px 20px",
                minWidth: 220,
              }}>
                <div style={{
                  width: 10, height: 10, borderRadius: "50%",
                  backgroundColor: meta.color,
                  boxShadow: `0 0 8px ${meta.color}80`,
                  marginTop: 4, flexShrink: 0,
                }} />
                <div>
                  <p style={{ fontSize: 13, fontWeight: 700, color: meta.color, marginBottom: 4 }}>
                    {meta.label}
                  </p>
                  <p style={{ fontSize: 12, color: "#6B7280", lineHeight: 1.5 }}>
                    {meta.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Capability sections */}
      <section style={{ padding: "1rem 0 5rem", backgroundColor: "#000000" }}>
        <div className="container-wide" style={{ display: "flex", flexDirection: "column", gap: 48 }}>
          {sections.map((section) => (
            <div key={section.title}>
              <h2 style={{
                fontSize: "1.15rem", fontWeight: 700, color: "#ffffff",
                letterSpacing: "-0.02em", marginBottom: 20,
                paddingBottom: 16, borderBottom: "1px solid #1E2335",
              }}>
                {section.title}
              </h2>

              {/* Mobile-friendly stacked cards on small screens, table feel on wide */}
              <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                {/* Header row */}
                <div style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 160px 1fr",
                  gap: 16,
                  padding: "8px 20px",
                  background: "#050508",
                  borderRadius: "8px 8px 0 0",
                }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "#4A5568", letterSpacing: "0.08em", textTransform: "uppercase" }}>Capability</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "#4A5568", letterSpacing: "0.08em", textTransform: "uppercase" }}>Status</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "#4A5568", letterSpacing: "0.08em", textTransform: "uppercase" }}>Notes</span>
                </div>

                {section.rows.map((row, i) => (
                  <div key={row.capability} style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 160px 1fr",
                    gap: 16,
                    padding: "14px 20px",
                    background: i % 2 === 0 ? "#0A0C12" : "#070910",
                    borderRadius: i === section.rows.length - 1 ? "0 0 8px 8px" : 0,
                    alignItems: "start",
                  }}>
                    <span style={{ fontSize: 13, color: "#D1D5DB", lineHeight: 1.5, fontWeight: 500 }}>
                      {row.capability}
                    </span>
                    <div>
                      <StatusBadge status={row.status} />
                    </div>
                    <span style={{ fontSize: 12, color: "#6B7280", lineHeight: 1.6 }}>
                      {row.notes ?? ""}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Bottom note */}
      <section style={{ padding: "3rem 0 4rem", backgroundColor: "#050508" }}>
        <div className="container-wide" style={{ textAlign: "center", maxWidth: 640, margin: "0 auto" }}>
          <p style={{ fontSize: 13, color: "#4A5568", lineHeight: 1.75 }}>
            Status reflects the current codebase and hosted deployment as of May 2026.
            Pilot-ready capabilities are available to design partners through a
            controlled onboarding. Configurable capabilities are implemented and
            tested — activate them with the noted API keys or operator configuration
            steps in the hosted SaaS stack or your own deployment. Contact us to
            request access or discuss deployment scope.
          </p>
        </div>
      </section>

      <FinalCTA />
    </div>
  );
}
