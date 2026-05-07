import { Eye, Bot, ShieldAlert, Database, UserCheck, Activity, FileText, Route, Link2 } from "lucide-react";

const capabilities = [
  {
    icon: Eye,
    title: "Shadow AI Discovery",
    body: "Surface unreviewed AI tools, model calls, browser usage, endpoint activity, APIs, and service connections through supported signals.",
  },
  {
    icon: Bot,
    title: "AI Agent Trust & Control",
    body: "Register AI agents, scope allowed tools, track delegation context, and preserve evidence around autonomous workflows as trust controls mature.",
  },
  {
    icon: ShieldAlert,
    title: "Prompt Injection Defense",
    body: "Detect prompt injection, jailbreak attempts, adversarial normalization patterns, and suspicious prompt behavior targeting AI applications and workflows.",
  },
  {
    icon: Database,
    title: "Sensitive Data Redaction",
    body: "Inspect AI-bound data for credentials, secrets, PII, PCI, bank-routing data, healthcare identifiers, and non-public indicators so supported paths can redact, warn, log, or block by policy.",
  },
  {
    icon: UserCheck,
    title: "Identity-Aware Policy Engine",
    body: "Apply contextual controls to humans, services, workloads, and AI agents with tenant-scoped policy evaluation and decision records.",
  },
  {
    icon: Route,
    title: "Provider Routing & Control",
    body: "Resolve approved AI providers, route OpenAI-compatible and Anthropic-style requests, handle provider credentials, track cost signals, and emit audit events.",
  },
  {
    icon: FileText,
    title: "Action Graph & Evidence",
    body: "Capture trace IDs, policy decisions, actor context, delegation chains, data classifications, signatures, and chain hashes for reviewable AI activity records.",
  },
  {
    icon: Activity,
    title: "Runtime Response",
    body: "Connect detection and policy decisions to response actions such as block, redact, route, notify, limit, revoke, or hand off into SOC workflows.",
  },
  {
    icon: Link2,
    title: "URL & Context Trust Gate",
    body: "Pre-ingestion safety check for URLs and external content destined for humans, browsers, endpoint agents, RASP-instrumented apps, and AI agents. Detects phishing, hidden prompt injection, promptware, and IOCs in CSS-hidden and Unicode-encoded text before content ever reaches AI context.",
  },
];

export default function Capabilities() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#000000" }}>
      <div className="container-wide">
        <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 56px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>Core Capabilities</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            Built for the Realities of{" "}
            <span className="gradient-text-blue">Enterprise AI Risk.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
            Every capability maps to the integrated runtime loop: identify AI activity,
            inspect risk, decide policy, enforce the approved response, and prove what happened.
          </p>
        </div>

        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: 20,
        }}>
          {capabilities.map(({ icon: Icon, title, body }) => (
            <div key={title} className="card-base" style={{ padding: "28px 24px" }}>
              <div style={{
                width: 44, height: 44,
                background: "rgba(0,163,255,0.08)",
                border: "1px solid rgba(0,163,255,0.15)",
                borderRadius: 10,
                display: "flex", alignItems: "center", justifyContent: "center",
                marginBottom: 18,
              }}>
                <Icon size={20} style={{ color: "#00A3FF" }} />
              </div>
              <h3 style={{
                fontSize: "0.95rem", fontWeight: 700, color: "#ffffff",
                letterSpacing: "-0.02em", marginBottom: 10, lineHeight: 1.3,
              }}>
                {title}
              </h3>
              <p style={{ fontSize: 13.5, color: "#8892A4", lineHeight: 1.65 }}>
                {body}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
