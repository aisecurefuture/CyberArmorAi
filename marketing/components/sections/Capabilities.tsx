import { Eye, Bot, ShieldAlert, Database, UserCheck, Activity, FileText, Zap } from "lucide-react";

const capabilities = [
  {
    icon: Eye,
    title: "Shadow AI Discovery",
    body: "Surface unauthorized AI tools, model calls, and AI service connections through endpoint, browser, API, and integration signals.",
  },
  {
    icon: Bot,
    title: "AI Agent Trust & Control",
    body: "Define identity-aware policies for AI agents, verify scope, and monitor autonomous workflows as agent trust controls mature.",
  },
  {
    icon: ShieldAlert,
    title: "Prompt Injection Defense",
    body: "Detect prompt injection, jailbreak attempts, and adversarial inputs targeting AI applications, chatbots, and LLM-powered workflows.",
  },
  {
    icon: Database,
    title: "Sensitive Data Protection",
    body: "Inspect AI-bound data for PII, IP, credentials, and regulated content so risky requests can be flagged, redacted in supported paths, logged, or blocked by policy.",
  },
  {
    icon: UserCheck,
    title: "Identity-Aware Policy Engine",
    body: "Apply contextual access controls to humans, services, workloads, and AI agents — with policies that adapt to risk posture in real time.",
  },
  {
    icon: Activity,
    title: "Runtime Monitoring & Enforcement",
    body: "Observe and enforce security policy at the moment of execution — not hours later in a SIEM. Block, alert, or limit AI actions as they happen.",
  },
  {
    icon: FileText,
    title: "Evidence & Decision Traceability",
    body: "Capture structured records of AI actions, policy decisions, and security events for compliance review, investigation, and accountability.",
  },
  {
    icon: Zap,
    title: "Incident Response for AI",
    body: "Accelerate investigation of AI-related incidents with structured evidence, context-rich telemetry, and response hooks.",
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
            Every capability maps to a concrete AI security workflow: discover usage,
            decide policy, inspect runtime activity, preserve evidence, and support response.
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
