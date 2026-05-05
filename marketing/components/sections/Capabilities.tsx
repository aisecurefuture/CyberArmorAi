import { Eye, Bot, ShieldAlert, Database, UserCheck, Activity, FileText, Zap } from "lucide-react";

const capabilities = [
  {
    icon: Eye,
    title: "Shadow AI Discovery",
    body: "Automatically surface unauthorized AI tools, models, and API connections across every user, team, and workload in your organization.",
  },
  {
    icon: Bot,
    title: "AI Agent Trust & Control",
    body: "Define identity-aware trust policies for AI agents. Verify, bound, and monitor autonomous AI systems before they act in production environments.",
  },
  {
    icon: ShieldAlert,
    title: "Prompt Injection Defense",
    body: "Detect and block prompt injection, jailbreak attempts, and adversarial inputs targeting AI applications, chatbots, and LLM-powered workflows.",
  },
  {
    icon: Database,
    title: "Sensitive Data Protection",
    body: "Prevent unauthorized data exposure across AI pipelines. Identify when PII, IP, or regulated data is being processed by ungoverned AI systems.",
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
    body: "Capture a full, tamper-resistant audit trail of AI actions, policy decisions, and security events for compliance, forensics, and accountability.",
  },
  {
    icon: Zap,
    title: "Incident Response for AI",
    body: "Accelerate investigation and response to AI-related security incidents with structured evidence, context-rich telemetry, and automated containment.",
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
            Every capability is designed for the actual threat surface of modern enterprise AI —
            not hypothetical risks, but the attacks and exposures already happening inside your organization.
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
