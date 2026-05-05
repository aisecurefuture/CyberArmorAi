import { AlertTriangle, Ghost, Network } from "lucide-react";

const problems = [
  {
    icon: Ghost,
    title: "Shadow AI Is Already Inside Your Perimeter",
    body:
      "Employees, developers, contractors, and vendors are already using AI tools, APIs, and assistants outside formal review paths. You cannot govern what you cannot inventory, and most organizations still do not have a reliable AI asset picture.",
  },
  {
    icon: Network,
    title: "AI Agents Operate Without Boundaries",
    body:
      "Autonomous agents can take actions, access systems, and trigger workflows across multiple trust boundaries. Without identity-aware controls and runtime guardrails, teams struggle to verify, constrain, or reconstruct what those agents actually did.",
  },
  {
    icon: AlertTriangle,
    title: "Governance Without Enforcement Is Just a Document",
    body:
      "Most AI governance efforts begin as policy documents, committee decisions, and vendor questionnaires. When those controls are not tied to technical enforcement, violations become exceptions without response, evidence, or accountability.",
  },
];

export default function ProblemStatement() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#000000" }}>
      <div className="container-wide">
        {/* Heading */}
        <div style={{ textAlign: "center", maxWidth: 720, margin: "0 auto 56px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>The Problem</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            Enterprise AI Is Moving Faster Than<br />
            <span className="gradient-text-blue">Security Can Follow.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
            Security teams are being asked to govern AI systems, agents, and
            workflows that move faster than traditional review cycles and cross
            the same trust boundaries the enterprise spent years hardening.
          </p>
        </div>

        {/* Problem cards */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: 24,
        }}>
          {problems.map(({ icon: Icon, title, body }) => (
            <div key={title} className="card-base" style={{ padding: "32px 28px", position: "relative", overflow: "hidden" }}>
              {/* Top accent */}
              <div style={{
                position: "absolute", top: 0, left: 0, right: 0, height: 2,
                background: "linear-gradient(90deg, transparent, rgba(239,68,68,0.4), transparent)",
              }} />

              <div style={{
                width: 48, height: 48,
                background: "rgba(239,68,68,0.08)",
                border: "1px solid rgba(239,68,68,0.2)",
                borderRadius: 12,
                display: "flex", alignItems: "center", justifyContent: "center",
                marginBottom: 20,
              }}>
                <Icon size={22} style={{ color: "#EF4444" }} />
              </div>

              <h3 style={{
                fontSize: "1.05rem", fontWeight: 700, color: "#ffffff",
                letterSpacing: "-0.02em", lineHeight: 1.3, marginBottom: 12,
              }}>
                {title}
              </h3>
              <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7 }}>
                {body}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
