import { AlertTriangle, Ghost, Network } from "lucide-react";

const problems = [
  {
    icon: Ghost,
    title: "AI Activity Is Spreading Across Uncontrolled Paths",
    body:
      "Employees, developers, contractors, apps, and vendors are using AI tools, APIs, assistants, and providers outside formal review paths. Security teams need more than a list of tools; they need control points that can act when AI activity happens.",
  },
  {
    icon: AlertTriangle,
    title: "Sensitive Data Can Leak Before Anyone Sees the Alert",
    body:
      "Credentials, API keys, payment data, bank details, PII, and non-public information can be pasted into generative AI before a traditional ticket, alert, or review workflow ever fires. Detection has to connect to redaction, blocking, routing, and evidence.",
  },
  {
    icon: Network,
    title: "Governance Without Enforcement Is Just a Document",
    body:
      "Most AI governance efforts begin as policy documents, committee decisions, and vendor questionnaires. When those controls are not tied to runtime enforcement and decision-level evidence, violations become exceptions without response, proof, or accountability.",
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
            Security teams are being asked to govern AI systems, agents, providers,
            and workflows that move faster than traditional review cycles. The
            hard part is not only seeing AI risk. It is controlling it and proving
            the control worked.
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
