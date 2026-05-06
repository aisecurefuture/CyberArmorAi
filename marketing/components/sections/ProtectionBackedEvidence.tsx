import { Bot, FileSearch, Fingerprint, Route, ShieldCheck } from "lucide-react";

const loop = [
  {
    icon: Fingerprint,
    step: "01",
    title: "Identify",
    body: "Attribute the AI action to a tenant, user, app, workload, agent, provider, and model where the deployment path provides that context.",
  },
  {
    icon: ShieldCheck,
    step: "02",
    title: "Inspect",
    body: "Evaluate prompt risk, sensitive data, credential leakage, provider posture, and policy-relevant context before the action is trusted.",
  },
  {
    icon: Route,
    step: "03",
    title: "Control",
    body: "Apply the approved response: monitor, warn, block, route, limit, or redact in supported browser, endpoint, SDK, extension, and RASP paths.",
  },
  {
    icon: Bot,
    step: "04",
    title: "Connect",
    body: "Preserve the relationship between actors, agents, tool use, policy decisions, response actions, and downstream evidence records.",
  },
  {
    icon: FileSearch,
    step: "05",
    title: "Prove",
    body: "Produce reviewable decision-level evidence for SOC teams, AppSec, legal, compliance, audit, and executive stakeholders.",
  },
];

export default function ProtectionBackedEvidence() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#000000" }}>
      <div className="container-wide">
        <div style={{ maxWidth: 820, margin: "0 auto 56px", textAlign: "center" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>
            Protection-Backed Evidence
          </div>
          <h2 className="section-headline" style={{ marginBottom: 18 }}>
            Evidence Is Strongest When It Is{" "}
            <span className="gradient-text-blue">Attached to Control.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.75 }}>
            CyberArmor.AI is built around one operating loop: identify the AI action,
            inspect the risk, enforce the right control, and preserve evidence that
            explains what happened. Logs alone are not enough. Controls without proof
            are hard to defend. The platform is designed to bind both together.
          </p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
            gap: 14,
            marginBottom: 28,
          }}
        >
          {loop.map(({ icon: Icon, step, title, body }) => (
            <div
              key={title}
              style={{
                background: "#0F1117",
                border: "1px solid #1E2335",
                borderRadius: 14,
                padding: "22px 20px",
                minHeight: 220,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
                <div
                  style={{
                    width: 40,
                    height: 40,
                    borderRadius: 10,
                    background: "rgba(0,163,255,0.08)",
                    border: "1px solid rgba(0,163,255,0.18)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <Icon size={18} style={{ color: "#00A3FF" }} />
                </div>
                <span style={{ fontSize: 12, fontWeight: 800, color: "#1E2335", letterSpacing: "0.08em" }}>{step}</span>
              </div>
              <h3 style={{ color: "#ffffff", fontSize: "1rem", fontWeight: 750, marginBottom: 10, letterSpacing: "-0.02em" }}>
                {title}
              </h3>
              <p style={{ color: "#8892A4", fontSize: 13.5, lineHeight: 1.65 }}>{body}</p>
            </div>
          ))}
        </div>

        <div
          style={{
            background: "#050508",
            border: "1px solid #1E2335",
            borderRadius: 16,
            padding: "clamp(22px, 4vw, 34px)",
            display: "grid",
            gridTemplateColumns: "minmax(0, 1.05fr) minmax(0, 1fr)",
            gap: 28,
            alignItems: "start",
          }}
          className="protection-proof-grid"
        >
          <div>
            <p style={{ color: "#00A3FF", fontSize: 12, fontWeight: 800, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 14 }}>
              Pre-Breach Data Protection Example
            </p>
            <h3 style={{ color: "#ffffff", fontSize: "1.25rem", fontWeight: 800, letterSpacing: "-0.03em", lineHeight: 1.3, marginBottom: 14 }}>
              Redact the secret before it becomes an incident.
            </h3>
            <p style={{ color: "#8892A4", fontSize: 14.5, lineHeight: 1.75 }}>
              Credential leakage into generative AI is a practical enterprise risk.
              CyberArmor.AI redaction modes are designed to turn policy into an
              optional response action: remove supported secrets, PII, PCI, NACHA,
              NPI, or non-public indicators while preserving evidence about the
              control that ran.
            </p>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ background: "#0F1117", border: "1px solid #1E2335", borderRadius: 10, padding: 14 }}>
              <p style={{ color: "#EF4444", fontSize: 11, fontWeight: 800, letterSpacing: "0.08em", marginBottom: 8 }}>BEFORE</p>
              <code style={{ color: "#A0AEC0", fontSize: 12.5, lineHeight: 1.65, whiteSpace: "normal", overflowWrap: "anywhere" }}>
                Summarize this log: OPENAI_API_KEY=sk-... and password=hunter22
              </code>
            </div>
            <div style={{ background: "#0F1117", border: "1px solid rgba(34,197,94,0.24)", borderRadius: 10, padding: 14 }}>
              <p style={{ color: "#22C55E", fontSize: 11, fontWeight: 800, letterSpacing: "0.08em", marginBottom: 8 }}>AFTER</p>
              <code style={{ color: "#A0AEC0", fontSize: 12.5, lineHeight: 1.65, whiteSpace: "normal", overflowWrap: "anywhere" }}>
                Summarize this log: OPENAI_API_KEY=[REDACTED-OPENAI-KEY] and [REDACTED-PASSWORD]
              </code>
            </div>
            <div style={{ background: "rgba(0,163,255,0.06)", border: "1px solid rgba(0,163,255,0.18)", borderRadius: 10, padding: 14 }}>
              <p style={{ color: "#60C8FF", fontSize: 12.5, lineHeight: 1.65, margin: 0 }}>
                Evidence: decision=ALLOW_WITH_REDACTION, policy=redact-secrets,
                findings=OPENAI_API_KEY/PASSWORD, raw secret preview suppressed.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
