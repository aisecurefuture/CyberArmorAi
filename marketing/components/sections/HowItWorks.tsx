const steps = [
  {
    step: "01",
    phase: "Identify",
    title: "Attribute the AI Action",
    points: [
      "Connect AI activity to tenant, actor, app, agent, provider, model, and request context where available",
      "Surface unreviewed AI tools, model calls, browser activity, endpoints, and integration signals",
      "Create the foundation for policy decisions that are attributable instead of anonymous",
    ],
    color: "#00A3FF",
  },
  {
    step: "02",
    phase: "Inspect",
    title: "Score Risk and Resolve Policy",
    points: [
      "Evaluate prompt injection, sensitive data, credential leakage, provider posture, and tenant policy",
      "Use policy logic to decide whether the action should be monitored, warned, blocked, routed, limited, or redacted",
      "Preserve the reason code and policy context so the decision can be reviewed later",
    ],
    color: "#A855F7",
  },
  {
    step: "03",
    phase: "Control",
    title: "Enforce the Approved Response",
    points: [
      "Block high-risk actions, redact supported sensitive values, route to approved providers, or warn users depending on policy",
      "Apply controls in supported browser, endpoint, IDE, Office, SDK, RASP, provider, and runtime paths",
      "Connect response actions to incidents, telemetry, audit events, and downstream SOC workflows",
    ],
    color: "#22C55E",
  },
  {
    step: "04",
    phase: "Prove",
    title: "Generate Evidence That Explains the Control",
    points: [
      "Capture structured records of actor, request, model/provider context, data classification, policy, decision, and response",
      "Give SOC, AppSec, legal, compliance, and executive teams reviewable AI activity evidence",
      "Build organizational trust in AI adoption with controls that can be demonstrated, not merely asserted",
    ],
    color: "#F59E0B",
  },
];

export default function HowItWorks() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#050508", position: "relative" }}>
      <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.3, pointerEvents: "none" }} />

      <div className="container-wide" style={{ position: "relative" }}>
        <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 64px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>How It Works</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            From AI Activity to{" "}
            <span className="gradient-text-blue">Controlled Evidence.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
            CyberArmor.AI follows a practical runtime model: attribute the AI action,
            inspect risk, enforce the policy, and preserve evidence. That is the loop
            security teams need to make AI governance operational.
          </p>
        </div>

        <div style={{ position: "relative" }}>
          {/* Vertical connector line */}
          <div style={{
            position: "absolute",
            left: "50%",
            top: 0, bottom: 0,
            width: 1,
            background: "linear-gradient(180deg, transparent, #1E2335 10%, #1E2335 90%, transparent)",
            transform: "translateX(-50%)",
          }} className="hidden lg:block" />

          <div style={{ display: "flex", flexDirection: "column", gap: 48 }}>
            {steps.map(({ step, phase, title, points, color }, i) => (
              <div
                key={step}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 80px 1fr",
                  gap: 32,
                  alignItems: "center",
                }}
                className="timeline-step-grid"
              >
                {/* Left content (even indices) */}
                <div className="timeline-card" style={{
                  gridColumn: i % 2 === 0 ? 1 : 3,
                  background: "#0F1117",
                  border: "1px solid #1E2335",
                  borderRadius: 16,
                  padding: "36px",
                  position: "relative",
                  overflow: "hidden",
                }}>
                  <div style={{
                    position: "absolute", top: 0, left: 0, right: 0, height: 2,
                    background: `linear-gradient(90deg, transparent, ${color}60, transparent)`,
                  }} />
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                    <span className="label-tag" style={{ fontSize: 10, background: `${color}15`, borderColor: `${color}30`, color }}>
                      {phase}
                    </span>
                  </div>
                  <h3 style={{
                    fontSize: "1.15rem", fontWeight: 700, color: "#ffffff",
                    letterSpacing: "-0.02em", marginBottom: 20, lineHeight: 1.3,
                  }}>{title}</h3>
                  <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 12 }}>
                    {points.map((pt) => (
                      <li key={pt} style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                        <div style={{
                          width: 6, height: 6, borderRadius: "50%", backgroundColor: color,
                          marginTop: 7, flexShrink: 0,
                          boxShadow: `0 0 6px ${color}80`,
                        }} />
                        <span style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.6 }}>{pt}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Center step indicator */}
                <div className="timeline-indicator" style={{
                  gridColumn: 2,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}>
                  <div style={{
                    width: 52, height: 52,
                    borderRadius: "50%",
                    background: `${color}15`,
                    border: `2px solid ${color}40`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 14, fontWeight: 800, color,
                  }}>
                    {step}
                  </div>
                </div>

                {/* Empty right column for alternating layout */}
                {i % 2 === 0 && <div className="timeline-spacer" style={{ gridColumn: 3 }} />}
                {i % 2 !== 0 && <div className="timeline-spacer" style={{ gridColumn: 1 }} />}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
