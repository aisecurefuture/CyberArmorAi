const diffs = [
  {
    number: "01",
    title: "Governance That Actually Enforces",
    body:
      "Most governance products stop at visibility, questionnaires, or policy documentation. CyberArmor AI ties governance to runtime decisioning so controls can be enforced when AI use actually happens.",
    tag: "Governance → Enforcement",
  },
  {
    number: "02",
    title: "Evidence-Driven Trust — Not Assumptions",
    body:
      "AI actions, policy decisions, and control outcomes are captured as structured evidence so security, legal, and compliance teams can review what happened without relying on memory or screenshots.",
    tag: "Decision Traceability",
  },
  {
    number: "03",
    title: "Cross-Layer Coverage by Design",
    body:
      "CyberArmor AI brings together a control plane, policy engine, AI router, endpoint signals, agent identity, audit, compliance, and integration paths so teams can validate coverage layer by layer.",
    tag: "Layered Architecture",
  },
  {
    number: "04",
    title: "Built for Enterprise Operations, Not Lab Demos",
    body:
      "Enterprise AI programs inherit hybrid environments, uneven ownership, legacy systems, and limited security capacity. CyberArmor AI is shaped around that operating reality through controlled pilots and design-partner feedback.",
    tag: "Operational Fit",
  },
];

export default function Differentiators() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#050508", position: "relative" }}>
      <div style={{
        position: "absolute",
        bottom: 0, left: 0, right: 0, height: 400,
        background: "radial-gradient(ellipse 60% 50% at 50% 100%, rgba(0,163,255,0.04) 0%, transparent 70%)",
        pointerEvents: "none",
      }} />

      <div className="container-wide" style={{ position: "relative" }}>
        <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 64px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>Why CyberArmor AI</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            This Is What{" "}
            <span className="gradient-text-blue">Different Looks Like.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
            The AI security category is getting crowded with point products and
            retrofitted tooling. CyberArmor AI is aimed at the harder problem:
            turning AI governance into operating controls that stand up in real
            enterprise environments.
          </p>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {diffs.map(({ number, title, body, tag }, i) => (
            <div
              key={number}
              className="card-base"
              style={{
                padding: "36px 40px",
                display: "grid",
                gridTemplateColumns: "72px 1fr auto",
                alignItems: "start",
                gap: "32px",
              }}
            >
              {/* Number */}
              <div style={{
                fontSize: "2.5rem",
                fontWeight: 800,
                color: "#1E2335",
                letterSpacing: "-0.04em",
                lineHeight: 1,
                paddingTop: 4,
              }}>
                {number}
              </div>

              {/* Content */}
              <div>
                <h3 style={{
                  fontSize: "1.15rem", fontWeight: 700, color: "#ffffff",
                  letterSpacing: "-0.02em", marginBottom: 12, lineHeight: 1.3,
                }}>
                  {title}
                </h3>
                <p style={{ fontSize: 15, color: "#8892A4", lineHeight: 1.7 }}>
                  {body}
                </p>
              </div>

              {/* Tag */}
              <div style={{ paddingTop: 4, flexShrink: 0 }}>
                <span className="label-tag" style={{ whiteSpace: "nowrap", fontSize: 10 }}>{tag}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
