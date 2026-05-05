const diffs = [
  {
    number: "01",
    title: "Governance That Actually Enforces",
    body:
      "Most governance platforms produce policies and reports. CyberArmor AI connects governance to technical enforcement — so when a policy says 'no unauthorized AI,' the platform makes it so. Automatically, at runtime.",
    tag: "Governance → Enforcement",
  },
  {
    number: "02",
    title: "Evidence-Driven Trust — Not Assumptions",
    body:
      "Every AI action, policy decision, and security event is captured as structured, reviewable evidence. Security teams can trace exactly what happened, when, by whom, and under what policy — not reconstruct it hours later.",
    tag: "Decision Traceability",
  },
  {
    number: "03",
    title: "Cross-Layer Coverage by Design",
    body:
      "CyberArmor AI is built to operate across the full AI stack: models, agents, applications, APIs, identities, and data pipelines. Not a point solution for one layer. A unified trust system for the entire environment.",
    tag: "Unified Architecture",
  },
  {
    number: "04",
    title: "Built for Enterprise Operations, Not Lab Demos",
    body:
      "Enterprise deployments are messy. CyberArmor AI is designed for real-world complexity — hybrid environments, legacy integrations, multi-cloud workloads, and security teams that don't have unlimited capacity.",
    tag: "Enterprise-Ready",
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
            The AI security category is filling with point solutions and repurposed tools.
            CyberArmor AI is built from first principles for a threat surface those tools were never designed to address.
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
