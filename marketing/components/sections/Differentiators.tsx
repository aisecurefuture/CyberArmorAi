const diffs = [
  {
    number: "01",
    title: "Governance That Becomes Runtime Control",
    body:
      "Most governance products stop at visibility, questionnaires, or policy documentation. CyberArmor.AI ties governance to runtime decisioning so policy can result in monitor, warn, block, route, limit, or redact actions where supported.",
    tag: "Policy to Action",
  },
  {
    number: "02",
    title: "Protection-Backed Evidence",
    body:
      "Evidence is valuable because it is bound to control. CyberArmor.AI records who or what acted, which policy applied, what response ran, what data classification was involved, and why the decision happened.",
    tag: "Control + Proof",
  },
  {
    number: "03",
    title: "Cross-Layer Causality by Design",
    body:
      "CyberArmor.AI brings together detection, policy, AI routing, endpoint signals, browser and IDE workflows, agent identity, secrets, response, audit, and compliance evidence so teams can reconstruct the chain.",
    tag: "Action Graph",
  },
  {
    number: "04",
    title: "Honest Platform Boundaries",
    body:
      "Enterprise buyers trust specific claims. CyberArmor.AI separates pilot-ready capabilities from roadmap expansion, because a security runtime has to be credible before it can be trusted.",
    tag: "Buyer-Safe Roadmap",
  },
  {
    number: "05",
    title: "Pre-Ingestion AI Safe Browsing",
    body:
      "Existing URL filters answer 'is this site safe for a human?' CyberArmor.AI also answers 'is this content safe for an AI agent to ingest?' The URL Trust Gate evaluates external destinations for promptware, hidden prompt injection, phishing, IOCs, and credential harvesting before content ever reaches AI context — with policy-based enforcement and evidence written to audit.",
    tag: "URL Trust Gate",
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
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>Why CyberArmor.AI</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            This Is What{" "}
            <span className="gradient-text-blue">Different Looks Like.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
            The AI security category is getting crowded with point products and
            retrofitted tooling. CyberArmor.AI is aimed at the harder problem:
            making AI activity controllable, attributable, and provable across
            the places where enterprise AI actually runs.
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
