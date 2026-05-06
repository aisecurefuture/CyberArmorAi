const signals = [
  {
    value: "97%",
    label: "IBM reported that organizations with an AI-related security incident often lacked proper AI access controls.",
  },
  {
    value: "OWASP",
    label: "Prompt injection, sensitive information disclosure, supply chain risk, and excessive agency are recognized GenAI security risks.",
  },
  {
    value: "NIST",
    label: "AI risk management is moving into governed, measurable, and managed operating practice.",
  },
  {
    value: "EU AI Act",
    label: "High-risk AI obligations emphasize logging, documentation, transparency, oversight, robustness, and cybersecurity.",
  },
];

const sources = [
  { label: "IBM Cost of a Data Breach 2025", href: "https://www.ibm.com/reports/data-breach" },
  { label: "OWASP GenAI Security Project", href: "https://owasp.org/www-project-top-10-for-large-language-model-applications" },
  { label: "NIST AI RMF", href: "https://www.nist.gov/itl/ai-risk-management-framework" },
  { label: "ISO/IEC 42001", href: "https://www.iso.org/standard/42001" },
  { label: "EU AI Act", href: "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai" },
];

export default function WhyNow() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#050508", position: "relative", overflow: "hidden" }}>
      {/* Top accent */}
      <div className="glow-line" />

      <div style={{
        position: "absolute", top: "50%", right: -200,
        width: 500, height: 500,
        background: "radial-gradient(circle, rgba(0,163,255,0.04) 0%, transparent 70%)",
        transform: "translateY(-50%)",
        pointerEvents: "none",
      }} />

      <div className="container-wide" style={{ position: "relative" }}>
        <div className="whynow-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 80, alignItems: "center" }}>

          <div>
            <div className="label-tag" style={{ marginBottom: 20 }}>Why Now</div>
            <h2 className="section-headline" style={{ marginBottom: 24 }}>
              Enterprise AI Has Outpaced{" "}
              <span className="gradient-text-blue">The Control Stack</span> Built for It.
            </h2>
            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7, marginBottom: 20 }}>
              IBM&apos;s 2025 Cost of a Data Breach research puts hard numbers behind the AI
              oversight gap: among organizations reporting an AI-related security incident,
              97% lacked proper AI access controls and 63% lacked AI governance policies.
            </p>
            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7, marginBottom: 20 }}>
              OWASP&apos;s GenAI security work identifies risks like prompt injection, sensitive
              information disclosure, supply chain vulnerabilities, excessive agency, and model
              theft. NIST AI RMF and ISO/IEC 42001 give enterprises a governance language; the
              EU AI Act adds pressure for documentation, traceability, oversight, and cybersecurity.
            </p>
            <p style={{ color: "#ffffff", fontSize: "1.05rem", lineHeight: 1.7, fontWeight: 500 }}>
              Governance alone is not enough. Enterprises need visibility, runtime controls,
              and evidence they can show to security, legal, audit, and executive stakeholders.
            </p>

            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 28 }}>
              {sources.map((source) => (
                <a
                  key={source.label}
                  href={source.href}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    color: "#60C8FF",
                    border: "1px solid #1E2335",
                    background: "#0F1117",
                    borderRadius: 8,
                    padding: "8px 10px",
                    fontSize: 12,
                    fontWeight: 600,
                    textDecoration: "none",
                  }}
                >
                  {source.label}
                </a>
              ))}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            {signals.map(({ value, label }) => (
              <div key={value} style={{
                background: "#0F1117",
                border: "1px solid #1E2335",
                borderRadius: 14,
                padding: "28px 24px",
                position: "relative",
                overflow: "hidden",
              }}>
                <div style={{
                  position: "absolute", top: 0, left: 0, right: 0, height: 2,
                  background: "linear-gradient(90deg, transparent, rgba(0,163,255,0.3), transparent)",
                }} />
                <p style={{
                  fontSize: "clamp(1.6rem, 4vw, 2.2rem)",
                  fontWeight: 800,
                  letterSpacing: "-0.04em",
                  marginBottom: 10,
                  background: "linear-gradient(135deg, #00A3FF, #60C8FF)",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  backgroundClip: "text",
                }}>
                  {value}
                </p>
                <p style={{ fontSize: 13.5, color: "#8892A4", lineHeight: 1.6 }}>{label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="glow-line" style={{ marginTop: "5rem" }} />
    </section>
  );
}
