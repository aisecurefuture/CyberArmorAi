const stats = [
  { value: "78%", label: "of enterprises have deployed AI systems with no formal security review" },
  { value: "3.2×", label: "increase in AI-related security incidents reported in the past 18 months" },
  { value: "91%", label: "of security leaders say AI governance is a top priority but lack technical enforcement" },
  { value: "$4.8M", label: "average cost of an enterprise data breach involving AI or ML systems" },
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
              The Window for Establishing{" "}
              <span className="gradient-text-blue">AI Security Leadership</span> Is Now.
            </h2>
            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7, marginBottom: 20 }}>
              Enterprise AI adoption is accelerating faster than any technology shift in a generation.
              Generative AI, autonomous agents, and AI-enabled workflows are being deployed across
              every business function — without the security infrastructure to match.
            </p>
            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7, marginBottom: 20 }}>
              Regulators are moving. Boards are asking. Attackers are already exploiting.
              The enterprises that establish a governed, defensible AI security posture today will
              have a structural advantage over those that wait.
            </p>
            <p style={{ color: "#ffffff", fontSize: "1.05rem", lineHeight: 1.7, fontWeight: 500 }}>
              CyberArmor AI exists to give security-minded enterprises that advantage — with a
              platform built for this moment.
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            {stats.map(({ value, label }) => (
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
                  fontSize: "2.2rem",
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
