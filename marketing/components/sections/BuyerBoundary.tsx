const items = [
  {
    label: "Pilot-ready",
    color: "#22C55E",
    text: "URL Trust Gate runs end-to-end. 15-minute local PoC available. Three optional reputation feeds configurable via environment variables.",
  },
  {
    label: "Deployable today",
    color: "#00A3FF",
    text: "The broader platform — control plane, policy, detection, response, secrets, and endpoint agent — is deployable for controlled pilots, internal deployments, and operator-led staging environments.",
  },
  {
    label: "Still maturing",
    color: "#F59E0B",
    text: "Some customer-facing SaaS workflows, self-service onboarding, and MFA enforcement are still being refined and are marked as such in the capability status table.",
  },
];

export default function BuyerBoundary() {
  return (
    <section style={{ padding: "5rem 0", backgroundColor: "#050508" }}>
      <div className="container-wide">
        <div style={{ maxWidth: 720, margin: "0 auto 48px", textAlign: "center" }}>
          <div className="label-tag" style={{ display: "inline-flex", marginBottom: 20 }}>
            Current Boundary
          </div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            Built for pilots.{" "}
            <span className="gradient-text-blue">Honest about the boundary.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1rem", lineHeight: 1.75 }}>
            Security buyers deserve to know exactly what is working end-to-end,
            what requires configuration, and what is on the roadmap. Here is where
            CyberArmor stands today.
          </p>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 820, margin: "0 auto" }}>
          {items.map(({ label, color, text }) => (
            <div key={label} style={{
              display: "flex", alignItems: "flex-start", gap: 20,
              background: "#0F1117",
              border: "1px solid #1E2335",
              borderRadius: 12,
              padding: "24px 28px",
            }}>
              <div style={{
                marginTop: 3,
                minWidth: 10, height: 10, borderRadius: "50%",
                backgroundColor: color,
                boxShadow: `0 0 8px ${color}80`,
                flexShrink: 0,
              }} />
              <div>
                <p style={{ fontSize: 13, fontWeight: 700, color, letterSpacing: "0.04em", textTransform: "uppercase", marginBottom: 8 }}>
                  {label}
                </p>
                <p style={{ fontSize: 15, color: "#8892A4", lineHeight: 1.7 }}>{text}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
