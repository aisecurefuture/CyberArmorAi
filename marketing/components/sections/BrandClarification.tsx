import { ShieldCheck } from "lucide-react";

export default function BrandClarification() {
  return (
    <section style={{ backgroundColor: "#050508", padding: "3.5rem 0" }}>
      <div className="container-wide">
        <div style={{
          border: "1px solid #1E2335",
          background: "#0F1117",
          borderRadius: 14,
          padding: "clamp(22px, 4vw, 34px)",
          display: "flex",
          gap: 18,
          alignItems: "flex-start",
          flexWrap: "wrap",
        }}>
          <ShieldCheck size={24} style={{ color: "#00A3FF", flexShrink: 0, marginTop: 2 }} />
          <div>
            <h2 style={{ color: "#ffffff", fontSize: 18, fontWeight: 800, marginBottom: 10 }}>
              Official Brand and Domains
            </h2>
            <p style={{ color: "#A0AEC0", fontSize: 14.5, lineHeight: 1.75, maxWidth: 920 }}>
              CyberArmor.AI is the public brand and product site operated by CyberArmor AI, Inc.
              Official CyberArmor.AI web properties are served from <strong style={{ color: "#ffffff" }}>cyberarmor.ai</strong> and
              its subdomains, including <strong style={{ color: "#ffffff" }}>app.cyberarmor.ai</strong>,
              <strong style={{ color: "#ffffff" }}> admin.cyberarmor.ai</strong>,
              <strong style={{ color: "#ffffff" }}> docs.cyberarmor.ai</strong>, and
              <strong style={{ color: "#ffffff" }}> support.cyberarmor.ai</strong>. CyberArmor.AI is not affiliated
              with similarly named third-party domains, services, or social profiles unless they are explicitly
              linked from one of those official properties.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
