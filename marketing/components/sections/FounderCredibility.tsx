import Link from "next/link";
import { ArrowRight, BadgeCheck, Code2, LockKeyhole, Network } from "lucide-react";

const signals = [
  { icon: LockKeyhole, label: "Security practitioner", body: "Built from application, data, cloud, endpoint, identity, and AI security operating problems." },
  { icon: Code2, label: "Hands-on builder", body: "Rooted in working controls, tests, demos, runbooks, and deployment paths instead of slideware." },
  { icon: Network, label: "Enterprise lens", body: "Designed for regulated environments, uneven ownership, legacy systems, and real security-team workflows." },
];

export default function FounderCredibility({ compact = false }: { compact?: boolean }) {
  const ctaHref = compact ? "/contact" : "/about#founder-story";
  const ctaLabel = compact ? "Talk to our team" : "Read the company story";

  return (
    <section id="founder-story" style={{ backgroundColor: compact ? "#050508" : "#000000", padding: compact ? "4rem 0" : "5rem 0" }}>
      <div className="container-wide">
        <div style={{
          background: "#0F1117",
          border: "1px solid #1E2335",
          borderRadius: 16,
          padding: "clamp(24px, 5vw, 44px)",
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 320px), 1fr))",
          gap: 32,
          alignItems: "start",
        }}>
          <div>
            <div className="label-tag" style={{ marginBottom: 16, display: "inline-flex" }}>
              <BadgeCheck size={12} /> Founder-Led
            </div>
            <h2 style={{ color: "#ffffff", fontSize: "clamp(1.8rem, 3.2vw, 2.6rem)", lineHeight: 1.12, fontWeight: 800, letterSpacing: "-0.04em", marginBottom: 18 }}>
              Built by a Security Practitioner for Teams That Need Control and Proof.
            </h2>
            <p style={{ color: "#8892A4", fontSize: 15.5, lineHeight: 1.75, marginBottom: 16 }}>
              CyberArmor.AI is founder-led by Patrick Kelly and built from the operating reality of
              enterprise security: policy has to become enforcement, sensitive data has to be protected
              before exposure, incidents need evidence, and AI adoption cannot wait for a perfect governance program.
            </p>
            <p style={{ color: "#A0AEC0", fontSize: 14.5, lineHeight: 1.7, marginBottom: 24 }}>
              The company is intentionally transparent about product maturity, design-partner work,
              and where the platform is strongest today. That posture is part of the product.
            </p>
            <Link href={ctaHref} className="btn-ghost" style={{ padding: "12px 20px", fontSize: 14 }}>
              {ctaLabel} <ArrowRight size={15} />
            </Link>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 210px), 1fr))", gap: 14 }}>
            {signals.map(({ icon: Icon, label, body }) => (
              <div key={label} style={{
                background: "#050508",
                border: "1px solid #1E2335",
                borderRadius: 12,
                padding: 20,
              }}>
                <Icon size={20} style={{ color: "#00A3FF", marginBottom: 14 }} />
                <h3 style={{ color: "#ffffff", fontSize: 14.5, fontWeight: 800, marginBottom: 9 }}>{label}</h3>
                <p style={{ color: "#8892A4", fontSize: 13.5, lineHeight: 1.65 }}>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
