import { CheckCircle2, Clock3, FileCheck2, ShieldCheck } from "lucide-react";

const availableToday = [
  "AI request monitoring and policy decision logging",
  "Prompt-risk, credential leak, and sensitive-data inspection",
  "Redaction-mode policy decisions for supported SDK and provider paths",
  "Endpoint-assisted AI tool and connection discovery",
  "Tenant-scoped policy builder, artifacts, and API-key flows",
  "Bootstrap onboarding for agents, SDKs, and extensions",
  "Audit logs, telemetry, incidents, and evidence capture",
];

const pilotPhase = [
  "Expanded shadow AI inventory across SaaS and identity sources",
  "Agent trust verification and delegation-chain workflows",
  "Proof Vault evidence packaging and external audit exports",
  "Production SIEM/SOAR integration workflows",
  "Advanced runtime enforcement across more enterprise control points",
  "Industry-specific compliance and reporting packs",
];

const proofPoints = [
  { icon: ShieldCheck, label: "Control plane, policy engine, runtime, and AI router services exist in the platform." },
  { icon: FileCheck2, label: "Audit, compliance, and evidence paths are part of the operating model, not just marketing copy." },
  { icon: CheckCircle2, label: "Endpoint agents, browser/IDE extensions, SDKs, and RASP surfaces support pilot validation." },
];

function ListColumn({
  title,
  eyebrow,
  items,
  tone,
}: {
  title: string;
  eyebrow: string;
  items: string[];
  tone: "green" | "amber";
}) {
  const color = tone === "green" ? "#22C55E" : "#F59E0B";
  const Icon = tone === "green" ? CheckCircle2 : Clock3;

  return (
    <div style={{
      background: "#0F1117",
      border: `1px solid ${tone === "green" ? "rgba(34,197,94,0.24)" : "rgba(245,158,11,0.26)"}`,
      borderRadius: 16,
      padding: 28,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
        <Icon size={18} style={{ color, flexShrink: 0 }} />
        <span style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: "0.08em", textTransform: "uppercase" }}>
          {eyebrow}
        </span>
      </div>
      <h3 style={{ fontSize: "1.2rem", color: "#ffffff", fontWeight: 700, letterSpacing: "-0.02em", marginBottom: 18 }}>
        {title}
      </h3>
      <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 12 }}>
        {items.map((item) => (
          <li key={item} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: color, marginTop: 8, flexShrink: 0 }} />
            <span style={{ color: "#A0AEC0", fontSize: 14, lineHeight: 1.6 }}>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function ProductAvailability() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#000000" }}>
      <div className="container-wide">
        <div style={{ maxWidth: 760, marginBottom: 48 }}>
          <div className="label-tag" style={{ marginBottom: 16 }}>Product Availability</div>
          <h2 className="section-headline" style={{ marginBottom: 18 }}>
            A Clear Boundary Between{" "}
            <span className="gradient-text-blue">What Is Deployable</span> and What Is Being Expanded.
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.75 }}>
            CyberArmor AI is being built with security-led design partners and controlled pilot deployments.
            The platform already includes working control, policy, detection, audit, endpoint, and onboarding
            paths. Some broader enterprise workflows are intentionally marked as pilot-stage while they mature.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 20, marginBottom: 24 }}>
          <ListColumn title="Available Today" eyebrow="Pilot-ready capabilities" items={availableToday} tone="green" />
          <ListColumn title="In Pilot / Design Partner Phase" eyebrow="Expanding with customers" items={pilotPhase} tone="amber" />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14 }}>
          {proofPoints.map(({ icon: Icon, label }) => (
            <div key={label} style={{
              display: "flex",
              gap: 12,
              alignItems: "flex-start",
              background: "#050508",
              border: "1px solid #1E2335",
              borderRadius: 12,
              padding: 18,
            }}>
              <Icon size={17} style={{ color: "#00A3FF", flexShrink: 0, marginTop: 2 }} />
              <p style={{ color: "#8892A4", fontSize: 13.5, lineHeight: 1.6 }}>{label}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
