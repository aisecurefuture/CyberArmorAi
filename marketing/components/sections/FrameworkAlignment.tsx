import { BookOpenCheck, ClipboardCheck, FileCheck2, Globe2, ShieldCheck } from "lucide-react";

const frameworks = [
  {
    icon: ShieldCheck,
    name: "OWASP GenAI Security",
    focus: "Prompt injection, sensitive information disclosure, excessive agency, supply chain risk, and model theft.",
    href: "https://owasp.org/www-project-top-10-for-large-language-model-applications",
  },
  {
    icon: ClipboardCheck,
    name: "NIST AI RMF",
    focus: "Govern, map, measure, and manage AI risk through an operational risk-management model.",
    href: "https://www.nist.gov/itl/ai-risk-management-framework",
  },
  {
    icon: FileCheck2,
    name: "ISO/IEC 42001",
    focus: "AI management system practices for organizations building, using, or governing AI systems.",
    href: "https://www.iso.org/standard/42001",
  },
  {
    icon: Globe2,
    name: "EU AI Act",
    focus: "Documentation, logging, transparency, human oversight, robustness, accuracy, and cybersecurity expectations.",
    href: "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai",
  },
];

export default function FrameworkAlignment() {
  return (
    <section style={{ backgroundColor: "#050508", borderTop: "1px solid #1E2335", borderBottom: "1px solid #1E2335", padding: "4rem 0" }}>
      <div className="container-wide">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 320px), 1fr))", gap: 28, alignItems: "start" }}>
          <div>
            <div className="label-tag" style={{ marginBottom: 16, display: "inline-flex" }}>
              <BookOpenCheck size={12} /> Framework Alignment
            </div>
            <h2 style={{ color: "#ffffff", fontSize: "clamp(1.8rem, 3vw, 2.5rem)", fontWeight: 800, letterSpacing: "-0.04em", lineHeight: 1.12, marginBottom: 16 }}>
              Built to Map AI Controls to the Language Buyers Already Use.
            </h2>
            <p style={{ color: "#8892A4", fontSize: 15, lineHeight: 1.75 }}>
              CyberArmor.AI is designed to help security teams translate AI governance into runtime
              controls and evidence records that can be reviewed against recognized AI security,
              risk, and management-system frameworks.
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 230px), 1fr))", gap: 14 }}>
            {frameworks.map(({ icon: Icon, name, focus, href }) => (
              <a
                key={name}
                href={href}
                target="_blank"
                rel="noreferrer"
                style={{
                  background: "#0F1117",
                  border: "1px solid #1E2335",
                  borderRadius: 14,
                  padding: 20,
                  textDecoration: "none",
                  minHeight: 170,
                  display: "flex",
                  flexDirection: "column",
                }}
              >
                <Icon size={21} style={{ color: "#00A3FF", marginBottom: 14 }} />
                <h3 style={{ color: "#ffffff", fontSize: 15, fontWeight: 800, marginBottom: 10 }}>{name}</h3>
                <p style={{ color: "#8892A4", fontSize: 13.5, lineHeight: 1.65 }}>{focus}</p>
              </a>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
