import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Building2, Heart, Plane, Shield, Code2, Briefcase } from "lucide-react";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "Industries — AI Security for Regulated & High-Risk Sectors",
  description:
    "CyberArmor AI helps financial services, healthcare, insurance, airlines, and technology enterprises secure AI adoption against industry-specific risks.",
};

const industries = [
  {
    id: "financial",
    icon: Building2,
    color: "#00A3FF",
    title: "Financial Services",
    subtitle: "Banks, Investment Firms, Capital Markets",
    context:
      "Financial institutions are deploying AI across trading, fraud detection, customer service, credit decisioning, and compliance — at a pace that has outrun existing security controls. Regulatory scrutiny from the OCC, Fed, CFPB, and SEC is increasing.",
    risks: [
      "AI models making credit and lending decisions without explainable audit trails",
      "Unauthorized third-party AI tools processing customer financial data",
      "AI chatbots vulnerable to prompt injection and social engineering",
      "Shadow AI adoption by trading and quant teams creating unmanaged model risk",
    ],
    value: "CyberArmor AI gives financial security and compliance teams continuous discovery of AI usage, policy enforcement at the model and application layer, and decision-level evidence for regulatory examination.",
    regulatory: ["OCC AI Guidance", "SEC Reg SCI", "GDPR Article 22", "FFIEC Cybersecurity Framework"],
  },
  {
    id: "insurance",
    icon: Shield,
    color: "#A855F7",
    title: "Insurance",
    subtitle: "P&C, Life, Health, Specialty Lines",
    context:
      "Insurers are using AI for underwriting, claims processing, fraud detection, and customer interaction. Each use creates data risk, model explainability obligations, and potential regulatory exposure if AI systems operate outside defined bounds.",
    risks: [
      "AI underwriting models with no explainability or adverse action documentation",
      "Claims AI processing sensitive medical and financial data without data policy enforcement",
      "Vendor AI tools accessing policyholder data without governance oversight",
      "Agent-driven claims workflows with no trust verification or behavioral bounds",
    ],
    value: "CyberArmor AI provides the technical enforcement layer that insurance security and compliance teams need to operate AI systems within regulatory and actuarial governance requirements.",
    regulatory: ["NAIC AI Model Bulletin", "GDPR", "State Insurance AI Regulations", "FCRA"],
  },
  {
    id: "healthcare",
    icon: Heart,
    color: "#22C55E",
    title: "Healthcare & Life Sciences",
    subtitle: "Health Systems, Payers, Pharma, Biotech",
    context:
      "Healthcare AI is moving from administrative automation to clinical decision support, diagnostics assistance, and patient-facing interaction. Every AI touchpoint creates HIPAA exposure, patient safety risk, and liability if not properly governed.",
    risks: [
      "Clinical AI tools accessing PHI without data handling controls or audit trails",
      "Patient-facing AI chatbots vulnerable to manipulation and data extraction",
      "Shadow AI usage by clinical and administrative staff in non-compliant tools",
      "AI agent workflows in revenue cycle and care management without scope controls",
    ],
    value: "CyberArmor AI provides HIPAA-aligned AI governance, real-time PHI protection in AI workflows, and the compliance evidence infrastructure required for healthcare AI programs.",
    regulatory: ["HIPAA Security Rule", "21st Century Cures Act", "FDA AI/ML Guidance", "ONC Rules"],
  },
  {
    id: "airlines",
    icon: Plane,
    color: "#F59E0B",
    title: "Airlines & Transportation",
    subtitle: "Commercial Aviation, Rail, Logistics, Freight",
    context:
      "Airlines and transportation operators are deploying AI for scheduling optimization, maintenance prediction, customer experience, and safety-adjacent operations. The safety and security implications of AI system failures or manipulation are uniquely severe in this sector.",
    risks: [
      "AI maintenance and operations tools with no runtime behavioral monitoring",
      "Customer service AI processing PII and payment data without data policy enforcement",
      "Shadow AI usage by operations and engineering teams with access to critical systems",
      "Autonomous workflow agents in logistics and ground operations without trust controls",
    ],
    value: "CyberArmor AI provides the operational security infrastructure for transportation AI programs — with particular focus on runtime integrity, behavioral monitoring, and evidence capture for safety-critical AI systems.",
    regulatory: ["TSA Cybersecurity Directives", "FAA AI Safety Guidance", "GDPR", "DOT Data Requirements"],
  },
  {
    id: "technology",
    icon: Code2,
    color: "#06B6D4",
    title: "Technology & SaaS",
    subtitle: "Enterprise Software, Cloud Platforms, AI-Native Companies",
    context:
      "Technology companies are both deploying AI internally and embedding it in products shipped to enterprise customers. Both dimensions create security obligations: protecting internal AI operations and ensuring customer-facing AI features meet enterprise security standards.",
    risks: [
      "Internal LLM tooling used in software development and operations without security review",
      "Customer-facing AI features with prompt injection vulnerabilities and data leakage risks",
      "AI model training pipelines processing sensitive data without governance oversight",
      "Third-party AI APIs embedded in products without security assessment or monitoring",
    ],
    value: "CyberArmor AI helps technology companies build security into their AI development lifecycle — and supports enterprise customers who require security attestation for AI-enabled products.",
    regulatory: ["SOC 2 Type II", "ISO 27001", "GDPR / CCPA", "EU AI Act (High-Risk Classification)"],
  },
  {
    id: "regulated",
    icon: Briefcase,
    color: "#EF4444",
    title: "Regulated Enterprises",
    subtitle: "Energy, Government, Defense, Critical Infrastructure",
    context:
      "Regulated enterprises operate in environments where the security, explainability, and auditability of AI systems is not optional — it is mandated. These organizations need AI security infrastructure that can withstand regulatory examination and adversarial scrutiny.",
    risks: [
      "AI adoption outpacing the security review and approval processes required by regulation",
      "Ungoverned AI tools in privileged environments with access to sensitive systems or data",
      "Lack of documented evidence for AI system behavior during compliance examinations",
      "Autonomous AI agents operating in environments with strict access control requirements",
    ],
    value: "CyberArmor AI provides the governance rigor, technical enforcement, and evidence architecture that regulated enterprises need to deploy AI within their existing compliance and risk management frameworks.",
    regulatory: ["NIST AI RMF", "CMMC", "FISMA", "NERC CIP", "Sector-Specific AI Mandates"],
  },
];

export default function IndustriesPage() {
  return (
    <div style={{ backgroundColor: "#000000" }}>
      {/* Hero */}
      <section style={{ paddingTop: "10rem", paddingBottom: "6rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.1) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />
        <div className="container-wide" style={{ position: "relative", textAlign: "center" }}>
          <div className="label-tag" style={{ display: "inline-flex", marginBottom: 20 }}>Industries</div>
          <h1 style={{
            fontSize: "clamp(2.4rem, 5vw, 3.6rem)",
            fontWeight: 800, letterSpacing: "-0.04em", lineHeight: 1.08,
            marginBottom: 24, color: "#ffffff",
          }}>
            AI Security Built for<br />
            <span className="gradient-text-blue">High-Stakes Environments.</span>
          </h1>
          <p style={{
            fontSize: "1.1rem", color: "#8892A4", lineHeight: 1.75,
            maxWidth: 680, margin: "0 auto 40px",
          }}>
            CyberArmor AI is designed for regulated, risk-sensitive industries where AI security is not
            a suggestion — it is a compliance requirement, a board obligation, and a competitive differentiator.
          </p>
          {/* Industry quick links */}
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", justifyContent: "center" }}>
            {industries.map(({ id, title, icon: Icon, color }) => (
              <a key={id} href={`#${id}`} className="industry-tag" style={{
                display: "flex", alignItems: "center", gap: 8,
                background: "#0F1117",
                border: "1px solid #1E2335",
                borderRadius: 8,
                padding: "8px 16px",
                fontSize: 13, color: "#8892A4",
                fontWeight: 500,
                textDecoration: "none",
                transition: "all 0.2s",
              }}>
                <Icon size={14} style={{ color }} />
                {title}
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* Industries */}
      <section style={{ paddingBottom: "6rem" }}>
        <div className="container-wide">
          <div style={{ display: "flex", flexDirection: "column", gap: 40 }}>
            {industries.map(({ id, icon: Icon, color, title, subtitle, context, risks, value, regulatory }) => (
              <div key={id} id={id} className="card-base" style={{ padding: "48px", position: "relative", overflow: "hidden" }}>
                {/* Top color bar */}
                <div style={{
                  position: "absolute", top: 0, left: 0, right: 0, height: 3,
                  background: `linear-gradient(90deg, ${color}, ${color}30)`,
                }} />

                {/* Header */}
                <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 28 }}>
                  <div style={{
                    width: 56, height: 56,
                    background: `${color}15`,
                    border: `1px solid ${color}30`,
                    borderRadius: 14,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    flexShrink: 0,
                  }}>
                    <Icon size={26} style={{ color }} />
                  </div>
                  <div>
                    <h2 style={{
                      fontSize: "1.4rem", fontWeight: 700, color: "#ffffff",
                      letterSpacing: "-0.02em", marginBottom: 4, lineHeight: 1.2,
                    }}>{title}</h2>
                    <p style={{ fontSize: 13, color: "#8892A4" }}>{subtitle}</p>
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 48, alignItems: "start" }}>
                  <div>
                    <p style={{ fontSize: 15, color: "#8892A4", lineHeight: 1.75, marginBottom: 28 }}>{context}</p>

                    <div style={{ marginBottom: 28 }}>
                      <p style={{ fontSize: 11, fontWeight: 700, color: "#EF4444", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 12 }}>
                        Industry-Specific AI Risks
                      </p>
                      <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 12 }}>
                        {risks.map((r) => (
                          <li key={r} style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                            <div style={{
                              width: 6, height: 6, borderRadius: "50%",
                              backgroundColor: "#EF4444",
                              marginTop: 7, flexShrink: 0,
                            }} />
                            <span style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.6 }}>{r}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div style={{
                      background: `${color}08`,
                      border: `1px solid ${color}20`,
                      borderRadius: 10,
                      padding: "20px 24px",
                    }}>
                      <p style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 10 }}>
                        How CyberArmor AI Helps
                      </p>
                      <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7 }}>{value}</p>
                    </div>
                  </div>

                  <div>
                    <div style={{
                      background: "#12151E",
                      border: "1px solid #1E2335",
                      borderRadius: 12,
                      padding: "24px",
                      marginBottom: 20,
                    }}>
                      <p style={{ fontSize: 11, fontWeight: 700, color: "#00A3FF", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 14 }}>
                        Relevant Regulatory Context
                      </p>
                      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        {regulatory.map((r) => (
                          <div key={r} style={{
                            display: "flex", alignItems: "center", gap: 10,
                            background: "#0F1117",
                            border: "1px solid #1E2335",
                            borderRadius: 8,
                            padding: "10px 14px",
                          }}>
                            <div style={{ width: 6, height: 6, borderRadius: "50%", backgroundColor: "#00A3FF", flexShrink: 0 }} />
                            <span style={{ fontSize: 13, color: "#8892A4" }}>{r}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <Link href="/contact" className="btn-primary" style={{ width: "100%", justifyContent: "center", fontSize: 14 }}>
                      Talk to an {title} Expert <ArrowRight size={14} />
                    </Link>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <FinalCTA />
    </div>
  );
}
