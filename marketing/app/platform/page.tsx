import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Eye, Shield, Lock, FileSearch, Cpu, Network, UserCheck, Activity } from "lucide-react";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "Platform — AI Security & Cyber Trust Architecture",
  description:
    "Explore the CyberArmor AI platform: unified discovery, policy enforcement, runtime protection, and evidence-based trust across every AI system in your enterprise.",
};

const layers = [
  {
    id: "discovery",
    icon: Eye,
    title: "AI Asset Discovery & Inventory",
    color: "#00A3FF",
    description:
      "You cannot govern what you cannot see. CyberArmor AI continuously discovers and catalogs every AI system, model, API connection, and agent operating across your enterprise environment — authorized or not.",
    capabilities: [
      "Automated discovery of shadow AI tools and unauthorized model connections",
      "Real-time inventory of AI systems, APIs, agents, and workloads",
      "Continuous monitoring for new AI deployments and drift detection",
      "Integration with cloud-native environments, SaaS platforms, and on-prem infrastructure",
    ],
  },
  {
    id: "policy",
    icon: Shield,
    title: "Policy Enforcement Engine",
    color: "#A855F7",
    description:
      "CyberArmor AI's policy engine translates governance requirements into executable, context-sensitive rules that apply across users, workloads, AI agents, and AI systems — and enforces them automatically.",
    capabilities: [
      "Role-based, identity-aware policy assignment for AI access and usage",
      "Context-sensitive rule evaluation based on risk posture, data sensitivity, and user behavior",
      "Policy inheritance and exception management for large enterprise environments",
      "Integration with existing IAM, PAM, and access governance systems",
    ],
  },
  {
    id: "runtime",
    icon: Lock,
    title: "Runtime Protection",
    color: "#22C55E",
    description:
      "Runtime protection means acting at the moment of execution — not analyzing logs hours later. CyberArmor AI intercepts AI interactions in real time and takes enforcement action based on live policy evaluation.",
    capabilities: [
      "Real-time interception of AI API calls, model queries, and agent actions",
      "Prompt injection detection and blocking before reaching the model layer",
      "Adaptive enforcement: block, redact in supported paths, alert, limit, or redirect based on risk level",
      "Protection for AI chatbots, LLM-powered applications, and autonomous workflows",
    ],
  },
  {
    id: "identity",
    icon: UserCheck,
    title: "Identity-Aware Trust Controls",
    color: "#F59E0B",
    description:
      "In AI environments, identity is not just about users. CyberArmor AI applies identity-aware trust controls to humans, services, workloads, and AI agents — creating a unified trust model across the entire AI stack.",
    capabilities: [
      "Trust verification for AI agents: identity confirmation, scope validation, behavioral bounds",
      "Service and workload identity management for AI API access",
      "Cross-domain trust decisions spanning human, non-human, and AI actor types",
      "Integration with existing identity providers and zero trust frameworks",
    ],
  },
  {
    id: "evidence",
    icon: FileSearch,
    title: "Evidence & Decision Traceability",
    color: "#EF4444",
    description:
      "Every AI interaction, policy decision, and enforcement action generates structured, tamper-resistant evidence. CyberArmor AI gives security, compliance, and legal teams a reviewable record of exactly what happened — and why.",
    capabilities: [
      "Decision-level telemetry for every AI action, model call, and agent behavior",
      "Tamper-resistant audit log optimized for compliance and legal review",
      "Incident response acceleration through structured, context-rich evidence",
      "Exportable evidence formats compatible with SIEM, SOAR, and GRC platforms",
    ],
  },
  {
    id: "response",
    icon: Activity,
    title: "Detection, Enforcement & Response",
    color: "#06B6D4",
    description:
      "CyberArmor AI closes the loop from detection to enforcement to response. When a threat or policy violation is identified, the platform acts — and gives security operations teams the context they need to respond decisively.",
    capabilities: [
      "Automated response playbooks for AI-specific threat scenarios",
      "Bi-directional integration with SIEM and SOAR platforms",
      "Structured alert context: policy violated, actor identity, action taken, evidence ID",
      "Containment capabilities: redaction-mode response, agent suspension, scope reduction, access revocation",
    ],
  },
];

const integrations = [
  "Microsoft Entra ID", "Okta", "AWS", "Azure", "Google Cloud",
  "Splunk", "Palo Alto Cortex", "CrowdStrike", "ServiceNow", "Wiz",
];

export default function PlatformPage() {
  return (
    <div style={{ backgroundColor: "#000000" }}>
      {/* Hero */}
      <section style={{ paddingTop: "10rem", paddingBottom: "6rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.1) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />
        <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.3 }} />
        <div className="container-wide" style={{ position: "relative", textAlign: "center" }}>
          <div className="label-tag" style={{ marginBottom: 20, display: "inline-flex" }}>
            <Cpu size={12} /> The Platform
          </div>
          <h1 className="section-headline" style={{
            fontSize: "clamp(2.4rem, 5vw, 3.6rem)",
            marginBottom: 24, maxWidth: 800, margin: "0 auto 24px",
          }}>
            A Unified Cyber Trust Layer<br />
            <span className="gradient-text-blue">for Enterprise AI.</span>
          </h1>
          <p style={{
            fontSize: "1.1rem", color: "#8892A4", lineHeight: 1.75,
            maxWidth: 680, margin: "0 auto 40px",
          }}>
            CyberArmor AI is not a collection of point tools. It is a purpose-built platform that connects discovery,
            governance, runtime protection, identity trust, and evidence capture into a single operational system.
          </p>
          <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
            <Link href="/contact" className="btn-primary">
              Request a Demo <ArrowRight size={16} />
            </Link>
            <Link href="/solutions" className="btn-ghost">
              See Use Cases <ArrowRight size={15} />
            </Link>
          </div>
        </div>
      </section>

      {/* Architecture diagram */}
      <section style={{ padding: "4rem 0", backgroundColor: "#050508" }}>
        <div className="container-wide">
          <div style={{
            background: "#0F1117",
            border: "1px solid #1E2335",
            borderRadius: 20,
            padding: "48px",
            textAlign: "center",
          }}>
            <p style={{ fontSize: 12, color: "#00A3FF", fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 32 }}>
              Platform Architecture — Unified Cyber Trust System
            </p>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 0, flexWrap: "wrap" }}>
              {["Discover", "Classify", "Govern", "Enforce", "Monitor", "Prove"].map((step, i, arr) => (
                <div key={step} style={{ display: "flex", alignItems: "center" }}>
                  <div style={{
                    background: "rgba(0,163,255,0.08)",
                    border: "1px solid rgba(0,163,255,0.2)",
                    borderRadius: 10,
                    padding: "14px 24px",
                    textAlign: "center",
                  }}>
                    <p style={{ fontSize: 13, fontWeight: 700, color: "#00A3FF", letterSpacing: "-0.01em" }}>{step}</p>
                  </div>
                  {i < arr.length - 1 && (
                    <ArrowRight size={16} style={{ color: "#1E2335", margin: "0 4px", flexShrink: 0 }} />
                  )}
                </div>
              ))}
            </div>
            <div className="glow-line" style={{ margin: "40px 0 32px" }} />
            <div style={{ display: "flex", justifyContent: "center", gap: 12, flexWrap: "wrap" }}>
              {["AI Systems", "AI Agents", "Applications & APIs", "Data Pipelines", "Identities", "Runtime Environments"].map((layer) => (
                <span key={layer} style={{
                  background: "#12151E",
                  border: "1px solid #1E2335",
                  borderRadius: 6,
                  padding: "6px 14px",
                  fontSize: 13,
                  color: "#8892A4",
                }}>
                  {layer}
                </span>
              ))}
            </div>
            <p style={{ fontSize: 12, color: "#4A5568", marginTop: 16 }}>
              CyberArmor AI protects across all layers simultaneously — not one at a time.
            </p>
          </div>
        </div>
      </section>

      {/* Platform layers */}
      <section className="section-padding" style={{ backgroundColor: "#000000" }}>
        <div className="container-wide">
          <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 64px" }}>
            <h2 className="section-headline" style={{ marginBottom: 16 }}>
              Six Layers of Protection.<br />
              <span className="gradient-text-blue">One Integrated System.</span>
            </h2>
            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
              Each capability layer is designed to operate independently or as part of the unified platform —
              giving enterprises a deployment path that meets them where they are.
            </p>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 32 }}>
            {layers.map(({ id, icon: Icon, title, color, description, capabilities }) => (
              <div key={id} id={id} className="card-base" style={{ padding: "44px 48px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 48, alignItems: "start" }}>
                  <div>
                    <div style={{
                      width: 52, height: 52,
                      background: `${color}15`,
                      border: `1px solid ${color}30`,
                      borderRadius: 12,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      marginBottom: 20,
                    }}>
                      <Icon size={24} style={{ color }} />
                    </div>
                    <h3 style={{
                      fontSize: "1.3rem", fontWeight: 700, color: "#ffffff",
                      letterSpacing: "-0.02em", marginBottom: 16, lineHeight: 1.3,
                    }}>
                      {title}
                    </h3>
                    <p style={{ fontSize: 15, color: "#8892A4", lineHeight: 1.75 }}>{description}</p>
                  </div>
                  <div>
                    <p style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 16 }}>
                      Key Capabilities
                    </p>
                    <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 14 }}>
                      {capabilities.map((cap) => (
                        <li key={cap} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                          <div style={{
                            width: 6, height: 6, borderRadius: "50%",
                            backgroundColor: color,
                            marginTop: 7, flexShrink: 0,
                            boxShadow: `0 0 6px ${color}80`,
                          }} />
                          <span style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.6 }}>{cap}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Integrations */}
      <section className="section-padding" style={{ backgroundColor: "#050508" }}>
        <div className="container-wide">
          <div style={{ textAlign: "center", maxWidth: 600, margin: "0 auto 48px" }}>
            <div className="label-tag" style={{ display: "inline-flex", marginBottom: 16 }}>
              <Network size={12} /> Integrations
            </div>
            <h2 className="section-headline" style={{ marginBottom: 16 }}>
              Built to Work With Your{" "}
              <span className="gradient-text-blue">Existing Stack.</span>
            </h2>
            <p style={{ color: "#8892A4", lineHeight: 1.7 }}>
              CyberArmor AI extends your security investment — integrating with the identity, cloud,
              and security platforms your team already relies on.
            </p>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 12, justifyContent: "center" }}>
            {integrations.map((name) => (
              <div key={name} className="platform-integration" style={{
                background: "#0F1117",
                border: "1px solid #1E2335",
                borderRadius: 10,
                padding: "14px 24px",
                fontSize: 14,
                color: "#8892A4",
                fontWeight: 500,
                transition: "border-color 0.2s, color 0.2s",
              }}>
                {name}
              </div>
            ))}
            <div style={{
              background: "rgba(0,163,255,0.08)",
              border: "1px solid rgba(0,163,255,0.2)",
              borderRadius: 10,
              padding: "14px 24px",
              fontSize: 14,
              color: "#00A3FF",
              fontWeight: 500,
            }}>
              + Many more
            </div>
          </div>
        </div>
      </section>

      <FinalCTA />
    </div>
  );
}
