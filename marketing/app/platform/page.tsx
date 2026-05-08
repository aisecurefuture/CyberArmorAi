import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Eye, Shield, Lock, FileSearch, Cpu, Network, UserCheck, Activity, Link2 } from "lucide-react";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "Platform — AI Security Runtime with URL Trust Gate",
  description:
    "Explore CyberArmor.AI's AI security runtime: URL Trust Gate for pre-ingestion promptware and phishing defense, ML-based detection, policy enforcement, routing, identity, audit, and protection-backed evidence.",
};

const layers = [
  {
    id: "url-trust-gate",
    icon: Link2,
    title: "URL & Context Trust Gate",
    color: "#0EA5E9",
    description:
      "A pre-ingestion control point that evaluates URLs and external content before a human, browser, endpoint agent, RASP-instrumented app, or AI agent fetches them. Existing URL filters answer 'is this site malicious for a human?'; CyberArmor.AI also answers 'is this content safe for an AI agent to ingest?' A 15-minute pilot PoC is available.",
    capabilities: [
      "Canonicalisation, querystring redaction, and homoglyph / punycode checks before any network call",
      "SSRF-guarded safe crawl plus optional Playwright detonation to surface CSS-hidden, off-screen, and Unicode-tag-encoded promptware",
      "Detection-service fan-out for phishing, hidden prompt injection, promptware, data-exfil, and IOC scoring with optional Safe Browsing v4, Microsoft SmartScreen, and VirusTotal reputation feeds",
      "Policy decisions across allow, warn, redact, sandbox, block, and isolate — with evidence written to audit",
    ],
  },
  {
    id: "discovery",
    icon: Eye,
    title: "AI Asset Discovery & Inventory",
    color: "#00A3FF",
    description:
      "You cannot control what you cannot see. CyberArmor.AI uses supported endpoint, browser, API, and integration signals to surface AI tools, model calls, provider connections, and agent activity.",
    capabilities: [
      "Discovery signals for shadow AI tools and unauthorized model connections",
      "Tenant-scoped inventory views for AI systems, APIs, agents, and workloads",
      "Monitoring for new AI activity and deployment drift in supported paths",
      "Expansion across SaaS, identity, cloud, and on-prem sources through design-partner work",
    ],
  },
  {
    id: "policy",
    icon: Shield,
    title: "Policy Enforcement Engine",
    color: "#A855F7",
    description:
      "CyberArmor.AI translates governance requirements into executable policy decisions tied to tenant, actor, workload, model, provider, data, and risk context.",
    capabilities: [
      "Tenant-scoped policy rules for AI access, routing, redaction, blocking, and monitoring",
      "Context-sensitive evaluation based on risk posture, data sensitivity, provider, and actor context",
      "OPA-backed evaluation paths with fallback behavior for pilot validation",
      "Artifact references and policy outcomes that can be preserved in evidence records",
    ],
  },
  {
    id: "runtime",
    icon: Lock,
    title: "Runtime Protection",
    color: "#22C55E",
    description:
      "Runtime protection means acting when AI activity happens, not simply reviewing logs later. CyberArmor.AI connects detection and policy to approved enforcement outcomes in supported control points.",
    capabilities: [
      "Inspection of AI API calls, model queries, prompt fields, SDK requests, and agent actions where deployed",
      "Prompt injection detection, credential leak detection, and sensitive-data inspection",
      "Adaptive enforcement: monitor, warn, block, redact in supported paths, route, limit, or redirect",
      "Protection patterns for AI chatbots, LLM-powered applications, developer workflows, and autonomous workflows",
    ],
  },
  {
    id: "identity",
    icon: UserCheck,
    title: "Identity-Aware Trust Controls",
    color: "#F59E0B",
    description:
      "In AI environments, identity is not just about users. CyberArmor.AI models humans, services, workloads, and AI agents so security teams can reason about who or what acted.",
    capabilities: [
      "Agent registration, tenant scoping, owner metadata, allowed and denied tools, delegation chains, and revocation paths",
      "Service and workload context for AI API access and provider use",
      "Cross-domain trust decisions spanning human, non-human, and AI actor types",
      "Integration patterns for identity providers and zero trust programs as pilots mature",
    ],
  },
  {
    id: "evidence",
    icon: FileSearch,
    title: "Evidence & Decision Traceability",
    color: "#EF4444",
    description:
      "CyberArmor.AI is designed to preserve evidence that is attached to controls: actor, request, provider, data classification, policy decision, response action, and downstream trace context.",
    capabilities: [
      "Decision-level telemetry for AI actions, model calls, and agent behavior in monitored paths",
      "Audit-chain modeling with trace IDs, span IDs, chain hashes, signatures, and previous-event references",
      "Incident response acceleration through structured, context-rich evidence",
      "Evidence export patterns for SOC, audit, legal, compliance, and executive review",
    ],
  },
  {
    id: "response",
    icon: Activity,
    title: "Detection, Enforcement & Response",
    color: "#06B6D4",
    description:
      "CyberArmor.AI closes the loop from detection to policy to enforcement to response. When a threat or policy violation is identified, the platform records context and can trigger approved actions.",
    capabilities: [
      "Response actions for AI-specific threat scenarios, including block, notify, ticket, webhook, and containment patterns",
      "SIEM/SOAR integration workflows moving from pilot into production hardening",
      "Structured alert context: policy violated, actor identity, action taken, evidence ID",
      "Containment capabilities: redaction-mode response, agent suspension, scope reduction, access revocation, and routing changes",
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
            AI Runtime Control<br />
            <span className="gradient-text-blue">with Evidence Built In.</span>
          </h1>
          <p style={{
            fontSize: "1.1rem", color: "#8892A4", lineHeight: 1.75,
            maxWidth: 680, margin: "0 auto 40px",
          }}>
            CyberArmor.AI is not a collection of point tools or a reporting layer.
            It connects discovery, detection, policy, routing, identity, enforcement,
            response, secrets, audit, and evidence into a single runtime control system.
          </p>
          <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
            <Link href="/contact" className="btn-primary">
              Request a Demo <ArrowRight size={16} />
            </Link>
            <Link href="/url-trust-gate" className="btn-ghost">
              URL Trust Gate — 15-min PoC <ArrowRight size={15} />
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
              Platform Architecture — AI Security Runtime
            </p>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 0, flexWrap: "wrap" }}>
              {["Identify", "Gate", "Inspect", "Decide", "Control", "Respond", "Prove"].map((step, i, arr) => (
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
              {["External URLs & Content", "Users", "Applications", "AI Agents", "APIs", "Providers", "Models", "Data", "Evidence"].map((layer) => (
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
              Coverage depends on deployment pattern; the architecture is designed to connect the layers as control points mature.
            </p>
          </div>
        </div>
      </section>

      {/* Platform layers */}
      <section className="section-padding" style={{ backgroundColor: "#000000" }}>
        <div className="container-wide">
          <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 64px" }}>
            <h2 className="section-headline" style={{ marginBottom: 16 }}>
              Seven Runtime Capabilities.<br />
              <span className="gradient-text-blue">One Integrated Control Loop.</span>
            </h2>
            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
              Each capability can support a focused pilot, but the real value appears when the pieces work together:
              pre-ingestion trust gating, identity, detection, policy, routing, response, and evidence in one explainable flow.
            </p>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 32 }}>
            {layers.map(({ id, icon: Icon, title, color, description, capabilities }) => (
              <div key={id} id={id} className="card-base" style={{ padding: "44px 48px" }}>
                <div className="platform-layer-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 48, alignItems: "start" }}>
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
              CyberArmor.AI extends your security investment — integrating with the identity, cloud,
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
