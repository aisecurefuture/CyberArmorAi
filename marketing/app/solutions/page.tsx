import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Ghost, Bot, ShieldAlert, Database, UserCheck, FileSearch, Activity, Lock } from "lucide-react";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "Solutions — AI Security Use Cases for Enterprise Security Teams",
  description:
    "Discover how CyberArmor AI addresses the real security challenges of enterprise AI: shadow AI, agent risk, prompt injection, data protection, and more.",
};

const solutions = [
  {
    id: "shadow-ai",
    icon: Ghost,
    color: "#00A3FF",
    tag: "Visibility & Governance",
    title: "Shadow AI Discovery & Governance",
    roles: ["CISO", "Head of Security", "CIO"],
    pain: "Your employees are using AI tools you don't know exist. Developers are calling external LLM APIs. Vendors are processing your data through third-party AI systems. None of it has been reviewed. None of it is under policy.",
    solution: "CyberArmor AI gives you continuous, automated discovery of every AI tool, model, and API connection in use across your organization — then brings it under governed policy without blocking legitimate productivity.",
    outcomes: [
      "Complete AI asset inventory, updated continuously",
      "Unauthorized AI usage surfaced and flagged automatically",
      "Policy-based governance applied without manual review",
      "Audit-ready records of all AI usage events",
    ],
  },
  {
    id: "agents",
    icon: Bot,
    color: "#A855F7",
    tag: "AI Agent Security",
    title: "AI Agent Trust & Control",
    roles: ["Security Architect", "Head of AppSec", "Platform Engineering"],
    pain: "Autonomous AI agents are being deployed to automate decisions, access systems, and orchestrate workflows. Without identity controls, behavioral bounds, and trust verification, these agents represent a new and largely unmanaged attack surface.",
    solution: "CyberArmor AI verifies agent identity, applies behavioral policy, enforces scope limitations, and generates trust attestations — so your security program knows exactly what each agent can do, is doing, and has done.",
    outcomes: [
      "Agent identity verification before runtime execution",
      "Behavioral scope enforcement and anomaly detection",
      "Trust attestation records for every agent action",
      "Blast radius limitation and automated containment",
    ],
  },
  {
    id: "prompt",
    icon: ShieldAlert,
    color: "#EF4444",
    tag: "Application Security",
    title: "Prompt Injection & Misuse Defense",
    roles: ["Head of AppSec", "Security Engineer", "CISO"],
    pain: "AI chatbots and LLM-powered applications are being actively targeted by adversarial inputs designed to extract data, bypass controls, or manipulate model behavior. Traditional WAFs and input sanitization don't understand the semantics of AI prompts.",
    solution: "CyberArmor AI provides runtime detection and blocking of adversarial prompts, jailbreak patterns, and indirect injection attempts — before they reach the model, with full forensic logging of every attempt.",
    outcomes: [
      "Real-time prompt classification and threat scoring",
      "Blocking of adversarial inputs before model exposure",
      "Full forensic log of all injection attempts",
      "Coverage for direct and indirect prompt injection vectors",
    ],
  },
  {
    id: "data",
    icon: Database,
    color: "#22C55E",
    tag: "Data Protection",
    title: "Sensitive Data Protection in AI Workflows",
    roles: ["CISO", "Data Protection Officer", "Compliance Lead"],
    pain: "AI systems are processing PII, financial records, trade secrets, and regulated data without data residency controls, classification enforcement, or visibility into what's being shared with which model or vendor.",
    solution: "CyberArmor AI classifies data entering AI pipelines, enforces data handling policy at the point of ingestion, prevents unauthorized processing, and generates compliance evidence for regulated data in AI workflows.",
    outcomes: [
      "Real-time data classification in AI interactions",
      "Policy-based data handling enforcement per AI system",
      "Prevention of unauthorized PII or regulated data exposure",
      "Compliance-ready evidence for AI data processing activities",
    ],
  },
  {
    id: "adoption",
    icon: Lock,
    color: "#F59E0B",
    tag: "Secure AI Adoption",
    title: "Governed Enterprise AI Adoption",
    roles: ["CIO", "CTO", "CISO", "Head of Digital Transformation"],
    pain: "Business teams want to move fast on AI. Security and legal are blocking initiatives because there is no technical framework for safe, accountable AI deployment at enterprise scale. The result is either delayed value or ungoverned risk.",
    solution: "CyberArmor AI provides the technical governance infrastructure that allows enterprises to move fast on AI without accumulating security debt — policy rails, enforcement, and audit trails built into the AI adoption lifecycle.",
    outcomes: [
      "Security policy framework for AI deployment programs",
      "Automated enforcement that doesn't slow delivery teams",
      "Audit trails for AI system approvals and usage",
      "Accelerated security review cycles for AI initiatives",
    ],
  },
  {
    id: "investigation",
    icon: FileSearch,
    color: "#06B6D4",
    tag: "Incident Response",
    title: "Evidence-Based AI Incident Investigation",
    roles: ["Security Operations", "IR Teams", "Legal & Compliance"],
    pain: "When an AI-related security incident occurs — a data leak through a chatbot, a compromised agent, a prompt injection that succeeded — security teams have no structured forensic evidence. Reconstructing what happened is expensive, slow, and incomplete.",
    solution: "CyberArmor AI captures decision-level telemetry for every AI interaction throughout the kill chain, creating a structured, reviewable record that makes AI incident response faster, more precise, and legally defensible.",
    outcomes: [
      "Full decision-level telemetry across AI interactions",
      "Structured incident timeline reconstruction in minutes",
      "Evidence-backed root cause analysis for AI incidents",
      "Legally defensible documentation for regulatory response",
    ],
  },
  {
    id: "monitoring",
    icon: Activity,
    color: "#EC4899",
    tag: "Runtime Operations",
    title: "Continuous AI Runtime Monitoring",
    roles: ["Security Operations", "Platform Security", "CISO"],
    pain: "AI systems change behavior over time as models are updated, fine-tuned, or retrained. Without continuous runtime monitoring, drift from expected behavior — or adversarial manipulation — can go undetected for extended periods.",
    solution: "CyberArmor AI provides continuous behavioral monitoring of AI systems and agents at runtime, detecting anomalies, policy drift, and behavioral changes — and triggering investigation or containment automatically.",
    outcomes: [
      "Continuous behavioral baseline for every monitored AI system",
      "Anomaly detection for drift, manipulation, and misuse",
      "Automated alerting with structured investigation context",
      "Integration with existing SOC workflows and SIEM platforms",
    ],
  },
  {
    id: "identity",
    icon: UserCheck,
    color: "#8B5CF6",
    tag: "Identity & Access",
    title: "AI-Aware Identity & Access Control",
    roles: ["IAM Lead", "Security Architect", "CISO"],
    pain: "Traditional IAM was built for human users. Enterprise AI environments include services, workloads, and AI agents that all need access — but don't fit existing identity models. The result is over-provisioned, unmonitored non-human access.",
    solution: "CyberArmor AI extends identity-aware access control to the full range of AI actors: users, services, workloads, and agents — with dynamic trust decisions that account for context, risk level, and behavioral history.",
    outcomes: [
      "Unified identity policy spanning human and non-human actors",
      "Context-aware trust decisions at time of access",
      "Least-privilege enforcement for AI services and agents",
      "Integration with existing IAM and zero trust frameworks",
    ],
  },
];

export default function SolutionsPage() {
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
          <div className="label-tag" style={{ display: "inline-flex", marginBottom: 20 }}>Use Cases & Solutions</div>
          <h1 style={{
            fontSize: "clamp(2.4rem, 5vw, 3.6rem)",
            fontWeight: 800, letterSpacing: "-0.04em", lineHeight: 1.08,
            marginBottom: 24, color: "#ffffff",
          }}>
            Real Security Problems.<br />
            <span className="gradient-text-blue">Real Enterprise Answers.</span>
          </h1>
          <p style={{
            fontSize: "1.1rem", color: "#8892A4", lineHeight: 1.75,
            maxWidth: 680, margin: "0 auto 40px",
          }}>
            Every CyberArmor AI solution is built around a specific AI security challenge that enterprise teams
            are already facing — not theoretical risks, but the threats and exposures happening today.
          </p>
        </div>
      </section>

      {/* Solutions */}
      <section style={{ paddingBottom: "6rem" }}>
        <div className="container-wide">
          <div style={{ display: "flex", flexDirection: "column", gap: 32 }}>
            {solutions.map(({ id, icon: Icon, color, tag, title, roles, pain, solution, outcomes }) => (
              <div key={id} id={id} className="card-base" style={{ padding: "48px", position: "relative", overflow: "hidden" }}>
                <div style={{
                  position: "absolute", top: 0, left: 0, bottom: 0, width: 3,
                  background: `linear-gradient(180deg, ${color}, ${color}30)`,
                }} />

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 48, alignItems: "start" }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
                      <div style={{
                        width: 48, height: 48,
                        background: `${color}15`,
                        border: `1px solid ${color}30`,
                        borderRadius: 12,
                        display: "flex", alignItems: "center", justifyContent: "center",
                      }}>
                        <Icon size={22} style={{ color }} />
                      </div>
                      <span className="label-tag" style={{ fontSize: 10, background: `${color}10`, borderColor: `${color}25`, color }}>
                        {tag}
                      </span>
                    </div>

                    <h2 style={{
                      fontSize: "1.3rem", fontWeight: 700, color: "#ffffff",
                      letterSpacing: "-0.02em", marginBottom: 12, lineHeight: 1.3,
                    }}>
                      {title}
                    </h2>

                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 24 }}>
                      {roles.map((r) => (
                        <span key={r} style={{
                          fontSize: 11, color: "#8892A4",
                          background: "#12151E",
                          border: "1px solid #1E2335",
                          borderRadius: 4,
                          padding: "3px 8px",
                        }}>{r}</span>
                      ))}
                    </div>

                    <div style={{ marginBottom: 20 }}>
                      <p style={{ fontSize: 11, fontWeight: 700, color: "#EF4444", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
                        The Challenge
                      </p>
                      <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.75 }}>{pain}</p>
                    </div>

                    <div>
                      <p style={{ fontSize: 11, fontWeight: 700, color: "#22C55E", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
                        The CyberArmor AI Answer
                      </p>
                      <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.75 }}>{solution}</p>
                    </div>
                  </div>

                  <div>
                    <div style={{
                      background: "#12151E",
                      border: "1px solid #1E2335",
                      borderRadius: 12,
                      padding: "28px",
                      marginBottom: 24,
                    }}>
                      <p style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 16 }}>
                        Key Outcomes
                      </p>
                      <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 12 }}>
                        {outcomes.map((o) => (
                          <li key={o} style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
                            <div style={{
                              width: 6, height: 6, borderRadius: "50%",
                              backgroundColor: color,
                              marginTop: 7, flexShrink: 0,
                              boxShadow: `0 0 6px ${color}80`,
                            }} />
                            <span style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.6 }}>{o}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <Link href="/contact" className="btn-ghost" style={{ fontSize: 14, width: "100%", justifyContent: "center" }}>
                      Request a Demo for This Use Case <ArrowRight size={14} />
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
