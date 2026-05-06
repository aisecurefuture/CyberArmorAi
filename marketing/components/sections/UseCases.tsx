"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowRight, Ghost, Bot, ShieldAlert, Database, UserCheck, FileSearch } from "lucide-react";

const useCases = [
  {
    icon: Ghost,
    title: "Shadow AI Discovery & Governance",
    role: "CISO / Head of Security",
    pain: "Employees and vendors are connecting to AI tools, APIs, and models without security review. You have no inventory, no control, and no audit trail.",
    solution: "CyberArmor AI continuously discovers AI usage across your organization — unauthorized tools, API connections, model calls, and more — and brings them under governed policy automatically.",
    cta: "Explore Shadow AI Control",
  },
  {
    icon: Bot,
    title: "AI Agent Trust & Control",
    role: "Security Architect",
    pain: "Autonomous AI agents are being deployed to automate workflows, access systems, and make decisions at scale — without identity controls or behavioral bounds.",
    solution: "CyberArmor AI verifies agent identity, enforces behavioral policy, limits blast radius, and generates trust attestations for every agent action in your environment.",
    cta: "Explore Agent Security",
  },
  {
    icon: ShieldAlert,
    title: "Prompt Injection & Misuse Defense",
    role: "Head of AppSec",
    pain: "AI chatbots and LLM-powered applications are being targeted by prompt injection, jailbreak attempts, and adversarial inputs designed to extract data or subvert controls.",
    solution: "CyberArmor AI detects adversarial prompt patterns in real time, blocks malicious inputs before they reach the model, and logs every attempt with full forensic context.",
    cta: "Explore Prompt Defense",
  },
  {
    icon: Database,
    title: "Sensitive Data Protection in AI Workflows",
    role: "Data Protection Officer / CISO",
    pain: "AI systems are processing PII, financial records, and regulated data without data residency controls, consent boundaries, or visibility into what's being shared with which model.",
    solution: "CyberArmor AI classifies data entering AI pipelines, enforces data policy at the point of ingestion, and prevents unauthorized processing or exfiltration through AI interfaces.",
    cta: "Explore Data Protection",
  },
  {
    icon: UserCheck,
    title: "Secure Enterprise AI Adoption",
    role: "CIO / CTO",
    pain: "Your organization wants to move fast on AI, but security and legal are blocking every initiative because there's no framework for safe, accountable AI deployment.",
    solution: "CyberArmor AI provides the technical foundation for governed AI adoption — policy rails, audit trails, and runtime enforcement that let business move fast without security debt.",
    cta: "Explore AI Enablement",
  },
  {
    icon: FileSearch,
    title: "Evidence-Based Incident Investigation",
    role: "Security Operations / IR Teams",
    pain: "When an AI-related incident occurs — a data leak, a compromised agent, a policy bypass — security teams have no structured evidence to reconstruct what happened.",
    solution: "CyberArmor AI captures decision-level telemetry for every AI interaction, creating a tamper-resistant record that makes AI-related incident response fast, precise, and defensible.",
    cta: "Explore Evidence Layer",
  },
];

export default function UseCases() {
  const [active, setActive] = useState(0);
  const uc = useCases[active];

  return (
    <section className="section-padding" style={{ backgroundColor: "#000000" }}>
      <div className="container-wide">
        <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 56px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>Use Cases</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            Real Threats.{" "}
            <span className="gradient-text-blue">Real Buyers. Real Answers.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
            CyberArmor AI is built around the security challenges that enterprise teams are already facing — not hypothetical futures.
          </p>
        </div>

        <div className="use-cases-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: 32, alignItems: "start" }}>

          {/* Tabs */}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {useCases.map(({ icon: Icon, title, role }, i) => (
              <button
                key={title}
                onClick={() => setActive(i)}
                className="use-case-tab"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  padding: "16px 20px",
                  borderRadius: 10,
                  border: `1px solid ${active === i ? "rgba(0,163,255,0.3)" : "#1E2335"}`,
                  background: active === i ? "rgba(0,163,255,0.06)" : "#0F1117",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.2s ease",
                  width: "100%",
                }}
              >
                <Icon size={18} style={{ color: active === i ? "#00A3FF" : "#4A5568", flexShrink: 0 }} />
                <div>
                  <p style={{
                    fontSize: 14, fontWeight: 600,
                    color: active === i ? "#ffffff" : "#8892A4",
                    lineHeight: 1.3, marginBottom: 2,
                  }}>{title}</p>
                  <p style={{ fontSize: 12, color: "#4A5568" }}>{role}</p>
                </div>
              </button>
            ))}
          </div>

          {/* Active use case detail */}
          <div className="use-case-detail" style={{
            background: "#0F1117",
            border: "1px solid #1E2335",
            borderRadius: 16,
            padding: "40px",
            position: "sticky",
            top: 100,
          }}>
            <div style={{
              width: 52, height: 52,
              background: "rgba(0,163,255,0.08)",
              border: "1px solid rgba(0,163,255,0.2)",
              borderRadius: 12,
              display: "flex", alignItems: "center", justifyContent: "center",
              marginBottom: 24,
            }}>
              <uc.icon size={24} style={{ color: "#00A3FF" }} />
            </div>

            <div className="label-tag" style={{ marginBottom: 16, fontSize: 10 }}>{uc.role}</div>

            <h3 style={{
              fontSize: "1.25rem", fontWeight: 700, color: "#ffffff",
              letterSpacing: "-0.02em", lineHeight: 1.3, marginBottom: 20,
            }}>
              {uc.title}
            </h3>

            <div style={{ marginBottom: 20 }}>
              <p style={{ fontSize: 11, fontWeight: 700, color: "#EF4444", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
                The Problem
              </p>
              <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7 }}>{uc.pain}</p>
            </div>

            <div style={{ marginBottom: 32 }}>
              <p style={{ fontSize: 11, fontWeight: 700, color: "#22C55E", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
                The Solution
              </p>
              <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7 }}>{uc.solution}</p>
            </div>

            <Link href="/solutions" className="btn-ghost" style={{ fontSize: 14 }}>
              {uc.cta} <ArrowRight size={14} />
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
