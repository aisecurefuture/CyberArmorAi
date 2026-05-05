"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";

const faqs = [
  {
    q: "What exactly does CyberArmor AI protect?",
    a: "CyberArmor AI is designed to protect the full enterprise AI attack surface: AI systems and models, autonomous agents, AI-powered applications and APIs, user interactions with AI tools, data flowing through AI pipelines, and the runtime environments where AI workloads execute. It's a cross-layer platform — not a single-point solution.",
  },
  {
    q: "How is this different from existing security tools we already have?",
    a: "Traditional SIEM, DLP, and endpoint tools were designed for a world without AI agents, LLMs, and autonomous workflows. They don't understand the semantics of AI interactions, can't detect prompt injection, and have no way to verify agent identity or enforce behavioral policy. CyberArmor AI is purpose-built for the AI threat surface that existing tools weren't designed to address.",
  },
  {
    q: "What does 'shadow AI' mean and why should we care?",
    a: "Shadow AI refers to AI tools, models, and API connections that employees, developers, or vendors are using without security review or organizational approval — similar to shadow IT, but with the added risks of AI-specific vulnerabilities like data exfiltration via prompts, model misuse, and ungoverned training data. Most organizations have significantly more shadow AI usage than their security teams are aware of.",
  },
  {
    q: "What is 'AI runtime protection' and how does it work?",
    a: "AI runtime protection means applying security controls at the moment an AI system, agent, or application is executing — not after the fact. CyberArmor AI intercepts AI interactions, evaluates them against policy, and takes enforcement action (block, alert, limit, log) in real time. This is the difference between governance and actual defense.",
  },
  {
    q: "Does CyberArmor AI require replacing our existing security infrastructure?",
    a: "No. CyberArmor AI is designed to integrate with existing security toolchains — SIEM, SOAR, IAM, and cloud-native security platforms. It extends your existing investment rather than replacing it, bringing AI-specific visibility and enforcement that your current tools can't provide.",
  },
  {
    q: "How does the evidence and traceability capability help with compliance?",
    a: "Regulations like GDPR, HIPAA, SOC 2, and emerging AI-specific frameworks require organizations to demonstrate that AI systems are operating within defined boundaries and that decisions affecting individuals are explainable and reviewable. CyberArmor AI captures structured, tamper-resistant evidence for every AI interaction, providing the documentation trail that compliance and legal functions need.",
  },
  {
    q: "Is this relevant to my organization if we're early in AI adoption?",
    a: "Especially if you're early. The best time to establish AI security governance, policy enforcement, and trust controls is before AI usage proliferates — not after. Organizations that build the security infrastructure for AI adoption now are the ones that will be able to scale AI use safely and at speed. Organizations that wait will face a remediation project ten times more expensive.",
  },
  {
    q: "What does 'patent-pending' mean for the platform?",
    a: "CyberArmor AI's core architectural innovations — including our approach to AI trust verification, cross-layer policy enforcement, and decision-level evidence capture — are the subject of patent applications currently in process. This reflects our commitment to building defensible, differentiated technology rather than assembling existing tools under a new brand.",
  },
];

export default function FAQ() {
  const [open, setOpen] = useState<number | null>(0);

  return (
    <section className="section-padding" style={{ backgroundColor: "#000000" }}>
      <div className="container-wide">
        <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 56px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>FAQ</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            Questions Enterprise Buyers{" "}
            <span className="gradient-text-blue">Actually Ask.</span>
          </h2>
        </div>

        <div style={{ maxWidth: 820, margin: "0 auto", display: "flex", flexDirection: "column", gap: 8 }}>
          {faqs.map(({ q, a }, i) => (
            <div
              key={i}
              style={{
                background: "#0F1117",
                border: `1px solid ${open === i ? "rgba(0,163,255,0.3)" : "#1E2335"}`,
                borderRadius: 12,
                overflow: "hidden",
                transition: "border-color 0.2s",
              }}
            >
              <button
                onClick={() => setOpen(open === i ? null : i)}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "22px 28px",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  textAlign: "left",
                  gap: 16,
                }}
              >
                <span style={{
                  fontSize: 15.5, fontWeight: 600,
                  color: open === i ? "#ffffff" : "#8892A4",
                  letterSpacing: "-0.01em",
                  lineHeight: 1.4,
                  transition: "color 0.2s",
                }}>
                  {q}
                </span>
                <ChevronDown
                  size={18}
                  style={{
                    color: open === i ? "#00A3FF" : "#4A5568",
                    flexShrink: 0,
                    transform: open === i ? "rotate(180deg)" : "rotate(0deg)",
                    transition: "transform 0.3s ease, color 0.2s",
                  }}
                />
              </button>

              {open === i && (
                <div style={{ padding: "0 28px 22px" }}>
                  <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.75 }}>{a}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
