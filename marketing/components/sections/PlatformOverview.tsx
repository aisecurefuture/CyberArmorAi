"use client";

import Link from "next/link";
import { ArrowRight, Eye, Shield, Lock, FileSearch, Cpu, Users, Link2 } from "lucide-react";

const layers = [
  { icon: Eye, label: "Identify", desc: "Understand the actor, tenant, app, agent, provider, model, and data context behind an AI action" },
  { icon: Link2, label: "Gate", desc: "Evaluate external URLs and web content for phishing, promptware, and prompt injection before it reaches any human, browser, or AI agent" },
  { icon: Shield, label: "Inspect", desc: "Evaluate prompt risk, sensitive data, credentials, provider posture, and policy-relevant signals" },
  { icon: Lock, label: "Control", desc: "Monitor, warn, block, route, limit, or redact in supported runtime and user workflow paths" },
  { icon: FileSearch, label: "Prove", desc: "Capture decision-level evidence that explains what happened, what changed, and which policy applied" },
];

const protects = [
  { icon: Users, label: "Users & Identities" },
  { icon: Cpu, label: "Models & Providers" },
  { icon: Lock, label: "Applications & APIs" },
  { icon: Shield, label: "Agents & Workloads" },
  { icon: Eye, label: "Data & Prompts" },
  { icon: FileSearch, label: "Evidence & Audit Trails" },
];

export default function PlatformOverview() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#050508", position: "relative", overflow: "hidden" }}>
      {/* Background glow */}
      <div style={{
        position: "absolute",
        top: "50%", left: "50%",
        transform: "translate(-50%, -50%)",
        width: 600, height: 600,
        background: "radial-gradient(circle, rgba(0,163,255,0.04) 0%, transparent 70%)",
        pointerEvents: "none",
      }} />

      <div className="container-wide" style={{ position: "relative" }}>
        <div style={{ textAlign: "center", maxWidth: 700, margin: "0 auto 64px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>The Platform</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            An AI Security Runtime for{" "}
            <span className="gradient-text-blue">Control and Proof.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7 }}>
            CyberArmor.AI gates external content before it is trusted, then
            connects detection, policy, routing, identity, redaction, response,
            audit, and evidence into one operating model. Pre-ingestion control
            and protection-backed evidence.
          </p>
        </div>

        {/* 4-step flow */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: 2,
          marginBottom: 64,
          position: "relative",
        }}>
          {layers.map(({ icon: Icon, label, desc }, i) => (
            <div key={label} style={{
              background: "#0F1117",
              border: "1px solid #1E2335",
              borderRadius: i === 0 ? "12px 0 0 12px" : i === layers.length - 1 ? "0 12px 12px 0" : "0",
              padding: "32px 24px",
              position: "relative",
              textAlign: "center",
            }}>
              {/* Step number */}
              <div style={{
                position: "absolute", top: 16, right: 16,
                fontSize: 11, color: "#1E2335", fontWeight: 700, letterSpacing: "0.06em",
              }}>0{i + 1}</div>

              <div style={{
                width: 52, height: 52,
                background: "rgba(0,163,255,0.08)",
                border: "1px solid rgba(0,163,255,0.2)",
                borderRadius: 12,
                display: "flex", alignItems: "center", justifyContent: "center",
                margin: "0 auto 20px",
              }}>
                <Icon size={24} style={{ color: "#00A3FF" }} />
              </div>

              <h3 style={{
                fontSize: "1.2rem", fontWeight: 700, color: "#ffffff",
                letterSpacing: "-0.02em", marginBottom: 10,
              }}>
                {label}
              </h3>
              <p style={{ fontSize: 13.5, color: "#8892A4", lineHeight: 1.65 }}>{desc}</p>

              {/* Connector arrow */}
              {i < layers.length - 1 && (
                <div style={{
                  position: "absolute",
                  right: -12, top: "50%",
                  transform: "translateY(-50%)",
                  zIndex: 2,
                  background: "#000000",
                  border: "1px solid #1E2335",
                  borderRadius: "50%",
                  width: 24, height: 24,
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}>
                  <ArrowRight size={12} style={{ color: "#00A3FF" }} />
                </div>
              )}
            </div>
          ))}
        </div>

        {/* What it protects */}
        <div style={{
          background: "#0F1117",
          border: "1px solid #1E2335",
          borderRadius: 16,
          padding: "40px",
        }}>
          <div style={{ textAlign: "center", marginBottom: 32 }}>
            <p style={{ fontSize: 12, fontWeight: 700, color: "#00A3FF", letterSpacing: "0.1em", textTransform: "uppercase" }}>
              Cross-Layer AI Security Context
            </p>
          </div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
            gap: 16,
          }}>
            {protects.map(({ icon: Icon, label }) => (
              <div key={label} style={{
                background: "#12151E",
                border: "1px solid #1E2335",
                borderRadius: 10,
                padding: "16px",
                display: "flex",
                alignItems: "center",
                gap: 10,
                transition: "border-color 0.2s",
              }}
                onMouseEnter={(e) => (e.currentTarget.style.borderColor = "rgba(0,163,255,0.3)")}
                onMouseLeave={(e) => (e.currentTarget.style.borderColor = "#1E2335")}
              >
                <Icon size={16} style={{ color: "#00A3FF", flexShrink: 0 }} />
                <span style={{ fontSize: 13, color: "#8892A4", fontWeight: 500, lineHeight: 1.3 }}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ textAlign: "center", marginTop: 40 }}>
          <Link href="/platform" className="btn-ghost">
            Explore the Full Platform <ArrowRight size={15} />
          </Link>
        </div>
      </div>
    </section>
  );
}
