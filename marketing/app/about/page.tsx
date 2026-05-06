import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Shield, Target, Eye, FileCheck, Zap } from "lucide-react";
import FinalCTA from "@/components/sections/FinalCTA";
import FounderCredibility from "@/components/sections/FounderCredibility";
import BrandClarification from "@/components/sections/BrandClarification";

export const metadata: Metadata = {
  title: "About — CyberArmor.AI",
  description:
    "CyberArmor.AI is the AI security runtime operated by CyberArmor AI, Inc., built to make enterprise AI activity controllable, enforceable, and provable.",
};

const values = [
  {
    icon: Target,
    title: "Control Over Coverage Theater",
    body: "We build controls that can act, not diagrams that only imply coverage. Every capability should map to a demonstrable AI security workflow: inspect, decide, enforce, respond, or prove.",
  },
  {
    icon: Eye,
    title: "Transparency in Everything We Do",
    body: "We don't overclaim. We don't hype. We tell enterprises exactly what the platform does, what it doesn't yet do, and where we're taking it. Our customers make security decisions — they deserve accurate information.",
  },
  {
    icon: Shield,
    title: "Enterprise-Grade Rigor",
    body: "We build for production environments, not POC labs. That means real integration complexity, real operational constraints, and real security requirements. We hold our own engineering to the standard we ask our customers to hold their AI systems.",
  },
  {
    icon: FileCheck,
    title: "Protection-Backed Accountability",
    body: "Evidence matters most when it is bound to a control decision. We build for records that explain who or what acted, which policy applied, what response ran, and why.",
  },
  {
    icon: Zap,
    title: "Category Conviction",
    body: "We believe AI security is becoming one of the most consequential security categories of the next decade. We're building accordingly — with the architecture, the defensibility, and the long-term vision to lead it.",
  },
];

export default function AboutPage() {
  return (
    <div style={{ backgroundColor: "#000000" }}>
      {/* Hero */}
      <section style={{ paddingTop: "10rem", paddingBottom: "6rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.08) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />
        <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.25 }} />

        <div className="container-wide" style={{ position: "relative" }}>
          <div style={{ maxWidth: 800 }}>
            <div className="label-tag" style={{ marginBottom: 20, display: "inline-flex" }}>
              <Shield size={12} /> About CyberArmor.AI
            </div>

            <h1 style={{
              fontSize: "clamp(2.4rem, 5vw, 3.8rem)",
              fontWeight: 800, letterSpacing: "-0.04em", lineHeight: 1.08,
              marginBottom: 28, color: "#ffffff",
            }}>
              We&apos;re Building the AI Security Runtime<br />
              <span className="gradient-text-blue">Enterprise AI Needs.</span>
            </h1>

            <p style={{ fontSize: "1.15rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 24, maxWidth: 700 }}>
              CyberArmor.AI was founded on a straightforward observation: enterprise AI adoption is accelerating at a
              pace that the security industry was not built to address. Existing tools — SIEM, DLP, endpoint protection,
              network security — were designed for a world without autonomous AI agents, large language models, and
              AI-powered workflows that cross every trust boundary the enterprise spent years establishing.
            </p>

            <p style={{ fontSize: "1.15rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 24, maxWidth: 700 }}>
              The gap between AI adoption speed and AI security capability is real, growing, and creating risk at
              board-level scale. We built CyberArmor.AI to close that gap with runtime controls that inspect AI
              activity, enforce policy, redact or block risky content in supported paths, route approved provider
              traffic, and preserve decision-level evidence.
            </p>

            <p style={{ fontSize: "1.15rem", color: "#ffffff", lineHeight: 1.8, maxWidth: 700, fontWeight: 500 }}>
              This is not a dashboard company. This is not AI governance theater. CyberArmor.AI is a technical
              security runtime built for CISOs, AppSec teams, security architects, and operators who need controls
              they can enforce and evidence they can defend.
            </p>
          </div>
        </div>
      </section>

      <FounderCredibility compact />

      {/* Mission */}
      <section style={{ padding: "5rem 0", backgroundColor: "#050508" }}>
        <div className="container-wide">
          <div className="about-mission-grid" style={{
            display: "grid", gridTemplateColumns: "1fr 1fr", gap: 64, alignItems: "center",
          }}>
            <div>
              <div className="label-tag" style={{ marginBottom: 20 }}>Our Mission</div>
              <h2 className="section-headline" style={{ marginBottom: 24 }}>
                Make Enterprise AI Controllable.<br />
                <span className="gradient-text-blue">Make Trust Provable.</span>
              </h2>
              <p style={{ fontSize: "1.05rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 20 }}>
                Our mission is to help enterprises adopt AI with confidence by making AI activity controllable,
                attributable, and provable across users, applications, agents, APIs, providers, models, and data.
              </p>
              <p style={{ fontSize: "1.05rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 32 }}>
                We believe evidence without control is weak, and control without evidence is operationally dangerous.
                The enterprises that can show how AI requests were inspected, routed, redacted, blocked, allowed,
                and recorded will move faster with less ambiguity than teams relying on policy documents alone.
              </p>
              <Link href="/contact" className="btn-primary">
                Talk to Our Team <ArrowRight size={16} />
              </Link>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {[
                { label: "AI Security Runtime", desc: "Detection, policy, routing, identity, enforcement, response, and evidence" },
                { label: "Patent-Pending Architecture", desc: "Protection-backed evidence, AI trust verification, and cross-layer control" },
                { label: "Enterprise-Focused", desc: "Built for production complexity, not controlled demos" },
                { label: "Honest Product Maturity", desc: "Clear boundaries between pilot-ready capabilities and roadmap expansion" },
              ].map(({ label, desc }) => (
                <div key={label} style={{
                  background: "#0F1117",
                  border: "1px solid #1E2335",
                  borderRadius: 12,
                  padding: "20px 24px",
                  display: "flex",
                  alignItems: "center",
                  gap: 16,
                }}>
                  <div style={{
                    width: 8, height: 8, borderRadius: "50%",
                    background: "#00A3FF",
                    boxShadow: "0 0 10px rgba(0,163,255,0.5)",
                    flexShrink: 0,
                  }} />
                  <div>
                    <p style={{ fontSize: 14, fontWeight: 700, color: "#ffffff", marginBottom: 4 }}>{label}</p>
                    <p style={{ fontSize: 13, color: "#8892A4" }}>{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Values */}
      <section className="section-padding" style={{ backgroundColor: "#000000" }}>
        <div className="container-wide">
          <div style={{ textAlign: "center", maxWidth: 640, margin: "0 auto 56px" }}>
            <div className="label-tag" style={{ display: "inline-flex", marginBottom: 16 }}>What We Stand For</div>
            <h2 className="section-headline" style={{ marginBottom: 16 }}>
              How We Build.<br />
              <span className="gradient-text-blue">Why It Matters.</span>
            </h2>
          </div>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
            gap: 24,
          }}>
            {values.map(({ icon: Icon, title, body }) => (
              <div key={title} className="card-base" style={{ padding: "32px 28px" }}>
                <div style={{
                  width: 46, height: 46,
                  background: "rgba(0,163,255,0.08)",
                  border: "1px solid rgba(0,163,255,0.15)",
                  borderRadius: 10,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  marginBottom: 20,
                }}>
                  <Icon size={20} style={{ color: "#00A3FF" }} />
                </div>
                <h3 style={{
                  fontSize: "1rem", fontWeight: 700, color: "#ffffff",
                  letterSpacing: "-0.02em", marginBottom: 12, lineHeight: 1.3,
                }}>
                  {title}
                </h3>
                <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7 }}>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Patent note */}
      <section style={{ padding: "4rem 0", backgroundColor: "#050508" }}>
        <div className="container-wide">
          <div style={{
            background: "rgba(0,163,255,0.05)",
            border: "1px solid rgba(0,163,255,0.15)",
            borderRadius: 16,
            padding: "40px 48px",
            display: "flex",
            gap: 32,
            alignItems: "center",
          }}>
            <div style={{
              width: 64, height: 64,
              background: "rgba(0,163,255,0.1)",
              border: "1px solid rgba(0,163,255,0.2)",
              borderRadius: 16,
              display: "flex", alignItems: "center", justifyContent: "center",
              flexShrink: 0,
            }}>
              <FileCheck size={28} style={{ color: "#00A3FF" }} />
            </div>
            <div>
              <h3 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#ffffff", marginBottom: 10 }}>
                Patent-Pending Innovations
              </h3>
              <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7, maxWidth: 760 }}>
                CyberArmor.AI&apos;s core architectural innovations — including our approach to AI trust verification,
                protection-backed evidence, runtime policy enforcement, and cross-layer security operationalization —
                are the subject of patent applications currently in process. These innovations represent the
                foundational differentiators of the CyberArmor.AI platform and reflect our commitment to building
                a technically defensible, category-defining security capability.
              </p>
            </div>
          </div>
        </div>
      </section>

      <BrandClarification />

      <FinalCTA />
    </div>
  );
}
