"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Shield, FileText, MessageSquare, BookOpen, Star,
  CheckCircle, XCircle, ArrowRight, Clock, Lock, Zap
} from "lucide-react";

const tiers = [
  {
    id: "checklist",
    icon: BookOpen,
    label: "Starter",
    name: "AI Security Executive Checklist",
    price: "$29",
    priceNote: "one-time",
    turnaround: "Instant download",
    description: "A concise decision-support checklist for leaders reviewing AI tools, vendor claims, or new internal use cases.",
    includes: [
      "AI usage risk checklist",
      "Shadow AI warning signs",
      "Vendor evaluation questions",
      "Sensitive data red flags",
      "Executive decision framework",
      "Sample AI policy starter language",
    ],
    excludes: [
      "Advisory or review",
      "Legal or compliance opinion",
    ],
    cta: "Download Now",
    ctaType: "checkout",
    priceKey: "CHECKLIST",
    highlight: false,
  },
  {
    id: "snapshot",
    icon: Zap,
    label: "Report",
    name: "AI Risk Snapshot",
    price: "$97",
    priceNote: "one-time",
    turnaround: "3–5 business days",
    description: "A written review of up to 3 AI use cases with risk classification and practical next-step guidance.",
    includes: [
      "Review of up to 3 AI use cases",
      "Low / medium / high risk classification",
      "One-page written summary",
      "Top 5 practical recommendations",
      "100% async — submit a form, receive a written report",
    ],
    excludes: [
      "Calls or meetings",
      "Implementation or remediation",
      "Legal or compliance opinion",
    ],
    cta: "Get Risk Snapshot",
    ctaType: "checkout",
    priceKey: "SNAPSHOT",
    highlight: false,
  },
  {
    id: "qa",
    icon: MessageSquare,
    label: "Written Q&A",
    name: "AI Security Written Q&A",
    price: "$497",
    priceNote: "one-time",
    turnaround: "5 business days",
    description: "Submit targeted AI security questions and receive one structured written response set for executive or team use.",
    includes: [
      "Submit up to 5 specific questions",
      "Structured written response per question",
      "One round of Q&A (no back-and-forth)",
      "Delivered via email as a PDF brief",
      "100% async",
    ],
    excludes: [
      "Calls or meetings",
      "Multiple rounds of Q&A",
      "Implementation support",
      "Legal or compliance opinion",
    ],
    cta: "Get Written Q&A",
    ctaType: "checkout",
    priceKey: "QA",
    highlight: false,
  },
  {
    id: "brief",
    icon: FileText,
    label: "Most Popular",
    name: "Executive AI Security Brief",
    price: "$1,500",
    priceNote: "one-time",
    turnaround: "5–7 business days",
    description: "A boardroom-ready written brief for leaders deciding whether to build, buy, deploy, or scale AI capabilities.",
    includes: [
      "Review of up to 5 AI workflows, vendors, or product concepts",
      "AI risk map",
      "Vendor and governance questions",
      "Data exposure considerations",
      "Prompt injection and output-risk analysis",
      "30-day risk-reduction roadmap",
      "5–8 page executive brief (PDF)",
      "100% async — intake form + written delivery",
    ],
    excludes: [
      "Mandatory calls (optional async clarification only)",
      "Penetration testing or security audits",
      "Legal or compliance certification",
      "Production system access",
      "Implementation or remediation",
    ],
    cta: "Get Executive Brief",
    ctaType: "checkout",
    priceKey: "BRIEF",
    highlight: true,
  },
  {
    id: "advisory",
    icon: Star,
    label: "Application Only",
    name: "Priority Async Advisory",
    price: "$3,000",
    priceNote: "/ month",
    turnaround: "Response within 2 business days",
    description: "Ongoing written AI security advisory access for leaders who need decision support without a traditional consulting engagement.",
    includes: [
      "Up to 4 written advisory requests per month",
      "Strategy, vendor, policy, and executive material reviews",
      "Monthly AI risk prioritization memo",
      "Email-based async communication",
      "Response within 2 business days",
    ],
    excludes: [
      "Emergency response or 24/7 availability",
      "Production system access or hands-on remediation",
      "Employer-conflicting engagements",
      "Legal or compliance certification",
      "Mandatory calls or meetings",
    ],
    cta: "Apply Now",
    ctaType: "apply",
    priceKey: "ADVISORY",
    highlight: false,
  },
];

const boundaries = [
  "No legal advice or compliance certification",
  "No penetration testing or security audits",
  "No production system access",
  "No incident response or emergency support",
  "No work conflicting with employer obligations",
  "No managed security services",
];

export default function AdvisoryPage() {
  const [loadingTier, setLoadingTier] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheckout = async (priceKey: string, tierId: string) => {
    setLoadingTier(tierId);
    setError(null);
    try {
      const res = await fetch("/api/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ priceKey }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Checkout failed");
      window.location.href = data.url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setLoadingTier(null);
    }
  };

  return (
    <div style={{ backgroundColor: "#000000" }}>
      {/* Hero */}
      <section style={{ paddingTop: "8rem", paddingBottom: "5rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.08) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />
        <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.2 }} />

        <div className="container-wide" style={{ position: "relative", textAlign: "center" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 24 }}>
            <Shield size={12} /> Advisory Services
          </div>
          <h1 style={{
            fontSize: "clamp(2.2rem, 5vw, 3.5rem)",
            fontWeight: 800,
            letterSpacing: "-0.04em",
            lineHeight: 1.1,
            color: "#ffffff",
            marginBottom: 20,
            maxWidth: 800,
            margin: "0 auto 20px",
          }}>
            Independent AI Security Advisory.<br />
            <span className="gradient-text-blue">Written. Fixed-Scope. Executive-Ready.</span>
          </h1>
          <p style={{
            fontSize: "1.15rem",
            color: "#8892A4",
            lineHeight: 1.8,
            maxWidth: 640,
            margin: "0 auto 16px",
          }}>
            Independent AI security guidance for executives, founders, and
            security leaders making decisions about AI adoption, vendor risk,
            policy, and governance. Every engagement is written, fixed-scope,
            and delivered asynchronously.
          </p>
          <p style={{ fontSize: 13, color: "#4A5568", maxWidth: 560, margin: "0 auto" }}>
            Designed for leaders who want clear thinking, bounded deliverables,
            and practical decision support without a long consulting cycle.
          </p>
        </div>
      </section>

      {/* Offer Tiers */}
      <section style={{ paddingBottom: "6rem" }}>
        <div className="container-wide">
          {error && (
            <div style={{
              background: "rgba(248,113,113,0.08)",
              border: "1px solid rgba(248,113,113,0.3)",
              borderRadius: 10,
              padding: "12px 20px",
              marginBottom: 32,
              color: "#F87171",
              fontSize: 14,
              textAlign: "center",
            }}>
              {error}
            </div>
          )}

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
            gap: 24,
            marginBottom: 64,
          }}>
            {tiers.map((tier) => {
              const Icon = tier.icon;
              const isLoading = loadingTier === tier.id;

              return (
                <div
                  key={tier.id}
                  style={{
                    background: tier.highlight ? "linear-gradient(135deg, #0A1628 0%, #0D1F3C 100%)" : "#0A0E1A",
                    border: tier.highlight ? "1px solid rgba(0,163,255,0.4)" : "1px solid #1E2335",
                    borderRadius: 16,
                    padding: 32,
                    display: "flex",
                    flexDirection: "column",
                    position: "relative",
                    boxShadow: tier.highlight ? "0 0 40px rgba(0,163,255,0.08)" : "none",
                  }}
                >
                  {/* Label badge */}
                  <div style={{
                    position: "absolute",
                    top: -12,
                    left: 24,
                    background: tier.highlight ? "#00A3FF" : tier.label === "Application Only" ? "#7C3AED" : "#1E2335",
                    color: "#ffffff",
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: "0.08em",
                    padding: "4px 12px",
                    borderRadius: 20,
                    textTransform: "uppercase",
                  }}>
                    {tier.label}
                  </div>

                  {/* Icon + Name */}
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, marginTop: 8 }}>
                    <div style={{
                      width: 40, height: 40,
                      background: "rgba(0,163,255,0.08)",
                      border: "1px solid rgba(0,163,255,0.15)",
                      borderRadius: 10,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      flexShrink: 0,
                    }}>
                      <Icon size={18} style={{ color: "#00A3FF" }} />
                    </div>
                    <h3 style={{ fontSize: 15, fontWeight: 700, color: "#ffffff", letterSpacing: "-0.02em" }}>
                      {tier.name}
                    </h3>
                  </div>

                  {/* Price */}
                  <div style={{ marginBottom: 12 }}>
                    <span style={{ fontSize: 36, fontWeight: 800, color: "#ffffff", letterSpacing: "-0.04em" }}>
                      {tier.price}
                    </span>
                    <span style={{ fontSize: 14, color: "#8892A4", marginLeft: 6 }}>{tier.priceNote}</span>
                  </div>

                  {/* Turnaround */}
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 16 }}>
                    <Clock size={13} style={{ color: "#00A3FF", flexShrink: 0 }} />
                    <span style={{ fontSize: 13, color: "#8892A4" }}>{tier.turnaround}</span>
                  </div>

                  {/* Description */}
                  <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7, marginBottom: 24 }}>
                    {tier.description}
                  </p>

                  {/* Includes */}
                  <div style={{ marginBottom: 20, flex: 1 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: "#4A5568", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 10 }}>
                      Includes
                    </p>
                    {tier.includes.map((item) => (
                      <div key={item} style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 8 }}>
                        <CheckCircle size={13} style={{ color: "#22C55E", flexShrink: 0, marginTop: 2 }} />
                        <span style={{ fontSize: 13, color: "#8892A4", lineHeight: 1.5 }}>{item}</span>
                      </div>
                    ))}
                  </div>

                  {/* Excludes */}
                  <div style={{ marginBottom: 28 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: "#4A5568", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 10 }}>
                      Not included
                    </p>
                    {tier.excludes.map((item) => (
                      <div key={item} style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 6 }}>
                        <XCircle size={13} style={{ color: "#4A5568", flexShrink: 0, marginTop: 2 }} />
                        <span style={{ fontSize: 13, color: "#4A5568", lineHeight: 1.5 }}>{item}</span>
                      </div>
                    ))}
                  </div>

                  {/* CTA */}
                  {tier.ctaType === "apply" ? (
                    <Link
                      href="/advisory/apply"
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: 8,
                        padding: "13px 20px",
                        borderRadius: 8,
                        background: "rgba(124,58,237,0.15)",
                        border: "1px solid rgba(124,58,237,0.4)",
                        color: "#A78BFA",
                        fontWeight: 700,
                        fontSize: 15,
                        textDecoration: "none",
                        transition: "all 0.2s",
                        cursor: "pointer",
                      }}
                    >
                      {tier.cta} <ArrowRight size={15} />
                    </Link>
                  ) : (
                    <button
                      onClick={() => handleCheckout(tier.priceKey, tier.id)}
                      disabled={!!loadingTier}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        gap: 8,
                        padding: "13px 20px",
                        borderRadius: 8,
                        background: tier.highlight ? "linear-gradient(135deg, #00A3FF, #0066FF)" : "rgba(0,163,255,0.1)",
                        border: tier.highlight ? "none" : "1px solid rgba(0,163,255,0.3)",
                        color: "#ffffff",
                        fontWeight: 700,
                        fontSize: 15,
                        cursor: loadingTier ? "not-allowed" : "pointer",
                        opacity: loadingTier && !isLoading ? 0.5 : 1,
                        transition: "all 0.2s",
                        width: "100%",
                      }}
                    >
                      {isLoading ? "Redirecting..." : tier.cta}
                      {!isLoading && <ArrowRight size={15} />}
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {/* Global boundaries */}
          <div style={{
            background: "#0A0E1A",
            border: "1px solid #1E2335",
            borderRadius: 16,
            padding: "40px 48px",
            maxWidth: 860,
            margin: "0 auto 64px",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
              <Lock size={16} style={{ color: "#00A3FF" }} />
              <h3 style={{ fontSize: 16, fontWeight: 700, color: "#ffffff" }}>
                Scope & Boundary Statement — All Engagements
              </h3>
            </div>
            <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7, marginBottom: 20 }}>
              CyberArmor AI advisory services are independent and do not involve access to client systems, production environments, or confidential infrastructure.
              All deliverables are written documents — advisory opinions, not legal advice, compliance certification, or security guarantees.
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px 32px" }}>
              {boundaries.map((b) => (
                <div key={b} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <XCircle size={13} style={{ color: "#4A5568", flexShrink: 0 }} />
                  <span style={{ fontSize: 13, color: "#4A5568" }}>{b}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Trust strip */}
          <div style={{ textAlign: "center" }}>
            <p style={{ fontSize: 13, color: "#4A5568", marginBottom: 8 }}>
              Questions before purchasing? Email us directly.
            </p>
            <a href="mailto:hello@cyberarmor.ai" style={{ color: "#00A3FF", fontSize: 15, fontWeight: 600, textDecoration: "none" }}>
              hello@cyberarmor.ai
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}
