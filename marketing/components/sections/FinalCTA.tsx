import Link from "next/link";
import { ArrowRight, Calendar, MessageSquare } from "lucide-react";

export default function FinalCTA() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#000000", position: "relative", overflow: "hidden" }}>
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(ellipse 80% 60% at 50% 50%, rgba(0,163,255,0.06) 0%, transparent 65%)",
        pointerEvents: "none",
      }} />
      <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.3, pointerEvents: "none" }} />

      <div className="container-wide" style={{ position: "relative" }}>
        <div style={{
          maxWidth: 800,
          margin: "0 auto",
          textAlign: "center",
          padding: "80px 40px",
          background: "#0F1117",
          border: "1px solid #1E2335",
          borderRadius: 24,
          position: "relative",
          overflow: "hidden",
        }}>
          {/* Top glow bar */}
          <div style={{
            position: "absolute", top: 0, left: "10%", right: "10%", height: 2,
            background: "linear-gradient(90deg, transparent, #00A3FF, transparent)",
          }} />

          {/* Corner accents */}
          <div style={{
            position: "absolute", top: -1, left: -1, width: 60, height: 60,
            borderTop: "2px solid rgba(0,163,255,0.4)",
            borderLeft: "2px solid rgba(0,163,255,0.4)",
            borderRadius: "24px 0 0 0",
          }} />
          <div style={{
            position: "absolute", bottom: -1, right: -1, width: 60, height: 60,
            borderBottom: "2px solid rgba(0,163,255,0.4)",
            borderRight: "2px solid rgba(0,163,255,0.4)",
            borderRadius: "0 0 24px 0",
          }} />

          <div className="label-tag" style={{ marginBottom: 24, display: "inline-flex" }}>
            Get Started
          </div>

          <h2 style={{
            fontSize: "clamp(2rem, 4vw, 3rem)",
            fontWeight: 800,
            letterSpacing: "-0.04em",
            lineHeight: 1.1,
            marginBottom: 20,
            color: "#ffffff",
          }}>
            Ready to Secure Your Enterprise AI?
            <br />
            <span className="gradient-text-blue">Let&apos;s Talk.</span>
          </h2>

          <p style={{
            fontSize: "1.1rem",
            color: "#8892A4",
            lineHeight: 1.7,
            maxWidth: 560,
            margin: "0 auto 40px",
          }}>
            See how CyberArmor AI maps to your environment, your risks, and your security program.
            We talk to CISOs, architects, and security leaders — not to sell you something, but to help you
            understand what&apos;s actually at stake.
          </p>

          <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
            <Link href="/contact" className="btn-primary" style={{ padding: "14px 36px", fontSize: 16 }}>
              <Calendar size={16} />
              Request a Demo
            </Link>
            <Link href="/contact" className="btn-ghost" style={{ padding: "13px 32px", fontSize: 15 }}>
              <MessageSquare size={15} />
              Talk to an Expert
            </Link>
          </div>

          <p style={{ fontSize: 13, color: "#4A5568", marginTop: 24 }}>
            No spam. No hard sell. We respond within one business day.
          </p>
        </div>
      </div>
    </section>
  );
}
