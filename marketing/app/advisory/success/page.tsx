import Link from "next/link";
import { CheckCircle2, ArrowRight, Mail } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Order Confirmed | CyberArmor AI Advisory",
  robots: { index: false },
};

export default function SuccessPage() {
  return (
    <div style={{ backgroundColor: "#000000", minHeight: "100vh", display: "flex", alignItems: "center" }}>
      <div className="container-wide" style={{ maxWidth: 600, margin: "0 auto", textAlign: "center", padding: "6rem 24px" }}>
        <div style={{
          width: 80, height: 80, background: "rgba(34,197,94,0.1)",
          border: "1px solid rgba(34,197,94,0.3)", borderRadius: "50%",
          display: "flex", alignItems: "center", justifyContent: "center",
          margin: "0 auto 32px",
        }}>
          <CheckCircle2 size={40} style={{ color: "#22C55E" }} />
        </div>

        <h1 style={{
          fontSize: "clamp(1.8rem, 4vw, 2.4rem)", fontWeight: 800,
          letterSpacing: "-0.04em", color: "#ffffff", marginBottom: 16,
        }}>
          Payment Confirmed
        </h1>

        <p style={{ fontSize: "1.05rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 12 }}>
          Thank you for your purchase. You&apos;ll receive a confirmation email shortly with instructions
          on how to submit your intake information.
        </p>

        <p style={{ fontSize: "1.05rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 40 }}>
          All deliverables are sent via email as PDF documents within the stated turnaround window.
          If you have any questions, reach out directly at{" "}
          <a href="mailto:hello@cyberarmor.ai" style={{ color: "#00A3FF", textDecoration: "none" }}>
            hello@cyberarmor.ai
          </a>
        </p>

        <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
          <a href="mailto:hello@cyberarmor.ai" style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "12px 24px", borderRadius: 8,
            background: "rgba(0,163,255,0.1)", border: "1px solid rgba(0,163,255,0.3)",
            color: "#00A3FF", fontWeight: 600, fontSize: 15, textDecoration: "none",
          }}>
            <Mail size={15} /> Email Us
          </a>
          <Link href="/advisory" style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "12px 24px", borderRadius: 8,
            background: "transparent", border: "1px solid #1E2335",
            color: "#8892A4", fontWeight: 600, fontSize: 15, textDecoration: "none",
          }}>
            View Services <ArrowRight size={15} />
          </Link>
        </div>
      </div>
    </div>
  );
}
