"use client";

import Link from "next/link";
import { X, Globe, Mail } from "lucide-react";

const footerLinks = {
  Platform: [
    { label: "Overview", href: "/platform" },
    { label: "AI Runtime Protection", href: "/platform#runtime" },
    { label: "Policy Enforcement", href: "/platform#policy" },
    { label: "Evidence & Trust", href: "/platform#evidence" },
  ],
  Solutions: [
    { label: "Shadow AI Discovery", href: "/solutions#shadow-ai" },
    { label: "AI Agent Security", href: "/solutions#agents" },
    { label: "Data Protection", href: "/solutions#data" },
    { label: "Prompt Injection Defense", href: "/solutions#prompt" },
  ],
  Industries: [
    { label: "Financial Services", href: "/industries#financial" },
    { label: "Healthcare", href: "/industries#healthcare" },
    { label: "Insurance", href: "/industries#insurance" },
    { label: "Technology", href: "/industries#technology" },
  ],
  Company: [
    { label: "About", href: "/about" },
    { label: "Contact", href: "/contact" },
    { label: "Request Demo", href: "/contact" },
  ],
};

export default function Footer() {
  return (
    <footer style={{ backgroundColor: "#000000", borderTop: "1px solid #1E2335" }}>
      {/* Top glow */}
      <div className="glow-line" />

      <div className="container-wide" style={{ paddingTop: "4rem", paddingBottom: "2rem" }}>
        {/* Top row */}
        <div className="footer-grid" style={{ display: "grid", gridTemplateColumns: "1fr", gap: "3rem", marginBottom: "3rem" }}>

          {/* Brand col */}
          <div style={{ gridColumn: "span 1" }}>
            <Link href="/" style={{ display: "flex", alignItems: "center", gap: 8, textDecoration: "none", marginBottom: 16 }}>
              <div style={{
                width: 36, height: 36,
                borderRadius: 8, flexShrink: 0,
                border: "1px solid rgba(0,163,255,0.25)",
                boxShadow: "0 0 12px rgba(0,163,255,0.15)",
                backgroundImage: "url('/CyberArmorAI.png')",
                backgroundSize: "145%",
                backgroundPosition: "50% 50%",
                backgroundRepeat: "no-repeat",
              }} />
              <span style={{ fontSize: 16, fontWeight: 700, color: "#ffffff", letterSpacing: "-0.03em" }}>
                CyberArmor<span style={{ color: "#00A3FF" }}>.AI</span>
              </span>
            </Link>
            <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7, marginBottom: 20, maxWidth: 220 }}>
              The AI Security & Cyber Trust Platform for the enterprise.
            </p>
            <div style={{ display: "flex", gap: 10 }}>
              {[
                { icon: X, href: "#", label: "X (Twitter)" },
                { icon: Globe, href: "#", label: "LinkedIn" },
                { icon: Mail, href: "mailto:hello@cyberarmor.ai", label: "Email" },
              ].map(({ icon: Icon, href, label }) => (
                <a key={label} href={href} aria-label={label} style={{
                  width: 36, height: 36,
                  borderRadius: 8,
                  border: "1px solid #1E2335",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  color: "#8892A4",
                  textDecoration: "none",
                  transition: "border-color 0.2s, color 0.2s",
                }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLElement).style.borderColor = "rgba(0,163,255,0.4)";
                    (e.currentTarget as HTMLElement).style.color = "#00A3FF";
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLElement).style.borderColor = "#1E2335";
                    (e.currentTarget as HTMLElement).style.color = "#8892A4";
                  }}
                >
                  <Icon size={15} />
                </a>
              ))}
            </div>
          </div>

          {/* Link columns */}
          {Object.entries(footerLinks).map(([title, links]) => (
            <div key={title}>
              <p style={{ fontSize: 12, fontWeight: 700, color: "#ffffff", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 16 }}>
                {title}
              </p>
              <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 10 }}>
                {links.map((l) => (
                  <li key={l.label}>
                    <Link href={l.href} style={{
                      fontSize: 14, color: "#8892A4", textDecoration: "none",
                      transition: "color 0.2s",
                    }}
                      onMouseEnter={(e) => (e.currentTarget.style.color = "#ffffff")}
                      onMouseLeave={(e) => (e.currentTarget.style.color = "#8892A4")}
                    >
                      {l.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom row */}
        <div className="glow-line" style={{ marginBottom: 24 }} />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
          <p style={{ fontSize: 13, color: "#4A5568" }}>
            © {new Date().getFullYear()} CyberArmor AI, Inc. All rights reserved. Patent-pending innovations.
          </p>
          <div style={{ display: "flex", gap: 24 }}>
            {["Privacy Policy", "Terms of Service", "Security"].map((t) => (
              <Link key={t} href="#" style={{ fontSize: 13, color: "#4A5568", textDecoration: "none", transition: "color 0.2s" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "#8892A4")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "#4A5568")}
              >
                {t}
              </Link>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}
