"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, X } from "lucide-react";

const navLinks = [
  { label: "Platform", href: "/platform" },
  { label: "URL Trust Gate", href: "/url-trust-gate" },
  { label: "Pilots", href: "/pilots" },
  { label: "Status", href: "/status" },
  { label: "Solutions", href: "/solutions" },
  { label: "Industries", href: "/industries" },
  { label: "About", href: "/about" },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", handler, { passive: true });
    return () => window.removeEventListener("scroll", handler);
  }, []);

  useEffect(() => setMobileOpen(false), [pathname]);

  return (
    <>
      <header
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          zIndex: 50,
          transition: "all 0.3s ease",
          backgroundColor: scrolled ? "rgba(0,0,0,0.85)" : "transparent",
          backdropFilter: scrolled ? "blur(20px)" : "none",
          borderBottom: scrolled ? "1px solid rgba(30,35,53,0.8)" : "1px solid transparent",
        }}
      >
        <div className="container-wide">
          <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", height: "72px" }}>
            {/* Logo */}
            <Link href="/" style={{ display: "flex", alignItems: "center", gap: "8px", textDecoration: "none" }}>
              <div style={{
                width: 42, height: 42,
                borderRadius: 10,
                flexShrink: 0,
                border: "1px solid rgba(0,163,255,0.3)",
                boxShadow: "0 0 18px rgba(0,163,255,0.2), inset 0 0 0 1px rgba(0,163,255,0.1)",
                backgroundImage: "url('/CyberArmorAI.png')",
                backgroundSize: "145%",
                backgroundPosition: "50% 50%",
                backgroundRepeat: "no-repeat",
              }} />
              <span style={{ fontSize: 17, fontWeight: 700, color: "#ffffff", letterSpacing: "-0.03em" }}>
                CyberArmor<span style={{ color: "#00A3FF" }}>.AI</span>
              </span>
            </Link>

            {/* Desktop nav */}
            <div className="nav-desktop" style={{ alignItems: "center", gap: "8px" }}>
              {navLinks.map((l) => (
                <Link
                  key={l.href}
                  href={l.href}
                  style={{
                    padding: "8px 16px",
                    borderRadius: 8,
                    fontSize: 14,
                    fontWeight: 500,
                    color: pathname === l.href ? "#00A3FF" : "#8892A4",
                    textDecoration: "none",
                    transition: "color 0.2s ease",
                    letterSpacing: "-0.01em",
                  }}
                  onMouseEnter={(e) => { if (pathname !== l.href) (e.target as HTMLElement).style.color = "#ffffff"; }}
                  onMouseLeave={(e) => { if (pathname !== l.href) (e.target as HTMLElement).style.color = "#8892A4"; }}
                >
                  {l.label}
                </Link>
              ))}
            </div>

            {/* Desktop CTA */}
            <div className="nav-desktop" style={{ alignItems: "center", gap: 12 }}>
              <Link href="/contact" className="btn-primary" style={{ padding: "10px 22px", fontSize: 14 }}>
                Request Demo
              </Link>
            </div>

            {/* Mobile toggle */}
            <button
              className="nav-mobile-toggle"
              onClick={() => setMobileOpen((v) => !v)}
              style={{ background: "none", border: "none", cursor: "pointer", color: "#ffffff", padding: 8 }}
              aria-label="Toggle menu"
            >
              {mobileOpen ? <X size={22} /> : <Menu size={22} />}
            </button>
          </nav>
        </div>
      </header>

      {/* Mobile menu */}
      {mobileOpen && (
        <div style={{
          position: "fixed", top: 72, left: 0, right: 0, bottom: 0, zIndex: 49,
          backgroundColor: "rgba(0,0,0,0.97)",
          backdropFilter: "blur(20px)",
          borderTop: "1px solid #1E2335",
          padding: "24px",
          display: "flex", flexDirection: "column", gap: 8,
        }}>
          {navLinks.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              style={{
                display: "block",
                padding: "14px 16px",
                borderRadius: 10,
                fontSize: 17,
                fontWeight: 500,
                color: pathname === l.href ? "#00A3FF" : "#ffffff",
                textDecoration: "none",
                backgroundColor: pathname === l.href ? "rgba(0,163,255,0.08)" : "transparent",
                borderLeft: pathname === l.href ? "2px solid #00A3FF" : "2px solid transparent",
              }}
            >
              {l.label}
            </Link>
          ))}
          <div style={{ marginTop: 16 }}>
            <Link href="/contact" className="btn-primary" style={{ width: "100%", justifyContent: "center", fontSize: 16 }}>
              Request a Demo
            </Link>
          </div>
        </div>
      )}
    </>
  );
}
