"use client";

import Link from "next/link";
import { ArrowRight, Play, ShieldCheck } from "lucide-react";
import { useEffect, useRef } from "react";

export default function Hero() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();

    const particles: { x: number; y: number; vx: number; vy: number; opacity: number }[] = [];
    for (let i = 0; i < 60; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        opacity: Math.random() * 0.5 + 0.1,
      });
    }

    let raf: number;
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = canvas.width;
        if (p.x > canvas.width) p.x = 0;
        if (p.y < 0) p.y = canvas.height;
        if (p.y > canvas.height) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 163, 255, ${p.opacity})`;
        ctx.fill();
      });

      // Draw connections
      particles.forEach((a, i) => {
        particles.slice(i + 1).forEach((b) => {
          const dist = Math.hypot(a.x - b.x, a.y - b.y);
          if (dist < 100) {
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(0, 163, 255, ${0.05 * (1 - dist / 100)})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        });
      });

      raf = requestAnimationFrame(draw);
    };
    draw();
    window.addEventListener("resize", resize);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);

  return (
    <section style={{
      position: "relative",
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      overflow: "hidden",
      overflowX: "hidden",
      backgroundColor: "#000000",
      maxWidth: "100vw",
    }}>
      {/* Animated particle canvas */}
      <canvas
        ref={canvasRef}
        style={{
          position: "absolute", inset: 0, width: "100%", height: "100%", opacity: 0.7,
        }}
      />

      {/* Radial glow */}
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(ellipse 80% 60% at 50% -5%, rgba(0,163,255,0.12) 0%, transparent 65%)",
        pointerEvents: "none",
      }} />

      {/* Grid pattern */}
      <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.4, pointerEvents: "none" }} />

      <div className="container-wide" style={{ position: "relative", zIndex: 2, paddingTop: "10rem", paddingBottom: "8rem", width: "100%", boxSizing: "border-box" }}>
        <div style={{ maxWidth: 860, margin: "0 auto", textAlign: "center", width: "100%", boxSizing: "border-box" }}>

          {/* Badge */}
          <div style={{ marginBottom: 28, display: "flex", justifyContent: "center", padding: "0 8px" }}>
            <div className="label-tag" style={{ gap: 6, textAlign: "center", whiteSpace: "nowrap", overflow: "hidden", maxWidth: "100%", textOverflow: "ellipsis" }}>
              <ShieldCheck size={11} style={{ flexShrink: 0 }} />
              <span>Patent-pending AI security runtime architecture</span>
            </div>
          </div>

          {/* Hero headline */}
          <h1 className="hero-headline" style={{ marginBottom: 24, color: "#ffffff", maxWidth: "100%" }}>
            Stop hostile web content<br />
            <span className="gradient-text-blue">before it becomes AI context.</span>
          </h1>

          {/* Subheadline */}
          <p style={{
            fontSize: "clamp(1rem, 3.5vw, 1.2rem)",
            color: "#8892A4",
            lineHeight: 1.7,
            maxWidth: 720,
            width: "100%",
            margin: "0 auto 40px",
            overflowWrap: "break-word",
          }}>
            CyberArmor evaluates URLs, web pages, prompts, and agent-bound content
            before humans, browsers, apps, or AI agents trust them — then enforces
            policy and records decision-level evidence. The runtime connects that
            decision to redaction, routing, agent identity, response, and audit.
          </p>

          {/* CTAs */}
          <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap", marginBottom: 56 }}>
            <Link href="/url-trust-gate" className="btn-primary" style={{ padding: "14px 32px", fontSize: 16 }}>
              Run the 15-minute local PoC <ArrowRight size={16} />
            </Link>
            <Link href="/contact" className="btn-ghost" style={{ padding: "13px 32px", fontSize: 16 }}>
              <Play size={15} style={{ color: "#00A3FF" }} />
              Request a Design Partner Pilot
            </Link>
          </div>

          {/* Trust indicators */}
          <div style={{
            display: "flex",
            gap: 32,
            justifyContent: "center",
            flexWrap: "wrap",
          }}>
            {[
              "Pre-ingestion URL trust gate — 15-minute local PoC",
              "Runtime control: redaction, routing, identity, and audit evidence",
              "Built for security-led pilots and design partners",
            ].map((t) => (
              <div key={t} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{
                  width: 6, height: 6, borderRadius: "50%",
                  backgroundColor: "#00A3FF",
                  boxShadow: "0 0 8px rgba(0,163,255,0.6)",
                }} />
                <span style={{ fontSize: 13, color: "#8892A4", fontWeight: 500 }}>{t}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Platform preview card */}
          <div style={{
            marginTop: 80,
            maxWidth: 960,
            margin: "80px auto 0",
            position: "relative",
        }}>
          <div style={{
            position: "absolute",
            top: -20, left: "50%", transform: "translateX(-50%)",
            width: "70%", height: 1,
            background: "linear-gradient(90deg, transparent, rgba(0,163,255,0.5), transparent)",
          }} />
          <div className="hero-preview-shell" style={{
            background: "#0F1117",
            border: "1px solid #1E2335",
            borderRadius: 16,
            padding: "32px",
            position: "relative",
            overflow: "hidden",
          }}>
            {/* Window controls */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 24 }}>
              {["#FF5F57", "#FEBC2E", "#28C840"].map((c) => (
                <div key={c} style={{ width: 12, height: 12, borderRadius: "50%", backgroundColor: c }} />
              ))}
              <div className="hero-preview-url" style={{
                flex: 1,
                height: 28,
                background: "#12151E",
                borderRadius: 6,
                marginLeft: 12,
                display: "flex",
                alignItems: "center",
                paddingLeft: 12,
              }}>
                <span style={{ fontSize: 12, color: "#4A5568" }}>cyberarmor.ai / platform / runtime-control</span>
              </div>
            </div>

            {/* Mock dashboard */}
            <div className="hero-preview-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 20 }}>
              {[
                { label: "Actor", value: "Identified", delta: "Tenant, user, app, agent, provider, and model context", color: "#00A3FF" },
                { label: "Policy", value: "Enforced", delta: "Monitor, warn, block, route, limit, or redact by context", color: "#22C55E" },
                { label: "Evidence", value: "Recorded", delta: "Decision trace for SOC, audit, legal, and leadership", color: "#A855F7" },
              ].map((stat) => (
                <div key={stat.label} style={{
                  background: "#12151E",
                  border: "1px solid #1E2335",
                  borderRadius: 10,
                  padding: "16px 20px",
                }}>
                  <p style={{ fontSize: 11, color: "#4A5568", fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 8 }}>
                    {stat.label}
                  </p>
                  <p style={{ fontSize: 24, fontWeight: 700, color: stat.color, letterSpacing: "-0.03em", marginBottom: 6 }}>
                    {stat.value}
                  </p>
                  <p style={{ fontSize: 12, color: "#8892A4", lineHeight: 1.45 }}>{stat.delta}</p>
                </div>
              ))}
            </div>

            {/* Activity feed mock */}
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {[
                { type: "BLOCKED", msg: "URL trust gate: zero-width promptware detected — AI agent fetch blocked", time: "2s ago", color: "#EF4444" },
                { type: "REDACTED", msg: "Credential removed before AI submission — browser prompt", time: "18s ago", color: "#22C55E" },
                { type: "ROUTED", msg: "Provider policy applied — approved model path selected", time: "1m ago", color: "#00A3FF" },
              ].map((item) => (
                <div key={item.msg} style={{
                  display: "flex", alignItems: "center", gap: 12,
                  background: "#12151E",
                  borderRadius: 8,
                  padding: "10px 14px",
                  border: "1px solid #1E2335",
                }}>
                  <span style={{
                    fontSize: 10, fontWeight: 700, letterSpacing: "0.08em",
                    color: item.color,
                    background: `${item.color}15`,
                    padding: "2px 8px",
                    borderRadius: 4,
                    minWidth: 72,
                    textAlign: "center",
                  }}>{item.type}</span>
                  <span style={{ fontSize: 13, color: "#8892A4", flex: 1 }}>{item.msg}</span>
                  <span style={{ fontSize: 12, color: "#4A5568", whiteSpace: "nowrap" }}>{item.time}</span>
                </div>
              ))}
            </div>

            {/* Bottom glow */}
            <div style={{
              position: "absolute", bottom: 0, left: "50%", transform: "translateX(-50%)",
              width: "60%", height: 80,
              background: "radial-gradient(ellipse at 50% 100%, rgba(0,163,255,0.06) 0%, transparent 70%)",
            }} />
          </div>
        </div>
      </div>
    </section>
  );
}
