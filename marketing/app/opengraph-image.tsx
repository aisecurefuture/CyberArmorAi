import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "CyberArmor.AI — AI Security Runtime for Governed Enterprise AI";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function OGImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: 1200,
          height: 630,
          backgroundColor: "#000000",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          fontFamily: "system-ui, -apple-system, sans-serif",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Background glow */}
        <div
          style={{
            position: "absolute",
            top: -100,
            left: "50%",
            transform: "translateX(-50%)",
            width: 800,
            height: 500,
            borderRadius: "50%",
            background: "radial-gradient(ellipse, rgba(0,163,255,0.12) 0%, transparent 70%)",
            display: "flex",
          }}
        />

        {/* Grid dots pattern */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage: "radial-gradient(rgba(0,163,255,0.08) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
            display: "flex",
          }}
        />

        {/* Top accent line */}
        <div
          style={{
            position: "absolute",
            top: 0,
            left: "20%",
            right: "20%",
            height: 3,
            background: "linear-gradient(90deg, transparent, #00A3FF, transparent)",
            display: "flex",
          }}
        />

        {/* Logo + wordmark row */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
            marginBottom: 40,
          }}
        >
          {/* Shield icon placeholder — gradient box */}
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 14,
              background: "linear-gradient(135deg, #00A3FF 0%, #0044CC 100%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 30px rgba(0,163,255,0.4)",
            }}
          >
            {/* Simple shield shape via text */}
            <div style={{ fontSize: 28, display: "flex" }}>🛡</div>
          </div>
          <div
            style={{
              fontSize: 32,
              fontWeight: 800,
              color: "#ffffff",
              letterSpacing: "-0.03em",
              display: "flex",
            }}
          >
            CyberArmor
            <span style={{ color: "#00A3FF" }}>.AI</span>
          </div>
        </div>

        {/* Main headline */}
        <div
          style={{
            fontSize: 64,
            fontWeight: 800,
            color: "#ffffff",
            letterSpacing: "-0.04em",
            lineHeight: 1.05,
            textAlign: "center",
            maxWidth: 960,
            marginBottom: 24,
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "center",
          }}
        >
          Govern, Protect, and&nbsp;
          <span
            style={{
              background: "linear-gradient(135deg, #00A3FF, #60C8FF)",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Prove Trust
          </span>
          &nbsp;Across Enterprise AI.
        </div>

        {/* Subheadline */}
        <div
          style={{
            fontSize: 22,
            color: "#8892A4",
            textAlign: "center",
            maxWidth: 780,
            lineHeight: 1.5,
            marginBottom: 48,
            display: "flex",
          }}
        >
          The unified AI Security & Cyber Trust Platform — built for CISOs, security architects, and enterprise security teams.
        </div>

        {/* Badge row */}
        <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
          {["AI Runtime Protection", "Shadow AI Discovery", "Patent-Pending Architecture", "Evidence-Based Trust"].map(
            (tag) => (
              <div
                key={tag}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  background: "rgba(0,163,255,0.08)",
                  border: "1px solid rgba(0,163,255,0.25)",
                  borderRadius: 100,
                  padding: "8px 18px",
                  fontSize: 13,
                  fontWeight: 700,
                  color: "#00A3FF",
                  letterSpacing: "0.04em",
                  textTransform: "uppercase",
                }}
              >
                {tag}
              </div>
            )
          )}
        </div>

        {/* Domain watermark */}
        <div
          style={{
            position: "absolute",
            bottom: 32,
            right: 48,
            fontSize: 15,
            color: "#1E2335",
            fontWeight: 600,
            letterSpacing: "0.02em",
            display: "flex",
          }}
        >
          cyberarmor.ai
        </div>

        {/* Bottom accent line */}
        <div
          style={{
            position: "absolute",
            bottom: 0,
            left: "20%",
            right: "20%",
            height: 2,
            background: "linear-gradient(90deg, transparent, rgba(0,163,255,0.3), transparent)",
            display: "flex",
          }}
        />
      </div>
    ),
    { ...size }
  );
}
