import { FileSearch, Link2, Clock, Shield, CheckCircle2 } from "lucide-react";

const evidenceItems = [
  { icon: Clock, label: "Timestamped Actions", desc: "AI decisions are logged with precise timestamps and contextual metadata" },
  { icon: Link2, label: "Causality Chains", desc: "Trace relationships across actors, agents, prompts, policy, response, and provider context" },
  { icon: Shield, label: "Policy Attribution", desc: "Enforcement decisions are attributed to rule, identity, data classification, and deployment context" },
  { icon: CheckCircle2, label: "Audit-Ready Records", desc: "Structured evidence output designed for SOC, compliance, legal, and forensic review" },
];

export default function EvidenceLayer() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#000000", position: "relative" }}>
      <div style={{
        position: "absolute", inset: 0,
        background: "radial-gradient(ellipse 70% 50% at 50% 50%, rgba(0,163,255,0.03) 0%, transparent 70%)",
        pointerEvents: "none",
      }} />

      <div className="container-wide" style={{ position: "relative" }}>
        <div className="evidence-grid" style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 64,
          alignItems: "center",
        }}>

          {/* Left: Content */}
          <div>
            <div className="label-tag" style={{ marginBottom: 20 }}>
              <FileSearch size={12} />
              Runtime Evidence & Traceability
            </div>

            <h2 className="section-headline" style={{ marginBottom: 20, maxWidth: 520 }}>
              Not Just Logs.
              <br />
              <span className="gradient-text-blue">Control You Can Prove.</span>
            </h2>

            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7, marginBottom: 32 }}>
              When something goes wrong with AI — and it will — security teams need more than alerts.
              They need a structured, reviewable record of the control decision: which user or agent,
              which provider or model, what data was involved, which policy applied, and what response ran.
            </p>

            <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.7, marginBottom: 40 }}>
              CyberArmor.AI captures evidence as part of the runtime control loop. That makes investigations
              stronger because the proof is connected to the action: blocked, redacted, warned, routed,
              limited, or allowed.
            </p>

            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 10,
              background: "rgba(0,163,255,0.08)",
              border: "1px solid rgba(0,163,255,0.2)",
              borderRadius: 10,
              padding: "12px 20px",
            }}>
              <CheckCircle2 size={16} style={{ color: "#00A3FF" }} />
              <span style={{ fontSize: 14, color: "#ffffff", fontWeight: 500 }}>
                Protection-backed. Audit-ready. Decision-level granularity.
              </span>
            </div>
          </div>

          {/* Right: Visual */}
          <div>
            <div style={{
              background: "#0F1117",
              border: "1px solid #1E2335",
              borderRadius: 16,
              padding: "32px",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
                <div style={{
                  width: 8, height: 8, borderRadius: "50%",
                  background: "#22C55E",
                  boxShadow: "0 0 8px rgba(34,197,94,0.6)",
                }} />
                <span style={{ fontSize: 13, color: "#8892A4", fontWeight: 600 }}>EVIDENCE STREAM — LIVE</span>
              </div>

              {/* Evidence feed mock */}
              <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 28 }}>
                {[
                  {
                    id: "EVT-00482",
                    action: "URL trust gate: BLOCKED",
                    detail: "Zero-width prompt injection detected in external page — AI agent fetch blocked before content ingestion",
                    policy: "POL-URL-01: Block Promptware",
                    ts: "2026-04-11 09:14:38 UTC",
                    color: "#EF4444",
                  },
                  {
                    id: "EVT-00481",
                    action: "Policy enforcement: REDACT",
                    detail: "Credential removed before AI-bound browser prompt submission",
                    policy: "POL-DLP-04: Redact Secrets",
                    ts: "2026-04-11 09:14:32 UTC",
                    color: "#F59E0B",
                  },
                  {
                    id: "EVT-00480",
                    action: "Provider routing: APPROVED",
                    detail: "Request routed to approved model path with credential handling",
                    policy: "POL-ROUTE-02: Approved Provider",
                    ts: "2026-04-11 09:14:28 UTC",
                    color: "#22C55E",
                  },
                ].map((e) => (
                  <div key={e.id} style={{
                    background: "#12151E",
                    border: "1px solid #1E2335",
                    borderRadius: 10,
                    padding: "14px 16px",
                    borderLeft: `3px solid ${e.color}`,
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: e.color }}>{e.action}</span>
                      <span style={{ fontSize: 10, color: "#4A5568", fontFamily: "monospace" }}>{e.id}</span>
                    </div>
                    <p style={{ fontSize: 12.5, color: "#8892A4", marginBottom: 6, lineHeight: 1.4 }}>{e.detail}</p>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ fontSize: 11, color: "#00A3FF", opacity: 0.7 }}>{e.policy}</span>
                      <span style={{ fontSize: 11, color: "#4A5568", fontFamily: "monospace" }}>{e.ts}</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Feature pills */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {evidenceItems.map(({ icon: Icon, label }) => (
                  <div key={label} style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    background: "#12151E",
                    border: "1px solid #1E2335",
                    borderRadius: 6,
                    padding: "6px 10px",
                  }}>
                    <Icon size={12} style={{ color: "#00A3FF" }} />
                    <span style={{ fontSize: 12, color: "#8892A4" }}>{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
