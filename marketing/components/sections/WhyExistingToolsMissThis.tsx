import { Eye, EyeOff, Bot } from "lucide-react";

const gaps = [
  {
    icon: EyeOff,
    color: "#EF4444",
    title: "CSS and off-screen hidden text",
    body: "display:none, visibility:hidden, opacity:0, font-size:0. Invisible to a user, read verbatim by an LLM.",
  },
  {
    icon: Eye,
    color: "#F59E0B",
    title: "Unicode-tag and zero-width encoding",
    body: "Instructions encoded in Unicode tag characters (U+E0000–E007F) or zero-width spaces. Browsers render nothing; AI contexts ingest everything.",
  },
  {
    icon: Bot,
    color: "#A855F7",
    title: "Metadata, comments, and structured data",
    body: "JSON-LD, Open Graph tags, HTML comments, and schema markup are never shown to a human visitor. They can carry arbitrary instructions for an AI reader.",
  },
];

export default function WhyExistingToolsMissThis() {
  return (
    <section style={{ padding: "6rem 0", backgroundColor: "#050508" }}>
      <div className="container-wide">
        <div style={{ maxWidth: 760, margin: "0 auto 56px", textAlign: "center" }}>
          <div className="label-tag" style={{ display: "inline-flex", marginBottom: 20 }}>
            Why Existing Tools Miss This
          </div>
          <h2 className="section-headline" style={{ marginBottom: 20 }}>
            Traditional URL filters were built<br />
            <span className="gradient-text-blue">for human browsing.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.75 }}>
            A page can look completely harmless to a user while hiding
            instructions in CSS, comments, metadata, Unicode tags, or
            zero-width characters. Existing Safe Browsing, SmartScreen, and
            VirusTotal feeds answer{" "}
            <em>&ldquo;is this site malicious for a human?&rdquo;</em> — not{" "}
            <em>&ldquo;is this content safe for an AI agent to ingest?&rdquo;</em>
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 24 }}>
          {gaps.map(({ icon: Icon, color, title, body }) => (
            <div key={title} className="card-base" style={{ padding: "32px 36px" }}>
              <div style={{
                width: 48, height: 48,
                background: `${color}15`,
                border: `1px solid ${color}30`,
                borderRadius: 12,
                display: "flex", alignItems: "center", justifyContent: "center",
                marginBottom: 20,
              }}>
                <Icon size={22} style={{ color }} />
              </div>
              <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#ffffff", marginBottom: 12, lineHeight: 1.4 }}>
                {title}
              </h3>
              <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7 }}>{body}</p>
            </div>
          ))}
        </div>

        <div style={{
          marginTop: 48,
          background: "rgba(0,163,255,0.04)",
          border: "1px solid rgba(0,163,255,0.15)",
          borderRadius: 16,
          padding: "32px 40px",
          textAlign: "center",
        }}>
          <p style={{ color: "#8892A4", fontSize: "1rem", lineHeight: 1.75, maxWidth: 720, margin: "0 auto" }}>
            CyberArmor evaluates external content before it enters AI context, then
            allows, warns, redacts, sandboxes, blocks, or isolates based on tenant
            policy — with evidence written on every non-cached decision.
          </p>
        </div>
      </div>
    </section>
  );
}
