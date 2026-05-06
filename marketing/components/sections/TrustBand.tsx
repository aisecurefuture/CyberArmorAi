import { ShieldCheck, Lock, Eye, FileCheck, Zap } from "lucide-react";

const signals = [
  { icon: ShieldCheck, text: "Security-Led Design Partner Motion" },
  { icon: Eye, text: "Cross-Layer AI Context" },
  { icon: Lock, text: "Runtime Policy Control" },
  { icon: Zap, text: "Credential Redaction in Supported Paths" },
  { icon: FileCheck, text: "Protection-Backed Evidence" },
];

export default function TrustBand() {
  return (
    <div style={{
      borderTop: "1px solid #1E2335",
      borderBottom: "1px solid #1E2335",
      backgroundColor: "#0A0A0F",
      padding: "20px 0",
      overflow: "hidden",
    }}>
      <div className="container-wide">
        <div style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          gap: "clamp(24px, 4vw, 56px)",
          flexWrap: "wrap",
        }}>
          {signals.map(({ icon: Icon, text }) => (
            <div key={text} style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              whiteSpace: "nowrap",
            }}>
              <Icon size={15} style={{ color: "#00A3FF", flexShrink: 0 }} />
              <span style={{ fontSize: 13, color: "#8892A4", fontWeight: 500 }}>{text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
