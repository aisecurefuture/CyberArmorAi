import { CheckCircle2 } from "lucide-react";
import Link from "next/link";
import { ArrowRight } from "lucide-react";

const implemented = [
  "FastAPI service — end-to-end, health-checked, Prometheus metrics on port 8014",
  "URL canonicalization, querystring redaction, homoglyph / punycode normalization",
  "SSRF-guarded safe crawler — no cookies, no credentials, redirect-hop revalidation",
  "Playwright detonation sandbox on an isolated Docker network (port 8015, internal)",
  "Heuristic detection: prompt injection, credential harvest, brand impersonation, zero-width stripping",
  "ML-based detection via detection service — phishing, promptware, DLP, IOC scoring",
  "Google Safe Browsing v4, Microsoft SmartScreen, and VirusTotal v3 reputation feeds",
  "Tenant allow/block lists via policy service (GET /policies?tenant_id=…&scope=url-trust-gate)",
  "Policy decisions: allow, warn, redact, sandbox, block, isolate",
  "Evidence writes to audit service on every non-cached decision",
  "Consumer hooks: browser extension, endpoint agent, RASP Python, LangChain SDK, LlamaIndex SDK",
];

export default function ProofOfReality() {
  return (
    <section style={{ padding: "6rem 0", backgroundColor: "#000000" }}>
      <div className="container-wide">
        <div style={{ maxWidth: 760, margin: "0 auto 56px", textAlign: "center" }}>
          <div className="label-tag" style={{ display: "inline-flex", marginBottom: 20 }}>
            What Exists Today
          </div>
          <h2 className="section-headline" style={{ marginBottom: 20 }}>
            URL Trust Gate runs{" "}
            <span className="gradient-text-blue">end-to-end.</span>
          </h2>
          <p style={{ color: "#8892A4", fontSize: "1.05rem", lineHeight: 1.75 }}>
            The 15-minute local PoC installer brings up the full gate stack on any
            developer laptop and submits four crafted attack pages — benign,
            CSS-hidden promptware, zero-width injection, credential-harvest — all
            producing live verdicts in under 120 ms.
          </p>
        </div>

        <div className="card-base" style={{ padding: "44px 48px" }}>
          <p style={{ fontSize: 11, fontWeight: 700, color: "#00A3FF", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 28 }}>
            Implemented and Tested
          </p>
          <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: "14px 40px" }}>
            {implemented.map((item) => (
              <li key={item} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                <CheckCircle2 size={16} style={{ color: "#22C55E", flexShrink: 0, marginTop: 2 }} />
                <span style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.6 }}>{item}</span>
              </li>
            ))}
          </ul>

          <div style={{ marginTop: 36, paddingTop: 32, borderTop: "1px solid #1E2335", display: "flex", gap: 14, flexWrap: "wrap" }}>
            <Link href="/url-trust-gate" className="btn-primary" style={{ fontSize: 14 }}>
              See the full capability status <ArrowRight size={14} />
            </Link>
            <Link href="/contact" className="btn-ghost" style={{ fontSize: 14 }}>
              Request a Design Partner Pilot <ArrowRight size={14} />
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
