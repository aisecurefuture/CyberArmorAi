import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Support",
  description: "CyberArmor AI support guidance for deployment, bootstrap, endpoint-agent, and runtime issues.",
};

const cardStyle = {
  background: "#0F1117",
  border: "1px solid #1E2335",
  borderRadius: 16,
  padding: 24,
} as const;

export default function SupportPage() {
  return (
    <div style={{ background: "#000000", minHeight: "100vh" }}>
      <section className="container-wide" style={{ paddingTop: 140, paddingBottom: 96 }}>
        <div style={{ maxWidth: 760, marginBottom: 48 }}>
          <div className="label-tag" style={{ marginBottom: 16 }}>Support</div>
          <h1 className="section-headline" style={{ marginBottom: 20 }}>
            Support for Deployments, Enrollment, and Runtime Operations
          </h1>
          <p style={{ fontSize: 16, color: "#A0AEC0", lineHeight: 1.8 }}>
            If you&apos;re deploying CyberArmor, enrolling endpoint agents, or
            troubleshooting a public routing path, start with the support center
            and docs. They reflect the actual working platform and operator
            workflows in the repo.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 20, marginBottom: 36 }}>
          <div style={cardStyle}>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#ffffff", marginBottom: 12 }}>Technical docs</h2>
            <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7, marginBottom: 16 }}>
              Deployment, endpoint-agent, bootstrap, and routing guidance live in
              the technical docs.
            </p>
            <a href="https://docs.cyberarmor.ai" style={{ color: "#60C8FF", textDecoration: "none", fontWeight: 600 }}>
              Open docs
            </a>
          </div>

          <div style={cardStyle}>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#ffffff", marginBottom: 12 }}>Support center</h2>
            <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7, marginBottom: 16 }}>
              Use the support center for fast triage on `302`, `404`, `500`,
              `502`, bootstrap, agent, and secrets-path issues.
            </p>
            <a href="https://support.cyberarmor.ai" style={{ color: "#60C8FF", textDecoration: "none", fontWeight: 600 }}>
              Open support center
            </a>
          </div>

          <div style={cardStyle}>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#ffffff", marginBottom: 12 }}>Contact the team</h2>
            <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7, marginBottom: 16 }}>
              For a guided conversation about deployment or product fit, reach
              out directly.
            </p>
            <Link href="/contact" style={{ color: "#60C8FF", textDecoration: "none", fontWeight: 600 }}>
              Contact CyberArmor
            </Link>
          </div>
        </div>

        <div style={{ maxWidth: 820 }}>
          <h2 style={{ fontSize: 24, fontWeight: 700, color: "#ffffff", marginBottom: 12 }}>
            Common live issues
          </h2>
          <ul style={{ color: "#A0AEC0", lineHeight: 1.9, paddingLeft: 20 }}>
            <li>Bootstrap redemption returns the wrong control-plane URL</li>
            <li>Endpoint-agent registration is redirected or timing out</li>
            <li>Public `/pki/public-key` is failing even though backend services are healthy</li>
            <li>Detection models are cold, downloading, or hitting cache-permission issues</li>
            <li>Docs/support/public routes are serving the wrong upstream</li>
          </ul>
        </div>
      </section>
    </div>
  );
}
