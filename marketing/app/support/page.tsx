import type { Metadata } from "next";
import Link from "next/link";
import { AlertTriangle, CheckCircle2, FileText, LifeBuoy, Mail, ShieldAlert } from "lucide-react";
import SupportTicketForm from "@/components/support/SupportTicketForm";

export const metadata: Metadata = {
  title: "Support Center",
  description: "CyberArmor AI support center for deployment, bootstrap, endpoint-agent, runtime, evidence, and portal issues.",
};

const cardStyle = {
  background: "#0F1117",
  border: "1px solid #1E2335",
  borderRadius: 16,
  padding: 24,
} as const;

const triagePaths = [
  {
    title: "Deployment and routing",
    body: "Use this path for DNS, TLS, Caddy, docs, app, admin, support, or public route issues.",
    checks: ["Confirm the public hostname", "Compare local service health to public status", "Capture the exact failing URL and status code"],
  },
  {
    title: "Bootstrap and enrollment",
    body: "Use this path when endpoint agents, SDKs, browser extensions, or onboarding packages cannot redeem or register.",
    checks: ["Record tenant ID and package key", "Check bootstrap token expiry", "Verify control-plane URL and /pki/public-key"],
  },
  {
    title: "Runtime and evidence",
    body: "Use this path when policy decisions, detection results, incidents, audit logs, or evidence records are missing or inconsistent.",
    checks: ["Capture request ID or trace ID", "Check policy and detection health", "Attach audit/evidence timestamps"],
  },
];

const severity = [
  { label: "S1", title: "Production outage or security-critical exposure", detail: "Customer-facing service unavailable, active data exposure, or evidence/audit integrity risk." },
  { label: "S2", title: "Major workflow blocked", detail: "Tenant onboarding, policy enforcement, endpoint enrollment, or demo validation cannot proceed." },
  { label: "S3", title: "Degraded or isolated issue", detail: "A workaround exists, or the issue affects one environment, tenant, package, or integration." },
];

export default function SupportPage() {
  return (
    <div style={{ background: "#000000", minHeight: "100vh" }}>
      <section className="container-wide" style={{ paddingTop: 140, paddingBottom: 96 }}>
        <div style={{ maxWidth: 760, marginBottom: 48 }}>
          <div className="label-tag" style={{ marginBottom: 16 }}>Support</div>
          <h1 className="section-headline" style={{ marginBottom: 20 }}>
            Support Center for Deployments, Enrollment, and Runtime Operations
          </h1>
          <p style={{ fontSize: 16, color: "#A0AEC0", lineHeight: 1.8 }}>
            If you&apos;re deploying CyberArmor, enrolling agents, validating a demo,
            or troubleshooting a public route, start here. The fastest support
            path is to identify the affected surface, collect the request details,
            and separate service health from routing or tenant configuration.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 20, marginBottom: 36 }}>
          <div style={cardStyle}>
            <FileText size={22} style={{ color: "#00A3FF", marginBottom: 14 }} />
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
            <LifeBuoy size={22} style={{ color: "#00A3FF", marginBottom: 14 }} />
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#ffffff", marginBottom: 12 }}>Support runbooks</h2>
            <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7, marginBottom: 16 }}>
              Use support runbooks for fast triage on 302, 404, 500, 502,
              bootstrap, endpoint-agent, detection, and secrets-path issues.
            </p>
            <a href="https://support.cyberarmor.ai" style={{ color: "#60C8FF", textDecoration: "none", fontWeight: 600 }}>
              Open support home
            </a>
          </div>

          <div style={cardStyle}>
            <Mail size={22} style={{ color: "#00A3FF", marginBottom: 14 }} />
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#ffffff", marginBottom: 12 }}>Contact the team</h2>
            <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.7, marginBottom: 16 }}>
              For product, deployment, or account support, include the environment,
              tenant ID, affected URL, timestamp, and request ID if available.
            </p>
            <a href="mailto:hello@cyberarmor.ai" style={{ color: "#60C8FF", textDecoration: "none", fontWeight: 600 }}>
              hello@cyberarmor.ai
            </a>
          </div>
        </div>

        <SupportTicketForm />

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 20, marginBottom: 52 }}>
          {triagePaths.map((path) => (
            <div key={path.title} style={cardStyle}>
              <CheckCircle2 size={20} style={{ color: "#22C55E", marginBottom: 12 }} />
              <h2 style={{ fontSize: 18, fontWeight: 700, color: "#ffffff", marginBottom: 10 }}>{path.title}</h2>
              <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.7, marginBottom: 16 }}>{path.body}</p>
              <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 8 }}>
                {path.checks.map((check) => (
                  <li key={check} style={{ display: "flex", gap: 9, color: "#A0AEC0", fontSize: 13.5, lineHeight: 1.55 }}>
                    <span style={{ width: 5, height: 5, borderRadius: "50%", background: "#00A3FF", marginTop: 8, flexShrink: 0 }} />
                    {check}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 24, alignItems: "start" }}>
          <section style={cardStyle}>
            <AlertTriangle size={22} style={{ color: "#F59E0B", marginBottom: 14 }} />
            <h2 style={{ fontSize: 24, fontWeight: 700, color: "#ffffff", marginBottom: 12 }}>
              What to collect before escalation
            </h2>
            <ul style={{ color: "#A0AEC0", lineHeight: 1.9, paddingLeft: 20, margin: 0 }}>
              <li>Environment name and public hostname involved</li>
              <li>Exact URL, API path, or portal view that failed</li>
              <li>Timestamp, tenant ID, user email, request ID, or trace ID</li>
              <li>Whether the same path works locally on the server</li>
              <li>Relevant service logs from control-plane, policy, detection, audit, or Caddy</li>
              <li>Whether the issue is stable, intermittent, or tied to one tenant/package</li>
            </ul>
          </section>

          <section style={cardStyle}>
            <ShieldAlert size={22} style={{ color: "#EF4444", marginBottom: 14 }} />
            <h2 style={{ fontSize: 22, fontWeight: 700, color: "#ffffff", marginBottom: 16 }}>
              Severity guide
            </h2>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {severity.map((item) => (
                <div key={item.label} style={{ borderTop: "1px solid #1E2335", paddingTop: 14 }}>
                  <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6 }}>
                    <span style={{ color: "#F87171", fontWeight: 800, fontSize: 13 }}>{item.label}</span>
                    <span style={{ color: "#ffffff", fontWeight: 700, fontSize: 14 }}>{item.title}</span>
                  </div>
                  <p style={{ color: "#8892A4", fontSize: 13, lineHeight: 1.6 }}>{item.detail}</p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div style={{ marginTop: 48, padding: 24, background: "#050508", border: "1px solid #1E2335", borderRadius: 16 }}>
          <p style={{ color: "#8892A4", fontSize: 14.5, lineHeight: 1.75, margin: 0 }}>
            Need a guided walkthrough instead of break/fix support?{" "}
            <Link href="/contact" style={{ color: "#60C8FF", textDecoration: "none", fontWeight: 700 }}>
              Request a working session
            </Link>{" "}
            with the CyberArmor team.
          </p>
        </div>
      </section>
    </div>
  );
}
