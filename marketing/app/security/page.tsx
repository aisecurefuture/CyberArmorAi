import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Security",
  description: "CyberArmor AI website security overview and reporting guidance.",
};

const sectionStyle = { marginBottom: 32 };
const headingStyle = { fontSize: 22, fontWeight: 700, color: "#ffffff", marginBottom: 12 } as const;
const bodyStyle = { fontSize: 15, color: "#A0AEC0", lineHeight: 1.8 } as const;

export default function SecurityPage() {
  return (
    <div style={{ background: "#000000", minHeight: "100vh" }}>
      <section className="container-wide" style={{ paddingTop: 140, paddingBottom: 96, maxWidth: 900 }}>
        <div className="label-tag" style={{ marginBottom: 16 }}>Security</div>
        <h1 className="section-headline" style={{ marginBottom: 20 }}>
          Security Information
        </h1>
        <p style={{ ...bodyStyle, marginBottom: 40 }}>
          CyberArmor AI is a security company, so we take the security of our
          website, deployment surfaces, and product infrastructure seriously.
        </p>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Scope of this page</h2>
          <p style={bodyStyle}>
            This page is a lightweight public security reference for the
            marketing and support surface. It is not a substitute for a customer
            security package, contract, or deployment-specific security review.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Security expectations</h2>
          <p style={bodyStyle}>
            Hosted CyberArmor deployments commonly use TLS-terminated public
            domains, authenticated service-to-service communication, detection
            model isolation, OpenBao-backed secrets handling, and auditable
            control-plane workflows.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Reporting issues</h2>
          <p style={bodyStyle}>
            If you believe you have found a security issue affecting our public
            site or product surfaces, contact{" "}
            <a href="mailto:security@cyberarmor.ai" style={{ color: "#60C8FF" }}>
              security@cyberarmor.ai
            </a>
            . Please include the affected hostname, path, timestamp, and
            reproduction details.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Operational help</h2>
          <p style={bodyStyle}>
            For deployment triage, endpoint-agent enrollment help, or public
            routing issues, use the{" "}
            <a href="https://support.cyberarmor.ai" style={{ color: "#60C8FF" }}>
              support center
            </a>
            {" "}or the{" "}
            <Link href="/contact" style={{ color: "#60C8FF" }}>
              contact page
            </Link>.
          </p>
        </div>
      </section>
    </div>
  );
}
