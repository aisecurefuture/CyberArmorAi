import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: "CyberArmor AI website terms of service for public site usage and inquiry submission.",
};

const sectionStyle = { marginBottom: 32 };
const headingStyle = { fontSize: 22, fontWeight: 700, color: "#ffffff", marginBottom: 12 } as const;
const bodyStyle = { fontSize: 15, color: "#A0AEC0", lineHeight: 1.8 } as const;

export default function TermsPage() {
  return (
    <div style={{ background: "#000000", minHeight: "100vh" }}>
      <section className="container-wide" style={{ paddingTop: 140, paddingBottom: 96, maxWidth: 900 }}>
        <div className="label-tag" style={{ marginBottom: 16 }}>Terms</div>
        <h1 className="section-headline" style={{ marginBottom: 20 }}>
          Terms of Service
        </h1>
        <p style={{ ...bodyStyle, marginBottom: 40 }}>
          These terms govern use of the CyberArmor AI public website and related
          request, inquiry, and informational pages.
        </p>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Informational use</h2>
          <p style={bodyStyle}>
            The public website is provided for informational and business
            development purposes. Product descriptions, feature narratives, and
            service availability may evolve as the platform matures.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>No customer agreement formed here</h2>
          <p style={bodyStyle}>
            Viewing this site, submitting a contact form, or requesting a demo
            does not by itself create a customer contract, managed service
            obligation, legal representation, or compliance certification.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Use restrictions</h2>
          <p style={bodyStyle}>
            You may not misuse the site, interfere with its operation, probe it
            for unauthorized access, or use CyberArmor branding or materials in a
            misleading way.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Intellectual property</h2>
          <p style={bodyStyle}>
            CyberArmor AI branding, product copy, design elements, and related
            platform materials remain the property of CyberArmor AI except where
            otherwise stated. References to patent-pending innovations describe
            proprietary work claimed by the company.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Questions</h2>
          <p style={bodyStyle}>
            For commercial, legal, or website questions, contact{" "}
            <a href="mailto:hello@cyberarmor.ai" style={{ color: "#60C8FF" }}>
              hello@cyberarmor.ai
            </a>
            {" "}or visit the{" "}
            <Link href="/support" style={{ color: "#60C8FF" }}>
              support page
            </Link>.
          </p>
        </div>
      </section>
    </div>
  );
}
