import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: "CyberArmor AI privacy policy for website visitors, prospective customers, and product inquiries.",
};

const sectionStyle = { marginBottom: 32 };
const headingStyle = { fontSize: 22, fontWeight: 700, color: "#ffffff", marginBottom: 12 } as const;
const bodyStyle = { fontSize: 15, color: "#A0AEC0", lineHeight: 1.8 } as const;

export default function PrivacyPage() {
  return (
    <div style={{ background: "#000000", minHeight: "100vh" }}>
      <section className="container-wide" style={{ paddingTop: 140, paddingBottom: 96, maxWidth: 900 }}>
        <div className="label-tag" style={{ marginBottom: 16 }}>Privacy</div>
        <h1 className="section-headline" style={{ marginBottom: 20 }}>
          Privacy Policy
        </h1>
        <p style={{ ...bodyStyle, marginBottom: 40 }}>
          This page explains how CyberArmor AI handles information submitted through
          our public website, demo request forms, and related customer-facing
          marketing surfaces.
        </p>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>What we collect</h2>
          <p style={bodyStyle}>
            We may collect contact details you voluntarily submit, such as your
            name, business email address, company name, role, and the context you
            provide when requesting a demo, contacting us, or applying for
            advisory services.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>How we use it</h2>
          <p style={bodyStyle}>
            We use submitted information to respond to your request, evaluate fit
            for a product conversation or advisory engagement, improve our site,
            and maintain reasonable records of prospective customer interactions.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>How we share it</h2>
          <p style={bodyStyle}>
            We do not sell your personal information. We may share limited data
            with infrastructure or service providers that support our website,
            communications, analytics, or payment workflows, but only as needed
            to operate those services.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Security and retention</h2>
          <p style={bodyStyle}>
            We use reasonable administrative, technical, and organizational
            safeguards for submitted website data. We retain information only as
            long as needed for legitimate business, legal, operational, or
            security purposes.
          </p>
        </div>

        <div style={sectionStyle}>
          <h2 style={headingStyle}>Contact</h2>
          <p style={bodyStyle}>
            For privacy-related questions, contact{" "}
            <a href="mailto:hello@cyberarmor.ai" style={{ color: "#60C8FF" }}>
              hello@cyberarmor.ai
            </a>
            {" "}or use our{" "}
            <Link href="/contact" style={{ color: "#60C8FF" }}>
              contact page
            </Link>.
          </p>
        </div>
      </section>
    </div>
  );
}
