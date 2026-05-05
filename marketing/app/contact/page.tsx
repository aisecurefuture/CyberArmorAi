"use client";

import { useState } from "react";
import { z } from "zod";
import { Shield, CheckCircle2, ArrowRight, Clock, Users, Lock } from "lucide-react";

// ── Allowed enum values (whitelist) ──────────────────────────────────────────
const interestOptions = [
  "AI Security Platform Overview",
  "Shadow AI Discovery & Governance",
  "AI Agent Trust & Control",
  "AI Runtime Protection",
  "Prompt Injection Defense",
  "Data Protection in AI Workflows",
  "Evidence & Compliance",
  "Investor / Partnership Inquiry",
  "General Inquiry",
] as const;

const companySizes = [
  "1–50 employees",
  "51–200 employees",
  "201–1,000 employees",
  "1,001–5,000 employees",
  "5,001–10,000 employees",
  "10,000+ employees",
] as const;

// ── Zod schema ────────────────────────────────────────────────────────────────
const ContactSchema = z.object({
  name: z
    .string()
    .min(2, "Name must be at least 2 characters")
    .max(100, "Name is too long")
    .regex(/^[\p{L}\s'\-\.]+$/u, "Name contains invalid characters")
    .transform((v) => v.trim()),
  title: z
    .string()
    .min(1, "Title is required")
    .max(100, "Title is too long")
    .transform((v) => v.trim()),
  company: z
    .string()
    .min(1, "Company is required")
    .max(100, "Company name is too long")
    .transform((v) => v.trim()),
  email: z
    .string()
    .email("Please enter a valid email address")
    .max(254, "Email is too long")
    .toLowerCase()
    .refine(
      (email) => {
        const personalDomains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "aol.com"];
        const domain = email.split("@")[1];
        return !personalDomains.includes(domain);
      },
      { message: "Please use your work email address" }
    ),
  size: z.enum(companySizes, { message: "Please select a company size" }),
  interest: z.enum(interestOptions, { message: "Please select your primary interest" }),
  message: z
    .string()
    .max(2000, "Message is too long (max 2000 characters)")
    .transform((v) => v.trim())
    .optional(),
  // Honeypot — must be empty; bots fill it, humans don't see it
  _hp: z.literal("").optional(),
});

type FormData = z.input<typeof ContactSchema>;
type FormErrors = Partial<Record<keyof FormData, string>>;

const reasons = [
  { icon: Clock, text: "We respond within one business day" },
  { icon: Users, text: "You'll speak with a security professional, not an SDR" },
  { icon: Lock, text: "No spam, no pressure, no hard sell" },
];

const inputStyle: React.CSSProperties = {
  width: "100%",
  background: "#0F1117",
  border: "1px solid #1E2335",
  borderRadius: 8,
  padding: "12px 16px",
  fontSize: 15,
  color: "#ffffff",
  outline: "none",
  transition: "border-color 0.2s",
  fontFamily: "inherit",
};

const errorStyle: React.CSSProperties = {
  fontSize: 12,
  color: "#F87171",
  marginTop: 5,
};

const labelStyle: React.CSSProperties = {
  fontSize: 13,
  fontWeight: 600,
  color: "#8892A4",
  display: "block",
  marginBottom: 8,
  letterSpacing: "0.02em",
};

export default function ContactPage() {
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [submitterName, setSubmitterName] = useState("");
  const [errors, setErrors] = useState<FormErrors>({});
  const [submitError, setSubmitError] = useState("");
  const [form, setForm] = useState<FormData>({
    name: "", title: "", company: "", email: "",
    size: "" as FormData["size"], interest: "" as FormData["interest"],
    message: "", _hp: "",
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    // Enforce max length at input time as a UX safeguard
    const maxLengths: Record<string, number> = {
      name: 100, title: 100, company: 100, email: 254, message: 2000,
    };
    if (maxLengths[name] !== undefined && value.length > maxLengths[name]) return;
    setForm((prev) => ({ ...prev, [name]: value }));
    // Clear field error on change
    if (errors[name as keyof FormErrors]) {
      setErrors((prev) => ({ ...prev, [name]: undefined }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Honeypot check — silently reject bots
    if (form._hp) return;

    const result = ContactSchema.safeParse(form);
    if (!result.success) {
      const fieldErrors: FormErrors = {};
      result.error.issues.forEach((err) => {
        const field = err.path[0] as keyof FormErrors;
        if (!fieldErrors[field]) fieldErrors[field] = err.message;
      });
      setErrors(fieldErrors);
      return;
    }

    setLoading(true);
    setErrors({});
    setSubmitError("");
    setSubmitterName(result.data.name.split(" ")[0]);

    try {
      const response = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(result.data),
      });
      const payload = (await response.json().catch(() => ({}))) as { error?: string };
      if (!response.ok) {
        throw new Error(payload.error || "We couldn't send your request right now.");
      }
      setSubmitted(true);
    } catch (error) {
      setSubmitError(
        error instanceof Error
          ? error.message
          : "We couldn't send your request right now. Please email hello@cyberarmor.ai directly.",
      );
    } finally {
      setLoading(false);
    }
  };

  const fieldBorder = (field: keyof FormErrors) =>
    errors[field] ? { borderColor: "rgba(248,113,113,0.6)" } : {};

  return (
    <div style={{ backgroundColor: "#000000" }}>
      <section style={{ paddingTop: "10rem", paddingBottom: "8rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.08) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />
        <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.25 }} />

        <div className="container-wide" style={{ position: "relative" }}>
          <div className="contact-grid" style={{
            display: "grid",
            gridTemplateColumns: "1fr 1.4fr",
            gap: 64,
            alignItems: "start",
          }}>
            {/* Left: Info */}
            <div style={{ paddingTop: 8 }}>
              <div className="label-tag" style={{ marginBottom: 24 }}>
                <Shield size={12} /> Request a Demo
              </div>

              <h1 style={{
                fontSize: "clamp(2rem, 4vw, 2.8rem)",
                fontWeight: 800,
                letterSpacing: "-0.04em",
                lineHeight: 1.1,
                color: "#ffffff",
                marginBottom: 20,
              }}>
                See What AI Security<br />
                <span className="gradient-text-blue">Actually Looks Like.</span>
              </h1>

              <p style={{ fontSize: "1.05rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 32 }}>
                A CyberArmor AI demo is a working session — not a slide deck. We&apos;ll walk through your
                specific AI environment, threat surface, and security priorities, and show you exactly how
                the platform addresses them.
              </p>

              <p style={{ fontSize: "1.05rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 40 }}>
                We talk to CISOs, security architects, and heads of AI governance. If that&apos;s you —
                or close to you — we want to hear what you&apos;re dealing with.
              </p>

              <div style={{ display: "flex", flexDirection: "column", gap: 16, marginBottom: 40 }}>
                {reasons.map(({ icon: Icon, text }) => (
                  <div key={text} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <div style={{
                      width: 32, height: 32,
                      background: "rgba(0,163,255,0.08)",
                      border: "1px solid rgba(0,163,255,0.15)",
                      borderRadius: 8,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      flexShrink: 0,
                    }}>
                      <Icon size={15} style={{ color: "#00A3FF" }} />
                    </div>
                    <span style={{ fontSize: 14, color: "#8892A4" }}>{text}</span>
                  </div>
                ))}
              </div>

              {/* Contact info */}
              <div style={{
                background: "#0F1117",
                border: "1px solid #1E2335",
                borderRadius: 12,
                padding: "20px 24px",
              }}>
                <p style={{ fontSize: 13, color: "#4A5568", marginBottom: 6 }}>Or reach us directly at</p>
                <a href="mailto:hello@cyberarmor.ai" style={{
                  fontSize: 16, color: "#00A3FF", fontWeight: 600, textDecoration: "none",
                }}>
                  hello@cyberarmor.ai
                </a>
              </div>
            </div>

            {/* Right: Form */}
            <div>
              {submitted ? (
                <div style={{
                  background: "#0F1117",
                  border: "1px solid rgba(34,197,94,0.3)",
                  borderRadius: 20,
                  padding: "60px 48px",
                  textAlign: "center",
                }}>
                  <div style={{
                    width: 72, height: 72,
                    background: "rgba(34,197,94,0.1)",
                    border: "1px solid rgba(34,197,94,0.3)",
                    borderRadius: "50%",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    margin: "0 auto 24px",
                  }}>
                    <CheckCircle2 size={36} style={{ color: "#22C55E" }} />
                  </div>
                  <h2 style={{ fontSize: "1.6rem", fontWeight: 700, color: "#ffffff", marginBottom: 16, letterSpacing: "-0.02em" }}>
                    Request Received.
                  </h2>
                  <p style={{ fontSize: "1rem", color: "#8892A4", lineHeight: 1.7, maxWidth: 420, margin: "0 auto" }}>
                    Thank you, {submitterName || "there"}. We&apos;ll review your request and reach out
                    within one business day to schedule your session.
                  </p>
                </div>
              ) : (
                <form onSubmit={handleSubmit} noValidate style={{
                  background: "#0F1117",
                  border: "1px solid #1E2335",
                  borderRadius: 20,
                  padding: "48px",
                }}>
                  <h2 style={{ fontSize: "1.3rem", fontWeight: 700, color: "#ffffff", marginBottom: 8, letterSpacing: "-0.02em" }}>
                    Request Your Demo
                  </h2>
                  <p style={{ fontSize: 13, color: "#4A5568", marginBottom: 32 }}>
                    All fields required unless marked optional. We keep your information secure.
                  </p>

                  {/* Honeypot — hidden from humans, bots fill it */}
                  <div style={{ position: "absolute", left: "-9999px", top: "auto", width: 1, height: 1, overflow: "hidden" }} aria-hidden="true">
                    <label htmlFor="_hp">Leave this field empty</label>
                    <input id="_hp" name="_hp" type="text" tabIndex={-1} autoComplete="off" value={form._hp} onChange={handleChange} />
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
                    <div>
                      <label style={labelStyle} htmlFor="name">Full Name</label>
                      <input
                        id="name" name="name" type="text"
                        value={form.name} onChange={handleChange}
                        autoComplete="name"
                        placeholder="Jane Smith"
                        style={{ ...inputStyle, ...fieldBorder("name") }}
                        onFocus={(e) => { if (!errors.name) e.target.style.borderColor = "rgba(0,163,255,0.5)"; }}
                        onBlur={(e) => { if (!errors.name) e.target.style.borderColor = "#1E2335"; }}
                      />
                      {errors.name && <p style={errorStyle} role="alert">{errors.name}</p>}
                    </div>
                    <div>
                      <label style={labelStyle} htmlFor="title">Title</label>
                      <input
                        id="title" name="title" type="text"
                        value={form.title} onChange={handleChange}
                        autoComplete="organization-title"
                        placeholder="CISO"
                        style={{ ...inputStyle, ...fieldBorder("title") }}
                        onFocus={(e) => { if (!errors.title) e.target.style.borderColor = "rgba(0,163,255,0.5)"; }}
                        onBlur={(e) => { if (!errors.title) e.target.style.borderColor = "#1E2335"; }}
                      />
                      {errors.title && <p style={errorStyle} role="alert">{errors.title}</p>}
                    </div>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
                    <div>
                      <label style={labelStyle} htmlFor="company">Company</label>
                      <input
                        id="company" name="company" type="text"
                        value={form.company} onChange={handleChange}
                        autoComplete="organization"
                        placeholder="Acme Corp"
                        style={{ ...inputStyle, ...fieldBorder("company") }}
                        onFocus={(e) => { if (!errors.company) e.target.style.borderColor = "rgba(0,163,255,0.5)"; }}
                        onBlur={(e) => { if (!errors.company) e.target.style.borderColor = "#1E2335"; }}
                      />
                      {errors.company && <p style={errorStyle} role="alert">{errors.company}</p>}
                    </div>
                    <div>
                      <label style={labelStyle} htmlFor="email">Work Email</label>
                      <input
                        id="email" name="email" type="email"
                        value={form.email} onChange={handleChange}
                        autoComplete="email"
                        placeholder="jane@acmecorp.com"
                        style={{ ...inputStyle, ...fieldBorder("email") }}
                        onFocus={(e) => { if (!errors.email) e.target.style.borderColor = "rgba(0,163,255,0.5)"; }}
                        onBlur={(e) => { if (!errors.email) e.target.style.borderColor = "#1E2335"; }}
                      />
                      {errors.email && <p style={errorStyle} role="alert">{errors.email}</p>}
                    </div>
                  </div>

                  <div style={{ marginBottom: 20 }}>
                    <label style={labelStyle} htmlFor="size">Company Size</label>
                    <select
                      id="size" name="size"
                      value={form.size} onChange={handleChange}
                      style={{ ...inputStyle, appearance: "none", ...fieldBorder("size") }}
                      onFocus={(e) => { if (!errors.size) e.target.style.borderColor = "rgba(0,163,255,0.5)"; }}
                      onBlur={(e) => { if (!errors.size) e.target.style.borderColor = "#1E2335"; }}
                    >
                      <option value="">Select company size</option>
                      {companySizes.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                    {errors.size && <p style={errorStyle} role="alert">{errors.size}</p>}
                  </div>

                  <div style={{ marginBottom: 20 }}>
                    <label style={labelStyle} htmlFor="interest">Primary Interest</label>
                    <select
                      id="interest" name="interest"
                      value={form.interest} onChange={handleChange}
                      style={{ ...inputStyle, appearance: "none", ...fieldBorder("interest") }}
                      onFocus={(e) => { if (!errors.interest) e.target.style.borderColor = "rgba(0,163,255,0.5)"; }}
                      onBlur={(e) => { if (!errors.interest) e.target.style.borderColor = "#1E2335"; }}
                    >
                      <option value="">What are you most focused on?</option>
                      {interestOptions.map((o) => <option key={o} value={o}>{o}</option>)}
                    </select>
                    {errors.interest && <p style={errorStyle} role="alert">{errors.interest}</p>}
                  </div>

                  <div style={{ marginBottom: 32 }}>
                    <label style={labelStyle} htmlFor="message">
                      Tell Us About Your Environment <span style={{ color: "#4A5568", fontWeight: 400 }}>(Optional)</span>
                    </label>
                    <textarea
                      id="message" name="message"
                      value={form.message} onChange={handleChange}
                      rows={4}
                      maxLength={2000}
                      placeholder="What AI tools are you managing? What's your biggest security concern? What does your current security stack look like?"
                      style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6, ...fieldBorder("message") }}
                      onFocus={(e) => { if (!errors.message) e.target.style.borderColor = "rgba(0,163,255,0.5)"; }}
                      onBlur={(e) => { if (!errors.message) e.target.style.borderColor = "#1E2335"; }}
                    />
                    {form.message && (
                      <p style={{ fontSize: 11, color: "#4A5568", marginTop: 4, textAlign: "right" }}>
                        {form.message.length}/2000
                      </p>
                    )}
                    {errors.message && <p style={errorStyle} role="alert">{errors.message}</p>}
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="btn-primary"
                    style={{
                      width: "100%",
                      justifyContent: "center",
                      fontSize: 16,
                      padding: "14px",
                      opacity: loading ? 0.7 : 1,
                    }}
                  >
                    {loading ? "Sending..." : "Request My Demo"}
                    {!loading && <ArrowRight size={16} />}
                  </button>

                  {submitError && (
                    <p style={{ ...errorStyle, textAlign: "center", marginTop: 12 }} role="alert">
                      {submitError}
                    </p>
                  )}

                  <p style={{ fontSize: 12, color: "#4A5568", textAlign: "center", marginTop: 16 }}>
                    By submitting, you agree to our{" "}
                    <a href="/privacy" style={{ color: "#8892A4", textDecoration: "underline" }}>
                      Privacy Policy
                    </a>
                    . We don&apos;t share your information.
                  </p>
                </form>
              )}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
