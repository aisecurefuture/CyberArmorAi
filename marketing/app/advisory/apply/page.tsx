"use client";

import { useState } from "react";
import { z } from "zod";
import { Shield, CheckCircle2, Star, ArrowRight } from "lucide-react";

const ApplySchema = z.object({
  name: z.string().min(2, "Name is required").max(100).transform(v => v.trim()),
  title: z.string().min(1, "Title is required").max(100).transform(v => v.trim()),
  company: z.string().min(1, "Company is required").max(100).transform(v => v.trim()),
  email: z.string().email("Please enter a valid email").max(254).toLowerCase()
    .refine(email => {
      const personal = ["gmail.com","yahoo.com","hotmail.com","outlook.com","icloud.com","aol.com"];
      return !personal.includes(email.split("@")[1]);
    }, { message: "Please use your work email address" }),
  why: z.string().min(20, "Please tell us a bit more (min 20 characters)").max(1000).transform(v => v.trim()),
  aiTools: z.string().max(500).transform(v => v.trim()).optional(),
  urgency: z.enum(["Immediate – within 2 weeks","1–2 months","3–6 months","Exploring options"], {
    message: "Please select a timeframe",
  }),
  _hp: z.literal("").optional(),
});

type ApplyData = z.input<typeof ApplySchema>;
type ApplyErrors = Partial<Record<keyof ApplyData, string>>;

const inputStyle: React.CSSProperties = {
  width: "100%", background: "#0F1117", border: "1px solid #1E2335",
  borderRadius: 8, padding: "12px 16px", fontSize: 15, color: "#ffffff",
  outline: "none", transition: "border-color 0.2s", fontFamily: "inherit",
};
const labelStyle: React.CSSProperties = {
  fontSize: 13, fontWeight: 600, color: "#8892A4",
  display: "block", marginBottom: 8, letterSpacing: "0.02em",
};
const errorStyle: React.CSSProperties = { fontSize: 12, color: "#F87171", marginTop: 5 };

export default function ApplyPage() {
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<ApplyErrors>({});
  const [form, setForm] = useState<ApplyData>({
    name: "", title: "", company: "", email: "",
    why: "", aiTools: "", urgency: "" as ApplyData["urgency"], _hp: "",
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
    if (errors[name as keyof ApplyErrors]) setErrors(prev => ({ ...prev, [name]: undefined }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (form._hp) return;

    const result = ApplySchema.safeParse(form);
    if (!result.success) {
      const fieldErrors: ApplyErrors = {};
      result.error.issues.forEach(err => {
        const field = err.path[0] as keyof ApplyErrors;
        if (!fieldErrors[field]) fieldErrors[field] = err.message;
      });
      setErrors(fieldErrors);
      return;
    }

    setLoading(true);
    const res = await fetch("/api/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(result.data),
    });
    setLoading(false);
    if (res.ok) setSubmitted(true);
    else setErrors({ name: "Submission failed — please email hello@cyberarmor.ai directly." });
  };

  const fieldBorder = (field: keyof ApplyErrors) =>
    errors[field] ? { borderColor: "rgba(248,113,113,0.6)" } : {};

  return (
    <div style={{ backgroundColor: "#000000" }}>
      <section style={{ paddingTop: "9rem", paddingBottom: "8rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 60% 40% at 50% -5%, rgba(124,58,237,0.08) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />

        <div className="container-wide" style={{ position: "relative", maxWidth: 680, margin: "0 auto" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 24 }}>
            <Star size={12} /> Priority Advisory — Application
          </div>
          <h1 style={{
            fontSize: "clamp(1.8rem, 4vw, 2.6rem)", fontWeight: 800,
            letterSpacing: "-0.04em", lineHeight: 1.1,
            color: "#ffffff", marginBottom: 16, textAlign: "center",
          }}>
            Apply for Priority<br />
            <span style={{ color: "#A78BFA" }}>Async Advisory</span>
          </h1>
          <p style={{ fontSize: "1rem", color: "#8892A4", lineHeight: 1.8, marginBottom: 40, textAlign: "center" }}>
            $3,000/month · Application-only · Screened for fit before any payment is requested.
            If accepted, you&apos;ll receive a private payment link.
          </p>

          {submitted ? (
            <div style={{
              background: "#0F1117", border: "1px solid rgba(167,139,250,0.3)",
              borderRadius: 20, padding: "60px 48px", textAlign: "center",
            }}>
              <div style={{
                width: 72, height: 72, background: "rgba(167,139,250,0.1)",
                border: "1px solid rgba(167,139,250,0.3)", borderRadius: "50%",
                display: "flex", alignItems: "center", justifyContent: "center",
                margin: "0 auto 24px",
              }}>
                <CheckCircle2 size={36} style={{ color: "#A78BFA" }} />
              </div>
              <h2 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#ffffff", marginBottom: 12, letterSpacing: "-0.02em" }}>
                Application Received
              </h2>
              <p style={{ fontSize: "1rem", color: "#8892A4", lineHeight: 1.7, maxWidth: 420, margin: "0 auto" }}>
                Thank you. Applications are reviewed within 3 business days.
                If there&apos;s a fit, you&apos;ll receive an email with next steps and a private payment link.
              </p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} noValidate style={{
              background: "#0F1117", border: "1px solid #1E2335",
              borderRadius: 20, padding: "48px",
            }}>
              {/* Honeypot */}
              <div style={{ position: "absolute", left: "-9999px", top: "auto", width: 1, height: 1, overflow: "hidden" }} aria-hidden="true">
                <input name="_hp" type="text" tabIndex={-1} autoComplete="off" value={form._hp} onChange={handleChange} />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
                <div>
                  <label style={labelStyle} htmlFor="name">Full Name</label>
                  <input id="name" name="name" type="text" value={form.name} onChange={handleChange}
                    placeholder="Jane Smith" style={{ ...inputStyle, ...fieldBorder("name") }}
                    onFocus={e => { if (!errors.name) e.target.style.borderColor = "rgba(167,139,250,0.5)"; }}
                    onBlur={e => { if (!errors.name) e.target.style.borderColor = "#1E2335"; }} />
                  {errors.name && <p style={errorStyle} role="alert">{errors.name}</p>}
                </div>
                <div>
                  <label style={labelStyle} htmlFor="title">Title</label>
                  <input id="title" name="title" type="text" value={form.title} onChange={handleChange}
                    placeholder="CISO" style={{ ...inputStyle, ...fieldBorder("title") }}
                    onFocus={e => { if (!errors.title) e.target.style.borderColor = "rgba(167,139,250,0.5)"; }}
                    onBlur={e => { if (!errors.title) e.target.style.borderColor = "#1E2335"; }} />
                  {errors.title && <p style={errorStyle} role="alert">{errors.title}</p>}
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }}>
                <div>
                  <label style={labelStyle} htmlFor="company">Company</label>
                  <input id="company" name="company" type="text" value={form.company} onChange={handleChange}
                    placeholder="Acme Corp" style={{ ...inputStyle, ...fieldBorder("company") }}
                    onFocus={e => { if (!errors.company) e.target.style.borderColor = "rgba(167,139,250,0.5)"; }}
                    onBlur={e => { if (!errors.company) e.target.style.borderColor = "#1E2335"; }} />
                  {errors.company && <p style={errorStyle} role="alert">{errors.company}</p>}
                </div>
                <div>
                  <label style={labelStyle} htmlFor="email">Work Email</label>
                  <input id="email" name="email" type="email" value={form.email} onChange={handleChange}
                    placeholder="jane@acmecorp.com" style={{ ...inputStyle, ...fieldBorder("email") }}
                    onFocus={e => { if (!errors.email) e.target.style.borderColor = "rgba(167,139,250,0.5)"; }}
                    onBlur={e => { if (!errors.email) e.target.style.borderColor = "#1E2335"; }} />
                  {errors.email && <p style={errorStyle} role="alert">{errors.email}</p>}
                </div>
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={labelStyle} htmlFor="urgency">Timeline / Urgency</label>
                <select id="urgency" name="urgency" value={form.urgency} onChange={handleChange}
                  style={{ ...inputStyle, appearance: "none", ...fieldBorder("urgency") }}
                  onFocus={e => { if (!errors.urgency) e.target.style.borderColor = "rgba(167,139,250,0.5)"; }}
                  onBlur={e => { if (!errors.urgency) e.target.style.borderColor = "#1E2335"; }}>
                  <option value="">Select your timeline</option>
                  {["Immediate – within 2 weeks","1–2 months","3–6 months","Exploring options"].map(o =>
                    <option key={o} value={o}>{o}</option>
                  )}
                </select>
                {errors.urgency && <p style={errorStyle} role="alert">{errors.urgency}</p>}
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={labelStyle} htmlFor="aiTools">AI Tools / Platforms You&apos;re Using <span style={{ color: "#4A5568", fontWeight: 400 }}>(Optional)</span></label>
                <input id="aiTools" name="aiTools" type="text" value={form.aiTools} onChange={handleChange}
                  placeholder="ChatGPT, Copilot, custom LLM, etc." style={inputStyle}
                  onFocus={e => e.target.style.borderColor = "rgba(167,139,250,0.5)"}
                  onBlur={e => e.target.style.borderColor = "#1E2335"} />
              </div>

              <div style={{ marginBottom: 32 }}>
                <label style={labelStyle} htmlFor="why">What are you trying to solve?</label>
                <textarea id="why" name="why" value={form.why} onChange={handleChange}
                  rows={5} maxLength={1000}
                  placeholder="Describe your AI security challenge, governance gap, or decision you need help navigating..."
                  style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6, ...fieldBorder("why") }}
                  onFocus={e => { if (!errors.why) e.target.style.borderColor = "rgba(167,139,250,0.5)"; }}
                  onBlur={e => { if (!errors.why) e.target.style.borderColor = "#1E2335"; }} />
                {form.why && <p style={{ fontSize: 11, color: "#4A5568", marginTop: 4, textAlign: "right" }}>{form.why.length}/1000</p>}
                {errors.why && <p style={errorStyle} role="alert">{errors.why}</p>}
              </div>

              <button type="submit" disabled={loading} style={{
                display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
                width: "100%", padding: "14px", borderRadius: 8,
                background: "linear-gradient(135deg, #7C3AED, #5B21B6)",
                border: "none", color: "#ffffff", fontWeight: 700, fontSize: 16,
                cursor: loading ? "not-allowed" : "pointer",
                opacity: loading ? 0.7 : 1,
              }}>
                {loading ? "Submitting..." : "Submit Application"}
                {!loading && <ArrowRight size={16} />}
              </button>

              <p style={{ fontSize: 12, color: "#4A5568", textAlign: "center", marginTop: 16 }}>
                No payment required at this step. You&apos;ll hear back within 3 business days.
              </p>
            </form>
          )}
        </div>
      </section>
    </div>
  );
}
