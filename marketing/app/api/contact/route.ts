import { NextRequest, NextResponse } from "next/server";
import nodemailer from "nodemailer";
import { z } from "zod";

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

const ContactSchema = z.object({
  name: z.string().min(2).max(100).regex(/^[\p{L}\s'\-\.]+$/u).transform((v) => v.trim()),
  title: z.string().min(1).max(100).transform((v) => v.trim()),
  company: z.string().min(1).max(100).transform((v) => v.trim()),
  email: z
    .string()
    .email()
    .max(254)
    .toLowerCase()
    .refine((email) => {
      const personalDomains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "aol.com"];
      const domain = email.split("@")[1];
      return !personalDomains.includes(domain);
    }),
  size: z.enum(companySizes),
  interest: z.enum(interestOptions),
  message: z.string().max(2000).transform((v) => v.trim()).optional(),
  _hp: z.literal("").optional(),
});

function envFirst(...keys: string[]): string {
  for (const key of keys) {
    const value = (process.env[key] || "").trim();
    if (value) {
      return value;
    }
  }
  return "";
}

function getMailerConfig() {
  const host = envFirst("MARKETING_CONTACT_SMTP_HOST", "CUSTOMER_PORTAL_SMTP_HOST", "ADMIN_DASHBOARD_SMTP_HOST");
  const port = parseInt(
    envFirst("MARKETING_CONTACT_SMTP_PORT", "CUSTOMER_PORTAL_SMTP_PORT", "ADMIN_DASHBOARD_SMTP_PORT") || "587",
    10,
  );
  const user = envFirst("MARKETING_CONTACT_SMTP_USER", "CUSTOMER_PORTAL_SMTP_USER", "ADMIN_DASHBOARD_SMTP_USER");
  const password = envFirst(
    "MARKETING_CONTACT_SMTP_PASSWORD",
    "CUSTOMER_PORTAL_SMTP_PASSWORD",
    "ADMIN_DASHBOARD_SMTP_PASSWORD",
  );
  const from = envFirst(
    "MARKETING_CONTACT_SMTP_FROM",
    "CUSTOMER_PORTAL_SMTP_FROM",
    "ADMIN_DASHBOARD_SMTP_FROM",
  );
  const to =
    envFirst("MARKETING_CONTACT_TO") ||
    `hello@${(process.env.MARKETING_DOMAIN || "cyberarmor.ai").trim()}`;
  const useTls = (
    envFirst("MARKETING_CONTACT_SMTP_TLS", "CUSTOMER_PORTAL_SMTP_TLS", "ADMIN_DASHBOARD_SMTP_TLS") || "true"
  )
    .toLowerCase()
    .trim() in { "1": true, true: true, yes: true, on: true };

  return { host, port, user, password, from, to, useTls };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const parsed = ContactSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json({ error: "Invalid contact submission." }, { status: 400 });
    }

    if (parsed.data._hp) {
      return NextResponse.json({ ok: true }, { status: 202 });
    }

    const mailer = getMailerConfig();
    if (!mailer.host || !mailer.from || !mailer.to) {
      return NextResponse.json(
        { error: "Contact email is not configured yet. Please email hello@cyberarmor.ai directly." },
        { status: 503 },
      );
    }

    const transporter = nodemailer.createTransport({
      host: mailer.host,
      port: mailer.port,
      secure: mailer.port === 465,
      auth: mailer.user ? { user: mailer.user, pass: mailer.password } : undefined,
      requireTLS: mailer.port !== 465 && mailer.useTls,
    });

    const lead = parsed.data;
    const subject = `New CyberArmor demo request from ${lead.name} at ${lead.company}`;
    const text = [
      "New CyberArmor contact form submission",
      "",
      `Name: ${lead.name}`,
      `Title: ${lead.title}`,
      `Company: ${lead.company}`,
      `Email: ${lead.email}`,
      `Company Size: ${lead.size}`,
      `Primary Interest: ${lead.interest}`,
      "",
      "Message:",
      lead.message || "(none provided)",
    ].join("\n");

    const html = `
      <h2>New CyberArmor contact form submission</h2>
      <p><strong>Name:</strong> ${escapeHtml(lead.name)}</p>
      <p><strong>Title:</strong> ${escapeHtml(lead.title)}</p>
      <p><strong>Company:</strong> ${escapeHtml(lead.company)}</p>
      <p><strong>Email:</strong> ${escapeHtml(lead.email)}</p>
      <p><strong>Company Size:</strong> ${escapeHtml(lead.size)}</p>
      <p><strong>Primary Interest:</strong> ${escapeHtml(lead.interest)}</p>
      <p><strong>Message:</strong></p>
      <pre style="white-space: pre-wrap; font-family: Arial, sans-serif;">${escapeHtml(lead.message || "(none provided)")}</pre>
    `;

    await transporter.sendMail({
      from: mailer.from,
      to: mailer.to,
      replyTo: lead.email,
      subject,
      text,
      html,
    });

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("Marketing contact form delivery failed:", error);
    return NextResponse.json(
      { error: "We couldn't send your request right now. Please email hello@cyberarmor.ai directly." },
      { status: 500 },
    );
  }
}
