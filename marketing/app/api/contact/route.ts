import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { sendLeadEmail } from "@/lib/lead-mailer";
import { enforceAllowedOrigin, enforceRateLimit } from "@/lib/request-guards";

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
  email: z.string().email().max(254).toLowerCase(),
  size: z.enum(companySizes),
  interest: z.enum(interestOptions),
  message: z.string().max(2000).transform((v) => v.trim()).optional(),
  _hp: z.literal("").optional(),
});

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
    const originFailure = enforceAllowedOrigin(req);
    if (originFailure) {
      return originFailure;
    }

    const rateLimitFailure = enforceRateLimit(req, "contact");
    if (rateLimitFailure) {
      return rateLimitFailure;
    }

    const body = await req.json();
    const parsed = ContactSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: "Invalid form submission" }, { status: 400 });
    }

    const data = parsed.data;
    if (data._hp) {
      return NextResponse.json({ ok: true });
    }

    const text = [
      "New CyberArmor demo request",
      "",
      `Name: ${data.name}`,
      `Title: ${data.title}`,
      `Company: ${data.company}`,
      `Email: ${data.email}`,
      `Company size: ${data.size}`,
      `Primary interest: ${data.interest}`,
      `Environment details: ${data.message || "Not provided"}`,
    ].join("\n");

    const html = `
      <h2>New CyberArmor demo request</h2>
      <p><strong>Name:</strong> ${escapeHtml(data.name)}</p>
      <p><strong>Title:</strong> ${escapeHtml(data.title)}</p>
      <p><strong>Company:</strong> ${escapeHtml(data.company)}</p>
      <p><strong>Email:</strong> ${escapeHtml(data.email)}</p>
      <p><strong>Company size:</strong> ${escapeHtml(data.size)}</p>
      <p><strong>Primary interest:</strong> ${escapeHtml(data.interest)}</p>
      <p><strong>Environment details:</strong><br>${escapeHtml(data.message || "Not provided").replaceAll("\n", "<br>")}</p>
    `;

    await sendLeadEmail({
      subject: `Demo Request — ${data.name} @ ${data.company}`,
      replyTo: data.email,
      text,
      html,
    });

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("Contact handler error:", err);
    return NextResponse.json(
      { error: "We couldn't submit your request right now. Please email hello@cyberarmor.ai directly." },
      { status: 503 },
    );
  }
}
