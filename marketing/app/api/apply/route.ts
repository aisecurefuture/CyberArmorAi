import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { sendLeadEmail } from "@/lib/lead-mailer";

const ApplySchema = z.object({
  name: z.string().min(2).max(100).transform((v) => v.trim()),
  title: z.string().min(1).max(100).transform((v) => v.trim()),
  company: z.string().min(1).max(100).transform((v) => v.trim()),
  email: z.string().email().max(254).toLowerCase(),
  why: z.string().min(20).max(1000).transform((v) => v.trim()),
  aiTools: z.string().max(500).transform((v) => v.trim()).optional(),
  urgency: z.enum(["Immediate – within 2 weeks", "1–2 months", "3–6 months", "Exploring options"]),
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
    const body = await req.json();
    const parsed = ApplySchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json({ error: "Invalid application submission" }, { status: 400 });
    }

    const data = parsed.data;
    if (data._hp) {
      return NextResponse.json({ ok: true });
    }

    const text = [
      "New advisory application",
      "",
      `Name: ${data.name}`,
      `Title: ${data.title}`,
      `Company: ${data.company}`,
      `Email: ${data.email}`,
      `Urgency: ${data.urgency}`,
      `AI tools: ${data.aiTools || "Not specified"}`,
      "",
      "What they are trying to solve:",
      data.why,
    ].join("\n");

    const html = `
      <h2>New advisory application</h2>
      <p><strong>Name:</strong> ${escapeHtml(data.name)}</p>
      <p><strong>Title:</strong> ${escapeHtml(data.title)}</p>
      <p><strong>Company:</strong> ${escapeHtml(data.company)}</p>
      <p><strong>Email:</strong> ${escapeHtml(data.email)}</p>
      <p><strong>Urgency:</strong> ${escapeHtml(data.urgency)}</p>
      <p><strong>AI tools:</strong> ${escapeHtml(data.aiTools || "Not specified")}</p>
      <p><strong>What they are trying to solve:</strong><br>${escapeHtml(data.why).replaceAll("\n", "<br>")}</p>
    `;

    await sendLeadEmail({
      subject: `Advisory Application — ${data.name} @ ${data.company}`,
      replyTo: data.email,
      text,
      html,
    });

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("Apply handler error:", err);
    return NextResponse.json(
      { error: "We couldn't submit your application right now. Please email hello@cyberarmor.ai directly." },
      { status: 503 },
    );
  }
}
