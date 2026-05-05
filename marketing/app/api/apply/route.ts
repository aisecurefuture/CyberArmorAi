import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    // Basic sanity check — Zod validation already ran client-side
    if (!body.name || !body.email || !body.why) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 });
    }

    // Log for now — replace with email notification (Resend / SendGrid)
    console.log("📋 New Advisory Application:");
    console.log(`   Name:    ${body.name} — ${body.title} @ ${body.company}`);
    console.log(`   Email:   ${body.email}`);
    console.log(`   Urgency: ${body.urgency}`);
    console.log(`   Tools:   ${body.aiTools ?? "Not specified"}`);
    console.log(`   Why:     ${body.why}`);

    // TODO: Send email notification to hello@cyberarmor.ai using Resend:
    // await resend.emails.send({
    //   from: "noreply@cyberarmor.ai",
    //   to: "hello@cyberarmor.ai",
    //   subject: `Advisory Application — ${body.name} @ ${body.company}`,
    //   text: `Name: ${body.name}\nTitle: ${body.title}\nCompany: ${body.company}\nEmail: ${body.email}\nUrgency: ${body.urgency}\nTools: ${body.aiTools}\n\nWhy:\n${body.why}`,
    // });

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("Apply handler error:", err);
    return NextResponse.json({ error: "Server error" }, { status: 500 });
  }
}
