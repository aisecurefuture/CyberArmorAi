import { randomBytes, createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { sendLeadEmail } from "@/lib/lead-mailer";
import { enforceAllowedOrigin, enforceRateLimit } from "@/lib/request-guards";

export const runtime = "nodejs";

const MAX_FILES = 3;
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 8 * 1024 * 1024;

const allowedExtensions = new Set([
  ".log",
  ".txt",
  ".json",
  ".ndjson",
  ".csv",
  ".har",
  ".yaml",
  ".yml",
  ".zip",
  ".gz",
  ".tgz",
]);

const severityOptions = ["S1", "S2", "S3"] as const;
const surfaceOptions = [
  "Deployment / routing",
  "Customer portal",
  "Admin portal",
  "Docs / support",
  "Bootstrap / enrollment",
  "Runtime / policy",
  "Detection / evidence",
  "Other",
] as const;

const SupportTicketSchema = z.object({
  name: z.string().min(2).max(100).transform((v) => v.trim()),
  email: z.string().email().max(254).toLowerCase(),
  company: z.string().min(1).max(120).transform((v) => v.trim()),
  severity: z.enum(severityOptions),
  surface: z.enum(surfaceOptions),
  subject: z.string().min(5).max(160).transform((v) => v.trim()),
  tenantId: z.string().max(120).transform((v) => v.trim()).optional(),
  affectedUrl: z.string().max(500).transform((v) => v.trim()).optional(),
  requestId: z.string().max(160).transform((v) => v.trim()).optional(),
  description: z.string().min(20).max(4000).transform((v) => v.trim()),
  logConsent: z.string().optional(),
  _hp: z.literal("").optional(),
});

type Attachment = {
  filename: string;
  content: Buffer;
  contentType?: string;
  size: number;
  sha256: string;
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function field(formData: FormData, name: string): string | undefined {
  const value = formData.get(name);
  return typeof value === "string" ? value : undefined;
}

function extensionFor(filename: string): string {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".tar.gz")) {
    return ".tgz";
  }
  const dot = lower.lastIndexOf(".");
  return dot >= 0 ? lower.slice(dot) : "";
}

function safeFilename(rawName: string): string {
  const withoutPath = rawName.split(/[\\/]/).pop() || "support-log.txt";
  return withoutPath.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120) || "support-log.txt";
}

function newTicketId(): string {
  const date = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  return `CA-SUP-${date}-${randomBytes(3).toString("hex").toUpperCase()}`;
}

async function collectAttachments(formData: FormData): Promise<Attachment[]> {
  const files = formData.getAll("logs").filter((value): value is File => value instanceof File && value.size > 0);

  if (files.length > MAX_FILES) {
    throw new Error(`Upload up to ${MAX_FILES} log files.`);
  }

  let totalBytes = 0;
  const attachments: Attachment[] = [];

  for (const file of files) {
    const filename = safeFilename(file.name);
    const ext = extensionFor(filename);

    if (!allowedExtensions.has(ext)) {
      throw new Error(`Unsupported log file type: ${filename}`);
    }
    if (file.size > MAX_FILE_BYTES) {
      throw new Error(`File is too large: ${filename}`);
    }

    totalBytes += file.size;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("Total upload size is too large.");
    }

    const content = Buffer.from(await file.arrayBuffer());
    const sha256 = createHash("sha256").update(content).digest("hex");
    attachments.push({
      filename,
      content,
      contentType: file.type || "application/octet-stream",
      size: file.size,
      sha256,
    });
  }

  return attachments;
}

export async function POST(req: NextRequest) {
  try {
    const originFailure = enforceAllowedOrigin(req);
    if (originFailure) {
      return originFailure;
    }

    const rateLimitFailure = enforceRateLimit(req, "support");
    if (rateLimitFailure) {
      return rateLimitFailure;
    }

    const formData = await req.formData();
    const parsed = SupportTicketSchema.safeParse({
      name: field(formData, "name"),
      email: field(formData, "email"),
      company: field(formData, "company"),
      severity: field(formData, "severity"),
      surface: field(formData, "surface"),
      subject: field(formData, "subject"),
      tenantId: field(formData, "tenantId"),
      affectedUrl: field(formData, "affectedUrl"),
      requestId: field(formData, "requestId"),
      description: field(formData, "description"),
      logConsent: field(formData, "logConsent"),
      _hp: field(formData, "_hp"),
    });

    if (!parsed.success) {
      return NextResponse.json({ error: "Invalid support ticket submission" }, { status: 400 });
    }

    const data = parsed.data;
    if (data._hp) {
      return NextResponse.json({ ok: true });
    }

    const attachments = await collectAttachments(formData);
    if (attachments.length > 0 && data.logConsent !== "true") {
      return NextResponse.json({ error: "Confirm that uploaded logs are approved for secure support review." }, { status: 400 });
    }

    const ticketId = newTicketId();
    const attachmentSummary = attachments.length
      ? attachments.map((item) => `- ${item.filename} (${item.size} bytes, sha256=${item.sha256})`).join("\n")
      : "No logs attached";

    const text = [
      `New CyberArmor support ticket: ${ticketId}`,
      "",
      `Name: ${data.name}`,
      `Company: ${data.company}`,
      `Email: ${data.email}`,
      `Severity: ${data.severity}`,
      `Surface: ${data.surface}`,
      `Subject: ${data.subject}`,
      `Tenant ID: ${data.tenantId || "Not provided"}`,
      `Affected URL: ${data.affectedUrl || "Not provided"}`,
      `Request/trace ID: ${data.requestId || "Not provided"}`,
      "",
      "Description:",
      data.description,
      "",
      "Attachments:",
      attachmentSummary,
    ].join("\n");

    const html = `
      <h2>New CyberArmor support ticket: ${escapeHtml(ticketId)}</h2>
      <p><strong>Name:</strong> ${escapeHtml(data.name)}</p>
      <p><strong>Company:</strong> ${escapeHtml(data.company)}</p>
      <p><strong>Email:</strong> ${escapeHtml(data.email)}</p>
      <p><strong>Severity:</strong> ${escapeHtml(data.severity)}</p>
      <p><strong>Surface:</strong> ${escapeHtml(data.surface)}</p>
      <p><strong>Subject:</strong> ${escapeHtml(data.subject)}</p>
      <p><strong>Tenant ID:</strong> ${escapeHtml(data.tenantId || "Not provided")}</p>
      <p><strong>Affected URL:</strong> ${escapeHtml(data.affectedUrl || "Not provided")}</p>
      <p><strong>Request/trace ID:</strong> ${escapeHtml(data.requestId || "Not provided")}</p>
      <p><strong>Description:</strong><br>${escapeHtml(data.description).replaceAll("\n", "<br>")}</p>
      <p><strong>Attachments:</strong><br>${escapeHtml(attachmentSummary).replaceAll("\n", "<br>")}</p>
    `;

    await sendLeadEmail({
      subject: `[${data.severity}] Support Ticket ${ticketId} - ${data.subject}`,
      replyTo: data.email,
      text,
      html,
      attachments: attachments.map((item) => ({
        filename: item.filename,
        content: item.content,
        contentType: item.contentType,
      })),
    });

    return NextResponse.json({ ok: true, ticketId });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Support ticket submission failed";
    if (message.includes("Upload") || message.includes("Unsupported") || message.includes("large")) {
      return NextResponse.json({ error: message }, { status: 400 });
    }

    console.error("Support handler error:", message);
    return NextResponse.json(
      { error: "We couldn't submit your support ticket right now. Please email hello@cyberarmor.ai directly." },
      { status: 503 },
    );
  }
}
