import nodemailer from "nodemailer";

type MailPayload = {
  subject: string;
  replyTo?: string;
  text: string;
  html: string;
  to?: string;
  attachments?: Array<{
    filename: string;
    path: string;
    contentType?: string;
  }>;
};

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required mail configuration: ${name}`);
  }
  return value;
}

function parsePort(raw: string): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error("Invalid MARKETING_CONTACT_SMTP_PORT");
  }
  return parsed;
}

function smtpSecureMode(): boolean {
  const raw = (process.env.MARKETING_CONTACT_SMTP_TLS ?? "true").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

function shouldUseImplicitTls(port: number, tlsEnabled: boolean): boolean {
  // Port 465 uses implicit TLS. Port 587 typically upgrades via STARTTLS.
  return tlsEnabled && port === 465;
}

function buildTransport() {
  const port = parsePort(process.env.MARKETING_CONTACT_SMTP_PORT ?? "587");
  const tlsEnabled = smtpSecureMode();

  return nodemailer.createTransport({
    host: requiredEnv("MARKETING_CONTACT_SMTP_HOST"),
    port,
    secure: shouldUseImplicitTls(port, tlsEnabled),
    requireTLS: tlsEnabled,
    auth: {
      user: requiredEnv("MARKETING_CONTACT_SMTP_USER"),
      pass: requiredEnv("MARKETING_CONTACT_SMTP_PASSWORD"),
    },
  });
}

export async function sendLeadEmail(payload: MailPayload): Promise<void> {
  const transport = buildTransport();
  await transport.sendMail({
    from: requiredEnv("MARKETING_CONTACT_SMTP_FROM"),
    to: payload.to ?? requiredEnv("MARKETING_CONTACT_TO"),
    subject: payload.subject,
    replyTo: payload.replyTo,
    text: payload.text,
    html: payload.html,
    attachments: payload.attachments,
  });
}
