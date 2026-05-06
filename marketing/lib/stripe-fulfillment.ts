import fs from "node:fs/promises";
import path from "node:path";
import type Stripe from "stripe";

export type StripeProductKey = "CHECKLIST" | "SNAPSHOT" | "QA" | "BRIEF" | "ADVISORY";

export type FulfillmentEmail = {
  subject: string;
  text: string;
  html: string;
  attachments?: Array<{
    filename: string;
    path: string;
    contentType?: string;
  }>;
};

type FulfillmentConfig =
  | {
      kind: "attachment";
      label: string;
      attachmentEnv: string;
      fallbackMessage: string;
      fileName: string;
    }
  | {
      kind: "intake";
      label: string;
      intro: string;
      bullets: string[];
      turnaround: string;
    };

const MAX_ATTACHMENT_BYTES = 7 * 1024 * 1024;
const SUPPORT_EMAIL = "hello@cyberarmor.ai";

const FULFILLMENT_MAP: Record<StripeProductKey, FulfillmentConfig> = {
  CHECKLIST: {
    kind: "attachment",
    label: "AI Security Executive Checklist",
    attachmentEnv: "STRIPE_FULFILLMENT_CHECKLIST_PATH",
    fallbackMessage:
      "Your checklist is being prepared for delivery. Our team will send it manually as soon as possible.",
    fileName: "CyberArmor-AI-Security-Executive-Checklist.pdf",
  },
  SNAPSHOT: {
    kind: "intake",
    label: "AI Risk Snapshot",
    intro: "Reply to this email with the AI use cases you want reviewed.",
    bullets: [
      "Your company name and primary point of contact",
      "Up to 3 AI workflows, vendors, or planned use cases",
      "What data each use case touches",
      "Any upcoming board, security, or procurement deadline",
    ],
    turnaround: "3-5 business days after intake is received",
  },
  QA: {
    kind: "intake",
    label: "AI Security Written Q&A",
    intro: "Reply to this email with your questions and enough context for a precise written response.",
    bullets: [
      "Your company name and role",
      "Up to 5 specific AI security questions",
      "The AI tools, vendors, or workflows involved",
      "Any constraints or decision deadline we should keep in mind",
    ],
    turnaround: "5 business days after intake is received",
  },
  BRIEF: {
    kind: "intake",
    label: "Executive AI Security Brief",
    intro: "Reply to this email with the decision context for the brief so we can start immediately.",
    bullets: [
      "Your company name and executive sponsor",
      "Up to 5 AI workflows, vendors, or product concepts to review",
      "The audience for the brief: board, leadership team, security, or investors",
      "Any deadlines, launch targets, or procurement milestones",
    ],
    turnaround: "5-7 business days after intake is received",
  },
  ADVISORY: {
    kind: "intake",
    label: "Priority Async Advisory",
    intro: "This service is application-only, so we will review the request and follow up directly.",
    bullets: [
      "Your top advisory priorities",
      "The stakeholders involved",
      "Your expected response timeline",
    ],
    turnaround: "Response within 2 business days after review",
  },
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function getSiteUrl(): string {
  return (process.env.NEXT_PUBLIC_SITE_URL?.trim() || "https://cyberarmor.ai").replace(/\/+$/, "");
}

async function resolveAttachment(filePath: string, fileName: string) {
  const resolvedPath = path.resolve(filePath);
  const stat = await fs.stat(resolvedPath);

  if (!stat.isFile()) {
    throw new Error(`Fulfillment asset is not a file: ${resolvedPath}`);
  }

  if (stat.size > MAX_ATTACHMENT_BYTES) {
    throw new Error(`Fulfillment asset exceeds ${MAX_ATTACHMENT_BYTES} bytes: ${resolvedPath}`);
  }

  return {
    filename: fileName,
    path: resolvedPath,
    contentType: "application/pdf",
  };
}

export async function buildCustomerFulfillmentEmail(
  product: string,
  session: Stripe.Checkout.Session,
): Promise<FulfillmentEmail> {
  const config = FULFILLMENT_MAP[product as StripeProductKey];
  const customerName = session.customer_details?.name?.trim() || "there";
  const sessionId = session.id;
  const siteUrl = getSiteUrl();
  const supportLink = `${siteUrl}/support`;

  if (!config) {
    return {
      subject: "CyberArmor AI order received",
      text: [
        `Hi ${customerName},`,
        "",
        "Thank you for your purchase. Our team has your order and will follow up with next steps shortly.",
        "",
        `Order reference: ${sessionId}`,
        `Support: ${supportLink}`,
        `Email: ${SUPPORT_EMAIL}`,
      ].join("\n"),
      html: `
        <p>Hi ${escapeHtml(customerName)},</p>
        <p>Thank you for your purchase. Our team has your order and will follow up with next steps shortly.</p>
        <p><strong>Order reference:</strong> ${escapeHtml(sessionId)}</p>
        <p><a href="${escapeHtml(supportLink)}">Support center</a> or email <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a>.</p>
      `,
    };
  }

  if (config.kind === "attachment") {
    const configuredPath = process.env[config.attachmentEnv]?.trim();

    if (!configuredPath) {
      return {
        subject: `Your ${config.label} order is confirmed`,
        text: [
          `Hi ${customerName},`,
          "",
          "Thank you for your purchase.",
          config.fallbackMessage,
          "",
          `Order reference: ${sessionId}`,
          `Support: ${supportLink}`,
          `Email: ${SUPPORT_EMAIL}`,
        ].join("\n"),
        html: `
          <p>Hi ${escapeHtml(customerName)},</p>
          <p>Thank you for your purchase.</p>
          <p>${escapeHtml(config.fallbackMessage)}</p>
          <p><strong>Order reference:</strong> ${escapeHtml(sessionId)}</p>
          <p><a href="${escapeHtml(supportLink)}">Support center</a> or email <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a>.</p>
        `,
      };
    }

    const attachment = await resolveAttachment(configuredPath, config.fileName);

    return {
      subject: `Your ${config.label} is attached`,
      text: [
        `Hi ${customerName},`,
        "",
        "Thank you for your purchase.",
        `Your ${config.label} is attached to this email as a PDF.`,
        "",
        `Order reference: ${sessionId}`,
        `Support: ${supportLink}`,
        `Email: ${SUPPORT_EMAIL}`,
      ].join("\n"),
      html: `
        <p>Hi ${escapeHtml(customerName)},</p>
        <p>Thank you for your purchase.</p>
        <p>Your <strong>${escapeHtml(config.label)}</strong> is attached to this email as a PDF.</p>
        <p><strong>Order reference:</strong> ${escapeHtml(sessionId)}</p>
        <p><a href="${escapeHtml(supportLink)}">Support center</a> or email <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a>.</p>
      `,
      attachments: [attachment],
    };
  }

  const bulletText = config.bullets.map((item) => `- ${item}`).join("\n");
  const bulletHtml = config.bullets.map((item) => `<li>${escapeHtml(item)}</li>`).join("");

  return {
    subject: `Next steps for your ${config.label}`,
    text: [
      `Hi ${customerName},`,
      "",
      "Thank you for your purchase.",
      config.intro,
      "",
      bulletText,
      "",
      `Turnaround: ${config.turnaround}`,
      "",
      `Order reference: ${sessionId}`,
      `Support: ${supportLink}`,
      `Email: ${SUPPORT_EMAIL}`,
    ].join("\n"),
    html: `
      <p>Hi ${escapeHtml(customerName)},</p>
      <p>Thank you for your purchase.</p>
      <p>${escapeHtml(config.intro)}</p>
      <ul>${bulletHtml}</ul>
      <p><strong>Turnaround:</strong> ${escapeHtml(config.turnaround)}</p>
      <p><strong>Order reference:</strong> ${escapeHtml(sessionId)}</p>
      <p><a href="${escapeHtml(supportLink)}">Support center</a> or email <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a>.</p>
    `,
  };
}
