import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";
import { sendLeadEmail } from "@/lib/lead-mailer";
import { buildCustomerFulfillmentEmail } from "@/lib/stripe-fulfillment";

// Product labels for email notifications
const PRODUCT_LABELS: Record<string, string> = {
  CHECKLIST: "AI Security Executive Checklist ($29)",
  SNAPSHOT:  "AI Risk Snapshot ($97)",
  QA:        "AI Security Written Q&A ($497)",
  BRIEF:     "Executive AI Security Brief ($1,500)",
  ADVISORY:  "Priority Async Advisory ($3,000/month)",
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function getStripeClient(): Stripe {
  const secretKey = process.env.STRIPE_SECRET_KEY?.trim();
  if (!secretKey) {
    throw new Error("STRIPE_SECRET_KEY is not configured");
  }

  return new Stripe(secretKey, {
    apiVersion: "2026-04-22.dahlia",
  });
}

export async function POST(req: NextRequest) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature");

  if (!sig || !process.env.STRIPE_WEBHOOK_SECRET?.trim()) {
    return NextResponse.json({ error: "Missing signature" }, { status: 400 });
  }

  let stripe: Stripe;
  try {
    stripe = getStripeClient();
  } catch (err) {
    console.error("Webhook misconfiguration:", err);
    return NextResponse.json({ error: "Webhook unavailable" }, { status: 503 });
  }

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature verification failed:", err);
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const product = session.metadata?.product ?? "UNKNOWN";
        const customerEmail = session.customer_details?.email ?? session.customer_email ?? "unknown";
        const customerName  = session.customer_details?.name  ?? "Unknown";
        const amount = session.amount_total ? `$${(session.amount_total / 100).toFixed(2)}` : "N/A";

        console.log(`✅ New purchase: ${PRODUCT_LABELS[product] ?? product}`);
        console.log(`   Customer: ${customerName} <${customerEmail}>`);
        console.log(`   Amount:   ${amount}`);
        console.log(`   Session:  ${session.id}`);

        try {
          await sendLeadEmail({
            subject: `New CyberArmor purchase — ${PRODUCT_LABELS[product] ?? product}`,
            replyTo: customerEmail !== "unknown" ? customerEmail : undefined,
            text: [
              "New CyberArmor purchase",
              "",
              `Product: ${PRODUCT_LABELS[product] ?? product}`,
              `Customer: ${customerName}`,
              `Email: ${customerEmail}`,
              `Amount: ${amount}`,
              `Session: ${session.id}`,
            ].join("\n"),
            html: `
              <h2>New CyberArmor purchase</h2>
              <p><strong>Product:</strong> ${escapeHtml(PRODUCT_LABELS[product] ?? product)}</p>
              <p><strong>Customer:</strong> ${escapeHtml(customerName)}</p>
              <p><strong>Email:</strong> ${escapeHtml(customerEmail)}</p>
              <p><strong>Amount:</strong> ${escapeHtml(amount)}</p>
              <p><strong>Session:</strong> ${escapeHtml(session.id)}</p>
            `,
          });
        } catch (mailErr) {
          console.error("Purchase notification email failed:", mailErr);
        }

        if (customerEmail !== "unknown") {
          try {
            const fulfillmentEmail = await buildCustomerFulfillmentEmail(product, session);
            await sendLeadEmail({
              ...fulfillmentEmail,
              to: customerEmail,
            });
          } catch (fulfillmentErr) {
            console.error("Customer fulfillment email failed:", fulfillmentErr);
          }
        } else {
          console.warn(`Customer fulfillment skipped for session ${session.id}: no customer email found on Stripe session`);
        }

        break;
      }

      case "customer.subscription.created": {
        const sub = event.data.object as Stripe.Subscription;
        console.log(`🔄 New subscription: ${sub.id} — status: ${sub.status}`);
        break;
      }

      case "customer.subscription.deleted": {
        const sub = event.data.object as Stripe.Subscription;
        console.log(`❌ Subscription cancelled: ${sub.id}`);
        break;
      }

      case "invoice.payment_failed": {
        const inv = event.data.object as Stripe.Invoice;
        console.log(`⚠️  Payment failed: invoice ${inv.id} — customer: ${inv.customer}`);
        break;
      }

      default:
        // Ignore unhandled event types
        break;
    }
  } catch (err) {
    console.error("Webhook handler error:", err);
    return NextResponse.json({ error: "Handler error" }, { status: 500 });
  }

  return NextResponse.json({ received: true });
}
