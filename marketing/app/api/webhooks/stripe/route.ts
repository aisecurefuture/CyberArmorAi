import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";

function getStripeClient() {
  const apiKey = process.env.STRIPE_SECRET_KEY;
  if (!apiKey) {
    return null;
  }
  return new Stripe(apiKey, {
    apiVersion: "2026-04-22.dahlia",
  });
}

// Product labels for email notifications
const PRODUCT_LABELS: Record<string, string> = {
  CHECKLIST: "AI Security Executive Checklist ($29)",
  SNAPSHOT:  "AI Risk Snapshot ($97)",
  QA:        "AI Security Written Q&A ($497)",
  BRIEF:     "Executive AI Security Brief ($1,500)",
  ADVISORY:  "Priority Async Advisory ($3,000/month)",
};

export async function POST(req: NextRequest) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature");
  const stripe = getStripeClient();

  if (!sig || !process.env.STRIPE_WEBHOOK_SECRET || !stripe) {
    return NextResponse.json({ error: "Missing signature" }, { status: 400 });
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
        const customerEmail = session.customer_details?.email ?? "unknown";
        const customerName  = session.customer_details?.name  ?? "Unknown";
        const amount = session.amount_total ? `$${(session.amount_total / 100).toFixed(2)}` : "N/A";

        console.log(`✅ New purchase: ${PRODUCT_LABELS[product] ?? product}`);
        console.log(`   Customer: ${customerName} <${customerEmail}>`);
        console.log(`   Amount:   ${amount}`);
        console.log(`   Session:  ${session.id}`);

        // TODO: Replace with real email delivery (Resend, SendGrid, etc.)
        // await sendConfirmationEmail({ customerEmail, customerName, product, amount });
        // await sendAdminNotification({ customerEmail, customerName, product, amount });
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
