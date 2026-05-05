import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";

// Price keys map to environment variable names holding Stripe Price IDs
const PRICE_MAP: Record<string, string | undefined> = {
  CHECKLIST: process.env.STRIPE_PRICE_CHECKLIST,
  SNAPSHOT:  process.env.STRIPE_PRICE_SNAPSHOT,
  QA:        process.env.STRIPE_PRICE_QA,
  BRIEF:     process.env.STRIPE_PRICE_BRIEF,
  ADVISORY:  process.env.STRIPE_PRICE_ADVISORY,
};

export async function POST(req: NextRequest) {
  try {
    const { priceKey } = await req.json();

    if (!priceKey || typeof priceKey !== "string" || !PRICE_MAP[priceKey]) {
      return NextResponse.json({ error: "Invalid product selection" }, { status: 400 });
    }

    const priceId = PRICE_MAP[priceKey];
    if (!priceId) {
      return NextResponse.json({ error: "Product not configured. Please contact hello@cyberarmor.ai" }, { status: 503 });
    }

    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
      apiVersion: "2026-04-22.dahlia",
    });

    const isSubscription = priceKey === "ADVISORY";

    const session = await stripe.checkout.sessions.create({
      mode: isSubscription ? "subscription" : "payment",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.NEXT_PUBLIC_SITE_URL}/advisory/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.NEXT_PUBLIC_SITE_URL}/advisory`,
      allow_promotion_codes: true,
      billing_address_collection: "auto",
      customer_creation: isSubscription ? undefined : "always",
      metadata: {
        product: priceKey,
        source: "cyberarmor.ai",
      },
    });

    return NextResponse.json({ url: session.url });
  } catch (err) {
    console.error("Stripe checkout error:", err);
    const message = err instanceof Error ? err.message : "Unexpected error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
