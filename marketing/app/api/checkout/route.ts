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

    if (!priceKey || typeof priceKey !== "string" || !(priceKey in PRICE_MAP)) {
      return NextResponse.json({ error: "Invalid product selection" }, { status: 400 });
    }

    if (priceKey === "ADVISORY") {
      return NextResponse.json(
        { error: "Priority Advisory is application-only. Please submit the advisory application to continue." },
        { status: 403 },
      );
    }

    const priceId = PRICE_MAP[priceKey];
    if (!priceId) {
      return NextResponse.json({ error: "Product not configured. Please contact hello@cyberarmor.ai" }, { status: 503 });
    }

    const stripeSecretKey = process.env.STRIPE_SECRET_KEY?.trim();
    if (!stripeSecretKey) {
      return NextResponse.json(
        { error: "Checkout is temporarily unavailable. Please contact hello@cyberarmor.ai." },
        { status: 503 },
      );
    }

    const siteUrl = process.env.NEXT_PUBLIC_SITE_URL?.trim().replace(/\/+$/, "");
    if (!siteUrl) {
      return NextResponse.json(
        { error: "Site configuration is incomplete. Please contact hello@cyberarmor.ai." },
        { status: 503 },
      );
    }

    const stripe = new Stripe(stripeSecretKey, {
      apiVersion: "2026-04-22.dahlia",
    });

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${siteUrl}/advisory/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${siteUrl}/advisory`,
      allow_promotion_codes: true,
      billing_address_collection: "auto",
      customer_creation: "always",
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
