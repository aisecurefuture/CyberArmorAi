/**
 * Run once to create all CyberArmor AI advisory products in Stripe.
 *
 * Usage:
 *   STRIPE_SECRET_KEY=sk_live_xxx npx tsx scripts/stripe-setup.ts
 *
 * Copy the printed Price IDs into your .env.local file.
 */

import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2026-04-22.dahlia",
});

const products = [
  {
    key: "CHECKLIST",
    name: "AI Security Executive Checklist",
    description: "Practical AI risk checklist for executives. Instant PDF download.",
    amount: 2900,       // $29.00 in cents
    mode: "payment" as const,
  },
  {
    key: "SNAPSHOT",
    name: "AI Risk Snapshot",
    description: "Written review of up to 3 AI use cases. Risk-classified with recommendations. 3–5 business days. 100% async.",
    amount: 9700,       // $97.00
    mode: "payment" as const,
  },
  {
    key: "QA",
    name: "AI Security Written Q&A",
    description: "Submit up to 5 AI security questions. Receive a structured written response within 5 business days. One round. 100% async.",
    amount: 49700,      // $497.00
    mode: "payment" as const,
  },
  {
    key: "BRIEF",
    name: "Executive AI Security Brief",
    description: "5–8 page boardroom-ready AI security briefing. Reviews up to 5 workflows/vendors. 5–7 business days. 100% async.",
    amount: 150000,     // $1,500.00
    mode: "payment" as const,
  },
  {
    key: "ADVISORY",
    name: "Priority Async Advisory",
    description: "Monthly async AI security advisory. Up to 4 written requests/month. Response within 2 business days. Application-only.",
    amount: 300000,     // $3,000.00/month
    mode: "subscription" as const,
  },
];

async function main() {
  console.log("Creating CyberArmor AI advisory products in Stripe...\n");
  const results: Record<string, string> = {};

  for (const p of products) {
    // Create the product
    const product = await stripe.products.create({
      name: p.name,
      description: p.description,
      metadata: { key: p.key, source: "cyberarmor.ai" },
    });

    // Create the price
    const price = await stripe.prices.create({
      product: product.id,
      unit_amount: p.amount,
      currency: "usd",
      ...(p.mode === "subscription"
        ? { recurring: { interval: "month" } }
        : {}),
      metadata: { key: p.key },
    });

    results[p.key] = price.id;
    console.log(`✅ ${p.name}`);
    console.log(`   Product ID: ${product.id}`);
    console.log(`   Price ID:   ${price.id}\n`);
  }

  console.log("─".repeat(60));
  console.log("Paste these into your .env.local:\n");
  for (const [key, priceId] of Object.entries(results)) {
    console.log(`STRIPE_PRICE_${key}=${priceId}`);
  }
  console.log("\nDone. ✓");
}

main().catch(console.error);
