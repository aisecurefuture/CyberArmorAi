import type { Metadata } from "next";
import Link from "next/link";
import { LifeBuoy, Mail, Clock, ShieldCheck, BookOpen, ArrowRight } from "lucide-react";

export const metadata: Metadata = {
  title: "Support",
  description:
    "Get help with the CyberArmor AI platform. Contact our support team, browse documentation, or report a security issue.",
  alternates: {
    canonical: "https://support.cyberarmor.ai",
  },
};

const SUPPORT_EMAIL = "support@cyberarmor.ai";
const SECURITY_EMAIL = "security@cyberarmor.ai";

const faqs: { q: string; a: React.ReactNode }[] = [
  {
    q: "How do I get help with a deployment or runtime issue?",
    a: (
      <>
        Email{" "}
        <a className="text-indigo-600 hover:underline" href={`mailto:${SUPPORT_EMAIL}`}>
          {SUPPORT_EMAIL}
        </a>{" "}
        with the affected service, environment, recent log excerpts, and a
        timestamp. We respond within one business day.
      </>
    ),
  },
  {
    q: "Where do I find product documentation?",
    a: (
      <>
        Our docs live at{" "}
        <a className="text-indigo-600 hover:underline" href="https://docs.cyberarmor.ai">
          docs.cyberarmor.ai
        </a>{" "}
        — install guides, integration walkthroughs, and the policy reference.
      </>
    ),
  },
  {
    q: "How do I report a security vulnerability?",
    a: (
      <>
        Please email{" "}
        <a className="text-indigo-600 hover:underline" href={`mailto:${SECURITY_EMAIL}`}>
          {SECURITY_EMAIL}
        </a>{" "}
        rather than filing a public issue. We acknowledge reports within 48
        hours and will coordinate disclosure.
      </>
    ),
  },
  {
    q: "What is the support response SLA?",
    a: (
      <>
        Standard support targets one business day. Production-down incidents
        for customers on a paid tier are handled with priority — include
        &quot;P1&quot; in your subject line.
      </>
    ),
  },
  {
    q: "Can I request a feature or integration?",
    a: (
      <>
        Yes. Email support with the use case and the systems involved. We
        triage feature requests weekly and will let you know if it&apos;s on
        the roadmap.
      </>
    ),
  },
  {
    q: "I&apos;m evaluating CyberArmor — who do I talk to?",
    a: (
      <>
        Sales and pre-sales questions go through{" "}
        <Link className="text-indigo-600 hover:underline" href="/contact">
          our contact form
        </Link>
        , not support.
      </>
    ),
  },
];

export default function SupportPage() {
  return (
    <main className="bg-white">
      <section className="border-b border-slate-200 bg-gradient-to-b from-slate-50 to-white">
        <div className="mx-auto max-w-5xl px-6 py-20 text-center">
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-indigo-200 bg-indigo-50 px-4 py-1.5 text-sm font-medium text-indigo-700">
            <LifeBuoy className="h-4 w-4" />
            Customer Support
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-slate-900 sm:text-5xl">
            We&apos;re here to help.
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-lg text-slate-600">
            Reach the CyberArmor support team for product issues, integration
            questions, or anything that isn&apos;t working the way you expect.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 py-16">
        <div className="grid gap-6 sm:grid-cols-2">
          <a
            href={`mailto:${SUPPORT_EMAIL}`}
            className="group rounded-2xl border border-slate-200 bg-white p-8 shadow-sm transition hover:border-indigo-300 hover:shadow-md"
          >
            <Mail className="h-8 w-8 text-indigo-600" />
            <h2 className="mt-4 text-xl font-semibold text-slate-900">
              Email support
            </h2>
            <p className="mt-2 text-slate-600">
              For product, deployment, or runtime issues. We respond within one
              business day.
            </p>
            <div className="mt-4 inline-flex items-center gap-2 font-medium text-indigo-600">
              {SUPPORT_EMAIL}
              <ArrowRight className="h-4 w-4 transition group-hover:translate-x-0.5" />
            </div>
          </a>

          <a
            href={`mailto:${SECURITY_EMAIL}`}
            className="group rounded-2xl border border-slate-200 bg-white p-8 shadow-sm transition hover:border-indigo-300 hover:shadow-md"
          >
            <ShieldCheck className="h-8 w-8 text-indigo-600" />
            <h2 className="mt-4 text-xl font-semibold text-slate-900">
              Security disclosures
            </h2>
            <p className="mt-2 text-slate-600">
              Suspect a vulnerability? Report it privately. Acknowledgement
              within 48 hours, coordinated disclosure.
            </p>
            <div className="mt-4 inline-flex items-center gap-2 font-medium text-indigo-600">
              {SECURITY_EMAIL}
              <ArrowRight className="h-4 w-4 transition group-hover:translate-x-0.5" />
            </div>
          </a>
        </div>

        <div className="mt-6 grid gap-6 sm:grid-cols-2">
          <Link
            href="https://docs.cyberarmor.ai"
            className="group flex items-start gap-4 rounded-2xl border border-slate-200 bg-slate-50 p-6 transition hover:border-indigo-300 hover:bg-white hover:shadow-sm"
          >
            <BookOpen className="mt-1 h-6 w-6 flex-none text-slate-700" />
            <div>
              <div className="font-semibold text-slate-900">
                Browse the docs
              </div>
              <p className="mt-1 text-sm text-slate-600">
                Setup guides, integration recipes, and the policy reference.
              </p>
            </div>
          </Link>

          <div className="flex items-start gap-4 rounded-2xl border border-slate-200 bg-slate-50 p-6">
            <Clock className="mt-1 h-6 w-6 flex-none text-slate-700" />
            <div>
              <div className="font-semibold text-slate-900">Hours</div>
              <p className="mt-1 text-sm text-slate-600">
                Monday–Friday, 9am–6pm ET. P1 incidents on paid tiers handled
                outside business hours.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="border-t border-slate-200 bg-slate-50">
        <div className="mx-auto max-w-3xl px-6 py-16">
          <h2 className="text-3xl font-bold tracking-tight text-slate-900">
            Frequently asked
          </h2>
          <dl className="mt-10 space-y-8">
            {faqs.map((item, i) => (
              <div key={i} className="border-b border-slate-200 pb-8 last:border-b-0">
                <dt className="text-lg font-semibold text-slate-900">
                  {item.q}
                </dt>
                <dd className="mt-2 text-slate-600">{item.a}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>
    </main>
  );
}
