import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, ShieldCheck, Activity, Lock, Bot, CheckCircle2, Users } from "lucide-react";
import FinalCTA from "@/components/sections/FinalCTA";

export const metadata: Metadata = {
  title: "Pilot Programs — CyberArmor.AI",
  description:
    "Controlled AI security pilots for regulated enterprises. Start with the URL Trust Gate, expand to runtime control and evidence, or engage the full Agentic AI Trust Gate. Purpose-built for security-led evaluation.",
};

// ─── Program tiers ────────────────────────────────────────────────────────
const programs = [
  {
    id: "url-trust-gate",
    icon: ShieldCheck,
    color: "#00A3FF",
    number: "01",
    name: "URL Trust Gate Pilot",
    tagline: "Stop hostile web content before it enters AI context.",
    buyers: ["AppSec teams", "CISO office", "AI platform engineers"],
    problem:
      "Your AI systems fetch, ingest, and act on external URLs. Hidden prompt injection, CSS-concealed instructions, and zero-width-encoded payloads are invisible to existing filters — but read verbatim by LLMs. This pilot deploys the URL Trust Gate in front of one or more AI-connected workflows.",
    included: [
      "15-minute local PoC to validate the detection pipeline before you commit",
      "Controlled deployment of the URL Trust Gate service in your environment",
      "Integration with one consumer surface: LangChain SDK, LlamaIndex SDK, RASP Python, browser extension, or endpoint agent",
      "Three reputation feeds optionally enabled: Google Safe Browsing v4, Microsoft SmartScreen, VirusTotal v3",
      "Policy decisions — allow, warn, redact, sandbox, block, isolate — on every evaluated URL",
      "Evidence records written to audit service on every non-cached decision",
      "Bi-weekly pilot review calls and a pilot-close readout for your security leadership",
    ],
    outcome:
      "A measured, evidence-backed answer to: how much hostile content were your AI systems about to ingest, and what did the gate do about it?",
    href: "/contact?pilot=url-trust-gate",
  },
  {
    id: "runtime",
    icon: Activity,
    color: "#A855F7",
    number: "02",
    name: "Runtime Control + Evidence",
    tagline: "Detection, policy enforcement, and decision-level evidence across your AI deployment.",
    buyers: ["CISO", "Security architecture", "GRC / compliance teams"],
    problem:
      "Prompt injection, credential leaks, sensitive data exposure, and provider misuse are happening inside your AI applications today. Without runtime enforcement and decision-level evidence, you cannot detect them, prove they did not occur, or demonstrate control to auditors.",
    included: [
      "URL Trust Gate pilot (as above) plus runtime detection and enforcement",
      "Prompt injection, sensitive data, toxicity, and output-safety detection on AI requests",
      "Policy engine: tenant-scoped rules tied to actor, workload, model, provider, and data context",
      "Agent identity registration and delegation chain tracking for autonomous AI workflows",
      "Audit service with immutable, attributable evidence records for SOC, audit, and legal review",
      "Response orchestration: block, redact, notify, ticket, or route on policy violation",
      "Compliance evidence snapshot against relevant frameworks (NIST AI RMF, SOC 2, ISO 27001, and others)",
      "Dedicated pilot design partner engagement and quarterly business review",
    ],
    outcome:
      "Runtime control over what your AI systems do, with evidence you can show to a CISO, board, regulator, or auditor.",
    href: "/contact?pilot=runtime",
  },
  {
    id: "agentic",
    icon: Bot,
    color: "#22C55E",
    number: "03",
    name: "Agentic AI Trust Gate",
    tagline: "Full trust control for autonomous AI agent workflows.",
    buyers: ["Regulated enterprise", "AI platform team", "CISO / risk committee"],
    problem:
      "Autonomous AI agents act: they fetch URLs, call APIs, read documents, execute tools, and take decisions in production systems. Every action is a trust decision. Without pre-ingestion gating, runtime enforcement, agent identity, and evidence, you have no control over what your agents do or proof that they did not cross a policy boundary.",
    included: [
      "Everything in Runtime Control + Evidence",
      "URL Trust Gate on every agent-bound external fetch, document retrieval, and tool-call URL",
      "Agent identity: registration, tenant scoping, allowed/denied tools, delegation chains, revocation paths",
      "Policy enforcement on agent-issued API calls, model queries, and tool invocations",
      "Pre-ingestion filtering of RAG retrieval sources before content enters agent context",
      "Post-action evidence chain: what the agent saw, what it decided, what it did, what policy said",
      "Incident response integration: agent suspension, scope reduction, token revocation on anomaly",
      "Executive-level pilot design and a pilot-close briefing for board or risk committee",
    ],
    outcome:
      "Auditable, evidence-backed control over autonomous AI agent behaviour in regulated production workflows.",
    href: "/contact?pilot=agentic",
  },
];

// ─── Why controlled pilots ────────────────────────────────────────────────
const reasons = [
  {
    icon: Lock,
    title: "Scope is negotiated before deployment",
    body: "You define which workflows, consumer surfaces, and data flows are in scope. Nothing outside the agreed boundary is inspected or logged.",
  },
  {
    icon: ShieldCheck,
    title: "Evidence-first, not black-box",
    body: "Every gate decision and runtime enforcement action produces an attributable evidence record. You can review exactly what the system did and why.",
  },
  {
    icon: Users,
    title: "Security-led, not sales-led",
    body: "Pilots are designed with your AppSec or CISO team, not pushed through procurement. We start with the PoC on your hardware before any contract discussion.",
  },
  {
    icon: Activity,
    title: "Measurable outcome in 30–90 days",
    body: "A pilot-close readout gives your leadership a measured answer: detection rates, false-positive rates, latency impact, and evidence completeness.",
  },
];

// ─── Page ──────────────────────────────────────────────────────────────────
export default function PilotsPage() {
  return (
    <div style={{ backgroundColor: "#000000" }}>

      {/* Hero */}
      <section style={{ paddingTop: "10rem", paddingBottom: "5rem", position: "relative", overflow: "hidden" }}>
        <div style={{
          position: "absolute", inset: 0,
          background: "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,163,255,0.09) 0%, transparent 60%)",
          pointerEvents: "none",
        }} />
        <div className="bg-grid" style={{ position: "absolute", inset: 0, opacity: 0.25 }} />
        <div className="container-wide" style={{ position: "relative", textAlign: "center" }}>
          <div className="label-tag" style={{ marginBottom: 20, display: "inline-flex" }}>
            <ShieldCheck size={12} /> Pilot Programs
          </div>
          <h1 className="section-headline" style={{
            fontSize: "clamp(2rem, 4.5vw, 3.2rem)",
            marginBottom: 24, maxWidth: 780, margin: "0 auto 24px",
          }}>
            Controlled AI security pilots<br />
            <span className="gradient-text-blue">for regulated enterprises.</span>
          </h1>
          <p style={{
            fontSize: "1.1rem", color: "#8892A4", lineHeight: 1.75,
            maxWidth: 660, margin: "0 auto 16px",
          }}>
            CyberArmor owns the category of{" "}
            <strong style={{ color: "#ffffff" }}>
              pre-ingestion trust control for AI agents and enterprise AI workflows.
            </strong>{" "}
            These pilots give regulated enterprises a measured, evidence-backed way
            to evaluate that control before committing to production.
          </p>
          <p style={{ fontSize: 14, color: "#4A5568", margin: "0 auto 40px" }}>
            Three programs. Start anywhere. Expand when ready.
          </p>
          <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
            <Link href="/url-trust-gate" className="btn-ghost">
              Run the 15-minute local PoC first <ArrowRight size={15} />
            </Link>
            <Link href="/contact" className="btn-primary">
              Discuss a pilot <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </section>

      {/* Why controlled pilots */}
      <section style={{ padding: "4rem 0", backgroundColor: "#050508" }}>
        <div className="container-wide">
          <div style={{ textAlign: "center", maxWidth: 600, margin: "0 auto 48px" }}>
            <h2 className="section-headline" style={{ fontSize: "clamp(1.5rem, 3vw, 2rem)", marginBottom: 12 }}>
              Why a controlled pilot?
            </h2>
            <p style={{ color: "#8892A4", fontSize: "1rem", lineHeight: 1.7 }}>
              Security buyers in regulated industries cannot evaluate AI security tools
              the same way they evaluate SaaS productivity software. Trust boundaries,
              data handling, and evidence requirements demand a different model.
            </p>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 20 }}>
            {reasons.map(({ icon: Icon, title, body }) => (
              <div key={title} className="card-base" style={{ padding: "28px 32px" }}>
                <Icon size={20} style={{ color: "#00A3FF", marginBottom: 16 }} />
                <h3 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#ffffff", marginBottom: 10, lineHeight: 1.4 }}>
                  {title}
                </h3>
                <p style={{ fontSize: 13, color: "#8892A4", lineHeight: 1.65 }}>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Programs */}
      <section className="section-padding" style={{ backgroundColor: "#000000" }}>
        <div className="container-wide">
          <div style={{ textAlign: "center", maxWidth: 600, margin: "0 auto 56px" }}>
            <h2 className="section-headline" style={{ marginBottom: 16 }}>
              Three programs.<br />
              <span className="gradient-text-blue">One trust framework.</span>
            </h2>
            <p style={{ color: "#8892A4", fontSize: "1rem", lineHeight: 1.7 }}>
              Each program builds on the one before. Most security-led evaluations
              start with the URL Trust Gate pilot and expand from there.
            </p>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 32 }}>
            {programs.map(({ id, icon: Icon, color, number, name, tagline, buyers, problem, included, outcome, href }) => (
              <div key={id} className="card-base" style={{ padding: "44px 48px" }}>
                <div style={{ display: "flex", alignItems: "flex-start", gap: 20, marginBottom: 28, flexWrap: "wrap" }}>
                  <div style={{
                    width: 52, height: 52,
                    background: `${color}15`,
                    border: `1px solid ${color}30`,
                    borderRadius: 12,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    flexShrink: 0,
                  }}>
                    <Icon size={22} style={{ color }} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6 }}>
                      Program {number}
                    </p>
                    <h3 style={{ fontSize: "1.3rem", fontWeight: 700, color: "#ffffff", letterSpacing: "-0.02em", marginBottom: 6, lineHeight: 1.25 }}>
                      {name}
                    </h3>
                    <p style={{ fontSize: "1rem", color: "#8892A4", fontStyle: "italic" }}>{tagline}</p>
                  </div>
                </div>

                {/* Target buyers */}
                <div style={{ marginBottom: 24, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "#4A5568", textTransform: "uppercase", letterSpacing: "0.06em" }}>Target buyer:</span>
                  {buyers.map((b) => (
                    <span key={b} style={{
                      fontSize: 12, color: "#8892A4",
                      background: "#12151E", border: "1px solid #1E2335",
                      borderRadius: 6, padding: "3px 10px",
                    }}>{b}</span>
                  ))}
                </div>

                <div className="platform-layer-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 40, alignItems: "start" }}>
                  {/* Problem + outcome */}
                  <div>
                    <p style={{ fontSize: 11, fontWeight: 700, color: "#4A5568", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 10 }}>
                      The problem it solves
                    </p>
                    <p style={{ fontSize: 14, color: "#8892A4", lineHeight: 1.75, marginBottom: 28 }}>{problem}</p>

                    <div style={{
                      background: `${color}08`,
                      border: `1px solid ${color}20`,
                      borderRadius: 10,
                      padding: "16px 20px",
                      marginBottom: 24,
                    }}>
                      <p style={{ fontSize: 11, fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>
                        Pilot outcome
                      </p>
                      <p style={{ fontSize: 13, color: "#D1D5DB", lineHeight: 1.65 }}>{outcome}</p>
                    </div>

                    <Link href={href} className="btn-primary" style={{ fontSize: 14, display: "inline-flex" }}>
                      Discuss this pilot <ArrowRight size={14} />
                    </Link>
                  </div>

                  {/* What&apos;s included */}
                  <div>
                    <p style={{ fontSize: 11, fontWeight: 700, color, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 16 }}>
                      What&apos;s included
                    </p>
                    <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 12 }}>
                      {included.map((item) => (
                        <li key={item} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                          <CheckCircle2 size={14} style={{ color, flexShrink: 0, marginTop: 3 }} />
                          <span style={{ fontSize: 13, color: "#8892A4", lineHeight: 1.6 }}>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Category statement */}
      <section style={{ padding: "4rem 0", backgroundColor: "#050508" }}>
        <div className="container-wide">
          <div style={{
            background: "rgba(0,163,255,0.04)",
            border: "1px solid rgba(0,163,255,0.15)",
            borderRadius: 20,
            padding: "52px 56px",
            textAlign: "center",
            maxWidth: 860,
            margin: "0 auto",
          }}>
            <p style={{ fontSize: 11, fontWeight: 700, color: "#00A3FF", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 20 }}>
              The Category We Own
            </p>
            <h2 style={{
              fontSize: "clamp(1.5rem, 3.5vw, 2.2rem)",
              fontWeight: 800, color: "#ffffff",
              letterSpacing: "-0.03em", lineHeight: 1.3, marginBottom: 24,
            }}>
              Pre-ingestion trust control for AI agents<br />and enterprise AI workflows.
            </h2>
            <p style={{ color: "#8892A4", fontSize: "1rem", lineHeight: 1.75, maxWidth: 640, margin: "0 auto 32px" }}>
              Every threat that reaches an AI system after it has been fetched is harder
              to stop than one that was evaluated before ingestion. CyberArmor enforces
              that boundary — and records the evidence to prove it.
            </p>
            <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
              <Link href="/contact" className="btn-primary">
                Start a pilot conversation <ArrowRight size={16} />
              </Link>
              <Link href="/status" className="btn-ghost">
                View capability status <ArrowRight size={15} />
              </Link>
            </div>
          </div>
        </div>
      </section>

      <FinalCTA />
    </div>
  );
}
