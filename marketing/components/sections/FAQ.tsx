const faqs = [
  {
    q: "What exactly does CyberArmor.AI protect?",
    a: "CyberArmor.AI is designed to help security teams control and prove AI activity across users, applications, agents, APIs, providers, models, data, and runtime paths where policy decisions need to happen. Coverage depends on the deployment pattern, which is why the platform separates pilot-ready controls from capabilities being expanded with design partners.",
  },
  {
    q: "How is this different from existing security tools we already have?",
    a: "Existing SIEM, DLP, endpoint, IAM, and cloud tools remain important. CyberArmor.AI complements them by adding AI-specific runtime context: actor and agent identity, model and provider usage, prompt-risk signals, sensitive-data inspection, policy decisions, redaction or blocking outcomes, and evidence records that can feed the broader security stack.",
  },
  {
    q: "What does 'shadow AI' mean and why should we care?",
    a: "Shadow AI refers to AI tools, models, API connections, browser assistants, developer workflows, or vendor systems being used without security review. The risk is not only unauthorized software use; it is also sensitive data entering unmanaged AI systems, unreviewed model dependencies, unclear retention terms, and no evidence trail when something goes wrong.",
  },
  {
    q: "What is 'AI runtime protection' and how does it work?",
    a: "AI runtime protection means evaluating AI activity as requests, model calls, agent actions, provider routes, or data flows happen. Depending on deployment, CyberArmor.AI can inspect context, call detection and policy services, produce a decision, enforce an approved action such as monitor, warn, block, route, limit, or redact, and preserve evidence.",
  },
  {
    q: "Can CyberArmor.AI redact sensitive data before it reaches an AI provider?",
    a: "Yes, in supported paths. CyberArmor.AI redaction modes can remove supported secrets, credentials, PII, PCI, NACHA/bank data, NPI, and non-public indicators before AI-bound content leaves the protected surface. Redaction is optional policy behavior, not mandatory behavior, and evidence should capture labels, counts, policy, hashes, and action metadata without previewing raw secrets.",
  },
  {
    q: "Does CyberArmor.AI require replacing our existing security infrastructure?",
    a: "No. CyberArmor.AI is designed to integrate with existing security toolchains — SIEM, SOAR, IAM, and cloud-native security platforms. It extends your existing investment rather than replacing it, bringing AI-specific visibility, runtime context, policy outcomes, and evidence that your current tools do not usually provide.",
  },
  {
    q: "How does the evidence and traceability capability help with compliance?",
    a: "Security, legal, compliance, and audit teams need more than screenshots or meeting notes. CyberArmor.AI records structured evidence about AI activity, policy decisions, actors, timestamps, data classifications, and control outcomes so teams can investigate incidents, review governance exceptions, and map technical controls to frameworks such as NIST AI RMF, ISO/IEC 42001, OWASP GenAI guidance, and sector-specific requirements.",
  },
  {
    q: "Is this relevant to my organization if we're early in AI adoption?",
    a: "Especially if you're early. The best time to establish AI runtime policy, redaction, routing, evidence, and trust controls is before AI usage proliferates — not after. Organizations that build the security infrastructure for AI adoption now will have a cleaner path to scale AI use safely and at speed.",
  },
  {
    q: "What does 'patent-pending' mean for the platform?",
    a: "CyberArmor.AI uses 'patent-pending' to describe architectural innovations the company believes are differentiated and has chosen to protect through formal filing activity, including runtime control, AI trust evidence, and cross-layer security operationalization. It should be read as an intellectual-property signal, not as a substitute for product validation, security review, or procurement diligence.",
  },
];

export default function FAQ() {
  return (
    <section className="section-padding" style={{ backgroundColor: "#000000" }}>
      <div className="container-wide">
        <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 56px" }}>
          <div className="label-tag" style={{ justifyContent: "center", marginBottom: 16 }}>FAQ</div>
          <h2 className="section-headline" style={{ marginBottom: 16 }}>
            Questions Enterprise Buyers{" "}
            <span className="gradient-text-blue">Actually Ask.</span>
          </h2>
        </div>

        <div style={{ maxWidth: 820, margin: "0 auto", display: "flex", flexDirection: "column", gap: 8 }}>
          {faqs.map(({ q, a }, i) => (
            <details
              key={i}
              open={i === 0}
              style={{
                background: "#0F1117",
                border: "1px solid #1E2335",
                borderRadius: 12,
                overflow: "hidden",
              }}
            >
              <summary
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "22px 28px",
                  cursor: "pointer",
                  gap: 16,
                  listStyle: "none",
                }}
              >
                <span style={{
                  fontSize: 15.5, fontWeight: 600,
                  color: "#ffffff",
                  letterSpacing: "-0.01em",
                  lineHeight: 1.4,
                }}>
                  {q}
                </span>
                <span style={{ color: "#00A3FF", fontSize: 18, lineHeight: 1 }}>+</span>
              </summary>

              <div style={{ padding: "0 28px 22px" }}>
                <p style={{ fontSize: 14.5, color: "#8892A4", lineHeight: 1.75 }}>{a}</p>
              </div>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}
