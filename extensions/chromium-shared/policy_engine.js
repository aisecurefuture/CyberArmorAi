/**
 * CyberArmor Protect - Client-Side Policy Evaluation Engine
 * Mirrors the server-side AND/OR condition logic for real-time enforcement.
 * Shared across content scripts and AI monitor.
 */
"use strict";

const CyberArmorPolicyEngine = (() => {

  /* ------------------------------------------------------------------ */
  /*  Policy schema types                                               */
  /* ------------------------------------------------------------------ */

  /**
   * A policy has:
   *   id:          string
   *   name:        string
   *   enabled:     boolean
   *   action:      "monitor" | "warn" | "block" | "redact" | "redact-secrets" | "redact-pii" | "redact-pci" | "redact-nacha" | "redact-npi" | "redact-nonpublic"
   *   conditions:  ConditionGroup  (top-level AND/OR tree)
   *   metadata:    object (labels, description, severity, etc.)
   */

  /**
   * ConditionGroup:
   *   operator: "AND" | "OR"
   *   conditions: Array<Condition | ConditionGroup>
   *
   * Condition:
   *   field:    string   (e.g. "url", "domain", "input_text", "ai_service", "data_class")
   *   operator: "eq" | "neq" | "contains" | "not_contains" | "matches" | "gt" | "lt" | "in" | "not_in"
   *   value:    any
   */

  /* ------------------------------------------------------------------ */
  /*  Condition evaluation                                              */
  /* ------------------------------------------------------------------ */

  function evaluateCondition(condition, context) {
    if (condition.operator === "AND" || condition.operator === "OR") {
      return evaluateGroup(condition, context);
    }

    const fieldValue = resolveField(condition.field, context);
    const expected = condition.value;

    switch (condition.operator) {
      case "eq":
        return String(fieldValue).toLowerCase() === String(expected).toLowerCase();
      case "neq":
        return String(fieldValue).toLowerCase() !== String(expected).toLowerCase();
      case "contains":
        return String(fieldValue).toLowerCase().includes(String(expected).toLowerCase());
      case "not_contains":
        return !String(fieldValue).toLowerCase().includes(String(expected).toLowerCase());
      case "matches": {
        try {
          const re = new RegExp(expected, "i");
          return re.test(String(fieldValue));
        } catch {
          return false;
        }
      }
      case "gt":
        return Number(fieldValue) > Number(expected);
      case "lt":
        return Number(fieldValue) < Number(expected);
      case "in":
        if (Array.isArray(expected)) {
          const lower = String(fieldValue).toLowerCase();
          return expected.some(v => String(v).toLowerCase() === lower);
        }
        return false;
      case "not_in":
        if (Array.isArray(expected)) {
          const lower = String(fieldValue).toLowerCase();
          return !expected.some(v => String(v).toLowerCase() === lower);
        }
        return true;
      default:
        return false;
    }
  }

  function evaluateGroup(group, context) {
    const conditions = group.conditions || [];
    if (conditions.length === 0) return true;

    if (group.operator === "AND") {
      return conditions.every(c => evaluateCondition(c, context));
    }
    if (group.operator === "OR") {
      return conditions.some(c => evaluateCondition(c, context));
    }
    return false;
  }

  function resolveField(field, context) {
    if (!field || !context) return "";
    const parts = field.split(".");
    let value = context;
    for (const part of parts) {
      if (value == null) return "";
      value = value[part];
    }
    return value ?? "";
  }

  /* ------------------------------------------------------------------ */
  /*  Policy evaluation                                                 */
  /* ------------------------------------------------------------------ */

  /**
   * Evaluate all policies against the given context.
   * Returns array of { policy, matched: boolean, action } sorted by severity.
   */
  function evaluate(policies, context) {
    if (!Array.isArray(policies)) return [];

    const results = [];
    for (const policy of policies) {
      if (!policy.enabled) continue;

      const matched = evaluateGroup(policy.conditions || { operator: "AND", conditions: [] }, context);
      if (matched) {
        results.push({
          policyId: policy.id,
          policyName: policy.name,
          action: policy.action || "monitor",
          severity: policy.metadata?.severity || "medium",
          message: policy.metadata?.message || `Policy "${policy.name}" triggered.`,
          matched: true,
        });
      }
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    results.sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3));

    return results;
  }

  /**
   * Get the most restrictive action from a set of evaluation results.
   * block > redact* > warn > monitor
   */
  function getMostRestrictiveAction(results) {
    if (!results || results.length === 0) return "monitor";
    const order = {
      block: 0,
      redact: 1,
      "redact-sensitive": 1,
      "redact-nonpublic": 1,
      "redact-secrets": 1,
      "redact-credentials": 1,
      "redact-pii": 1,
      "redact-pci": 1,
      "redact-nacha": 1,
      "redact-bank": 1,
      "redact-npi": 1,
      warn: 2,
      monitor: 3,
    };
    let most = "monitor";
    for (const r of results) {
      if ((order[r.action] ?? 3) < (order[most] ?? 3)) {
        most = r.action;
      }
    }
    return most;
  }

  /* ------------------------------------------------------------------ */
  /*  Data classification                                               */
  /* ------------------------------------------------------------------ */

  const DATA_CLASSIFIERS = [
    { label: "SSN",              pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                            severity: "critical", category: "pii" },
    { label: "Credit-Card",      pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,                      severity: "critical", category: "pci" },
    { label: "Routing-Number",   pattern: /\b(?:routing\s*(?:number|no|#)?\s*[:=]?\s*)\d{9}\b/gi, severity: "critical", category: "nacha" },
    { label: "Bank-Account",     pattern: /\b(?:account\s*(?:number|no|#)?\s*[:=]?\s*)\d{8,17}\b/gi, severity: "critical", category: "nacha" },
    { label: "IBAN",             pattern: /\b[A-Z]{2}\d{2}[A-Za-z0-9]{4}\d{7,}\b/g,            severity: "critical", category: "nacha" },
    { label: "NPI",              pattern: /\bNPI\s*[:=]?\s*\d{10}\b/gi,                        severity: "critical", category: "npi" },
    { label: "DOB",              pattern: /\b(?:dob|date\s+of\s+birth|born)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/gi, severity: "high", category: "pii" },
    { label: "Email",            pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, severity: "high", category: "pii" },
    { label: "Phone",            pattern: /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g, severity: "high", category: "pii" },
    { label: "Drivers-License",  pattern: /\b(?:dl|driver'?s?\s+license|license\s+#?)\s*[:=]?\s*[A-Z0-9]{6,12}\b/gi, severity: "high", category: "pii" },
    { label: "IP-Address",       pattern: /\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b/g, severity: "medium", category: "nonpublic" },
    { label: "AWS-Key",          pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,                     severity: "critical", category: "secrets" },
    { label: "OpenAI-Key",       pattern: /\b(?:sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9_\-]{20,})\b/g, severity: "critical", category: "secrets" },
    { label: "Anthropic-Key",    pattern: /\bsk-ant-[A-Za-z0-9_\-]{60,}\b/g,                    severity: "critical", category: "secrets" },
    { label: "GitHub-Token",     pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g,                severity: "critical", category: "secrets" },
    { label: "Slack-Token",      pattern: /\bxox[bpoa]-[0-9A-Za-z\-]{10,}\b/g,                 severity: "critical", category: "secrets" },
    { label: "Stripe-Key",       pattern: /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g,      severity: "critical", category: "secrets" },
    { label: "Private-Key",      pattern: /-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE\sKEY-----/g, severity: "critical", category: "secrets" },
    { label: "JWT",              pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b/g, severity: "high", category: "secrets" },
    { label: "Bearer-Token",     pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/gi,               severity: "high", category: "secrets" },
    { label: "Password",         pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}["']?/gi, severity: "high", category: "secrets" },
    { label: "API-Key-Generic",  pattern: /\b(?:[A-Za-z0-9]+_)*(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}["']?\b/gi, severity: "high", category: "secrets" },
    { label: "ZIP-Code",         pattern: /\b\d{5}(?:-\d{4})?\b/g,                             severity: "low", category: "pii" },
  ];

  /**
   * Classify text and return array of { label, severity, matches[] }.
   */
  function classifyData(text) {
    if (!text) return [];
    const str = typeof text === "string" ? text : String(text);
    const results = [];

    for (const { label, pattern, severity, category } of DATA_CLASSIFIERS) {
      pattern.lastIndex = 0;
      const matches = str.match(pattern);
      if (matches && matches.length > 0) {
        results.push({ label, severity, category, count: matches.length, matches });
      }
    }
    return results;
  }

  /* ------------------------------------------------------------------ */
  /*  Threat detection patterns                                         */
  /* ------------------------------------------------------------------ */

  const PROMPT_INJECTION_PATTERNS = [
    { id: "pi_ignore",        pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?|context)/i, severity: "critical", description: "Ignore previous instructions" },
    { id: "pi_new_role",      pattern: /you\s+are\s+now\s+(?:a\s+)?(?:new|different|DAN|jailbroken|unrestricted)/i, severity: "critical", description: "Role reassignment attempt" },
    { id: "pi_system_prompt", pattern: /(?:system\s*prompt|<<\s*SYS|<\|im_start\|>system|\[INST\]|\[\/INST\])/i, severity: "high", description: "System prompt injection markers" },
    { id: "pi_delimiter",     pattern: /(?:---+\s*(?:NEW|REAL|ACTUAL)\s+(?:INSTRUCTIONS?|PROMPT)|={5,})/i, severity: "high", description: "Delimiter injection" },
    { id: "pi_encoding",      pattern: /(?:base64\s*decode|atob\s*\(|eval\s*\(|fromCharCode)/i, severity: "high", description: "Encoding/eval bypass" },
    { id: "pi_exfil",         pattern: /(?:send\s+(?:to|all|the)\s+(?:data|info|content|text)|fetch\s*\(\s*['"]https?:)/i, severity: "critical", description: "Data exfiltration attempt" },
    { id: "pi_override",      pattern: /(?:override|bypass|disable|turn\s*off)\s+(?:safety|security|filter|guard|protection|content\s*policy)/i, severity: "critical", description: "Safety bypass attempt" },
    { id: "pi_repeat",        pattern: /repeat\s+(?:the\s+)?(?:system|initial|original|first)\s+(?:prompt|message|instruction)/i, severity: "high", description: "System prompt extraction" },
    { id: "pi_markdown_img",  pattern: /!\[.*?\]\(https?:\/\/[^)]*(?:\?|&)(?:q|query|data|text|input)=/i, severity: "high", description: "Markdown image exfiltration" },
  ];

  const XSS_PATTERNS = [
    { id: "xss_script_tag",   pattern: /<script[\s>]/i,                          severity: "critical", description: "Script tag injection" },
    { id: "xss_event",        pattern: /\bon(?:error|load|click|mouse\w+|focus|blur)\s*=/i, severity: "high", description: "Event handler injection" },
    { id: "xss_javascript",   pattern: /javascript\s*:/i,                        severity: "high", description: "JavaScript URI" },
    { id: "xss_data_uri",     pattern: /data\s*:\s*text\/html/i,                 severity: "high", description: "Data URI HTML injection" },
    { id: "xss_svg",          pattern: /<svg[\s>].*?on\w+\s*=/is,               severity: "high", description: "SVG event handler" },
    { id: "xss_iframe",       pattern: /<iframe[\s>]/i,                          severity: "medium", description: "Iframe injection" },
    { id: "xss_expression",   pattern: /expression\s*\(/i,                       severity: "medium", description: "CSS expression injection" },
  ];

  const COMMAND_INJECTION_PATTERNS = [
    { id: "cmd_pipe",         pattern: /[|;&`]\s*(?:cat|ls|dir|type|echo|curl|wget|python|node|bash|sh|powershell|cmd)\b/i, severity: "critical", description: "Command pipe/chain" },
    { id: "cmd_subshell",     pattern: /\$\(.*\)|`[^`]+`/,                       severity: "high", description: "Subshell execution" },
    { id: "cmd_traversal",    pattern: /\.\.\/\.\.\/|\.\.\\\.\.\\|%2e%2e/i,      severity: "high", description: "Path traversal" },
    { id: "cmd_sql",          pattern: /(?:'\s*(?:OR|AND)\s+['"]?\d|UNION\s+SELECT|DROP\s+TABLE|;\s*DELETE\s+FROM)/i, severity: "critical", description: "SQL injection" },
    { id: "cmd_ldap",         pattern: /[()&|!][^()]*\)\s*\(/,                   severity: "medium", description: "LDAP injection pattern" },
  ];

  /**
   * Scan text for prompt injection patterns.
   * Returns array of { id, severity, description, match }.
   */
  function detectPromptInjection(text) {
    return _scanPatterns(text, PROMPT_INJECTION_PATTERNS);
  }

  function detectXSS(text) {
    return _scanPatterns(text, XSS_PATTERNS);
  }

  function detectCommandInjection(text) {
    return _scanPatterns(text, COMMAND_INJECTION_PATTERNS);
  }

  /**
   * Comprehensive threat scan combining all detectors.
   */
  function detectThreats(text) {
    const pi   = detectPromptInjection(text);
    const xss  = detectXSS(text);
    const cmd  = detectCommandInjection(text);
    return {
      promptInjection: pi,
      xss,
      commandInjection: cmd,
      hasThreats: pi.length > 0 || xss.length > 0 || cmd.length > 0,
      highestSeverity: _highestSeverity([...pi, ...xss, ...cmd]),
    };
  }

  function _scanPatterns(text, patterns) {
    if (!text) return [];
    const str = typeof text === "string" ? text : String(text);
    const findings = [];
    for (const { id, pattern, severity, description } of patterns) {
      pattern.lastIndex = 0;
      const m = str.match(pattern);
      if (m) {
        findings.push({ id, severity, description, match: m[0] });
      }
    }
    return findings;
  }

  function _highestSeverity(findings) {
    if (!findings.length) return null;
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    let best = "low";
    for (const f of findings) {
      if ((order[f.severity] ?? 3) < (order[best] ?? 3)) {
        best = f.severity;
      }
    }
    return best;
  }

  /* ------------------------------------------------------------------ */
  /*  Redaction                                                         */
  /* ------------------------------------------------------------------ */

  const REDACTION_ACTIONS = new Set([
    "redact",
    "redact-sensitive",
    "redact-nonpublic",
    "redact-secrets",
    "redact-credentials",
    "redact-pii",
    "redact-pci",
    "redact-nacha",
    "redact-bank",
    "redact-npi",
  ]);

  const REDACTION_CATEGORY_SETS = {
    redact: ["secrets", "pii", "pci", "nacha", "npi", "nonpublic"],
    "redact-sensitive": ["secrets", "pii", "pci", "nacha", "npi", "nonpublic"],
    "redact-nonpublic": ["nonpublic"],
    "redact-secrets": ["secrets"],
    "redact-credentials": ["secrets"],
    "redact-pii": ["pii"],
    "redact-pci": ["pci"],
    "redact-nacha": ["nacha"],
    "redact-bank": ["nacha"],
    "redact-npi": ["npi"],
  };

  function isRedactionAction(action) {
    return REDACTION_ACTIONS.has(String(action || "").toLowerCase());
  }

  function redactionCategoriesForAction(action) {
    return REDACTION_CATEGORY_SETS[String(action || "redact").toLowerCase()] || [];
  }

  function redactText(text, action = "redact") {
    if (!text) return text;
    const categories = new Set(Array.isArray(action) ? action : redactionCategoriesForAction(action));
    if (categories.size === 0) return text;
    let result = typeof text === "string" ? text : String(text);
    for (const { label, pattern, category } of DATA_CLASSIFIERS) {
      if (!categories.has(category)) continue;
      pattern.lastIndex = 0;
      result = result.replace(pattern, `[REDACTED-${label}]`);
    }
    return result;
  }

  function redactionFindings(text, action = "redact") {
    const categories = new Set(Array.isArray(action) ? action : redactionCategoriesForAction(action));
    return classifyData(text).filter((finding) => categories.has(finding.category));
  }

  function redactPII(text) {
    return redactText(text, "redact-pii");
  }

  function detectPII(text) {
    return redactionFindings(text, "redact-pii").map(({ label, count }) => ({ label, count }));
  }

  /* ------------------------------------------------------------------ */
  /*  AI Service Registry                                               */
  /* ------------------------------------------------------------------ */

  const AI_SERVICES = [
    { id: "chatgpt",    name: "ChatGPT",           domains: ["chat.openai.com", "chatgpt.com"] },
    { id: "claude",     name: "Claude",             domains: ["claude.ai"] },
    { id: "gemini",     name: "Gemini",             domains: ["gemini.google.com", "bard.google.com"] },
    { id: "copilot",    name: "Microsoft Copilot",  domains: ["copilot.microsoft.com"] },
    { id: "perplexity", name: "Perplexity",         domains: ["www.perplexity.ai", "perplexity.ai"] },
    { id: "huggingface",name: "HuggingFace Chat",   domains: ["huggingface.co"] },
    { id: "poe",        name: "Poe",                domains: ["poe.com"] },
    { id: "you",        name: "You.com",            domains: ["you.com"] },
    { id: "mistral",    name: "Mistral Chat",       domains: ["chat.mistral.ai"] },
    { id: "meta_ai",    name: "Meta AI",            domains: ["www.meta.ai", "meta.ai"] },
    { id: "deepseek",   name: "DeepSeek",           domains: ["chat.deepseek.com"] },
    { id: "cohere",     name: "Cohere",             domains: ["coral.cohere.com", "dashboard.cohere.com"] },
    { id: "google_labs",name: "Google AI Studio",   domains: ["labs.google.com", "aistudio.google.com"] },
  ];

  function identifyAIService(hostname) {
    if (!hostname) return null;
    const h = hostname.toLowerCase();
    for (const svc of AI_SERVICES) {
      if (svc.domains.some(d => h === d || h.endsWith("." + d))) {
        return svc;
      }
    }
    return null;
  }

  function isAIServiceDomain(hostname) {
    return identifyAIService(hostname) !== null;
  }

  /* ------------------------------------------------------------------ */
  /*  Public API                                                        */
  /* ------------------------------------------------------------------ */

  return Object.freeze({
    evaluate,
    evaluateCondition,
    evaluateGroup,
    getMostRestrictiveAction,

    classifyData,
    DATA_CLASSIFIERS,

    detectPromptInjection,
    detectXSS,
    detectCommandInjection,
    detectThreats,

    redactPII,
    redactText,
    redactionFindings,
    redactionCategoriesForAction,
    isRedactionAction,
    detectPII,

    identifyAIService,
    isAIServiceDomain,
    AI_SERVICES,

    PROMPT_INJECTION_PATTERNS,
    XSS_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
  });
})();

if (typeof globalThis !== "undefined") {
  globalThis.CyberArmorPolicyEngine = CyberArmorPolicyEngine;
}
