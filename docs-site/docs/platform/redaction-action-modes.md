# Redaction Action Modes

CyberArmor supports redaction as an enforcement action, not just a logging cleanup step. Redaction modes are optional policy responses that rewrite supported sensitive values before AI-bound content, editor content, clipboard data, or runtime payloads leave the protected surface.

## Modes

| Mode | Scope |
| --- | --- |
| `monitor` | Observe and preserve evidence without interrupting the workflow. |
| `warn` | Show a user-facing warning and preserve evidence. |
| `block` | Prevent the action when policy requires it. |
| `redact` | Redact supported secrets, credentials, PII, PCI, NACHA/bank data, NPI, and non-public indicators. |
| `redact-secrets` | Redact credentials, API keys, tokens, passwords, connection strings, JWTs, and private keys. |
| `redact-pii` | Redact personal identifiers such as SSNs, email addresses, phone numbers, and dates of birth. |
| `redact-pci` | Redact payment card data. |
| `redact-nacha` | Redact bank account, routing, and related payment-routing data. |
| `redact-npi` | Redact healthcare provider identifiers. |

`redact-nachi` is treated as an alias for `redact-nacha` for compatibility with older demo notes.

## Surface behavior

| Surface | Redaction behavior |
| --- | --- |
| Browser extensions | Rewrites AI prompt input fields before submit when the action mode is a redaction mode. |
| VS Code, Cursor, and Kiro | Adds a **Redact Findings** command and supports redaction-before-save when the IDE enforcement mode starts with `redact`. Findings use placeholders instead of raw secret previews. |
| Office add-in | Adds a task pane **Redact Findings** action and safe placeholder-only DLP findings. Word and Excel can rewrite document/worksheet content; PowerPoint rewrites the current selection. |
| Endpoint agent | Supports clipboard/paste redaction with evidence that includes counts, labels, categories, and hashes, not raw sensitive values. |
| RASP | Rewrites provider-bound request bodies in redaction modes and redacts supported sensitive values in text or JSON response bodies where the runtime can safely mutate the response. |
| Node SDK | Applies `ALLOW_WITH_REDACTION` policy decisions to outbound OpenAI-compatible chat requests when the policy service returns a redacted prompt. |

## Evidence model

Redaction evidence should identify what control ran without storing the raw sensitive value. A good evidence event contains:

- action mode
- finding labels and categories
- count of replacements
- original and redacted lengths
- content hashes when useful for traceability
- policy decision, reason code, and request or surface identifier

This supports pre-breach protection for credential leakage into generative AI while preserving enough evidence for security, legal, compliance, and executive review.
