# Questionnaire Answer Template Guide

Use the CSV workbook as the operating sheet for each client questionnaire.

## Recommended Column Rules

**Question ID**
- Keep a stable ID even if the client spreadsheet has none.
- Example: `Q-001`, `Q-002`

**Question / Prompt**
- Copy the question exactly from the customer request.

**Category**
- Use one of:
  `Access Control`
  `Infrastructure`
  `Encryption`
  `Backups`
  `Logging and Monitoring`
  `Vulnerability Management`
  `Secure SDLC`
  `Incident Response`
  `Business Continuity`
  `Privacy and Data Handling`
  `Vendor Management`
  `Compliance / Audit`
  `Other`

**Draft Answer**
- Keep the first draft concise and source-backed.
- Prefer clear sentences over legalistic filler.

**Answer Type**
- Use:
  `Confirmed`
  `Likely - needs approval`
  `Unknown / missing evidence`
  `Customer-specific`

**Source Document**
- Name the doc or artifact that supports the answer.
- Example: `Access Control Policy v2.1`

**Evidence Link / File**
- File path, shared drive link, or trust-center URL.

**Confidence**
- Use:
  `High`
  `Medium`
  `Low`

**Client Approval Needed**
- Use:
  `Yes`
  `No`

**Status**
- Use:
  `Drafted`
  `Awaiting client input`
  `Approved`
  `Delivered`

**Notes**
- Reserve for contradictions, follow-up questions, or customer-specific wording needs.

## Example Row

| Field | Example |
| --- | --- |
| Question ID | `Q-014` |
| Question / Prompt | `Do you enforce MFA for internal administrative access?` |
| Category | `Access Control` |
| Draft Answer | `Yes. MFA is required for internal administrative access to production systems and core cloud services.` |
| Answer Type | `Confirmed` |
| Source Document | `Access Control Policy v2.1` |
| Evidence Link / File | `evidence/access-control-policy-v2-1.pdf` |
| Confidence | `High` |
| Client Approval Needed | `No` |
| Status | `Drafted` |
| Notes | `Confirm wording matches current Okta rollout scope.` |

## Review Rules

- Every material security claim should map to a source.
- If a claim is not supported, mark it as unknown.
- Do not silently upgrade “partial” controls into “yes”.
- Normalize wording across the entire questionnaire before final delivery.
- Keep customer-specific commitments separate from globally reusable answers.
