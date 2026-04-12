# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues by email to **security@gratitech.com**. You should receive an acknowledgment within **2 business days** and a status update within **7 business days**.

Please include as much of the following as possible:

- Affected component or service (e.g., `services/secrets-service`, `agents/endpoint-agent`)
- Description of the vulnerability and its potential impact
- Steps to reproduce, including any proof-of-concept code or payloads
- Your estimated severity (Critical / High / Medium / Low)
- Any suggested mitigations you have identified

We request **90-day coordinated disclosure**. We will work with you to understand and remediate the issue before public disclosure. If a fix requires more time, we will communicate that and agree on a revised timeline.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch (latest) | Yes |
| Older tagged releases | Security fixes backported on a case-by-case basis |

## Scope

The following are **in scope** for vulnerability reports:

- All services under `services/` (control plane, policy, detection, response, identity, compliance, SIEM connector, agent identity, AI router, audit, secrets service, runtime, integration control)
- Transparent proxy and proxy agent (`services/proxy/`, `agents/proxy-agent/`)
- Endpoint agent (`agents/endpoint-agent/`)
- Browser and IDE extensions (`extensions/`)
- RASP agents (`rasp/`)
- Admin dashboard (`admin-dashboard/`)
- Shared crypto library (`libs/cyberarmor-core/`)
- Infrastructure configuration (`infra/`)
- OpenBao / secrets service integration

The following are **out of scope**:

- `services/llm-mock/` — development mock only, never deployed in production
- Insecure default secrets (`change-me-*`) in `.env.example` files — these are documented placeholders; operators are required to replace them
- Vulnerabilities requiring physical access to a deployed host
- Findings from automated scanners submitted without a demonstrated exploit or meaningful impact
- Social engineering of Gratitech staff

## Security Design Notes

CyberArmor is built with the following security properties that reporters should be aware of:

- **Post-quantum cryptography**: ML-KEM-1024 (Kyber) and ML-DSA-87 (Dilithium) are used throughout; classical-only attacks against PQC key material are expected
- **`CYBERARMOR_ENFORCE_SECURE_SECRETS`**: When set to `true`, services refuse to start with default/insecure secrets — this is the expected production posture
- **`CYBERARMOR_ENFORCE_MTLS`**: When set to `true`, inter-service calls require mutual TLS — findings that assume mTLS is disabled are treated as configuration issues, not product vulnerabilities
- **Multi-tenant isolation**: Tenant data separation is a hard security boundary; any cross-tenant data access is treated as Critical severity

## Severity Guidance

| Severity | Examples |
|----------|---------|
| Critical | Remote code execution, cross-tenant data access, secrets exfiltration from OpenBao, authentication bypass on any service |
| High | Privilege escalation, policy bypass (blocking a prompt that should have been blocked), PQC implementation flaw |
| Medium | Information disclosure (non-sensitive), audit log tampering, denial of service against a single service |
| Low | Minor information leakage, best-practice deviations with limited exploitability |

## Recognition

We appreciate responsible disclosure. Reporters who identify and responsibly disclose valid vulnerabilities will be acknowledged in the release notes for the fix (unless they prefer to remain anonymous).

## Contact

- Security disclosures: security@gratitech.com
- General support: support@gratitech.com
