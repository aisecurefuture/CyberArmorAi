# Contributing to CyberArmor

Thank you for your interest in contributing. CyberArmor is a proprietary security platform; contributions are accepted from authorized partners, collaborators, and internal team members only.

If you are not yet an authorized contributor and would like to become one, reach out to **support@gratitech.com**.

---

## Table of Contents

- [Before You Start](#before-you-start)
- [Development Setup](#development-setup)
- [Branching and Commits](#branching-and-commits)
- [Coding Standards](#coding-standards)
- [Security Requirements](#security-requirements)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)

---

## Before You Start

- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) — do not open a public issue.
- For significant changes (new services, architectural shifts, new compliance framework support), open an issue or start a discussion before writing code. This avoids wasted effort.

---

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker and Docker Compose
- (Optional) Kubernetes + Helm 3 for production-like testing

### Local Stack

```bash
cd infra/docker-compose
cp .env.example .env
# Fill in required secrets — do not use the change-me defaults for any real testing
docker-compose up -d
```

The admin dashboard will be available at `http://localhost:3000`.

### Running Tests

```bash
# Shared crypto library
cd libs/cyberarmor-core && python -m pytest tests/

# Individual services
cd services/policy      && python -m pytest
cd services/compliance  && python -m pytest
cd services/audit       && python -m pytest
```

---

## Branching and Commits

- Branch from `main`: `git checkout -b feat/short-description` or `fix/short-description`
- Keep branches focused — one logical change per PR
- Commit messages should be concise and describe *why*, not just *what*
- Reference issue numbers where applicable: `fix: correct PII redaction boundary (#42)`

---

## Coding Standards

### Python (services, agents, scripts)

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Type annotations required for all public functions and method signatures
- Use `pydantic` models for API request/response validation
- FastAPI services must expose `/health` and `/ready` endpoints

### TypeScript / JavaScript (extensions, dashboard)

- Follow existing ESLint configuration
- Prefer `const` over `let`; avoid `var`
- Browser extensions must not exfiltrate data outside of declared CyberArmor endpoints

### General

- No hardcoded secrets, API keys, or credentials — ever
- Do not disable `CYBERARMOR_ENFORCE_SECURE_SECRETS` or `CYBERARMOR_ENFORCE_MTLS` in production-facing code
- All new environment variables must be documented in the README and `.env.example`
- New services must include a `Dockerfile` and a `/health` endpoint

---

## Security Requirements

CyberArmor has non-negotiable security standards for all contributions:

1. **No hardcoded secrets.** Use environment variables. Default values in code must be clearly marked `change-me-*` and must never be valid credentials.
2. **PQC-compatible crypto only.** Do not introduce classical-only cryptographic primitives in security-critical paths. Use `libs/cyberarmor-core` for shared crypto operations.
3. **No new external dependencies without review.** Each new dependency is an attack surface. Justify new packages and pin versions.
4. **Input validation at every service boundary.** Use `pydantic` models; never trust raw user input.
5. **Audit-log security-relevant actions.** Any action that modifies policy, identity, secrets, or compliance state must emit an event to the Audit Service.
6. **Multi-tenant isolation.** All database queries on tenant-scoped data must filter by `tenant_id`. Cross-tenant data access is a Critical severity issue.

---

## Submitting a Pull Request

1. Ensure all tests pass locally before opening a PR.
2. Fill out the pull request template completely — incomplete PRs will be returned.
3. Link any related issues in the PR description.
4. Keep PRs focused. Large, multi-concern PRs are hard to review safely and will be asked to be split.
5. Be responsive to review feedback. PRs with no activity for 14 days may be closed.

All PRs require at least one maintainer approval before merging.

---

## Reporting Bugs

Open a [Bug Report issue](.github/ISSUE_TEMPLATE/bug_report.md) and include:

- The affected service or component
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log output (redact any secrets or PII)
- Environment details (OS, Docker version, Python/Node version)

---

## Reporting Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Follow the process in [SECURITY.md](SECURITY.md) and email **security@gratitech.com**.
