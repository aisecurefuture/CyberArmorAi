# CyberArmor

**Enterprise AI Security Platform** — Comprehensive protection for organizations deploying AI, Agentic AI, and LLM-powered applications.

## Overview

CyberArmor is a zero-trust, multi-layered security platform that provides real-time monitoring, policy enforcement, data loss prevention, and compliance management for enterprise AI workloads. Built with FIPS 140-3 and CNSA 2.0+ post-quantum cryptography throughout.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Admin Dashboard                          │
│                    (Vanilla JS SPA + Nginx)                     │
├─────────────────────────────────────────────────────────────────┤
│                       Ingress / Load Balancer                   │
├────────┬────────┬────────┬────────┬────────┬────────┬──────────┤
│Control │ Policy │Detect- │Response│Identity│  SIEM  │Compliance│
│ Plane  │ Engine │  ion   │        │Provider│Connector│ Engine  │
│ :8000  │ :8001  │ :8002  │ :8003  │ :8004  │ :8005  │ :8006   │
├────────┬────────┬────────┬────────┬────────┬────────┬──────────┤
│ Agent  │AI Router│ Audit │Integ-  │Runtime │Secrets │ OpenBao  │
│Identity│        │       │ration  │  API   │Service │  Vault   │
│ :8008  │ :8009  │ :8011 │ :8012  │ :8010  │ :8013  │          │
├────────┴────────┴────────┴────────┴────────┴────────┴──────────┤
│                   Transparent AI Proxy (:8080)                  │
│             (mitmproxy dev; HTTPS on :8443 in dev)              │
├─────────────────────────────────────────────────────────────────┤
│   PostgreSQL              Redis              Message Queue      │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│ Endpoint │ Browser  │   IDE    │ Office   │   RASP Agents       │
│  Agent   │Extensions│Extensions│ Add-ins  │  (9 languages)      │
├──────────┼──────────┼──────────┼──────────┼─────────────────────┤
│  macOS   │ Chrome   │ VS Code  │  Word    │  Java  │  .NET     │
│ Windows  │ Firefox  │ Visual   │  Excel   │ Python │  Node.js  │
│  Linux   │  Safari  │  Studio  │ PowerPt  │   Go   │  Rust     │
│          │   Edge   │  Cursor  │ OneNote  │  Ruby  │  PHP      │
│          │  Brave   │   Kiro   │ Outlook  │  C/C++ │           │
├──────────┴──────────┴──────────┴──────────┴────────┴───────────┤
│  Kernel: Linux eBPF │ macOS Endpoint Security │ Windows WFP    │
├─────────────────────┴────────────────────────┴─────────────────┤
│  ROS2 Agent (Robotics)  │  React Native Mobile (iOS/Android)   │
└─────────────────────────┴──────────────────────────────────────┘
```

## Core Services

| Service | Port | Description |
|---------|------|-------------|
| Control Plane | 8000 | Central API gateway, tenant management, API key CRUD |
| Policy Engine | 8001 | Extensible AND/OR policy evaluation, priority-based rules |
| Detection | 8002 | Prompt injection, jailbreak, toxicity, PII detection |
| Response | 8003 | Incident management, automated response actions |
| Identity Provider | 8004 | SSO integration (Entra ID, Okta, Ping, AWS IAM) |
| SIEM Connector | 8005 | Output to Splunk, Sentinel, QRadar, Elastic, Google SecOps, Syslog/CEF |
| Compliance Engine | 8006 | 14 compliance frameworks with evidence-based assessment |
| Agent Identity | 8008 | AI agent identities, credentials, tokens, and delegation chains |
| AI Router | 8009 | Unified gateway to AI providers with credential vault, request normalization, cost tracking, and governance |
| Proxy Agent | 8010 | Policy decision API and local block actions |
| Audit Service | 8011 | Immutable PQC-signed audit log and AI action graph |
| Integration Control | 8012 | SaaS integration discovery, OAuth scope visibility, and control actions |
| Secrets Service | 8013 | Thin CyberArmor control layer over OpenBao: tenant/provider credential storage, transit encrypt/decrypt/sign, key rotation |
| Transparent Proxy | 8080 / 8443 | AI traffic interception, inspection, and policy enforcement |
| OpenBao Vault | — | Underlying secret and cryptographic engine (KV, transit, key management) |

## Security Features

- **Post-Quantum Cryptography**: ML-KEM-1024 (Kyber) key encapsulation, ML-DSA-87 (Dilithium) signing
- **PQC API Key Transport**: `PQC:<base64>` header format with AES-256-GCM encryption
- **Zero Trust Architecture**: All inter-service communication authenticated
- **Multi-Tenant**: Complete tenant isolation across all services
- **FIPS 140-3 Compliant**: Validated cryptographic modules
- **CNSA 2.0+ Ready**: Post-quantum algorithm suite

## Compliance Frameworks (14)

| Framework | Controls | Description |
|-----------|----------|-------------|
| NIST CSF 2.0 | 18 | Cybersecurity Framework |
| NIST 800-53 r5 | 20 | Security and Privacy Controls |
| NIST AI RMF | 17 | AI Risk Management Framework |
| CMMC Level 3 | 16 | Cybersecurity Maturity Model |
| NYDFS 23 NYCRR 500 | 15 | NY Financial Services Cybersecurity |
| ISO 27001:2022 | 18 | Information Security Management |
| CIS Controls v8 | 16 | Center for Internet Security |
| CSA CCM v4 | 16 | Cloud Security Alliance |
| OWASP (Combined) | 19 | Web + API + LLM Top 10 2025 + Agentic AI |
| SANS Top 25 | 15 | Most Dangerous Software Weaknesses |
| PCI-DSS v4.0 | 17 | Payment Card Industry |
| SOC 2 | 19 | Trust Services Criteria |
| GDPR | 16 | EU General Data Protection |
| CCPA/CPRA | 14 | California Consumer Privacy |

## Quick Start

### Docker Compose (Development)

```bash
cd infra/docker-compose
cp .env.example .env
# Edit .env with your configuration
docker-compose up -d
```

Access the admin dashboard at `http://localhost:3000`

### Smoke Test

```bash
# Start stack + run validation
./scripts/smoke-test.sh --up

# Run validation only (stack already running)
./scripts/smoke-test.sh
```

## Deployment Docs

- Hetzner Ubuntu test deployment: [docs/deployment/hetzner-ubuntu-vm.md](/Users/patrickkelly/Documents/CyberArmorAi/docs/deployment/hetzner-ubuntu-vm.md)
- One-pass first-server checklist: [docs/deployment/hetzner-first-server-checklist.md](/Users/patrickkelly/Documents/CyberArmorAi/docs/deployment/hetzner-first-server-checklist.md)
- PQC auth rollout guide: [docs/security/pqc-auth-rollout.md](/Users/patrickkelly/Documents/CyberArmorAi/docs/security/pqc-auth-rollout.md)
- OpenBao + secrets service architecture: [docs/architecture/openbao-cyberarmor-secrets-service.md](/Users/patrickkelly/Documents/CyberArmorAi/docs/architecture/openbao-cyberarmor-secrets-service.md)
- Jenkins security and OpenBao integration pipeline: [docs/security/jenkins-security-pipeline.md](/Users/patrickkelly/Documents/CyberArmorAi/docs/security/jenkins-security-pipeline.md)
- Jenkins security pipeline: [docs/security/jenkins-security-pipeline.md](/Users/patrickkelly/Documents/CyberArmorAi/docs/security/jenkins-security-pipeline.md)
- V1 readiness and tenant onboarding plan: [docs/v1-readiness-plan.md](/Users/patrickkelly/Documents/CyberArmorAi/docs/v1-readiness-plan.md)
- Ubuntu hardening helper script: [scripts/hardening/harden_ubuntu_server.sh](/Users/patrickkelly/Documents/CyberArmorAi/scripts/hardening/harden_ubuntu_server.sh)

## Current Product Boundary

The current repository is deployable for internal testing, staging, demos, and controlled pilot validation. It is not yet a customer-ready SaaS control plane. The largest remaining gaps are tenant-facing authentication, self-service onboarding, MFA, and stronger separation between the future tenant app at `app.cyberarmor.ai` and the global CyberArmor operator/admin dashboard.

### Kubernetes / Helm (Production)

```bash
cd infra/helm/cyberarmor
# Edit values.yaml for your environment
helm install cyberarmor . -n cyberarmor --create-namespace
```

### Endpoint Agent

```bash
cd agents/endpoint-agent
pip install -r requirements.txt
sudo python installer.py install --server https://your-cyberarmor-server --api-key YOUR_KEY
```

## Project Structure

```
ai-protect-system-claude-4.6/
├── admin-dashboard/          # Vanilla JS admin SPA (16 views)
├── agents/
│   ├── endpoint-agent/       # Cross-platform endpoint security agent
│   │   ├── crypto/           # PQC key transport & signing
│   │   ├── dlp/              # Data loss prevention scanner
│   │   ├── monitors/         # Process, network, file, AI tool monitors
│   │   ├── platform/         # macOS, Windows, Linux integrations
│   │   └── zero_day/         # RCE guard & sandbox
│   ├── proxy-agent/          # Policy decision agent API
│   └── ros-agent/            # ROS2 robotics security agent
├── extensions/
│   ├── chromium-shared/      # Shared Chrome/Brave/Edge extension (MV3)
│   ├── edge/                 # Edge-specific manifest
│   ├── firefox/              # Firefox extension (MV2)
│   ├── safari/               # Safari Web Extension
│   ├── vscode/               # VS Code extension (TypeScript)
│   ├── visual-studio/        # Visual Studio extension (C#)
│   ├── cursor/               # Cursor IDE extension
│   ├── kiro/                 # Kiro IDE extension
│   └── office365/            # Office 365 add-in (Word, Excel, PPT, OneNote, Outlook)
├── infra/
│   ├── docker-compose/       # Docker Compose for local development
│   ├── envoy/                # Envoy proxy config + Lua filter
│   └── helm/cyberarmor/      # Kubernetes Helm chart
├── kernel/
│   ├── linux/                # eBPF monitoring programs
│   ├── macos/                # Endpoint Security system extension
│   └── windows/              # Minifilter + WFP driver
├── libs/
│   └── cyberarmor-core/      # Shared PQC crypto library
├── mobile/                   # React Native iOS/Android app
├── rasp/                     # Runtime Application Self-Protection
│   ├── java/                 # Java agent (javaagent)
│   ├── dotnet/               # .NET middleware
│   ├── python/               # Python WSGI/ASGI middleware
│   ├── nodejs/               # Node.js express/koa middleware
│   ├── go/                   # Go http.RoundTripper wrapper
│   ├── rust/                 # Rust inspector
│   ├── ruby/                 # Ruby Rack/Faraday middleware
│   ├── php/                  # PHP PSR-15/Laravel middleware
│   └── c_cpp/                # C/C++ LD_PRELOAD interceptor
└── services/
    ├── agent-identity/       # AI agent identity, credentials, and delegation chains
    ├── ai-router/            # Unified AI provider gateway with credential vault and cost tracking
    ├── audit/                # Immutable PQC-signed audit log and AI action graph
    ├── compliance/           # Compliance engine (14 frameworks)
    ├── control-plane/        # Central API gateway and tenant management
    ├── detection/            # Prompt injection, jailbreak, toxicity, PII detection
    ├── identity/             # Identity provider service
    ├── integration-control/  # SaaS integration discovery and OAuth scope control
    ├── llm-mock/             # Mock LLM endpoint for local development and testing
    ├── policy/               # Policy engine with AND/OR groups
    ├── proxy/                # Transparent proxy core
    ├── response/             # Incident management and automated response actions
    ├── runtime/              # Unified AISR runtime decision API (orchestrates detection, policy, response)
    ├── secrets-service/      # CyberArmor control layer over OpenBao (KV, transit, key rotation)
    └── siem-connector/       # SIEM output integrations
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONTROL_PLANE_URL` | Control plane service URL | `http://control-plane:8000` |
| `POLICY_API_SECRET` | Policy service API key | (required) |
| `DETECTION_API_SECRET` | Detection service API key | (required) |
| `POSTGRES_URL` | PostgreSQL connection string | `postgresql://...` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379` |
| `PQC_ENABLED` | Enable post-quantum crypto | `true` |
| `FIPS_MODE` | Enable FIPS 140-3 mode | `true` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `AGENT_IDENTITY_API_SECRET` | Agent identity service API key | (required) |
| `AGENT_IDENTITY_JWT_SECRET` | JWT signing secret for agent tokens | (required) |
| `ROUTER_API_SECRET` | AI router service API key | (required) |
| `ROUTER_ENCRYPTION_KEY` | AES-256 master key for provider credential encryption | (required) |
| `AUDIT_API_SECRET` | Audit service API key | (required) |
| `CYBERARMOR_AUDIT_SIGNING_KEY` | PQC signing key for immutable audit entries | (required) |
| `AUDIT_RETENTION_DAYS` | Audit log retention period | `365` |
| `SECRETS_SERVICE_API_SECRET` | Secrets service API key | (required) |
| `OPENBAO_ADDR` | OpenBao server address | (required) |
| `OPENBAO_TOKEN` | OpenBao root/service token | (required) |
| `OPENBAO_NAMESPACE` | OpenBao namespace | (optional) |
| `OPENBAO_KV_MOUNT` | OpenBao KV secrets mount path | (optional) |
| `OPENBAO_TRANSIT_MOUNT` | OpenBao transit engine mount path | (optional) |
| `CYBERARMOR_ENFORCE_SECURE_SECRETS` | Reject insecure default secrets at startup | `false` |
| `CYBERARMOR_ENFORCE_MTLS` | Require mTLS for inter-service calls | `false` |

### Identity Provider Setup

See [docs/azure-app-registration.md](docs/azure-app-registration.md) for Microsoft Entra ID setup instructions.

## RASP Integration

Each RASP agent intercepts AI API calls at the application layer:

```python
# Python example (canonical)
import cyberarmor_rasp
cyberarmor_rasp.init(server="https://your-server", api_key="YOUR_KEY")
# Canonical import is `cyberarmor_rasp`.

# Automatically intercepts requests/httpx calls to AI endpoints
```

```javascript
// Node.js example (canonical export path)
const cyberarmor = require('cyberarmor-rasp');
cyberarmor.init({ server: 'https://your-server', apiKey: 'YOUR_KEY' });
// Legacy import `require('cyberarmor-rasp/legacy')` remains supported.
// Automatically patches http/https modules
```

```go
// Go example
import ca "github.com/cyberarmor/rasp-go"
client := &http.Client{Transport: ca.New(config).RoundTripper(http.DefaultTransport)}
```

## Development

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- (Optional) Kubernetes cluster with Helm 3

### Running Services Locally

```bash
# Start infrastructure
docker-compose -f infra/docker-compose/docker-compose.yml up -d postgres redis

# Start individual services
cd services/policy && pip install -r requirements.txt && uvicorn main:app --port 8001
cd services/compliance && uvicorn main:app --port 8006
```

### Running Tests

```bash
# Shared crypto library
cd libs/cyberarmor-core && python -m pytest tests/

# Policy engine
cd services/policy && python -m pytest

# Compliance frameworks
cd services/compliance && python -m pytest
```

## License

Proprietary - Gratitech Research and Charitable Endeavor Corporation - All rights reserved.

## Support

- Enterprise Support: support@gratitech.com
- Security Issues: security@gratitech.com
