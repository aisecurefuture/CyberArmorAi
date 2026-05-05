# Architecture

*Placeholder — content to be filled in from existing internal architecture
notes.*

## Services at a glance

The platform is a set of cooperating Python (FastAPI) services plus a few
supporting components:

| Service              | Purpose                                          |
| -------------------- | ------------------------------------------------ |
| `control-plane`      | Tenant + configuration API                       |
| `policy`             | Policy decision and enforcement                  |
| `detection`          | ML-driven detection (PII, prompt injection)     |
| `response`           | Action handlers triggered by detections          |
| `identity`           | Workforce identity integrations                  |
| `agent-identity`     | Service/agent identity issuance and JWT         |
| `ai-router`          | Egress router for AI traffic                     |
| `audit`              | Tamper-evident audit log                         |
| `secrets-service`    | OpenBao-backed secret storage                    |
| `siem-connector`     | Telemetry export to customer SIEMs              |
| `compliance`         | Compliance evidence generation                   |
| `proxy-agent`        | Customer-side enforcing proxy                    |

## Data plane

*To be written.*

## Control plane

*To be written.*
