# Demo Runbooks

CyberArmor.AI includes three polished demo paths for different buyers.

## Available demos

- [CISO Demo](ciso.md)
- [Security Architect Demo](security-architect.md)
- [AppSec Demo](appsec.md)

## Seed and reset

Seed a persona-specific demo tenant:

```bash
bash scripts/demo/run_ciso_demo.sh
bash scripts/demo/run_security_architect_demo.sh
bash scripts/demo/run_appsec_demo.sh
```

Create a fresh reset tenant without deleting existing data:

```bash
PERSONA=ciso bash scripts/demo/reset_customer_portal_demo.sh
```

The reset path creates a new tenant namespace. This is safer on shared demo
servers than destructive cleanup.

## Core demo surfaces

- `app.cyberarmor.ai` for customer Mission Control and evidence export
- `admin.cyberarmor.ai` for operator readiness and tenant support
- `docs.cyberarmor.ai` for technical context
- `support.cyberarmor.ai` for intake and triage
