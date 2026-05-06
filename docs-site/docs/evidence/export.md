# Evidence Export

CyberArmor.AI evidence exports package tenant-scoped operational data for
reviews, demos, support handoff, and audit preparation.

## Export types

### Summary

Use summary exports for CISO demos, customer check-ins, and executive review.
They include bounded samples of:

- overview counts
- readiness checks
- policies
- agents
- provider posture
- recent telemetry
- recent audit records
- recent incidents

### Full

Use full exports for deeper investigation or customer support. Full exports
include larger record windows while staying tenant-scoped.

## Customer portal path

1. Open `app.cyberarmor.ai`
2. Go to **Reports & Evidence Export**
3. Select **Export Summary** or **Export Full Pack**
4. Review the JSON before sharing externally

## API path

The customer portal calls:

```text
GET /customer/evidence/export?scope=summary
GET /customer/evidence/export?scope=full
```

The endpoint requires a valid tenant-scoped customer session.

## Security boundary

Exports are generated from the authenticated tenant session. They should not
include write-only secrets or cross-tenant data.
