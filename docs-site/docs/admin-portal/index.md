# Admin Portal

The admin portal at `admin.cyberarmor.ai` is the CyberArmor operator console.
It is intentionally separate from the customer portal.

## Tenant readiness score

The admin overview and tenant table show tenant readiness based on:

- policy presence
- agent enrollment
- telemetry flow
- audit evidence
- provider visibility

This gives support, customer success, and operators a fast signal for whether a
tenant is demo-ready or needs onboarding work.

## Operator workflow

For each tenant:

1. confirm tenant and first admin exist
2. check readiness score
3. inspect service health
4. verify policies and OPA state
5. review endpoint/agent enrollment
6. confirm telemetry and audit evidence
7. guide the customer to evidence export

## What belongs in admin

Admin is for platform-wide and support-owned operations:

- tenant creation
- tenant readiness
- service health
- policy and OPA troubleshooting
- bootstrap support
- cross-service diagnostics

Customer-owned settings should stay in the customer portal.
