# Customer Portal

The customer portal at `app.cyberarmor.ai` is the tenant-scoped workspace for
security teams validating CyberArmor.AI.

## Mission Control

Mission Control is the default landing view. It rolls tenant posture into a
practical readiness score based on:

- policies created
- endpoints or agents enrolled
- telemetry received
- audit or incident evidence generated
- provider posture reviewed

The score is not a contractual security rating. It is a pilot-readiness guide
that helps customers see the next best action.

## Guided onboarding

Use **SDK & Onboarding** to move a tenant from blank state to demo-ready:

1. create or review a policy
2. enroll an endpoint, SDK, extension, or RASP package
3. send a test event
4. verify telemetry
5. confirm an audit or incident evidence record
6. export an evidence pack from Reports

## Evidence export

The **Reports & Evidence Export** view can produce:

- `summary` evidence packs for executive and demo review
- `full` evidence packs for deeper audit or support handoff

Exports are tenant-scoped and generated server-side from the authenticated
customer session. Write-only secrets are not included.

## Recommended first demo

Seed a demo tenant:

```bash
bash scripts/demo/run_ciso_demo.sh
```

Then open:

- Mission Control
- SDK & Onboarding
- Incidents
- Reports & Evidence Export
