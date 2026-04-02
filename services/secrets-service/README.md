# CyberArmor Secrets Service

Thin CyberArmor control layer in front of OpenBao.

Current scaffold includes:

- health, readiness, and metrics endpoints
- PQC-compatible shared `x-api-key` auth
- OpenBao health/status passthrough
- tenant/provider credential storage metadata endpoints
- Transit encrypt, decrypt, sign, and rotate wrappers

Environment variables:

- `SECRETS_SERVICE_API_SECRET`
- `OPENBAO_ADDR`
- `OPENBAO_TOKEN`
- `OPENBAO_NAMESPACE`
- `OPENBAO_KV_MOUNT`
- `OPENBAO_TRANSIT_MOUNT`
- `OPENBAO_TIMEOUT_SECONDS`

Default port:

- `8013`
