# Support Intake

Use the support intake workflow when a customer or operator needs help with a
deployment, portal, enrollment, runtime, evidence, or routing issue.

## Public support form

The support page includes a ticket form with secure log upload:

- origin checks
- rate limiting
- file count limits
- file size limits
- extension allow-list
- in-memory attachment handling
- SHA-256 metadata for uploaded logs

## What to collect

Before escalating, collect:

- environment name
- tenant ID
- affected public hostname
- exact URL or API path
- timestamp
- user email, request ID, or trace ID
- whether the same path works locally
- relevant service logs

## Severity guide

| Severity | Meaning |
| --- | --- |
| S1 | Production outage or security-critical exposure |
| S2 | Major workflow blocked |
| S3 | Degraded or isolated issue |

## Log handling

Customers should review logs for sensitive secrets where practical before
uploading. The form asks for explicit approval before accepting attachments.
