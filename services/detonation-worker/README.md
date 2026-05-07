# Detonation Worker

Isolated Playwright sandbox for the URL / Context Trust Gate. Renders
attacker-controlled URLs in a one-shot Chromium context, extracts
visible / CSS-hidden / Unicode-tag-hidden text + forms + scripts +
screenshot hash, and returns the result to the gate over HTTP.

## Why a separate service

The gate orchestrates calls into the backend (detection, policy,
audit). Mixing those calls and *fetching attacker-controlled web
pages* in the same network namespace is the wrong shape. A hostile
page that exploits a Chromium bug or attacks the worker via SSRF
cannot reach internal services if the worker has no route there.

The compose stack puts this service on a dedicated `detonation`
network. The gate joins both `default` and `detonation` so it can
talk to the worker; the worker has no membership on `default` and
therefore cannot reach `policy`, `detection`, `audit`, or anything
else internal.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/render` | Render a URL and return extracted artefacts. |
| `GET` | `/health` | Liveness. |
| `GET` | `/ready` | Readiness (process up; browser is launched lazily on first render). |
| `GET` | `/metrics` | Prometheus exposition (TODO). |

Auth: `x-api-key: $DETONATION_WORKER_API_SECRET`.

## Image

`mcr.microsoft.com/playwright/python:v1.49.0-jammy` — Microsoft's
published Playwright Python image. Pinned by tag. Already contains
Chromium / Firefox / WebKit and their OS libs.

This is the deliberate choice over installing Playwright onto the
gate's PQC base image: Microsoft's image tracks Chromium versions and
patches font / GTK / NSS dependencies. Building those onto a generic
Debian Trixie base means chasing the wrong taillights.

## Deployment notes

- One-shot context per request. Cookies, storage, service workers,
  and HTTP cache are wiped each render.
- Empty profile. No user identity or auth headers leak through.
- Hard caps via env: total wallclock, navigation timeout, request
  count, bytes transferred.
- Production: enforce CPU / memory / pids container limits AND keep
  the worker on its own egress-only network. Kubernetes equivalent:
  a NetworkPolicy that allows ingress only from the gate's pod and
  no egress to internal CIDR ranges or the cloud-metadata IP.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DETONATION_WORKER_API_SECRET` | `change-me-detonation-worker` | Inbound API key shared with the gate. |
| `DETONATION_NAV_TIMEOUT_MS` | `8000` | Per-page navigation timeout. |
| `DETONATION_TOTAL_TIMEOUT_S` | `12.0` | Total wallclock per render. |
| `DETONATION_MAX_REQUESTS` | `100` | Max network requests the rendered page can issue before we cut it off. |
| `DETONATION_MAX_BYTES` | `8388608` | Max bytes the rendered page can pull (8 MiB). |
| `DETONATION_VIEWPORT_W` / `_H` | `1280` / `800` | Viewport size. |

## How the gate calls it

The gate's `services/url-trust-gate/detonation.py` is a thin HTTP
client. It POSTs `{url, tenant_id, request_id}` to `/render` and
maps the response into the `DetonationResult` dataclass that the
extractors and evidence layer already understand. If the worker is
unreachable, deep-mode requests fall through with a structured error
and the gate downgrades to standard-depth behaviour for that request.
