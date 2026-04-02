# CyberArmor Detection Service

Content inspection service used by proxy, dashboard scan tools, and extensions.

## Endpoints
- `GET /health`
- `POST /scan` (proxy-compatible full scan)
- `POST /scan/prompt-injection`
- `POST /scan/promptware`
- `POST /scan/sensitive-data`
- `POST /scan/output-safety`
- `POST /scan/all`

## Auth
All scan endpoints require header `x-api-key` matching `DETECTION_API_SECRET`.

## Run locally
```bash
pip install fastapi uvicorn[standard] pydantic
uvicorn main:app --host 0.0.0.0 --port 8002
```

## Environment
- `DETECTION_API_SECRET` (default `change-me-detection`)
- `PROMPT_INJECTION_MODEL_THRESHOLD` (default `0.62`)
- `PROMPT_INJECTION_MODEL_BACKEND` (`transformer` or fallback local)
- `PROMPT_INJECTION_MODEL_PATH` (local fine-tuned checkpoint path)
- `PROMPT_INJECTION_MODEL_POSITIVE_LABEL_INDEX` (default `1`)
- `PROMPT_INJECTION_ENSEMBLE_THRESHOLD` (default `0.66`)
- `PROMPT_INJECTION_RISK_BASE` (default `0.32`)
- `PROMPT_INJECTION_RISK_MULTIPLIER` (default `0.85`)
- `PROMPT_INJECTION_RISK_CAP` (default `0.85`)
- `SEMANTIC_DLP_THRESHOLD` (default `0.62`)
- `CYBERARMOR_PROMPTWARE_SESSION_ENABLED` (default `true`)
- `PROMPTWARE_SESSION_WINDOW_SECONDS` (default `1800`)
- `PROMPTWARE_SESSION_MAX_EVENTS` (default `20`)
- `PROMPTWARE_CHAIN_WARN_THRESHOLD` (default `0.55`)
- `PROMPTWARE_CHAIN_BLOCK_THRESHOLD` (default `0.85`)
- `CYBERARMOR_ENABLE_LEGACY_PROMPT_REGEX` (default `false`; optional compatibility mode)

## Prompt-injection detection model
- Prompt-injection detection now uses an embedded local classifier (`local-pi-llm-v1`) instead of regex-only matching.
- Prompt-injection detection supports transformer-first local inference (`PROMPT_INJECTION_MODEL_BACKEND=transformer`) with local checkpoint loading.
- The model runs fully in-process with no external LLM/API dependency.
- Input is adversarially normalized before scoring (Unicode normalization, homoglyph folding, zero-width stripping, encoded-segment expansion).
- Ensemble detection combines model confidence with heuristic attack signals (override/exfil/indirect/tool-injection cues).
- Legacy regex matching can be enabled only as optional compatibility fallback.
- Session-aware promptware correlation detects multi-turn attack chains and emits `promptware_attack_chain` findings.
- Provide `session_id` on scan requests for best correlation fidelity.
- `POST /scan/promptware` returns:
- current detections for the request
- per-session chain state (`event_count`, `chain_confidence`, indicator mix)
- whether a chain detection was triggered on the current turn

## Output safety coverage
- Detects command-execution patterns (`rm -rf`, `curl | bash`, `powershell -enc`).
- Detects script/XSS-style payload patterns (`<script>...</script>`, event handlers like `onerror=`, `javascript:` URLs, common browser data exfil sinks).

## Sensitive data coverage
- Regex-based structured detections (SSN, payment card, AWS key, private key).
- Semantic DLP detections using local embedding similarity against sensitive concept prototypes.
- Entity-aware DLP detection for common high-risk entities (JWT/token-like values, IBAN, API-key-like patterns, etc.).
- Exfil-intent detection for semantic patterns indicating data export/leak behavior.
