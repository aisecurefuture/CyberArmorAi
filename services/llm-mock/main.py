from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="LLM Mock", version="1.0.0")
_REQUESTS_TOTAL = 0

@app.get("/health")
async def health():
    return {"status": "ok", "service": "llm-mock"}

@app.get("/ready")
async def ready():
    return {"status": "ready"}

@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    lines = [
        "# HELP cyberarmor_llm_mock_requests_total Total LLM mock requests",
        "# TYPE cyberarmor_llm_mock_requests_total counter",
        f"cyberarmor_llm_mock_requests_total {_REQUESTS_TOTAL}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")

@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    global _REQUESTS_TOTAL
    _REQUESTS_TOTAL += 1
    body = await req.json()
    # Minimal OpenAI-like shape so SDK demos can be swapped in later.
    return {
        "id": "cmpl-mock",
        "object": "chat.completion",
        "model": body.get("model", "mock"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "(mock) request received",
                },
                "finish_reason": "stop",
            }
        ],
    }
