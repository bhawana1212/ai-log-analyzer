import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from analyzer.ai import ExplanationUnavailable, explain
from analyzer.core import MAX_CONTEXT_CHARS, MAX_LOG_BYTES, analyze

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="AI Log Analyzer", version="0.1.0")


class RequestGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["method"] == "POST":
            headers = dict(scope["headers"])
            origin = headers.get(b"origin")
            host = headers.get(b"host", b"")
            if origin and origin not in (b"http://" + host, b"https://" + host):
                return await JSONResponse(
                    {"detail": "Cross-origin requests are not allowed."},
                    status_code=403,
                )(scope, receive, send)
            messages = []
            size = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                size += len(message.get("body", b""))
                if size > 6 * 1024 * 1024:
                    return await JSONResponse(
                        {"detail": "Request exceeds the 6 MiB transport limit."},
                        status_code=413,
                    )(scope, receive, send)
                messages.append(message)
                if not message.get("more_body", False):
                    break
            iterator = iter(messages)

            async def replay():
                return next(
                    iterator, {"type": "http.request", "body": b"", "more_body": False}
                )

            await self.app(scope, replay, send)
        else:
            await self.app(scope, receive, send)


app.add_middleware(RequestGuard)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if request.url.path in ("/docs", "/redoc"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
    return response


class LogRequest(BaseModel):
    log: str = Field(min_length=1, max_length=MAX_LOG_BYTES)


class ExplainRequest(BaseModel):
    context: str = Field(min_length=1, max_length=MAX_CONTEXT_CHARS)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "ai_enabled": bool(os.getenv("OPENAI_API_KEY", "").strip()),
        "max_log_bytes": MAX_LOG_BYTES,
    }


@app.post("/api/analyze")
async def analyze_log(payload: LogRequest):
    try:
        return await run_in_threadpool(analyze, payload.log)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/explain")
async def explain_log(payload: ExplainRequest):
    try:
        return {"explanation": await run_in_threadpool(explain, payload.context)}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except ExplanationUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
