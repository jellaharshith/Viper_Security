"""Exec API v1. Launch with `python -m vmapi.app` on the Linux VM."""

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from vmapi.auth import authorized
from vmapi.jobs import JobRegistry
from vmapi.toolrunner import TOOLS, build_command


class JobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    job_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,128}$")
    tool: str
    args: dict[str, Any]
    target: str


def create_app() -> FastAPI:
    registry = JobRegistry()
    targets = frozenset(filter(None, (s.strip() for s in
                        os.environ.get("VIPER_EXEC_EGRESS_ALLOWLIST", "").split(","))))

    @asynccontextmanager
    async def lifespan(app):
        yield
        registry.close()

    api = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    api.state.jobs = registry

    @api.middleware("http")
    async def authentication(request: Request, call_next):
        if not authorized(request.headers.get("authorization")):
            return JSONResponse({"detail": "Unauthorized"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)

    def get_job(job_id):
        try:
            return registry.get(job_id)
        except KeyError:
            raise HTTPException(404, "Job not found") from None

    @api.get("/health")
    def health():
        return {"status": "ok", "tools": list(TOOLS)}

    @api.post("/jobs", status_code=201)
    def start(body: JobRequest):
        try:
            command = build_command(body.tool, body.args, body.target, targets)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        try:
            registry.start(body.job_id, command)
        except ValueError:
            raise HTTPException(409, "Job ID already exists") from None
        except (OSError, RuntimeError):
            raise HTTPException(503, "Job could not be started") from None
        return {"job_id": body.job_id, "state": "running"}

    @api.get("/jobs/{job_id}")
    def status(job_id: str):
        job = get_job(job_id)
        with job.changed:
            return {"job_id": job_id, "state": job.state, "exit_code": job.exit_code}

    @api.get("/jobs/{job_id}/stream")
    def stream(job_id: str):
        return StreamingResponse(registry.stream(get_job(job_id)), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @api.post("/jobs/{job_id}/pause")
    def pause(job_id: str):
        job = get_job(job_id)
        try:
            registry.pause(job)
        except (ValueError, ProcessLookupError):
            raise HTTPException(409, "Job is not running") from None
        return {"state": "paused"}

    @api.post("/jobs/{job_id}/stop")
    def stop(job_id: str):
        job = get_job(job_id)
        try:
            registry.stop(job)
        except ValueError:
            raise HTTPException(409, "Job already finished") from None
        except (OSError, RuntimeError):
            raise HTTPException(503, "Process group termination not verified") from None
        return {"state": "killed"}

    return api


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("vmapi.app:app", host="127.0.0.1", port=8443, workers=1,
                ssl_certfile=os.environ["VIPER_EXEC_API_TLS_CERT"],
                ssl_keyfile=os.environ["VIPER_EXEC_API_TLS_KEY"])
