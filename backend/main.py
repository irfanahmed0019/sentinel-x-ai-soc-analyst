import asyncio
import json
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse

from config import settings
from models import HealthResponse, UploadResponse
from ollama_client import list_ollama_models
from pipeline import run_pipeline
from scanner import run_scan, ScanResponse

app = FastAPI(title="SENTINEL-X API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

progress_events: dict[str, list[dict[str, object]]] = {}
UPLOAD_CHUNK_SIZE = 8 * 1024 * 1024


def _job_dir(job_id: str) -> Path:
    return settings.jobs_dir / job_id


def _push_progress(job_id: str, stage: str, percent: int, message: str) -> None:
    progress_events.setdefault(job_id, []).append({"stage": stage, "percent": percent, "message": message})


def _run_job(
    job_id: str,
    upload_path: Path,
    original_name: str,
    ai_provider: str,
    gemini_api_key: str | None,
    ollama_model: str | None,
    ollama_base_url: str,
) -> None:
    run_pipeline(
        job_id,
        upload_path,
        original_name,
        ai_provider,
        gemini_api_key,
        ollama_model,
        ollama_base_url,
        lambda stage, percent, message: _push_progress(job_id, stage, percent, message),
    )


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        app="SENTINEL-X",
        ollama_available=bool(list_ollama_models()),
        gemini_configured=False,
    )


@app.get("/api/models/ollama")
def ollama_models(base_url: str = "http://localhost:11434") -> dict[str, list[str]]:
    return {"models": list_ollama_models(base_url)}


@app.post("/api/upload", response_model=UploadResponse)
async def upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    ai_provider: str = Form(...),
    gemini_api_key: str | None = Form(None),
    ollama_model: str | None = Form(None),
    ollama_base_url: str = Form("http://localhost:11434"),
) -> UploadResponse:
    if ai_provider not in {"gemini", "ollama", "none"}:
        raise HTTPException(status_code=400, detail="ai_provider must be gemini, ollama, or none")
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Upload a CSV file.")

    job_id = str(uuid.uuid4())
    job_dir = _job_dir(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    upload_path = job_dir / "upload.csv"

    max_bytes = settings.max_upload_mb * 1024 * 1024
    size = 0
    try:
        with upload_path.open("wb") as target:
            while chunk := await file.read(UPLOAD_CHUNK_SIZE):
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb}MB limit.")
                target.write(chunk)
    except HTTPException:
        upload_path.unlink(missing_ok=True)
        job_dir.rmdir()
        raise
    finally:
        await file.close()

    progress_events[job_id] = []
    _push_progress(job_id, "upload", 5, "File received, starting analysis...")
    background_tasks.add_task(
        _run_job,
        job_id,
        upload_path,
        file.filename,
        ai_provider,
        gemini_api_key,
        ollama_model,
        ollama_base_url,
    )
    return UploadResponse(job_id=job_id, status="processing")


@app.get("/api/progress/{job_id}")
async def progress(job_id: str) -> StreamingResponse:
    if job_id not in progress_events and not _job_dir(job_id).exists():
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_stream():
        index = 0
        retries = 0
        while retries < 1800:
            events = progress_events.get(job_id, [])
            while index < len(events):
                event = events[index]
                index += 1
                yield f"data: {json.dumps(event)}\n\n"
                if event["stage"] in {"done", "error"}:
                    return
            retries += 1
            await asyncio.sleep(1)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/report/{job_id}")
def report(job_id: str):
    report_path = _job_dir(job_id) / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not ready")
    return json.loads(report_path.read_text(encoding="utf-8"))


@app.get("/api/export/{job_id}")
def export(job_id: str) -> FileResponse:
    scored_path = _job_dir(job_id) / "scored.csv"
    if not scored_path.exists():
        raise HTTPException(status_code=404, detail="Scored dataset not ready")
    return FileResponse(scored_path, filename=f"sentinel-x-{job_id}-scored.csv")

@app.get("/api/scan", response_model=ScanResponse)
async def scan_target_api(
    target: str,
    ai_provider: str = "none",
    gemini_api_key: str | None = None,
    ollama_model: str | None = None,
    ollama_base_url: str = "http://localhost:11434"
) -> ScanResponse:
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    return await run_scan(target, ai_provider, gemini_api_key, ollama_model, ollama_base_url)
