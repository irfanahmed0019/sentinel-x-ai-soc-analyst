from typing import Any, Literal

from pydantic import BaseModel


AiProvider = Literal["gemini", "ollama", "none"]


class ProgressEvent(BaseModel):
    stage: str
    percent: int
    message: str


class UploadResponse(BaseModel):
    job_id: str
    status: str


class HealthResponse(BaseModel):
    status: str
    app: str
    ollama_available: bool
    gemini_configured: bool


class ReportResponse(BaseModel):
    job_id: str
    status: str
    file_name: str | None = None
    processed_at: str | None = None
    pipeline_duration_seconds: float | None = None
    ai_provider_used: AiProvider = "none"
    ollama_model_used: str | None = None
    summary: dict[str, Any] | None = None
    eda: dict[str, Any] | None = None
    ml: dict[str, Any] | None = None
    ai_analysis: dict[str, Any] | None = None
    error: str | None = None
