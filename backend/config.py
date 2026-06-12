from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    max_upload_mb: int = 2048
    subsample_rows: int = 200_000
    top_threats_count: int = 20
    jobs_dir: Path = Path("./jobs")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
settings.jobs_dir.mkdir(parents=True, exist_ok=True)
