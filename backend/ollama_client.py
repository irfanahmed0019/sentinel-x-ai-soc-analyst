import httpx


def call_ollama(prompt: str, model: str, base_url: str = "http://localhost:11434") -> str:
    response = httpx.post(
        f"{base_url.rstrip('/')}/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 800},
        },
        timeout=120.0,
    )
    response.raise_for_status()
    return response.json().get("response", "")


def list_ollama_models(base_url: str = "http://localhost:11434") -> list[str]:
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=5.0)
        response.raise_for_status()
        return [model["name"] for model in response.json().get("models", [])]
    except Exception:
        return []
