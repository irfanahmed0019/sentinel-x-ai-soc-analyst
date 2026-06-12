import google.generativeai as genai


GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-1.5-flash"]


def call_gemini(prompt: str, api_key: str) -> str:
    genai.configure(api_key=api_key)
    last_error: Exception | None = None
    for model_name in GEMINI_MODELS:
        try:
            model = genai.GenerativeModel(
                model_name=model_name,
                generation_config={"max_output_tokens": 1200, "temperature": 0.2},
            )
            response = model.generate_content(prompt)
            return response.text or ""
        except Exception as exc:
            last_error = exc
            if "not found" not in str(exc).lower() and "404" not in str(exc):
                raise
    raise RuntimeError(f"No configured Gemini model was available. Last error: {last_error}")
