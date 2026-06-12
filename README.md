# Sentinel‑X

**Sentinel‑X** is a modern cyber‑security platform that provides:

- Threat analysis with Isolation Forest & Random Forest models
- Live asset scanning
- MITRE ATT&CK mapping
- AI‑generated SOC reports (Gemini)
- PDF export and executive dashboards

It consists of a **React + TypeScript + Vite** frontend (Tailwind) and a **FastAPI** backend.

## Repository layout (inside `github/`)
```
.github/                # GitHub Actions workflows
│   └─ workflows/
│        └─ ci.yml      # CI pipeline
.gitignore              # Ignored files
README.md                # This file
CONTRIBUTING.md          # How to contribute
LICENSE                  # MIT License
netlify.toml            # Netlify configuration
Procfile                # Render start command
.env.example            # Backend env template (do not commit actual secrets)
.env.frontend.example   # Frontend Vite env template
```

## Quick start (local development)
```bash
# Clone repo
git clone <repo-url>
cd sentinel-x

# Backend setup
cp github/.env.example backend/.env   # fill in your keys
python -m pip install -r backend/requirements.txt
uvicorn main:app --reload

# Frontend setup
cp github/.env.frontend.example frontend/.env
cd frontend
npm install
npm run dev
```

## Deployment
- **Frontend** → Netlify. Set `VITE_API_URL` environment variable to your backend URL.
- **Backend** → Render. Provide the same env vars (`GEMINI_API_KEY`, `FASTAPI_SECRET_KEY`, etc.) and Render will use the `Procfile`.

## License
MIT – see the `LICENSE` file.
