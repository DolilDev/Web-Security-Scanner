# WebSec Scanner

WebSec Scanner is a passive web security audit orchestrator. It is designed to detect and report misconfigurations, outdated software versions, missing security headers and other security issues in a non-offensive way.

> Legal disclaimer: Use this tool only on domains for which you have explicit written permission from the owner to perform testing. Unauthorized scanning may be illegal and unethical.

## Project structure

- `backend/` — FastAPI backend, Celery worker, database models, security test engine
- `frontend/` — Next.js frontend and live streaming UI
- `tools/` — wrappers for external tools such as `nmap`, `testssl.sh`, and `whatweb`
- `tests/` — unit tests and integration tests
- `docs/` — project documentation

## Quickstart (runner + dashboard)

Run a scan and save JSON report:

```bash
python -m backend.app.scan_runner https://example.com --out backend/app/reports/report.json
```

Start the backend (FastAPI) and open the dashboard:

```bash
uvicorn backend.app.main:app --reload --port 8000
# then open http://localhost:8000/dashboard
```

Reports are read from `backend/app/reports/` by the dashboard UI.

## Getting started

1. Copy `.env.example` to `.env` and adjust settings.
2. Run `docker-compose up --build` to start the stack.
3. Access the backend at `http://localhost:8000` and frontend at `http://localhost:3000`.

## Disclaimer

This repository scaffold is intended for security auditing only, not for offensive exploitation. Do not use this project to target systems without clear permission.
