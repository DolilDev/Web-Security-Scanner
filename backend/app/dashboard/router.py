from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pathlib import Path
import json
from datetime import datetime

from ..tests_engine.orchestration.runner import run_scan, save_report

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR.parent / "reports"
STATIC_DIR = BASE_DIR / "static"


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard static not found")
    return FileResponse(index_file)


@router.get("/dashboard/reports")
async def list_reports():
    if not REPORTS_DIR.exists():
        return JSONResponse(content={"reports": []})
    files = [p.name for p in sorted(REPORTS_DIR.glob("*.json"))]
    return JSONResponse(content={"reports": files})


@router.get("/dashboard/report/{name}")
async def get_report(name: str):
    report_file = REPORTS_DIR / name
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        text = report_file.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return JSONResponse(content={"raw": text})
        if not isinstance(data, (dict, list)):
            return JSONResponse(content={"raw": data})
        return JSONResponse(content=data)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Cannot decode report file: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unexpected error reading report: {exc}")


@router.post("/api/scan")
async def start_scan(target: str = Query(..., min_length=5), filename: str | None = None):
    if not target:
        raise HTTPException(status_code=400, detail="Target query parameter is required")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not filename:
        filename = f"report-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    report = await run_scan(target, concurrency=5)
    save_report(report, str(REPORTS_DIR / filename))
    return JSONResponse(content={"report": filename, "results": report})
