from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pathlib import Path

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


@router.get("/dashboard/report/{name}")
async def get_report(name: str):
    report_file = REPORTS_DIR / name
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        return JSONResponse(content=report_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
