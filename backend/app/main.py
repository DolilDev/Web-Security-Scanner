from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from .dashboard import router as dashboard_router

app = FastAPI(title="WebSec Scanner Backend")


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/dashboard")


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(dashboard_router, prefix="")
