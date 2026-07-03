from fastapi import FastAPI
from .dashboard import router as dashboard_router

app = FastAPI(title="WebSec Scanner Backend")


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(dashboard_router, prefix="")
