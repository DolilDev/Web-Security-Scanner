from fastapi import FastAPI

app = FastAPI(title="WebSec Scanner Backend")


@app.get("/health")
async def health():
    return {"status": "ok"}
