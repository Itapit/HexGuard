# backend/main.py

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend import api
import os

app = FastAPI()
app.include_router(api.router)

# Serve static HTML from /frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/static", StaticFiles(directory=frontend_path), name="static")

# Serve index.html at root URL
@app.get("/")
def read_root():
    return FileResponse(os.path.join(frontend_path, "index.html"))
