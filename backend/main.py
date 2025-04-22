# backend/main.py

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from backend import api
import os

app = FastAPI()
app.include_router(api.router)

# Serve everything from /frontend (index.html, style.css, script.js)
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
