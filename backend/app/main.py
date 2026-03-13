"""
SentinelX — Production FastAPI Backend
=======================================
Hybrid malware detection: YARA static signatures + GBM heuristic + LLM semantic layer
Authors: K. Sharath Kumar, M. Archana, M. Abhign Reddy, K. Ananya
CMR College of Engineering & Technology, Telangana, India
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import time
import uuid
import logging
from pathlib import Path

from app.routers import analyze, benchmark, dataset, model
from app.core.config import settings
from app.core.model_loader import load_models

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SentinelX Malware Detection API",
    description="""
    **SentinelX** is a hybrid malware detection framework that combines:
    - 🔍 **YARA** static signature scanning (Path A: known threats)
    - 🤖 **GBM + LLM Semantic Layer** heuristic analysis (Path B: zero-day / evasive threats)
    - 📊 **Automated YARA rule synthesis** from detected patterns

    Built on a 250-sample PE feature dataset spanning 10 malware families.
    """,
    version="2.0.0",
    contact={
        "name": "K. Ananya",
        "url": "https://github.com/ananyaa-k/SentinelX",
    },
    license_info={"name": "MIT"},
)

# CORS — allow all for demo; restrict in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request timing middleware ──────────────────────────────────────────────
@app.middleware("http")
async def add_process_time(request, call_next):
    start = time.time()
    response = await call_next(request)
    response.headers["X-Process-Time"] = f"{(time.time()-start)*1000:.2f}ms"
    return response

# ── Routers ───────────────────────────────────────────────────────────────
app.include_router(analyze.router,   prefix="/analyze",   tags=["Detection"])
app.include_router(benchmark.router, prefix="/benchmark", tags=["Evaluation"])
app.include_router(dataset.router,   prefix="/dataset",   tags=["Dataset"])
app.include_router(model.router,     prefix="/model",     tags=["Model"])

# ── Root & Health ─────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "name": "SentinelX Malware Detection API",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "POST /analyze/file":      "Upload PE binary for threat analysis",
            "POST /analyze/features":  "Analyze via pre-extracted feature vector",
            "GET  /benchmark/results": "3-way benchmark: YARA vs Basic-ML vs SentinelX",
            "POST /benchmark/run":     "Run live benchmark on a sample subset",
            "GET  /dataset/info":      "Dataset statistics and composition",
            "GET  /dataset/samples":   "Paginated sample browser",
            "GET  /model/explain":     "Feature importance rankings",
            "GET  /model/info":        "Model architecture and hyperparameters",
        }
    }

@app.get("/health", tags=["Health"])
async def health():
    models = load_models()
    return {
        "status": "healthy",
        "models_loaded": list(models.keys()),
        "timestamp": time.time()
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
