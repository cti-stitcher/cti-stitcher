"""
cti-stitcher explorer — entry point.

Run with:
    python -m explorer

Or via uvicorn directly:
    uvicorn explorer.main:app --reload
"""

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

load_dotenv()

from core.db import init_db, get_session
from core.resolution import ResolutionIndex
from explorer.api.actors import router as actors_router
from explorer.api.controls import router as controls_router
from explorer.api.d3fend import router as d3fend_router
from explorer.api.gap import router as gap_router
from explorer.api.report import router as report_router
from explorer.api.software import router as software_router
from explorer.api.targeting import router as targeting_router
from explorer.api.rank import router as rank_router
from explorer.api.search import router as search_router
from explorer.api.sync import router as sync_router

UI_DIR = Path(__file__).parent / "ui"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB, resolution index, and shared session on startup."""
    init_db()
    session = get_session()
    resolver = ResolutionIndex(session)

    app.state.db_session = session
    app.state.resolver = resolver

    print("[OK] cti-stitcher explorer ready at http://localhost:8000")
    yield

    session.close()


app = FastAPI(
    title="cti-stitcher",
    description="Open source CTI toolchain — threat actor explorer",
    version="0.1.0",
    lifespan=lifespan,
)

# API routes
app.include_router(actors_router)
app.include_router(controls_router)
app.include_router(d3fend_router)
app.include_router(gap_router)
app.include_router(report_router)
app.include_router(software_router)
app.include_router(targeting_router)
app.include_router(rank_router)
app.include_router(search_router)
app.include_router(sync_router)

# Serve static UI files
app.mount("/static", StaticFiles(directory=str(UI_DIR / "static")), name="static")


@app.get("/")
def index():
    return FileResponse(str(UI_DIR / "index.html"))


@app.get("/actor/{actor_id}")
def actor_page(actor_id: int):
    return FileResponse(str(UI_DIR / "actor.html"))


@app.get("/controls")
def controls_page():
    return FileResponse(str(UI_DIR / "controls.html"))


@app.get("/controls/{control_id}")
def control_detail_page(control_id: str):
    return FileResponse(str(UI_DIR / "control_detail.html"))


@app.get("/gap-analysis")
def gap_analysis_page():
    return FileResponse(str(UI_DIR / "gap_analysis.html"))


@app.get("/d3fend")
def d3fend_page():
    return FileResponse(str(UI_DIR / "d3fend.html"))


@app.get("/software/{software_id}")
def software_page(software_id: int):
    return FileResponse(str(UI_DIR / "software.html"))


@app.get("/targeting/{target_type}/{value:path}")
def targeting_page(target_type: str, value: str):
    return FileResponse(str(UI_DIR / "targeting.html"))


@app.get("/rank")
def rank_page():
    return FileResponse(str(UI_DIR / "rank.html"))


@app.get("/settings")
def settings_page():
    return FileResponse(str(UI_DIR / "settings.html"))


def _open_browser():
    """Wait for the server to start, then open the browser."""
    import time
    import webbrowser
    time.sleep(1.5)
    webbrowser.open("http://localhost:8000")


def cli():
    """Entry point for `python -m explorer` and the cti-stitcher CLI script."""
    import threading
    import uvicorn
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run("explorer.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    cli()
