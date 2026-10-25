"""
app.py — Flask REST API for the AI Incident Investigator.

Run:
    cd backend
    python app.py

The frontend is served at http://127.0.0.1:5000/
"""

import os
import io
import json
import logging
import tempfile
import threading
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, Response, abort

import database as db
import log_analyzer as la
import ai_engine as ai
import incident_search as ise

# ──────────────────────────────────────────────────────────────────────────────
# Application setup
# ──────────────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR),
    static_url_path="",
)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024   # 16 MB


# ──────────────────────────────────────────────────────────────────────────────
# Startup — DB init + background model loading
# ──────────────────────────────────────────────────────────────────────────────

def _load_models_background():
    """Load both AI models on a daemon thread so the server starts instantly."""
    ai.load_model()
    ise.load_model()


db.init_db()
model_thread = threading.Thread(target=_load_models_background, daemon=True)
model_thread.start()


# ──────────────────────────────────────────────────────────────────────────────
# Frontend serving
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(FRONTEND_DIR), "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(str(FRONTEND_DIR), path)


# ──────────────────────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────────────────────

def _safe_filename(filename: str) -> str:
    """Strip directory components and limit length."""
    name = os.path.basename(filename)
    return name[:200] if name else "upload.log"


def _error(message: str, status: int = 400) -> Response:
    return jsonify({"error": message}), status


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/analyze
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Upload and analyze a log file.

    Multipart form field: file
    Returns: JSON incident report
    """
    if "file" not in request.files:
        return _error("No file provided. Include a file in the 'file' form field.")

    upload = request.files["file"]
    if not upload.filename:
        return _error("No filename found in the uploaded file.")

    filename = _safe_filename(upload.filename)

    # Read file bytes (flask already enforces MAX_CONTENT_LENGTH)
    file_bytes = upload.read()

    # Validate file
    validation_error = la.validate_file(filename, file_bytes)
    if validation_error:
        return _error(validation_error, 422)

    # Decode text
    log_text, decode_error = la.decode_log(file_bytes)
    if decode_error:
        return _error(decode_error, 422)

    # Parse log
    analysis = la.analyze(log_text, filename)

    # Generate AI/fallback report
    report_data = ai.generate_report(analysis)

    # Save to SQLite
    incident_id = db.save_incident(
        filename=filename,
        error_count=analysis.error_count,
        warn_count=analysis.warn_count,
        severity=analysis.severity,
        summary=report_data["summary"],
        evidence=report_data["evidence"],
        causes=report_data["causes"],
        actions=report_data["actions"],
        report=report_data["report"],
        metadata={
            "pattern_hits": list(analysis.pattern_hits.keys()),
            "total_lines": analysis.total_lines,
            "generation_method": report_data.get("generation_method", "rules"),
            "model_used": report_data.get("model_used"),
            "exception_count": len(analysis.exceptions),
        },
    )

    # Save embedding for similarity search
    search_text = ise.build_search_text(analysis)
    emb_bytes = ise.embed_text(search_text)
    if emb_bytes:
        db.save_embedding(incident_id, emb_bytes, search_text)

    # Find similar incidents (using all stored embeddings)
    stored = db.get_all_embeddings()
    similar = ise.find_similar(search_text, stored, exclude_incident_id=incident_id)

    response = {
        "incident_id": incident_id,
        "filename": filename,
        "severity": analysis.severity,
        "error_count": analysis.error_count,
        "warn_count": analysis.warn_count,
        "total_lines": analysis.total_lines,
        "summary": report_data["summary"],
        "evidence": report_data["evidence"],
        "causes": report_data["causes"],
        "actions": report_data["actions"],
        "additional_checks": report_data.get("additional_checks", []),
        "report": report_data["report"],
        "similar_incidents": similar,
        "generation_method": report_data.get("generation_method", "rules"),
        "model_used": report_data.get("model_used"),
        "pattern_hits": list(analysis.pattern_hits.keys()),
    }

    return jsonify(response), 201


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/incidents
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/incidents", methods=["GET"])
def list_incidents():
    """
    Return paginated incident history.

    Query params: limit, offset, search, severity
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return _error("limit and offset must be integers.")

    search = request.args.get("search", "").strip() or None
    severity = request.args.get("severity", "").strip().upper() or None

    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    if severity and severity not in valid_severities:
        return _error(f"severity must be one of: {', '.join(sorted(valid_severities))}")

    incidents = db.get_all_incidents(limit=limit, offset=offset, search=search, severity=severity)
    stats = db.get_stats()

    return jsonify({
        "incidents": incidents,
        "stats": stats,
        "limit": limit,
        "offset": offset,
    })


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/incidents/<id>
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/incidents/<int:incident_id>", methods=["GET"])
def get_incident(incident_id: int):
    """Return the full incident report for a given ID."""
    incident = db.get_incident_by_id(incident_id)
    if incident is None:
        return _error(f"Incident {incident_id} not found.", 404)

    # Optionally include similar incident results
    include_similar = request.args.get("similar", "false").lower() == "true"
    similar = []
    if include_similar:
        meta = incident.get("metadata") or {}
        search_text = incident.get("summary", "")
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        pattern_hits = meta.get("pattern_hits", [])
        if pattern_hits:
            search_text += " Patterns: " + ", ".join(pattern_hits)

        stored = db.get_all_embeddings()
        similar = ise.find_similar(search_text, stored, exclude_incident_id=incident_id)

    incident["similar_incidents"] = similar
    return jsonify(incident)


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/incidents/<id>/download
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/incidents/<int:incident_id>/download", methods=["GET"])
def download_incident(incident_id: int):
    """Download a saved incident report as .txt or .json."""
    fmt = request.args.get("format", "txt").lower()
    if fmt not in ("txt", "json"):
        return _error("format must be 'txt' or 'json'.")

    incident = db.get_incident_by_id(incident_id)
    if incident is None:
        return _error(f"Incident {incident_id} not found.", 404)

    safe_name = f"incident_{incident_id}"

    if fmt == "json":
        # Exclude binary-unfriendly fields
        export = {k: v for k, v in incident.items()}
        content = json.dumps(export, indent=2, default=str)
        mimetype = "application/json"
        disposition = f'attachment; filename="{safe_name}.json"'
    else:
        content = incident.get("report", "No report available.")
        mimetype = "text/plain"
        disposition = f'attachment; filename="{safe_name}.txt"'

    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": disposition},
    )


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/health
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Return status of backend, SQLite DB, and AI models."""
    db_ok = True
    db_error = None
    try:
        db.get_incident_count()
    except Exception as exc:
        db_ok = False
        db_error = str(exc)

    return jsonify({
        "status": "ok" if db_ok else "degraded",
        "database": {
            "ok": db_ok,
            "path": str(db.DB_PATH),
            "error": db_error,
        },
        "ai_model": ai.model_status(),
        "search_model": ise.model_status(),
        "incident_count": db.get_incident_count() if db_ok else None,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Error handlers
# ──────────────────────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(_e):
    return _error("File is too large. Maximum allowed size is 16 MB.", 413)


@app.errorhandler(404)
def not_found(_e):
    return _error("Resource not found.", 404)


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Unhandled server error")
    return jsonify({"error": "An internal server error occurred."}), 500


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Starting AI Incident Investigator on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
