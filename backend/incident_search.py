"""
incident_search.py — MiniLM embedding-based similar-incident search.

Uses sentence-transformers/all-MiniLM-L6-v2 locally.
Falls back gracefully when the model cannot be loaded.
"""

import logging
import struct
import math
from typing import List, Dict, Optional, Any, Tuple

logger = logging.getLogger(__name__)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# ── Module-level singletons ───────────────────────────────────────────────────
_st_model = None
_model_available = False
_model_error: Optional[str] = None


def load_model() -> bool:
    """Load the SentenceTransformer model. Returns True on success."""
    global _st_model, _model_available, _model_error

    if _model_available:
        return True
    if _model_error:
        return False

    try:
        from sentence_transformers import SentenceTransformer

        logger.info("Loading %s...", MODEL_NAME)
        _st_model = SentenceTransformer(MODEL_NAME)
        _model_available = True
        logger.info("MiniLM loaded successfully.")
        return True
    except Exception as exc:
        _model_error = str(exc)
        logger.warning("Could not load MiniLM (%s): %s", MODEL_NAME, exc)
        return False


def model_status() -> Dict[str, Any]:
    return {
        "model": MODEL_NAME,
        "available": _model_available,
        "error": _model_error,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Embedding helpers
# ─────────────────────────────────────────────────────────────────────────────

def embed_text(text: str) -> Optional[bytes]:
    """
    Generate a MiniLM embedding for *text* and return it as raw bytes.
    Returns None if the model is unavailable.
    """
    if not _model_available or _st_model is None:
        return None
    try:
        vec = _st_model.encode(text[:512], normalize_embeddings=True)
        # Serialize as packed floats
        return struct.pack(f"{len(vec)}f", *vec)
    except Exception as exc:
        logger.warning("Embedding failed: %s", exc)
        return None


def bytes_to_vector(data: bytes) -> List[float]:
    n = len(data) // 4
    return list(struct.unpack(f"{n}f", data))


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Pure-Python cosine similarity (vectors are already L2-normalised)."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# ─────────────────────────────────────────────────────────────────────────────
# Search
# ─────────────────────────────────────────────────────────────────────────────

SIMILARITY_THRESHOLD = 0.50   # minimum score to surface a result
MAX_RESULTS = 5


def find_similar(
    query_text: str,
    stored_embeddings: List[Dict],
    exclude_incident_id: Optional[int] = None,
) -> List[Dict]:
    """
    Find similar stored incidents using cosine similarity of MiniLM embeddings.

    Parameters
    ----------
    query_text        : text describing the current incident (summary + patterns)
    stored_embeddings : rows from database.get_all_embeddings()
    exclude_incident_id : ID of the current incident (skip self-match)

    Returns a list of result dicts, sorted by similarity descending.
    """
    if not _model_available:
        return []

    query_bytes = embed_text(query_text)
    if query_bytes is None:
        return []

    query_vec = bytes_to_vector(query_bytes)

    scored: List[Tuple[float, Dict]] = []
    for row in stored_embeddings:
        if exclude_incident_id and row["incident_id"] == exclude_incident_id:
            continue
        try:
            stored_vec = bytes_to_vector(row["embedding"])
            score = cosine_similarity(query_vec, stored_vec)
            if score >= SIMILARITY_THRESHOLD:
                scored.append((score, row))
        except Exception:
            continue

    scored.sort(key=lambda x: x[0], reverse=True)

    results = []
    seen_incidents = set()
    for score, row in scored[:MAX_RESULTS * 2]:   # deduplicate by incident_id
        iid = row["incident_id"]
        if iid in seen_incidents:
            continue
        seen_incidents.add(iid)
        results.append({
            "incident_id": iid,
            "filename": row.get("filename", ""),
            "summary": row.get("summary", ""),
            "severity": row.get("severity", ""),
            "analyzed_at": row.get("analyzed_at", ""),
            "similarity_score": round(score, 4),
            "text_snippet": row.get("text_snippet", ""),
            "note": "Similarity score indicates textual resemblance only — does not confirm the same root cause.",
        })
        if len(results) >= MAX_RESULTS:
            break

    return results


def build_search_text(analysis_result) -> str:
    """
    Compose a representative text blob from an AnalysisResult for embedding.
    """
    ar = analysis_result
    parts = [ar.summary_text]
    if ar.pattern_hits:
        parts.append("Patterns: " + ", ".join(ar.pattern_hits.keys()))
    if ar.evidence_lines:
        parts.append("Evidence: " + " | ".join(ar.evidence_lines[:5]))
    return " ".join(parts)[:512]
