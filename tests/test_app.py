"""
tests/test_app.py — Automated test suite for the AI Incident Investigator.

Run from project root:
    cd backend
    python -m pytest ../tests/test_app.py -v

Or from tests directory:
    cd tests
    python -m pytest test_app.py -v
"""

import sys
import os
import json
import io
import pytest

# ── Path setup ────────────────────────────────────────────
BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

SAMPLE_LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_logs")


# ═══════════════════════════════════════════════════════════
# Log Analyzer tests
# ═══════════════════════════════════════════════════════════

import log_analyzer as la


class TestLogAnalyzer:

    def test_empty_file_returns_parse_error(self):
        result = la.analyze("", "empty.log")
        assert result.parse_error is not None

    def test_whitespace_only_file(self):
        result = la.analyze("   \n\t\n  ", "whitespace.log")
        assert result.parse_error is not None

    def test_no_errors_file(self):
        text = (
            "2024-03-19 10:00:00 INFO [app] Server started\n"
            "2024-03-19 10:00:01 INFO [db] Connected\n"
            "2024-03-19 10:05:12 INFO [api] GET /health 200 OK\n"
        )
        result = la.analyze(text, "no_errors.log")
        assert result.error_count == 0
        assert result.warn_count == 0
        assert result.severity == "INFO"
        assert result.parse_error is None

    def test_error_counting(self):
        text = (
            "2024-03-15 08:12:01 ERROR [db] Connection timeout\n"
            "2024-03-15 08:12:02 ERROR [db] Connection timeout\n"
            "2024-03-15 08:12:03 WARN  [db] Pool at 90%\n"
        )
        result = la.analyze(text, "errors.log")
        assert result.error_count == 2
        assert result.warn_count == 1

    def test_fatal_counted_as_error(self):
        text = "2024-01-01 00:00:00 FATAL [app] Crash\n"
        result = la.analyze(text, "fatal.log")
        assert result.error_count == 1

    def test_db_timeout_detected(self):
        text = "2024-03-15 08:15:12 ERROR [db] database connection timed out after 30000ms\n"
        result = la.analyze(text, "db.log")
        assert "db_timeout" in result.pattern_hits

    def test_http_500_detected(self):
        text = "2024-03-16 14:23:01 ERROR [nginx] POST /api/order HTTP/1.1 500 Internal Server Error\n"
        result = la.analyze(text, "http.log")
        assert "http_500" in result.pattern_hits

    def test_auth_failure_detected(self):
        text = "2024-03-17 09:30:01 ERROR [auth] Authentication failed for user admin: invalid token\n"
        result = la.analyze(text, "auth.log")
        assert "auth_failure" in result.pattern_hits

    def test_oom_detected(self):
        text = "2024-03-18 02:03:01 ERROR [batch] java.lang.OutOfMemoryError: Java heap space\n"
        result = la.analyze(text, "oom.log")
        assert "memory_error" in result.pattern_hits

    def test_severity_critical_for_oom(self):
        text = "2024-03-18 02:03:01 ERROR [batch] java.lang.OutOfMemoryError: Java heap space\n"
        result = la.analyze(text, "oom.log")
        assert result.severity == "CRITICAL"

    def test_severity_high_for_many_errors(self):
        lines = "\n".join(
            f"2024-01-01 0{i}:00:00 ERROR [app] Error {i}" for i in range(10)
        )
        result = la.analyze(lines, "many_errors.log")
        assert result.severity in ("HIGH", "CRITICAL")

    def test_severity_medium_for_single_error(self):
        text = "2024-01-01 00:00:00 ERROR [app] An error occurred\n"
        result = la.analyze(text, "one_error.log")
        assert result.severity == "MEDIUM"

    def test_evidence_lines_captured(self):
        text = (
            "2024-01-01 00:00:00 ERROR [app] First error\n"
            "2024-01-01 00:00:01 INFO  [app] Normal line\n"
            "2024-01-01 00:00:02 WARN  [app] A warning\n"
        )
        result = la.analyze(text, "evidence.log")
        assert len(result.evidence_lines) >= 2

    def test_malformed_file_does_not_crash(self):
        malformed = (
            "not a log line at all\n"
            "NULL\x00\x01\x02 binary garbage\n"
            "2024-13-99 99:99:99 BADLEVEL garbled line\n"
            "2024-01-01 12:00:00 ERROR real error line\n"
        )
        result = la.analyze(malformed, "malformed.log")
        # Should not raise; should find at least the one real error
        assert result.error_count >= 1

    def test_total_lines_counted(self):
        text = "line1\nline2\nline3\n"
        result = la.analyze(text, "count.log")
        assert result.total_lines == 3

    def test_summary_text_populated(self):
        text = "2024-01-01 00:00:00 ERROR [app] error\n"
        result = la.analyze(text, "summary.log")
        assert result.summary_text
        assert "summary.log" in result.summary_text


class TestFileValidation:

    def test_valid_log_file(self):
        err = la.validate_file("server.log", b"2024 INFO something")
        assert err is None

    def test_valid_txt_file(self):
        err = la.validate_file("server.txt", b"some log content")
        assert err is None

    def test_invalid_extension(self):
        err = la.validate_file("server.csv", b"content")
        assert err is not None
        assert ".csv" in err or "not supported" in err.lower()

    def test_empty_file(self):
        err = la.validate_file("server.log", b"")
        assert err is not None
        assert "empty" in err.lower()

    def test_oversized_file(self):
        big = b"x" * (17 * 1024 * 1024)
        err = la.validate_file("big.log", big)
        assert err is not None
        assert "large" in err.lower() or "16" in err

    def test_path_traversal_sanitized(self):
        # validate_file only checks extension — path safety is in app.py's _safe_filename
        # Here we check that the extension check works for weird names
        err = la.validate_file("../../etc/passwd.log", b"content")
        assert err is None   # extension .log is OK; path safety is separate concern


class TestDecoding:

    def test_utf8_decode(self):
        text, err = la.decode_log("hello world\n".encode("utf-8"))
        assert err is None
        assert "hello" in text

    def test_latin1_decode(self):
        text, err = la.decode_log("caf\xe9\n".encode("latin-1"))
        assert err is None
        assert "caf" in text


# ═══════════════════════════════════════════════════════════
# Database tests — use an in-memory / temp DB
# ═══════════════════════════════════════════════════════════

import tempfile

import database as db_module


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    """Point db module to a temporary database file for each test."""
    tmp_db_path = str(tmp_path / "test_incidents.db")
    monkeypatch.setattr(db_module, "DB_PATH", tmp_db_path)
    db_module.init_db()
    yield tmp_db_path


class TestDatabase:

    def test_init_creates_db(self, tmp_db):
        assert os.path.exists(tmp_db)

    def test_save_and_retrieve_incident(self, tmp_db):
        iid = db_module.save_incident(
            filename="test.log",
            error_count=3,
            warn_count=1,
            severity="HIGH",
            summary="Test incident",
            evidence=["line1", "line2"],
            causes=["[POSSIBLE] cause A"],
            actions=["Check logs"],
            report="Full report text",
            metadata={"test": True},
        )
        assert iid > 0

        record = db_module.get_incident_by_id(iid)
        assert record is not None
        assert record["filename"] == "test.log"
        assert record["error_count"] == 3
        assert record["severity"] == "HIGH"
        assert "line1" in record["evidence"]
        assert record["summary"] == "Test incident"

    def test_list_incidents(self, tmp_db):
        for i in range(3):
            db_module.save_incident(
                filename=f"file{i}.log", error_count=i, warn_count=0,
                severity="LOW", summary=f"Summary {i}",
                evidence=[], causes=[], actions=[], report=""
            )
        incidents = db_module.get_all_incidents()
        assert len(incidents) == 3

    def test_search_incidents(self, tmp_db):
        db_module.save_incident(
            filename="database_crash.log", error_count=5, warn_count=0,
            severity="HIGH", summary="DB went down",
            evidence=[], causes=[], actions=[], report=""
        )
        db_module.save_incident(
            filename="auth_issue.log", error_count=2, warn_count=0,
            severity="MEDIUM", summary="Auth failures",
            evidence=[], causes=[], actions=[], report=""
        )
        results = db_module.get_all_incidents(search="database")
        assert len(results) == 1
        assert results[0]["filename"] == "database_crash.log"

    def test_filter_by_severity(self, tmp_db):
        db_module.save_incident(
            filename="a.log", error_count=1, warn_count=0, severity="HIGH",
            summary="", evidence=[], causes=[], actions=[], report=""
        )
        db_module.save_incident(
            filename="b.log", error_count=0, warn_count=1, severity="LOW",
            summary="", evidence=[], causes=[], actions=[], report=""
        )
        results = db_module.get_all_incidents(severity="HIGH")
        assert len(results) == 1
        assert results[0]["severity"] == "HIGH"

    def test_get_stats(self, tmp_db):
        db_module.save_incident(
            filename="x.log", error_count=5, warn_count=2, severity="CRITICAL",
            summary="", evidence=[], causes=[], actions=[], report=""
        )
        stats = db_module.get_stats()
        assert stats["total_incidents"] >= 1
        assert stats["total_errors"] >= 5
        assert stats["critical_count"] >= 1

    def test_not_found_returns_none(self, tmp_db):
        result = db_module.get_incident_by_id(99999)
        assert result is None

    def test_save_and_retrieve_embedding(self, tmp_db):
        iid = db_module.save_incident(
            filename="emb.log", error_count=0, warn_count=0, severity="INFO",
            summary="emb test", evidence=[], causes=[], actions=[], report=""
        )
        dummy_embedding = bytes([0, 64, 0, 0] * 4)  # 4 floats
        db_module.save_embedding(iid, dummy_embedding, "test snippet")

        rows = db_module.get_all_embeddings()
        assert any(r["incident_id"] == iid for r in rows)


# ═══════════════════════════════════════════════════════════
# Flask API tests
# ═══════════════════════════════════════════════════════════

import app as flask_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Flask test client with isolated temp database."""
    tmp_db_path = str(tmp_path / "test_api.db")
    monkeypatch.setattr(db_module, "DB_PATH", tmp_db_path)
    db_module.init_db()

    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        yield c


class TestHealthEndpoint:

    def test_health_returns_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data
        assert "database" in data
        assert "ai_model" in data
        assert "search_model" in data


class TestAnalyzeEndpoint:

    def _upload(self, client, content, filename="test.log"):
        return client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(content.encode()), filename)},
            content_type="multipart/form-data",
        )

    def test_analyze_valid_log(self, client):
        resp = self._upload(
            client,
            "2024-01-01 00:00:00 ERROR [app] Database connection timed out\n"
            "2024-01-01 00:00:01 ERROR [db] Timeout waiting for connection\n",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "incident_id" in data
        assert data["error_count"] >= 1
        assert data["severity"] in ("MEDIUM", "HIGH", "CRITICAL")

    def test_analyze_no_file(self, client):
        resp = client.post("/api/analyze", content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_analyze_empty_file(self, client):
        resp = client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(b""), "empty.log")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 422

    def test_analyze_invalid_extension(self, client):
        resp = client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(b"content"), "server.csv")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 422

    def test_analyze_no_errors_log(self, client):
        resp = self._upload(
            client,
            "2024-01-01 10:00:00 INFO [app] Server started normally\n"
            "2024-01-01 10:05:00 INFO [api] GET /health 200 OK\n",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["error_count"] == 0

    def test_analyze_txt_file(self, client):
        resp = self._upload(
            client,
            "2024-01-01 00:00:00 ERROR [app] Auth failure\n",
            filename="log.txt",
        )
        assert resp.status_code == 201

    def test_analyze_returns_evidence(self, client):
        resp = self._upload(
            client,
            "2024-01-01 00:00:00 ERROR [db] Connection timeout\n",
        )
        data = resp.get_json()
        assert isinstance(data["evidence"], list)

    def test_analyze_returns_causes(self, client):
        resp = self._upload(
            client,
            "2024-01-01 00:00:00 ERROR [db] database connection timed out\n",
        )
        data = resp.get_json()
        assert isinstance(data["causes"], list)
        assert len(data["causes"]) > 0


class TestIncidentEndpoints:

    def _analyze_one(self, client, text="2024-01-01 00:00:01 ERROR [app] err\n"):
        return client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(text.encode()), "sample.log")},
            content_type="multipart/form-data",
        ).get_json()

    def test_list_incidents_empty(self, client):
        resp = client.get("/api/incidents")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["incidents"] == []

    def test_list_incidents_after_analysis(self, client):
        self._analyze_one(client)
        resp = client.get("/api/incidents")
        data = resp.get_json()
        assert len(data["incidents"]) == 1

    def test_get_incident_by_id(self, client):
        created = self._analyze_one(client)
        iid = created["incident_id"]
        resp = client.get(f"/api/incidents/{iid}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["id"] == iid

    def test_get_incident_not_found(self, client):
        resp = client.get("/api/incidents/99999")
        assert resp.status_code == 404

    def test_search_incidents(self, client):
        client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(b"2024-01-01 00:00:00 ERROR db timeout\n"), "db_crash.log")},
            content_type="multipart/form-data",
        )
        resp = client.get("/api/incidents?search=db_crash")
        data = resp.get_json()
        assert len(data["incidents"]) == 1

    def test_filter_by_severity(self, client):
        client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(b"2024-01-01 00:00:00 INFO normal\n"), "info.log")},
            content_type="multipart/form-data",
        )
        resp = client.get("/api/incidents?severity=CRITICAL")
        data = resp.get_json()
        # INFO log should not appear in CRITICAL filter
        for inc in data["incidents"]:
            assert inc["severity"] == "CRITICAL"

    def test_download_txt(self, client):
        created = self._analyze_one(client)
        iid = created["incident_id"]
        resp = client.get(f"/api/incidents/{iid}/download?format=txt")
        assert resp.status_code == 200
        assert b"INCIDENT" in resp.data or len(resp.data) > 0

    def test_download_json(self, client):
        created = self._analyze_one(client)
        iid = created["incident_id"]
        resp = client.get(f"/api/incidents/{iid}/download?format=json")
        assert resp.status_code == 200
        parsed = json.loads(resp.data)
        assert "id" in parsed

    def test_download_invalid_format(self, client):
        created = self._analyze_one(client)
        iid = created["incident_id"]
        resp = client.get(f"/api/incidents/{iid}/download?format=xml")
        assert resp.status_code == 400

    def test_incident_persisted_across_requests(self, client):
        """Ensure incidents survive multiple requests (DB persistence check)."""
        created = self._analyze_one(client)
        iid = created["incident_id"]
        # Retrieve it a second time
        resp2 = client.get(f"/api/incidents/{iid}")
        assert resp2.status_code == 200

    def test_invalid_severity_filter(self, client):
        resp = client.get("/api/incidents?severity=INVALID")
        assert resp.status_code == 400


class TestSampleLogFiles:
    """Integration tests using real sample log files."""

    @pytest.mark.parametrize("log_filename,expected_severity", [
        ("db_timeout.log",        "HIGH"),
        ("http500.log",           "HIGH"),
        ("auth_failure.log",      "HIGH"),
        ("memory_exhaustion.log", "CRITICAL"),
        ("no_errors.log",         "INFO"),
        ("malformed.log",         None),  # any severity is fine
    ])
    def test_sample_log_analyzed(self, client, log_filename, expected_severity):
        file_path = os.path.join(SAMPLE_LOGS_DIR, log_filename)
        if not os.path.exists(file_path):
            pytest.skip(f"Sample file not found: {log_filename}")

        with open(file_path, "rb") as f:
            content = f.read()

        resp = client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(content), log_filename)},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "incident_id" in data

        if expected_severity is not None:
            assert data["severity"] == expected_severity, (
                f"{log_filename}: expected {expected_severity}, got {data['severity']}"
            )


# ═══════════════════════════════════════════════════════════
# AI Engine fallback tests
# ═══════════════════════════════════════════════════════════

import ai_engine


class TestAIEngineFallback:

    def _make_result(self, **kwargs):
        """Helper to build minimal AnalysisResult-like object."""
        import log_analyzer
        res = log_analyzer.AnalysisResult()
        for k, v in kwargs.items():
            setattr(res, k, v)
        return res

    def test_fallback_report_no_errors(self):
        ar = self._make_result(
            filename="no_err.log",
            error_count=0,
            warn_count=0,
            severity="INFO",
            pattern_hits={},
            evidence_lines=[],
            exceptions=[],
            summary_text="",
        )
        report = ai_engine.generate_report(ar)
        assert "summary" in report
        assert "causes" in report
        assert "actions" in report
        assert "report" in report
        assert report["generation_method"] in ("rules", "ai+rules")

    def test_fallback_report_with_patterns(self):
        ar = self._make_result(
            filename="db.log",
            error_count=5,
            warn_count=2,
            severity="HIGH",
            pattern_hits={"db_timeout": ["line1", "line2"]},
            evidence_lines=["2024-01-01 ERROR db timed out"],
            exceptions=[],
            summary_text="db.log | Errors: 5",
        )
        report = ai_engine.generate_report(ar)
        assert len(report["causes"]) > 0
        assert "[POSSIBLE]" in report["causes"][0]

    def test_report_keys_present(self):
        ar = self._make_result(
            filename="x.log", error_count=1, warn_count=0,
            severity="MEDIUM", pattern_hits={}, evidence_lines=[],
            exceptions=[], summary_text="",
        )
        report = ai_engine.generate_report(ar)
        for key in ("summary", "evidence", "causes", "actions", "report", "generation_method"):
            assert key in report, f"Missing key: {key}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
