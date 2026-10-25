"""
log_analyzer.py — Rule-based log file parser.

Parses raw log text into structured evidence without sending untrusted
content to any AI model. The AI layer receives only the structured output.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from collections import Counter

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Regex patterns
# ──────────────────────────────────────────────────────────────────────────────

# Standard timestamp patterns (ISO 8601, Java/Python common formats)
_TS_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}",           # Apache
    r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",            # syslog
]
_TS_RE = re.compile("|".join(_TS_PATTERNS))

# Log level tokens
_LEVEL_RE = re.compile(
    r"\b(CRITICAL|FATAL|ERROR|SEVERE|WARN(?:ING)?|INFO|DEBUG|TRACE)\b",
    re.IGNORECASE,
)

# Specific error-pattern matchers
_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("db_timeout",        re.compile(r"(database|db|connection|jdbc).{0,60}(timeout|timed out|deadlock)", re.I), "Database timeout or deadlock"),
    ("conn_failure",      re.compile(r"(connection refused|unable to connect|connection reset|econnrefused)", re.I), "Connection failure"),
    ("http_500",          re.compile(r"(HTTP[/ ]\d\.\d\s+)?5\d{2}\b|internal server error|response code[: ]+5\d{2}", re.I), "HTTP 5xx server error"),
    ("auth_failure",      re.compile(r"(auth(?:entication|orization)? (fail|error|denied)|invalid (token|credentials|password)|access denied|401|403)", re.I), "Authentication/authorization failure"),
    ("memory_error",      re.compile(r"(out of memory|oom|java\.lang\.OutOfMemoryError|memory exhausted|heap space|cannot allocate memory)", re.I), "Memory exhaustion"),
    ("null_pointer",      re.compile(r"(NullPointerException|null reference|cannot read propert)", re.I), "Null reference / NullPointerException"),
    ("stack_overflow",    re.compile(r"(StackOverflowError|maximum recursion|stack overflow)", re.I), "Stack overflow"),
    ("disk_full",         re.compile(r"(no space left|disk full|ENOSPC)", re.I), "Disk space exhaustion"),
    ("service_unavail",   re.compile(r"(service unavailable|503|upstream (down|timeout))", re.I), "Service unavailable"),
    ("ssl_error",         re.compile(r"(SSL|TLS).{0,40}(error|handshake|certificate|expired|invalid)", re.I), "SSL/TLS error"),
    ("exception_general", re.compile(r"(Exception|Error|Traceback \(most recent call last\))", re.I), "Generic exception"),
]

MAX_FILE_BYTES = 16 * 1024 * 1024   # 16 MB
MAX_EVIDENCE_LINES = 50             # lines kept as evidence
MAX_ANALYSIS_LINES = 5_000          # lines analyzed (head+tail for large files)


# ──────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    filename: str = ""
    total_lines: int = 0
    error_count: int = 0
    warn_count: int = 0
    severity: str = "LOW"
    pattern_hits: dict = field(default_factory=dict)   # pattern_name -> [lines]
    error_lines: List[str] = field(default_factory=list)
    warn_lines: List[str] = field(default_factory=list)
    evidence_lines: List[str] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)
    summary_text: str = ""
    parse_error: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def analyze(log_text: str, filename: str = "upload.log") -> AnalysisResult:
    """
    Parse *log_text* and return a structured AnalysisResult.
    The input text is treated as untrusted data — it is never executed.
    """
    result = AnalysisResult(filename=filename)

    if not log_text or not log_text.strip():
        result.parse_error = "Log file is empty."
        return result

    lines = log_text.splitlines()
    result.total_lines = len(lines)

    # For very large files, analyze head + tail to stay within limits
    if len(lines) > MAX_ANALYSIS_LINES:
        head = lines[: MAX_ANALYSIS_LINES // 2]
        tail = lines[-(MAX_ANALYSIS_LINES // 2) :]
        analysis_lines = head + ["... [truncated] ..."] + tail
        logger.info("Large file (%d lines) — analyzing head+tail only", len(lines))
    else:
        analysis_lines = lines

    error_lines: List[str] = []
    warn_lines: List[str] = []
    pattern_hits: dict = {name: [] for name, _, _ in _PATTERNS}
    in_exception_block = False
    exception_buffer: List[str] = []

    for raw_line in analysis_lines:
        line = raw_line.rstrip()

        level = _detect_level(line)

        if level in ("ERROR", "CRITICAL", "FATAL", "SEVERE"):
            result.error_count += 1
            error_lines.append(line)
        elif level in ("WARN", "WARNING"):
            result.warn_count += 1
            warn_lines.append(line)

        # Pattern matching
        for name, pat, _ in _PATTERNS:
            if pat.search(line):
                if len(pattern_hits[name]) < 10:
                    pattern_hits[name].append(line)

        # Very simple exception/traceback collector
        if re.search(r"Traceback|Exception:|Error:", line):
            in_exception_block = True
            exception_buffer = [line]
        elif in_exception_block:
            if line.strip():
                exception_buffer.append(line)
                if len(exception_buffer) > 15:
                    in_exception_block = False
                    result.exceptions.append("\n".join(exception_buffer))
                    exception_buffer = []
            else:
                in_exception_block = False
                if exception_buffer:
                    result.exceptions.append("\n".join(exception_buffer))
                    exception_buffer = []

    # Flush any open exception buffer
    if exception_buffer:
        result.exceptions.append("\n".join(exception_buffer))

    # ── Collect evidence lines (errors first, then warns) ──────────────────
    evidence: List[str] = []
    for category in (error_lines, warn_lines):
        for line in category:
            if line not in evidence:
                evidence.append(line)
            if len(evidence) >= MAX_EVIDENCE_LINES:
                break
        if len(evidence) >= MAX_EVIDENCE_LINES:
            break

    result.error_lines = error_lines[:50]
    result.warn_lines = warn_lines[:50]
    result.evidence_lines = evidence
    result.pattern_hits = {k: v for k, v in pattern_hits.items() if v}

    # ── Severity classification ────────────────────────────────────────────
    result.severity = _classify_severity(result)

    # ── Human-readable summary ─────────────────────────────────────────────
    result.summary_text = _build_summary(result)

    return result


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _detect_level(line: str) -> Optional[str]:
    m = _LEVEL_RE.search(line)
    if m:
        token = m.group(1).upper()
        return "ERROR" if token in ("FATAL", "SEVERE") else token
    return None


def _classify_severity(r: AnalysisResult) -> str:
    if r.pattern_hits.get("memory_error") or r.pattern_hits.get("disk_full"):
        return "CRITICAL"
    if r.error_count >= 10 or r.pattern_hits.get("http_500") or r.pattern_hits.get("db_timeout"):
        return "HIGH"
    if r.error_count >= 1 or r.warn_count >= 5:
        return "MEDIUM"
    if r.warn_count >= 1:
        return "LOW"
    return "INFO"


def _build_summary(r: AnalysisResult) -> str:
    parts = []
    parts.append(f"File: {r.filename} ({r.total_lines} lines)")
    parts.append(f"Errors: {r.error_count}  Warnings: {r.warn_count}")
    parts.append(f"Severity: {r.severity}")

    if r.pattern_hits:
        detected = []
        label_map = {name: label for name, _, label in _PATTERNS}
        for name, lines in r.pattern_hits.items():
            detected.append(f"{label_map.get(name, name)} ({len(lines)} occurrence(s))")
        parts.append("Detected patterns: " + "; ".join(detected))
    else:
        parts.append("No specific error patterns detected.")

    return " | ".join(parts)


def validate_file(filename: str, file_bytes: bytes) -> Optional[str]:
    """
    Return an error message string if the upload is invalid, else None.
    """
    allowed_ext = {".log", ".txt"}
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in allowed_ext:
        return f"File type '{ext}' is not supported. Please upload a .log or .txt file."
    if len(file_bytes) == 0:
        return "The uploaded file is empty."
    if len(file_bytes) > MAX_FILE_BYTES:
        return f"File is too large ({len(file_bytes)//1024//1024} MB). Maximum allowed size is 16 MB."
    return None


def decode_log(file_bytes: bytes) -> Tuple[str, Optional[str]]:
    """
    Try to decode bytes as UTF-8 then Latin-1. Returns (text, error_or_None).
    """
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return file_bytes.decode(enc), None
        except UnicodeDecodeError:
            continue
    return "", "Could not decode file — ensure it is a plain-text log file."
