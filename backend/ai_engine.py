"""
ai_engine.py — FLAN-T5-small report generator with rule-based fallback.

The AI model is treated as an optional enhancement. When unavailable,
the fallback produces a structured report from rule-based analysis alone.
"""

import logging
import textwrap
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ── Model state (module-level singletons) ─────────────────────────────────────
_pipeline = None          # transformers text2text pipeline
_model_available = False
_model_error: Optional[str] = None

MODEL_NAME = "google/flan-t5-small"


def load_model() -> bool:
    """
    Attempt to load FLAN-T5-small. Returns True on success.
    Safe to call multiple times — loads only once.
    """
    global _pipeline, _model_available, _model_error

    if _model_available:
        return True
    if _model_error:
        return False  # Previous attempt failed — skip retry

    try:
        from transformers import pipeline as hf_pipeline

        logger.info("Loading %s — this may take a minute on first run...", MODEL_NAME)
        _pipeline = hf_pipeline(
            "text2text-generation",
            model=MODEL_NAME,
            max_new_tokens=400,
            do_sample=False,
        )
        _model_available = True
        logger.info("FLAN-T5-small loaded successfully.")
        return True

    except Exception as exc:
        _model_error = str(exc)
        logger.warning("Could not load AI model (%s): %s", MODEL_NAME, exc)
        return False


def model_status() -> Dict[str, Any]:
    return {
        "model": MODEL_NAME,
        "available": _model_available,
        "error": _model_error,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Prompt builder — guards against prompt injection
# ─────────────────────────────────────────────────────────────────────────────

_MAX_EVIDENCE_CHARS = 800   # cap evidence sent to model


def _build_prompt(
    filename: str,
    error_count: int,
    warn_count: int,
    severity: str,
    detected_patterns: List[str],
    evidence_lines: List[str],
) -> str:
    """Build a structured, injection-resistant prompt."""

    # Sanitize evidence to avoid prompt injection — only include lines that
    # look like real log lines (timestamp or log-level prefix).
    safe_evidence = []
    import re
    safe_re = re.compile(
        r"^\s*(?:\d{4}|[A-Z]{3,}|\w+\s+\d{2}|\d{2}[:/])", re.I
    )
    for line in evidence_lines[:30]:
        if safe_re.match(line):
            safe_evidence.append(line[:200])   # cap per-line length

    evidence_block = "\n".join(safe_evidence[:15]) if safe_evidence else "(no evidence lines captured)"
    evidence_block = evidence_block[:_MAX_EVIDENCE_CHARS]

    patterns_txt = ", ".join(detected_patterns) if detected_patterns else "none"

    prompt = textwrap.dedent(f"""
        You are an expert systems reliability engineer. Analyze the following log evidence and write a concise incident report.

        Log file: {filename}
        Severity: {severity}
        Error count: {error_count}
        Warning count: {warn_count}
        Detected patterns: {patterns_txt}

        Log evidence (do not invent new log lines):
        ---
        {evidence_block}
        ---

        Write a report with these sections:
        1. Incident Summary
        2. Possible Root Causes (label as POSSIBLE, not confirmed)
        3. Recommended Actions
        4. Additional Checks

        Keep it factual and based only on the evidence above.
    """).strip()

    return prompt


# ─────────────────────────────────────────────────────────────────────────────
# Main report generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(analysis_result) -> Dict[str, Any]:
    """
    Generate an incident report dict from an AnalysisResult.
    Uses FLAN-T5 if available, else falls back to rule-based report.
    """
    ar = analysis_result

    label_map = {
        "db_timeout":        "Database timeout/deadlock",
        "conn_failure":      "Connection failure",
        "http_500":          "HTTP 5xx server error",
        "auth_failure":      "Auth/authorization failure",
        "memory_error":      "Memory exhaustion",
        "null_pointer":      "Null pointer / NullPointerException",
        "stack_overflow":    "Stack overflow",
        "disk_full":         "Disk space exhaustion",
        "service_unavail":   "Service unavailable (503)",
        "ssl_error":         "SSL/TLS error",
        "exception_general": "Unhandled exception",
    }
    detected = [label_map.get(k, k) for k in ar.pattern_hits]

    # ── Try AI report ────────────────────────────────────────────────────────
    ai_report_text: Optional[str] = None
    used_ai = False

    if _model_available and _pipeline is not None:
        try:
            prompt = _build_prompt(
                ar.filename, ar.error_count, ar.warn_count,
                ar.severity, detected, ar.evidence_lines,
            )
            outputs = _pipeline(prompt)
            raw = outputs[0]["generated_text"].strip() if outputs else ""
            if raw and len(raw) > 80:
                ai_report_text = raw
                used_ai = True
            else:
                logger.warning("AI output too short — using fallback.")
        except Exception as exc:
            logger.warning("AI generation failed: %s", exc)

    # ── Rule-based report ────────────────────────────────────────────────────
    report_dict = _fallback_report(ar, detected, ai_report_text, used_ai)
    return report_dict


# ─────────────────────────────────────────────────────────────────────────────
# Rule-based / fallback report builder
# ─────────────────────────────────────────────────────────────────────────────

_CAUSE_MAP = {
    "db_timeout":     "A database server may be overloaded, unreachable, or misconfigured with a very short timeout.",
    "conn_failure":   "A dependent service (database, cache, API) may be down or network routing may be broken.",
    "http_500":       "The application threw an unhandled exception while processing a request.",
    "auth_failure":   "Credentials may be expired, revoked, or misconfigured. A token signing key may have changed.",
    "memory_error":   "The process ran out of heap memory. A memory leak or unexpectedly large dataset may be the cause.",
    "null_pointer":   "A code path received an unexpected null/None value. May indicate missing data or a race condition.",
    "stack_overflow": "Infinite or excessively deep recursion is occurring in the application.",
    "disk_full":      "The server disk or log partition is at capacity. New writes are failing.",
    "service_unavail":"An upstream service dependency is not responding.",
    "ssl_error":      "An SSL/TLS certificate may be expired, self-signed without trust, or incorrectly configured.",
}

_ACTION_MAP = {
    "db_timeout":     "Check database server health, connection pool settings, and query performance.",
    "conn_failure":   "Verify service is running, firewall rules, and DNS resolution for dependent hosts.",
    "http_500":       "Review the full application stack trace in logs. Check recent deployments.",
    "auth_failure":   "Rotate or refresh credentials/tokens. Review IAM permissions and token expiry settings.",
    "memory_error":   "Increase heap allocation or investigate memory-heavy operations. Profile for leaks.",
    "null_pointer":   "Add null checks to the code path indicated in the stack trace.",
    "stack_overflow": "Identify the recursive call chain and add a base case or depth limit.",
    "disk_full":      "Free disk space: rotate logs, archive old data, or expand storage.",
    "service_unavail":"Check upstream service status pages. Review load balancer health checks.",
    "ssl_error":      "Renew the certificate, verify the trust chain, and check the server clock/time sync.",
}

_DEFAULT_CHECKS = [
    "Collect metrics (CPU, RAM, disk) from the time the incident started.",
    "Review recent deployments, configuration changes, or dependency updates.",
    "Check if the issue is reproducible in a staging environment.",
    "Correlate with alerts from monitoring systems (e.g., Prometheus, Datadog).",
]


def _fallback_report(ar, detected: List[str], ai_text: Optional[str], used_ai: bool) -> Dict:
    # Incident summary
    if ar.parse_error:
        summary = f"The log file could not be parsed: {ar.parse_error}"
    elif ar.error_count == 0 and ar.warn_count == 0:
        summary = (
            f"No errors or warnings were found in '{ar.filename}'. "
            "The system appears to have been operating normally during the logged period."
        )
    else:
        pattern_str = ", ".join(detected) if detected else "general errors"
        summary = (
            f"The log file '{ar.filename}' contains {ar.error_count} error(s) "
            f"and {ar.warn_count} warning(s) at severity level {ar.severity}. "
            f"Detected issues: {pattern_str}."
        )

    # Possible causes (rule-based, clearly labeled POSSIBLE)
    label_to_key = {v: k for k, v in {
        "Database timeout/deadlock": "db_timeout",
        "Connection failure": "conn_failure",
        "HTTP 5xx server error": "http_500",
        "Auth/authorization failure": "auth_failure",
        "Memory exhaustion": "memory_error",
        "Null pointer / NullPointerException": "null_pointer",
        "Stack overflow": "stack_overflow",
        "Disk space exhaustion": "disk_full",
        "Service unavailable (503)": "service_unavail",
        "SSL/TLS error": "ssl_error",
    }.items()}

    causes: List[str] = []
    actions: List[str] = []
    for label in detected:
        key = label_to_key.get(label)
        if key:
            cause = _CAUSE_MAP.get(key)
            action = _ACTION_MAP.get(key)
            if cause:
                causes.append(f"[POSSIBLE] {cause}")
            if action:
                actions.append(action)

    if not causes:
        if ar.error_count > 0:
            causes = ["[POSSIBLE] Application-level errors were detected; review stack traces for specific cause."]
        else:
            causes = ["No specific root cause identified from the available log evidence."]

    if not actions:
        actions = ["Review the full log file for additional context.", "Check recent deployment or configuration changes."]

    # Additional checks
    checks = list(_DEFAULT_CHECKS)

    # Evidence
    evidence = ar.evidence_lines[:20] if ar.evidence_lines else []

    # Full report text (AI or rule-based)
    if used_ai and ai_text:
        full_report = (
            "=== AI-GENERATED ANALYSIS (google/flan-t5-small) ===\n"
            "[Note: AI suggestions are based on extracted evidence, not confirmed facts.]\n\n"
            + ai_text
            + "\n\n=== RULE-BASED ANALYSIS ===\n"
            + _format_text_report(summary, evidence, causes, actions, checks)
        )
        generation_method = "ai+rules"
    else:
        full_report = (
            "=== RULE-BASED ANALYSIS ===\n"
            "[AI model unavailable — report generated from deterministic log parsing.]\n\n"
            + _format_text_report(summary, evidence, causes, actions, checks)
        )
        generation_method = "rules"

    return {
        "summary": summary,
        "evidence": evidence,
        "causes": causes,
        "actions": actions,
        "additional_checks": checks,
        "report": full_report,
        "generation_method": generation_method,
        "model_used": MODEL_NAME if used_ai else None,
    }


def _format_text_report(summary, evidence, causes, actions, checks) -> str:
    lines = [
        "INCIDENT SUMMARY",
        "─" * 60,
        summary,
        "",
        "OBSERVED EVIDENCE",
        "─" * 60,
    ]
    if evidence:
        for line in evidence[:10]:
            lines.append(f"  {line}")
    else:
        lines.append("  (no specific log lines captured as evidence)")

    lines += [
        "",
        "POSSIBLE ROOT CAUSES",
        "─" * 60,
    ]
    for c in causes:
        lines.append(f"  • {c}")

    lines += [
        "",
        "RECOMMENDED ACTIONS",
        "─" * 60,
    ]
    for a in actions:
        lines.append(f"  1. {a}")

    lines += [
        "",
        "ADDITIONAL CHECKS",
        "─" * 60,
    ]
    for ch in checks:
        lines.append(f"  • {ch}")

    return "\n".join(lines)
