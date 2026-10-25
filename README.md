# AI Incident Investigator

An AI-powered tool that helps developers investigate software incidents by analyzing server log files, identifying errors, finding possible causes, and recommending troubleshooting steps.

---

## Overview

Upload a `.log` or `.txt` file → the app parses errors, generates a structured incident report (optionally with FLAN-T5-small), and finds similar past incidents using MiniLM sentence embeddings — all stored in SQLite, served by Flask.

### Key Features

- **Rule-based log parsing** — timestamps, ERROR/WARN/CRITICAL levels, DB timeouts, HTTP 500s, auth failures, OOM errors, and more
- **AI-generated reports** — `google/flan-t5-small` (optional, runs locally)
- **Semantic similarity search** — `sentence-transformers/all-MiniLM-L6-v2` (optional, runs locally)
- **SQLite storage** — no separate database server required
- **Reliable fallback** — if AI models are unavailable, rule-based analysis still works fully
- **Dark developer dashboard** — vanilla HTML/CSS/JS, no frontend frameworks

---

## Prerequisites

| Requirement | Minimum version |
|---|---|
| Python | 3.9+ |
| pip | 22+ |
| RAM | 4 GB (8 GB recommended for AI models) |
| Disk | 2 GB free (for AI model weights) |

> **Windows users:** Use PowerShell or Command Prompt. No admin rights required (models download to your user profile cache).

---

## Setup

### 1. Create a virtual environment

```powershell
cd "d:\MYOWNPROJECTS\Incident investigator\backend"
python -m venv venv
.\venv\Scripts\activate
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

> **First-time model download:** On the first analysis request, the app automatically downloads:
> - `google/flan-t5-small` (~300 MB) → `%USERPROFILE%\.cache\huggingface\hub\`
> - `sentence-transformers/all-MiniLM-L6-v2` (~90 MB) → same cache directory
>
> Downloads happen in the background. The app is usable immediately with rule-based analysis.

### 3. PyTorch (Windows CPU)

The `requirements.txt` installs the default PyTorch. If you want to be explicit about CPU-only (smaller download):

```powershell
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

---

## SQLite Database

- **Location:** `backend/incidents.db`
- **Auto-created** on first startup — no setup required
- Stores incident reports, evidence, causes, actions, embeddings
- Persists across restarts

### Schema summary

| Table | Purpose |
|---|---|
| `incidents` | All incident records (summary, evidence, causes, actions, report) |
| `incident_embeddings` | MiniLM embeddings for similarity search |

---

## Running the Application

```powershell
cd "d:\MYOWNPROJECTS\Incident investigator\backend"
.\venv\Scripts\activate
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

The AI models load in the background. You can start uploading immediately — the sidebar status indicator shows when models are ready.

---

## Using the Application

### Dashboard
- View total incidents, errors, warnings, and critical incidents
- Click any recent incident to open its full report

### Analyze Log
1. Click **Analyze Log** in the sidebar or click **+ Analyze Log** in the header
2. Drag and drop a `.log` or `.txt` file, or click to browse
3. Click **Analyze Log**
4. Review the incident report (evidence, causes, recommended actions, similar incidents)
5. Download the report as `.txt` or `.json`

### Incident History
- Search and filter all past incidents
- Click **View** to open any saved report

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload and analyze a log file |
| `GET` | `/api/incidents` | List incidents (`?limit=50&offset=0&search=…&severity=HIGH`) |
| `GET` | `/api/incidents/<id>` | Get full incident report (`?similar=true` for similar incidents) |
| `GET` | `/api/incidents/<id>/download` | Download report (`?format=txt\|json`) |
| `GET` | `/api/health` | Backend, DB, and model status |

---

## Running Tests

```powershell
cd "d:\MYOWNPROJECTS\Incident investigator\backend"
.\venv\Scripts\activate
python -m pytest ../tests/test_app.py -v
```

Test coverage:
- Log parsing (counts, severity, pattern detection)
- File validation (extension, size, encoding)
- Database CRUD operations
- All REST API endpoints
- Sample log files (6 scenarios)
- AI engine fallback behavior

---

## Sample Log Files

Located in `sample_logs/`:

| File | Scenario |
|---|---|
| `db_timeout.log` | Database connection pool exhausted |
| `http500.log` | HTTP 500 cascading failures |
| `auth_failure.log` | JWT key rotation causing auth failures |
| `memory_exhaustion.log` | Java OOM during batch processing |
| `no_errors.log` | Normal operation — no errors |
| `malformed.log` | Mixed/garbled content for parser resilience |

---

## Project Structure

```
Incident investigator/
├── frontend/
│   ├── index.html          # Single-page app
│   ├── style.css           # Dark developer theme
│   └── script.js           # Vanilla JS, no frameworks
├── backend/
│   ├── app.py              # Flask REST API
│   ├── log_analyzer.py     # Rule-based log parser
│   ├── ai_engine.py        # FLAN-T5 report generator + fallback
│   ├── incident_search.py  # MiniLM similarity search
│   ├── database.py         # SQLite schema and queries
│   ├── requirements.txt
│   └── incidents.db        # Auto-created at runtime
├── sample_logs/            # 6 test scenarios
├── tests/
│   └── test_app.py         # pytest suite
└── README.md
```

---

## Known Limitations

- **FLAN-T5-small** produces short outputs and may occasionally generate generic text. The rule-based analysis always runs alongside it.
- **Model first-run download** requires internet access (~390 MB total). After that, models run fully offline from the local cache.
- **Large log files** over 5,000 lines are analyzed using head + tail sampling to stay within memory limits.
- **Similarity search** requires at least 2 incidents in the database to return meaningful results.
- **AI model loading** takes 20–60 seconds on first startup depending on CPU speed.
- **No authentication** — this is a local developer tool, not intended for public deployment.

---

## Deployment

This application is designed for local developer use. For team deployment:

1. Replace `app.run(host="127.0.0.1")` with `app.run(host="0.0.0.0")` — or use gunicorn:
   ```powershell
   pip install gunicorn
   gunicorn -w 2 -b 0.0.0.0:5000 app:app
   ```
2. Add authentication (e.g., HTTP Basic Auth via a reverse proxy like nginx)
3. Use a persistent volume for `incidents.db`
4. Set `MAX_CONTENT_LENGTH` in environment for different file size limits

> **Warning:** Do not expose this tool publicly without authentication. It accepts file uploads.

---

## Security Notes

- Uploaded log files are **never executed** — treated as untrusted text only
- SQL queries use **parameterized statements** — no SQL injection
- Filenames are **sanitized** (directory components stripped)
- Model prompts include **only extracted, sanitized evidence** — not raw log text
- No API keys, passwords, or secrets are stored
- Internal server errors are logged but **not exposed** to the client
