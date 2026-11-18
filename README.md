# CodeSentinel AI — Architecture-Agnostic Codebase Auditor

A lightweight codebase audit agent. It scans public GitHub repositories or ZIP archives for security-risk patterns, code-quality smells and unfinished implementation markers. Findings are severity-sorted and include file locations and suggested remediation.

## Features
- GitHub URL scanning and ZIP upload.
- Language discovery across common Python, JS/TS, Java, Go, PHP, Ruby, C/C++ and config files.
- Security heuristics for exposed credentials, eval/exec, disabled TLS verification, unsafe pickle deserialization and wildcard CORS.
- Python AST checks for pass-only functions and bare except clauses.
- Completeness checks for TODO/FIXME/HACK markers, placeholder returns, missing README and .gitignore.
- Optional Semgrep integration when installed.
- Read-only scanning and exportable JSON report.

## Run locally (Python 3.10+; Git needed for GitHub URL scans)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000.

## Optional Gemini AI review
1. Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/apikey).
2. Copy `.env.example` to `.env` and add your key:
   ```env
   GEMINI_API_KEY=your_key_here
   GEMINI_MODEL=gemini-3.8-flash
   ```
3. Install dependencies with `python -m pip install -r requirements.txt` and restart the server.
4. Run a repository scan, then click **Generate AI insights**. Only the scan report (not source files) is sent to Gemini.

Without a key, static scanning continues to work; the AI review endpoint remains unavailable. Never commit `.env` or expose the key in frontend code.

## Docker
```bash
docker build -t codesentinel-ai .
docker run --rm -p 8000:8000 codesentinel-ai
```

## API
- `GET /api/health`
- `POST /api/ai/analyze` JSON scan report for optional Gemini review
- `POST /api/scan/github` JSON: `{"github_url":"https://github.com/owner/repo"}`
- `POST /api/scan/upload` multipart field `file` containing a ZIP.

## Limitations
Hackathon MVP, not a formal security audit or replacement for SAST, dependency auditing or penetration testing. Heuristic findings can be false positives or miss context-dependent vulnerabilities; verify results. Supported text files only, maximum 500 KB per file and 1,500 files. ZIP limit 20 MB, extracted size limit 50 MB. Public repositories only. Repository code is never executed.
