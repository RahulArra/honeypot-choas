# Honeypot Chaos Engine

Adaptive SSH honeypot with threat detection, chaos experiments, learning-based retest logic, and a React dashboard.

## What This Project Includes

- SSH honeypot on `127.0.0.1:2222`
- Rule + AI threat classification
- Threat to experiment mapping (`cpu_stress`, `memory_stress`, `disk_io`, `process_disruption`)
- Chaos execution inside Docker container (`chaos-executor`)
- Metrics + adaptive learning stored in SQLite
- FastAPI backend (`http://127.0.0.1:8000`)
- React dashboard (Vite)

## Prerequisites

Install these on the target system first:

- Python 3.10+ (recommended 3.10/3.11)
- Git
- Docker Desktop (or Docker Engine) with daemon running
- Node.js 18+ and npm (for dashboard)
- OpenSSH client (usually preinstalled)

## 1. Clone

```bash
git clone <your-repo-url>
cd honeypot-choas
```

## 2. Python Environment

Windows (PowerShell):

```powershell
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Environment Variables (`.env`)

Create a `.env` file in project root:

```env
# Optional but recommended for AI fallback
GROK_API_KEY=your_groq_api_key

# Optional API override
API_HOST=127.0.0.1
API_PORT=8000
```

If `GROK_API_KEY` is missing, the project still runs (AI fallback becomes disabled).

## 4. Build Chaos Docker Image

Build once:

```bash
docker build -f Dockerfile.chaos -t chaos-executor .
```

Verify:

```bash
docker images
```

You should see `chaos-executor`.

## 5. Start Backend + SSH Honeypot

From project root:

```bash
python -m core.main
```

This starts:

- DB initialization/migrations
- chaos watcher
- FastAPI backend on `http://127.0.0.1:8000`
- SSH honeypot on `127.0.0.1:2222`

## 6. Start Dashboard

In a new terminal:

```bash
cd dashboard
npm install
npm run dev
```

Open the URL shown by Vite (usually `http://localhost:5173`).

## 7. Connect to Honeypot

In another terminal:

```bash
ssh root@127.0.0.1 -p 2222
```

Try commands like:

- `nmap -sS -T4 192.168.1.0/24 2>/dev/null`
- `dd if=/dev/zero of=/tmp/fill bs=1M count=5000`
- `while true; do openssl speed rsa2048 > /dev/null; done &`

## 8. Database Location

SQLite file:

- `database/honeypot.db`

Useful tables:

- `sessions`
- `commands`
- `threats`
- `chaos_results`
- `adaptive_scores`
- `global_threat_stats`

## 9. Quick Troubleshooting

- Docker metrics show fallback/0:
  - Ensure Docker Desktop is running.
  - Ensure `chaos-executor` image exists.
- Dashboard says API not reachable:
  - Confirm `python -m core.main` is running.
  - Check `http://127.0.0.1:8000/api/overview`.
- SSH disconnect/session timeout:
  - Default timeout is `300s` in `core/config.py`.

## 10. Project Structure

```text
honeypot-choas/
  core/
    api/
    chaos/
    database/
    intelligence/
    ssh/
    main.py
  dashboard/
    src/
    package.json
  database/
    schema.sql
    honeypot.db
  Dockerfile.chaos
  requirements.txt
  README.md
```

## 11. Git Ignore Recommendations

Keep these out of Git:

- `venv/`
- `database/honeypot.db`
- `dashboard/node_modules/`
- `.env`
- `__pycache__/`

