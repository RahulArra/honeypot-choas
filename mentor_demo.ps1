Param(
    [switch]$Quick
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== Honeypot Chaos: Mentor Demo Script ===" -ForegroundColor Cyan
Write-Host "Repo: $(Get-Location)"
Write-Host ""

function Show-Step($title) {
    Write-Host ""
    Write-Host ("--- " + $title + " ---") -ForegroundColor Yellow
}

function Test-Cmd($name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    return $null -ne $cmd
}

Show-Step "1) Environment Readiness"
$tools = @("python", "docker", "node", "npm", "git", "ssh")
foreach ($t in $tools) {
    if (Test-Cmd $t) {
        Write-Host "[OK]   $t found" -ForegroundColor Green
    } else {
        Write-Host "[WARN] $t not found in PATH" -ForegroundColor Red
    }
}

if (Test-Cmd "docker") {
    try {
        $dockerOk = docker info 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK]   Docker daemon is running" -ForegroundColor Green
        } else {
            Write-Host "[WARN] Docker daemon is not reachable" -ForegroundColor Red
        }
    } catch {
        Write-Host "[WARN] Docker check failed: $_" -ForegroundColor Red
    }

    try {
        docker image inspect chaos-executor >$null 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK]   chaos-executor image exists" -ForegroundColor Green
        } else {
            Write-Host "[WARN] chaos-executor image missing. Build with:" -ForegroundColor Red
            Write-Host "       docker build -f Dockerfile.chaos -t chaos-executor ."
        }
    } catch {
        Write-Host "[WARN] Could not inspect chaos-executor image" -ForegroundColor Red
    }
}

Show-Step "2) Core Project Test/Validation Files"
$testFiles = @(
    "core\check_db.py",
    "core\check_intell.py",
    "core\integration_test.py",
    "core\escalation_test.py",
    "core\verify_threats.py",
    "core\test_rule_engine.py",
    "test_ai_fallback.py",
    "mentor_demo.ps1"
)

foreach ($f in $testFiles) {
    if (Test-Path $f) {
        Write-Host "[OK]   $f" -ForegroundColor Green
    } else {
        Write-Host "[MISS] $f" -ForegroundColor Red
    }
}

Show-Step "3) DB Analytics Snapshot (Counts + Adaptive Evidence)"
$dbPy = @'
import sqlite3
from pathlib import Path

db_candidates = [Path("database/honeypot.db"), Path("core/database/honeypot.db")]
db_path = None
for p in db_candidates:
    if p.exists():
        db_path = p
        break

if db_path is None:
    print("[WARN] No DB file found at database/honeypot.db or core/database/honeypot.db")
    raise SystemExit(0)

print(f"[OK] DB: {db_path}")
conn = sqlite3.connect(str(db_path))
cur = conn.cursor()

def one(q):
    cur.execute(q)
    r = cur.fetchone()
    return r[0] if r else 0

print("")
print("Total Sessions      :", one("SELECT COUNT(*) FROM sessions"))
print("Total Commands      :", one("SELECT COUNT(*) FROM commands"))
print("Total Threats       :", one("SELECT COUNT(*) FROM threats"))
print("Total Chaos Runs    :", one("SELECT COUNT(*) FROM chaos_results"))
print("Vulnerable Runs     :", one("SELECT COUNT(*) FROM chaos_results WHERE result='Vulnerable'"))

print("")
print("Threat Distribution:")
cur.execute("""
SELECT threat_type, COUNT(*) as c
FROM threats
GROUP BY threat_type
ORDER BY c DESC
""")
rows = cur.fetchall()
if not rows:
    print("  (no threats yet)")
for t, c in rows:
    print(f"  - {t}: {c}")

print("")
print("Adaptive Increment Evidence (per threat):")
cur.execute("""
SELECT
  t.threat_type,
  MIN(cr.intensity_level) as min_lv,
  MAX(cr.intensity_level) as max_lv,
  COUNT(*) as runs,
  ROUND(AVG(CASE WHEN cr.result='Vulnerable' THEN 1.0 ELSE 0.0 END), 2) as fail_rate
FROM chaos_results cr
JOIN threats t ON t.threat_id = cr.threat_id
GROUP BY t.threat_type
ORDER BY runs DESC
""")
rows = cur.fetchall()
if not rows:
    print("  (no chaos runs yet)")
for threat, min_lv, max_lv, runs, fail_rate in rows:
    print(f"  - {threat}: Lv {min_lv} -> Lv {max_lv}, runs={runs}, fail_rate={fail_rate}")

print("")
print("Recent Chaos Runs (latest 10):")
cur.execute("""
SELECT experiment_id, threat_id, experiment_type, intensity_level, result, recovery_time_secs, started_at
FROM chaos_results
ORDER BY experiment_id DESC
LIMIT 10
""")
rows = cur.fetchall()
if not rows:
    print("  (no chaos runs yet)")
for r in rows:
    print(f"  - #{r[0]} threat#{r[1]} {r[2]} Lv{r[3]} -> {r[4]} ({r[5]}s) @ {r[6]}")

conn.close()
'@

if (Test-Cmd "python") {
    $dbPy | python -
} else {
    Write-Host "[WARN] Python unavailable; skipping DB snapshot." -ForegroundColor Red
}

if (-not $Quick) {
    Show-Step "4) Quick Built-in Validation Scripts"
    $scripts = @(
        "core\check_db.py",
        "core\check_intell.py",
        "core\verify_threats.py",
        "core\escalation_test.py"
    )
    foreach ($s in $scripts) {
        if (Test-Path $s -and (Test-Cmd "python")) {
            Write-Host ""
            Write-Host "Running: python $s" -ForegroundColor DarkCyan
            try {
                python $s
            } catch {
                Write-Host "[WARN] Failed: $s" -ForegroundColor Red
            }
        }
    }
}

Show-Step "5) Live Demo Command Pack (Different Threat Styles)"
$demoCommands = @(
    "# Reconnaissance",
    "nmap -sS -T4 192.168.1.0/24 2>/dev/null",
    "netstat -an",
    "",
    "# CPU Exhaustion",
    "while true; do openssl speed rsa2048 2>/dev/null | base64 > /dev/null; done &",
    ":(){ :|:& };:",
    "",
    "# Integrity / Disk I/O",
    "dd if=/dev/zero of=/tmp/test bs=1M count=5000 2>/dev/null",
    "fallocate -l 2G /tmp/bigfile",
    "shred -vfz /tmp/testfile",
    "",
    "# Privilege Escalation / Process Disruption",
    "find / -perm -4000 -type f 2>/dev/null",
    "pkill -f sshd",
    "",
    "# Data Exfiltration",
    "openssl enc -aes-256-cbc -in /tmp/testfile -out /tmp/testfile.enc -k \"password\"",
    "tar -czf /tmp/archive.tar.gz /etc 2>/dev/null",
    "",
    "# Persistence Attempt",
    "echo '* * * * * /tmp/.x' >> /etc/crontab",
    "",
    "# Lateral Movement style",
    "ssh user@192.168.1.10",
    "scp /tmp/testfile user@192.168.1.10:/tmp/",
    "",
    "# Benign commands (control group)",
    "ls",
    "pwd",
    "whoami"
)

$cmdFile = "mentor_demo_commands.txt"
$demoCommands | Set-Content -Path $cmdFile -Encoding UTF8
Write-Host "Saved demo commands to: $cmdFile" -ForegroundColor Green
Write-Host ""
Write-Host "Paste/run these manually in honeypot SSH session:" -ForegroundColor Cyan
foreach ($c in $demoCommands) {
    if ($c.StartsWith("#")) {
        Write-Host $c -ForegroundColor Yellow
    } elseif ($c -eq "") {
        Write-Host ""
    } else {
        Write-Host ("  " + $c)
    }
}

Show-Step "6) Demo Flow for Mentor"
Write-Host "1. Start backend:   python -m core.main"
Write-Host "2. Start dashboard: cd dashboard ; npm run dev"
Write-Host "3. Connect honeypot: ssh root@127.0.0.1 -p 2222"
Write-Host "4. Run commands from mentor_demo_commands.txt"
Write-Host "5. Show dashboard tabs: Threat Feed, Activity, Chaos & Risk, Overview"
Write-Host "6. Re-run this script to show increments/adaptive changes in DB"

Write-Host ""
Write-Host "=== Mentor demo prep complete ===" -ForegroundColor Cyan
