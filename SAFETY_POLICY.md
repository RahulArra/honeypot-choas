🔐 Adaptive Defense System – Safety Policy (v1.0)
1️⃣ Development Safety

SSH server binds to 127.0.0.1 during local development

No router port forwarding

No public exposure during development

No real OS command execution

No subprocess usage in shell logic

2️⃣ Chaos Safety

Never run stress tests on host machine

All chaos experiments must run inside Docker container

Docker container must enforce:

CPU limit

Memory limit

Only one chaos experiment runs at a time

3️⃣ Input Safety

Maximum command length: 512 characters

Input normalized before processing

Special characters sanitized

Empty input safely ignored

Rapid spam handled with session timeout

4️⃣ Session Safety

Session timeout: 5 minutes inactivity

Hard session cap: 20 minutes

Max concurrent sessions: 3 (for t2.micro)

5️⃣ AI Safety

AI never executes commands

AI never modifies filesystem

AI failure must not crash system

Retry once, then fallback safely

6️⃣ Database Safety

Log all commands

Threat classification deterministic first

Adaptive escalation only after ≥5 occurrences

SQLite schema locked before implementation

7️⃣ Deployment Safety (EC2)

Security group restricts IPs (you + teammate)

Outbound traffic blocked

No public dashboard access

Chaos isolated via Docker