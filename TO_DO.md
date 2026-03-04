
# WEEK 1
Create-Issue "Setup SQLite Database Schema" "Milestone: Week 1

- Create sessions table
- Create commands table
- Create threats table
- Create chaos_results table
- Create adaptive_scores table
- Test DB connection" "Seshmanuvarthi"

Create-Issue "Implement SSH Server on Port 2222" "Milestone: Week 1

- Setup Python SSH server
- Bind to port 2222
- Accept any password
- Display prompt" "RahulArra"

Create-Issue "Implement Session Manager" "Milestone: Week 1

- Generate session_id
- Track start_time
- Track end_time
- Insert session into DB" "RahulArra"

Create-Issue "Implement Virtual Filesystem Loader" "Milestone: Week 1

- Create base filesystem JSON
- Deep copy per session
- Track current working directory" "RahulArra"

Create-Issue "Implement Database Connection Module" "Milestone: Week 1

- Create DB connection helper
- Implement insert methods
- Test select queries" "Seshmanuvarthi"

# WEEK 2
Create-Issue "Implement Command Parser" "Milestone: Week 2

- Normalize input
- Extract command token
- Handle empty input
- Limit command length" "RahulArra"

Create-Issue "Implement Rule-Based Commands (ls, cd, pwd, etc.)" "Milestone: Week 2

- ls
- cd
- pwd
- mkdir
- touch
- rm
- cat
- whoami
- uname" "RahulArra"

Create-Issue "Implement Unknown Command Handling" "Milestone: Week 2

- Return bash-style error
- Log command
- Do NOT trigger AI" "RahulArra"

Create-Issue "Implement Threat Keyword Mapping" "Milestone: Week 2

- Define dangerous keywords
- Map keyword to threat_type
- Insert threat into DB" "RahulArra"

Create-Issue "Integrate AI Fallback for Unknown Commands" "Milestone: Week 2

- Connect AI API
- Retry once on failure
- Validate JSON response" "Seshmanuvarthi"

Create-Issue "Log All Commands to Database" "Milestone: Week 2

- Store command text
- Store session_id
- Store timestamp
- Store source (rule/AI)" "RahulArra"

# WEEK 3
Create-Issue "Implement Chaos Watcher Background Process" "Milestone: Week 3

- Poll DB for unprocessed threats
- Prevent blocking SSH
- Mark threat processed" "Seshmanuvarthi"

Create-Issue "Implement CPU Stress Simulation" "Milestone: Week 3

- Controlled CPU load
- Timeout limit
- Record CPU peak" "Seshmanuvarthi"

Create-Issue "Implement Memory Stress Simulation" "Milestone: Week 3

- Allocate memory safely
- Record usage
- Release memory" "Seshmanuvarthi"

Create-Issue "Implement Disk I/O Simulation" "Milestone: Week 3

- Simulate disk writes
- Measure duration
- Clean up files" "Seshmanuvarthi"

Create-Issue "Implement Occurrence Counter" "Milestone: Week 3

- Count repeated threats
- Update adaptive_scores table" "RahulArra"

Create-Issue "Implement Severity Escalation Logic" "Milestone: Week 3

- Escalate after 5 occurrences
- Update severity
- Log change" "RahulArra"

Create-Issue "Implement Chaos Intensity Escalation" "Milestone: Week 3

- Increase stress duration
- Increase load level
- Update adaptive table" "RahulArra"

# WEEK 4
Create-Issue "Create REST API Base Setup" "Milestone: Week 4

- Setup Flask/FastAPI
- Connect to SQLite
- Test base route" "Seshmanuvarthi"

Create-Issue "Implement Overview API Endpoint" "Milestone: Week 4

- Total sessions
- Total threats
- Highest severity
- Chaos executed count" "Seshmanuvarthi"

Create-Issue "Implement Sessions API Endpoint" "Milestone: Week 4

- Fetch session list
- Fetch command history
- Return structured JSON" "Seshmanuvarthi"

Create-Issue "Build React Dashboard Layout" "Milestone: Week 4

- Create pages
- Add navigation
- Apply dark theme" "Seshmanuvarthi"

Create-Issue "Build Executive Overview Panel" "Milestone: Week 4

- Metric cards
- Charts" "Seshmanuvarthi"

Create-Issue "Build Adaptive Learning Panel" "Milestone: Week 4

- Show severity evolution
- Show chaos intensity levels" "Seshmanuvarthi"

Create-Issue "Implement Edge Case Handling" "Milestone: Week 4

- Typos
- Long input
- Empty input
- Special characters" "RahulArra"

Create-Issue "Full System Integration Test" "Milestone: Week 4

- SSH test
- Threat logging test
- Chaos trigger test
- Adaptive escalation test
- Dashboard validation" "RahulArra"