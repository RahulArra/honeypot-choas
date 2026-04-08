import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, Server, Shield, Terminal, Zap } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [overview, setOverview] = useState({ total_sessions: 0, total_threats: 0, vulnerable_runs: 0 });
  const [sessions, setSessions] = useState([]);
  const [threats, setThreats] = useState([]);
  const [chaosData, setChaosData] = useState([]);
  const [vulnerabilityMetrics, setVulnerabilityMetrics] = useState([]);
  const [apiError, setApiError] = useState('');

  const fetchData = async () => {
    try {
      const [overviewRes, sessionsRes, threatsRes, chaosRes, vulnRes] = await Promise.all([
        fetch(`${API_BASE}/overview`),
        fetch(`${API_BASE}/sessions`),
        fetch(`${API_BASE}/threats`),
        fetch(`${API_BASE}/chaos_analytics`),
        fetch(`${API_BASE}/vulnerability_metrics`),
      ]);

      if (!overviewRes.ok || !sessionsRes.ok || !threatsRes.ok || !chaosRes.ok || !vulnRes.ok) {
        throw new Error('API returned non-200 response');
      }

      const [overviewData, sessionsData, threatsData, chaosDataResponse, vulnData] = await Promise.all([
        overviewRes.json(),
        sessionsRes.json(),
        threatsRes.json(),
        chaosRes.json(),
        vulnRes.json(),
      ]);

      setOverview(overviewData);
      setSessions(sessionsData);
      setThreats(threatsData);
      setChaosData(chaosDataResponse);
      setVulnerabilityMetrics(vulnData);
      setApiError('');
    } catch (e) {
      setApiError(`Cannot connect to API at ${API_BASE}. Start backend and refresh.`);
      console.error('API Error', e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const sourceBreakdown = threats.reduce(
    (acc, t) => {
      const key = t.source === 'ai' ? 'ai' : 'rule';
      acc[key] += 1;
      return acc;
    },
    { ai: 0, rule: 0 }
  );

  const topThreatClasses = Object.entries(
    threats.reduce((acc, t) => {
      acc[t.threat_type] = (acc[t.threat_type] || 0) + 1;
      return acc;
    }, {})
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  return (
    <div className="dashboard-container">
      <div className="panel" style={{ borderRadius: 0, borderTop: 0, borderBottom: 0, borderLeft: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 32 }}>
          <Shield color="var(--accent-cyan)" size={30} />
          <h2 style={{ fontSize: '1.1rem', letterSpacing: '1px' }}>
            CHAOS<span style={{ color: 'var(--accent-purple)' }}>ENGINE</span>
          </h2>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <button className={`nav-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
            <Activity size={18} /> Overview
          </button>
          <button className={`nav-btn ${activeTab === 'sessions' ? 'active' : ''}`} onClick={() => setActiveTab('sessions')}>
            <Server size={18} /> Sessions
          </button>
          <button className={`nav-btn ${activeTab === 'threats' ? 'active' : ''}`} onClick={() => setActiveTab('threats')}>
            <Terminal size={18} /> Threat Feed
          </button>
          <button className={`nav-btn ${activeTab === 'chaos' ? 'active' : ''}`} onClick={() => setActiveTab('chaos')}>
            <Zap size={18} /> Chaos & Risk
          </button>
        </nav>
      </div>

      <div style={{ padding: 32, overflowY: 'auto' }}>
        {apiError && (
          <div className="panel" style={{ marginBottom: 20, borderColor: 'var(--danger)' }}>
            <span style={{ color: 'var(--danger)', fontWeight: 600 }}>{apiError}</span>
          </div>
        )}

        {activeTab === 'overview' && (
          <div>
            <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>System Overview</h1>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20, marginBottom: 20 }}>
              <div className="panel">
                <div style={{ color: 'var(--text-secondary)' }}>Sessions</div>
                <div className="stat-value">{overview.total_sessions}</div>
              </div>
              <div className="panel">
                <div style={{ color: 'var(--text-secondary)' }}>Threats</div>
                <div className="stat-value">{overview.total_threats}</div>
              </div>
              <div className="panel">
                <div style={{ color: 'var(--text-secondary)' }}>Vulnerable Runs</div>
                <div className="stat-value">{overview.vulnerable_runs}</div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
              <div className="panel">
                <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Detection Source Mix</h3>
                <p>Rule Engine: <strong>{sourceBreakdown.rule}</strong></p>
                <p>AI Model: <strong>{sourceBreakdown.ai}</strong></p>
              </div>
              <div className="panel">
                <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Top Threat Classes</h3>
                {topThreatClasses.map(([name, count]) => (
                  <p key={name}>{name.replaceAll('_', ' ')}: <strong>{count}</strong></p>
                ))}
                {topThreatClasses.length === 0 && <p>No threats yet.</p>}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'sessions' && (
          <div>
            <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>Session Activity</h1>
            <div className="panel">
              <table>
                <thead>
                  <tr>
                    <th>Session ID</th>
                    <th>Source IP</th>
                    <th>Start Time</th>
                    <th>Commands</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr key={s.session_id}>
                      <td className="code-font">{s.session_id}</td>
                      <td>{s.source_ip}</td>
                      <td>{s.start_time}</td>
                      <td>{s.total_commands}</td>
                      <td><span className={`badge ${s.status === 'active' ? 'medium' : 'low'}`}>{s.status}</span></td>
                    </tr>
                  ))}
                  {sessions.length === 0 && <tr><td colSpan="5" style={{ textAlign: 'center' }}>No sessions recorded yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div>
            <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>Live Threat Feed</h1>
            <div className="panel">
              <table>
                <thead>
                  <tr>
                    <th>Class</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Mapped Test</th>
                    <th>Raw Command</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map((t) => (
                    <tr key={t.threat_id}>
                      <td style={{ fontWeight: 600 }}>{t.threat_type.replaceAll('_', ' ')}</td>
                      <td><span className={`badge ${String(t.severity || '').toLowerCase()}`}>{t.severity}</span></td>
                      <td>{Number(t.confidence || 0).toFixed(2)}</td>
                      <td className="code-font">{t.mapped_experiment_type || t.experiment_type}</td>
                      <td className="code-font">{`> ${t.raw_input}`}</td>
                      <td>{t.source === 'ai' ? 'AI Model' : 'Rule Engine'}</td>
                    </tr>
                  ))}
                  {threats.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center' }}>Listening on port 2222...</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'chaos' && (
          <div>
            <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>Chaos & Risk</h1>
            <div className="panel">
              <table>
                <thead>
                  <tr>
                    <th>Experiment ID</th>
                    <th>Threat Ref</th>
                    <th>Type</th>
                    <th>CPU Peak</th>
                    <th>Metric Src</th>
                    <th>Recovery (s)</th>
                    <th>Result</th>
                    <th>Re-Test</th>
                  </tr>
                </thead>
                <tbody>
                  {chaosData.map((run) => (
                    <tr key={run.experiment_id}>
                      <td>{run.experiment_id}</td>
                      <td className="code-font">#{run.threat_id}</td>
                      <td className="code-font">{run.experiment_type} (Lv {run.intensity_level})</td>
                      <td>{run.cpu_peak}%</td>
                      <td>{(run.notes || "").includes("MetricSource=docker") ? "docker" : "fallback"}</td>
                      <td>{run.recovery_time_secs}s</td>
                      <td><span className={`badge ${run.result === 'Resilient' ? 'low' : 'high'}`}>{run.result}</span></td>
                      <td>{run.is_retest ? 'Yes' : 'No'}</td>
                    </tr>
                  ))}
                  {chaosData.length === 0 && <tr><td colSpan="8" style={{ textAlign: 'center' }}>No adaptive runs recorded yet.</td></tr>}
                </tbody>
              </table>
            </div>

            <div className="panel" style={{ marginTop: 20 }}>
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Global Vulnerability Metrics</h3>
              <table>
                <thead>
                  <tr>
                    <th>Threat Type</th>
                    <th>Total Runs</th>
                    <th>Failures</th>
                    <th>Failure Rate</th>
                    <th>Risk Score</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerabilityMetrics.map((v) => (
                    <tr key={v.threat_type}>
                      <td>{v.threat_type.replaceAll('_', ' ')}</td>
                      <td>{v.total_runs}</td>
                      <td>{v.total_failures}</td>
                      <td>{v.failure_rate}</td>
                      <td style={{ color: Number(v.risk_score) >= 0.6 ? 'var(--danger)' : 'var(--text-primary)' }}>{v.risk_score}</td>
                    </tr>
                  ))}
                  {vulnerabilityMetrics.length === 0 && <tr><td colSpan="5" style={{ textAlign: 'center' }}>No metrics available yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
