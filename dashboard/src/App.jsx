import { useState, useEffect } from 'react';
import { Shield, Activity, Terminal, AlertTriangle, Hexagon, Zap, Server } from 'lucide-react';

const API_BASE = "http://localhost:8000/api";

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [overview, setOverview] = useState({ total_sessions: 0, total_threats: 0, vulnerable_runs: 0 });
  const [threats, setThreats] = useState([]);
  const [chaosData, setChaosData] = useState([]);

  const fetchData = async () => {
    try {
      const p1 = await fetch(`${API_BASE}/overview`).then(r => r.json());
      const p2 = await fetch(`${API_BASE}/threats`).then(r => r.json());
      const p3 = await fetch(`${API_BASE}/chaos_analytics`).then(r => r.json());
      setOverview(p1);
      setThreats(p2);
      setChaosData(p3);
    } catch (e) {
      console.error("API Error", e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000); // Polling for real-time vibe
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-container">
      {/* Sidebar Navigation */}
      <div className="panel" style={{ borderRadius: 0, borderTop: 0, borderBottom: 0, borderLeft: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '40px' }}>
          <Shield color="var(--accent-cyan)" size={32} />
          <h2 style={{ fontSize: '1.2rem', letterSpacing: '1px' }}>CHAOS<span style={{ color: 'var(--accent-purple)' }}>ENGINE</span></h2>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <button
            onClick={() => setActiveTab('overview')}
            style={{
              background: activeTab === 'overview' ? 'var(--bg-glass-hover)' : 'transparent',
              border: 'none', color: activeTab === 'overview' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              padding: '12px', display: 'flex', alignItems: 'center', gap: '12px', borderRadius: '8px', cursor: 'pointer',
              fontWeight: 600, textAlign: 'left', transition: 'all 0.2s'
            }}>
            <Activity size={20} /> Overview Hub
          </button>
          <button
            onClick={() => setActiveTab('threats')}
            style={{
              background: activeTab === 'threats' ? 'var(--bg-glass-hover)' : 'transparent',
              border: 'none', color: activeTab === 'threats' ? 'var(--accent-pink)' : 'var(--text-secondary)',
              padding: '12px', display: 'flex', alignItems: 'center', gap: '12px', borderRadius: '8px', cursor: 'pointer',
              fontWeight: 600, textAlign: 'left', transition: 'all 0.2s'
            }}>
            <Terminal size={20} /> Live Threat Feed
          </button>
          <button
            onClick={() => setActiveTab('chaos')}
            style={{
              background: activeTab === 'chaos' ? 'var(--bg-glass-hover)' : 'transparent',
              border: 'none', color: activeTab === 'chaos' ? 'var(--warning)' : 'var(--text-secondary)',
              padding: '12px', display: 'flex', alignItems: 'center', gap: '12px', borderRadius: '8px', cursor: 'pointer',
              fontWeight: 600, textAlign: 'left', transition: 'all 0.2s'
            }}>
            <Zap size={20} /> Adaptive Validation
          </button>
        </nav>
      </div>

      {/* Main Content Area */}
      <div style={{ padding: '40px', overflowY: 'auto' }}>
        {activeTab === 'overview' && (
          <div>
            <h1 style={{ marginBottom: '30px', fontWeight: 300, fontSize: '2rem' }}>System Overview</h1>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px', marginBottom: '40px' }}>
              <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <span style={{ color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.85rem' }}>Active Sessions Captured</span>
                <span className="stat-value">{overview.total_sessions}</span>
                <Server size={24} color="var(--accent-cyan)" style={{ alignSelf: 'flex-end', opacity: 0.5, marginTop: '-35px' }} />
              </div>
              <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <span style={{ color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.85rem' }}>Threats Identified</span>
                <span className="stat-value" style={{ background: 'linear-gradient(90deg, var(--accent-pink), var(--accent-purple))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                  {overview.total_threats}
                </span>
                <AlertTriangle size={24} color="var(--accent-pink)" style={{ alignSelf: 'flex-end', opacity: 0.5, marginTop: '-35px' }} />
              </div>
              <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <span style={{ color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.85rem' }}>Chaos Escalations Triggered</span>
                <span className="stat-value" style={{ background: 'linear-gradient(90deg, var(--warning), #ff5722)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                  {overview.vulnerable_runs}
                </span>
                <Hexagon size={24} color="var(--warning)" style={{ alignSelf: 'flex-end', opacity: 0.5, marginTop: '-35px' }} />
              </div>
            </div>

            <div className="panel">
              <h3 style={{ marginBottom: '20px', color: 'var(--text-secondary)' }}>Recent Adaptive Engine Runs</h3>
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Result</th>
                    <th>Threshold Peaked</th>
                    <th>Intensity Lvl</th>
                    <th>Re-Test</th>
                  </tr>
                </thead>
                <tbody>
                  {chaosData.slice(0, 5).map(run => (
                    <tr key={run.experiment_id}>
                      <td><span className="code-font">{run.experiment_type}</span></td>
                      <td><span className={`badge ${run.result === 'Resilient' ? 'low' : 'high'}`}>{run.result}</span></td>
                      <td>{run.cpu_peak}%</td>
                      <td>Lv {run.intensity_level}</td>
                      <td>{run.is_retest ? 'Yes' : 'No'}</td>
                    </tr>
                  ))}
                  {chaosData.length === 0 && <tr><td colSpan="5" style={{ textAlign: 'center' }}>No adaptive runs recorded yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div>
            <h1 style={{ marginBottom: '30px', fontWeight: 300, fontSize: '2rem' }}>Live Threat Feed</h1>
            <div className="panel">
              <table>
                <thead>
                  <tr>
                    <th>Class</th>
                    <th>Severity</th>
                    <th>Raw Command Invocation</th>
                    <th>Detection Source</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map(t => (
                    <tr key={t.threat_id}>
                      <td style={{ fontWeight: 600 }}>{t.threat_type.replace('_', ' ')}</td>
                      <td><span className={`badge ${t.severity.toLowerCase()}`}>{t.severity}</span></td>
                      <td className="code-font">❯ {t.raw_input}</td>
                      <td>{t.source === 'ai' ? ' AI Model' : ' Rule Engine'}</td>
                    </tr>
                  ))}
                  {threats.length === 0 && <tr><td colSpan="4" style={{ textAlign: 'center' }}>Listening on port 2222...</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'chaos' && (
          <div>
            <h1 style={{ marginBottom: '30px', fontWeight: 300, fontSize: '2rem' }}>Chaos Validation Engine History</h1>
            <div className="panel">
              <table>
                <thead>
                  <tr>
                    <th>Experiment ID</th>
                    <th>Threat ID Ref</th>
                    <th>Agent Type</th>
                    <th>CPU Threshold Peaked</th>
                    <th>System Recovery (s)</th>
                    <th>Validation Result</th>
                  </tr>
                </thead>
                <tbody>
                  {chaosData.map(run => (
                    <tr key={run.experiment_id}>
                      <td>{run.experiment_id}</td>
                      <td><span className="code-font">#{run.threat_id}</span></td>
                      <td><span className="code-font">{run.experiment_type}</span> (Lv {run.intensity_level})</td>
                      <td style={{ color: run.cpu_peak > 80 ? 'var(--danger)' : 'var(--text-primary)' }}>{run.cpu_peak}%</td>
                      <td style={{ color: run.recovery_time_secs > 8 ? 'var(--danger)' : 'var(--text-primary)' }}>{run.recovery_time_secs}s</td>
                      <td><span className={`badge ${run.result === 'Resilient' ? 'low' : 'high'}`}>{run.result}</span></td>
                    </tr>
                  ))}
                  {chaosData.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center' }}>No adaptive runs recorded yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default App
