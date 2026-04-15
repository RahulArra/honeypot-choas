import { useEffect, useState } from 'react';
import { Activity, Server, Shield, Terminal, Zap } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8001/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [overview, setOverview] = useState({ total_sessions: 0, total_threats: 0, vulnerable_runs: 0 });
  const [sessions, setSessions] = useState([]);
  const [threats, setThreats] = useState([]);
  const [chaosData, setChaosData] = useState([]);
  const [sessionActivity, setSessionActivity] = useState([]);
  const [vulnerabilityMetrics, setVulnerabilityMetrics] = useState([]);
  const [criticalThreats, setCriticalThreats] = useState([]);
  const [learningInsights, setLearningInsights] = useState({ report: [], config_memory: [] });
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [selectedSessionDetail, setSelectedSessionDetail] = useState(null);
  const [sessionDetailLoading, setSessionDetailLoading] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [filterResult, setFilterResult] = useState('all');
  const [filterIntensity, setFilterIntensity] = useState('all');
  const [filterSource, setFilterSource] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [activitySessionFilter, setActivitySessionFilter] = useState('all');
  const [selectedActivity, setSelectedActivity] = useState(null);
  const [expandedTopCommand, setExpandedTopCommand] = useState(null);
  const [expandAiInsight, setExpandAiInsight] = useState(false);
  const [apiError, setApiError] = useState('');

  const fetchSessionDetail = async (sessionId) => {
    setSessionDetailLoading(true);
    try {
      const res = await fetch(`${API_BASE}/sessions/${sessionId}`);
      const data = await res.json();
      setSelectedSessionDetail(data);
    } catch {
      setSelectedSessionDetail(null);
    }
    setSessionDetailLoading(false);
  };

  const fetchData = async () => {
    try {
      const [o, s, a, t, c, v, k, l] = await Promise.all([
        fetch(`${API_BASE}/overview`),
        fetch(`${API_BASE}/sessions`),
        fetch(`${API_BASE}/session_activity`),
        fetch(`${API_BASE}/threats`),
        fetch(`${API_BASE}/chaos_analytics`),
        fetch(`${API_BASE}/vulnerability_metrics`),
        fetch(`${API_BASE}/critical_threats`),
        fetch(`${API_BASE}/learning_insights`),
      ]);
      if (![o, s, a, t, c, v, k, l].every((x) => x.ok)) throw new Error('non-200');
      const [ov, ss, aa, tt, cc, vv, kk, ll] = await Promise.all([o.json(), s.json(), a.json(), t.json(), c.json(), v.json(), k.json(), l.json()]);
      setOverview(ov); setSessions(ss); setSessionActivity(aa); setThreats(tt); setChaosData(cc); setVulnerabilityMetrics(vv); setCriticalThreats(kk);
      setLearningInsights(ll || { report: [], config_memory: [] });
      setApiError('');
    } catch {
      setApiError(`Cannot connect to API at ${API_BASE}. Start backend and refresh.`);
    }
  };

  useEffect(() => { fetchData(); const i = setInterval(fetchData, 3000); return () => clearInterval(i); }, []);

  useEffect(() => {
    if (!selectedSessionId && sessions.length) {
      setSelectedSessionId(sessions[0].session_id);
    }
  }, [sessions, selectedSessionId]);

  const filteredThreats = threats.filter((t) => {
    if (filterType !== 'all' && t.threat_type !== filterType) return false;
    if (filterSource !== 'all' && t.source !== filterSource) return false;
    if (search && !`${t.raw_input} ${t.threat_type}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });
  const filteredChaos = chaosData.filter((r) => {
    if (filterType !== 'all' && r.threat_type !== filterType) return false;
    if (filterResult !== 'all' && r.result !== filterResult) return false;
    if (filterIntensity !== 'all' && Number(r.intensity_level) !== Number(filterIntensity)) return false;
    if (search && !`${r.raw_input} ${r.threat_type} ${r.experiment_type}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });
  const filteredSessions = sessions.filter((s) => {
    if (filterStatus !== 'all' && s.status !== filterStatus) return false;
    if (search && !`${s.session_id} ${s.source_ip}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });
  const filteredActivity = sessionActivity.filter((x) => {
    if (activitySessionFilter !== 'all' && x.session_id !== activitySessionFilter) return false;
    if (search && !`${x.raw_input} ${x.threat_type} ${x.result} ${x.session_id}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });
  const activityCommandText = (raw) => String(raw || '').replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '').trim();
  const selectedActivityRuns = selectedActivity?.threat_id
    ? chaosData.filter((r) => Number(r.threat_id) === Number(selectedActivity.threat_id)).sort((a, b) => Number(a.experiment_id) - Number(b.experiment_id))
    : [];

  const topRisk = vulnerabilityMetrics[0];
  const failureRatePct = topRisk ? Math.round(Number(topRisk.failure_rate || 0) * 100) : 0;
  const systemRisk = failureRatePct >= 80 ? 'HIGH' : failureRatePct >= 45 ? 'MEDIUM' : 'LOW';
  const vulnerableRuns = chaosData.filter((x) => x.result === 'Vulnerable');
  const avgRecovery = chaosData.length ? chaosData.reduce((a, b) => a + Number(b.recovery_time_secs || 0), 0) / chaosData.length : 0;
  const worstRecovery = chaosData.length ? Math.max(...chaosData.map((x) => Number(x.recovery_time_secs || 0))) : 0;
  const avgIntensity = chaosData.length ? chaosData.reduce((a, b) => a + Number(b.intensity_level || 1), 0) / chaosData.length : 1;
  const failRate = chaosData.length ? vulnerableRuns.length / chaosData.length : 0;
  const healthScore = Math.max(0, Math.min(100, Math.round(100 - failRate * 60 - Math.min(worstRecovery, 30) * 1.2 - Math.min(avgIntensity, 6) * 4)));

  const sourceBreakdown = threats.reduce((a, t) => ({ ...a, [t.source === 'ai' ? 'ai' : 'rule']: (a[t.source === 'ai' ? 'ai' : 'rule'] || 0) + 1 }), { ai: 0, rule: 0 });
  const topThreatClasses = Object.entries(threats.reduce((a, t) => { a[t.threat_type] = (a[t.threat_type] || 0) + 1; return a; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const uniqueThreatTypes = Array.from(new Set(threats.map((t) => t.threat_type))).sort();

  const orderedChaos = filteredChaos.slice().sort((a, b) => Number(a.experiment_id) - Number(b.experiment_id));
  const recoverySeries = orderedChaos.map((x) => Number(x.recovery_time_secs || 0));
  const FAILURE_WINDOW = 5;
  const failureSeries = orderedChaos.map((_, i) => {
    const start = Math.max(0, i - FAILURE_WINDOW + 1);
    const window = orderedChaos.slice(start, i + 1);
    const failsInWindow = window.filter((w) => w.result === 'Vulnerable').length;
    return (failsInWindow / Math.max(1, window.length)) * 100;
  });
  const intensityBuckets = orderedChaos.reduce((acc, run) => {
    const lvl = Number(run.intensity_level || 1);
    if (!acc[lvl]) acc[lvl] = { total: 0, recovery: 0 };
    acc[lvl].total += 1;
    acc[lvl].recovery += Number(run.recovery_time_secs || 0);
    return acc;
  }, {});
  const intensityLevels = Object.keys(intensityBuckets).map(Number).sort((a, b) => a - b);
  const intensityRecoverySeries = intensityLevels.map((lvl) => intensityBuckets[lvl].recovery / Math.max(1, intensityBuckets[lvl].total));
  const linePts = (arr) => {
    if (!arr.length) return '';
    const max = Math.max(...arr, 1), step = arr.length > 1 ? 496 / (arr.length - 1) : 0;
    return arr.map((v, i) => `${12 + i * step},${168 - (Math.max(0, Number(v || 0)) / max) * 156}`).join(' ');
  };
  const renderLineChart = (points, lineColor, yLabel, xLabel, topLabel = '', bottomLabel = '') => (
    <svg width="100%" height="200" viewBox="0 0 520 180">
      <rect x="0" y="0" width="520" height="180" fill="rgba(255,255,255,0.02)" />
      <line x1="12" y1="168" x2="508" y2="168" stroke="rgba(255,255,255,0.2)" strokeWidth="1" />
      <line x1="12" y1="12" x2="12" y2="168" stroke="rgba(255,255,255,0.2)" strokeWidth="1" />
      <polyline fill="none" stroke={lineColor} strokeWidth="3" points={points} />
      <text x="16" y="20" fill="var(--text-secondary)" fontSize="10">{topLabel}</text>
      <text x="16" y="176" fill="var(--text-secondary)" fontSize="10">{bottomLabel}</text>
      <text x="260" y="176" textAnchor="middle" fill="var(--text-secondary)" fontSize="10">{xLabel}</text>
      <text x="6" y="90" fill="var(--text-secondary)" fontSize="10" transform="rotate(-90 6 90)">{yLabel}</text>
    </svg>
  );
  const anomalies = [];
  for (let i = 1; i < orderedChaos.length; i += 1) {
    const p = Number(orderedChaos[i - 1].recovery_time_secs || 0), c = Number(orderedChaos[i].recovery_time_secs || 0);
    if (c - p >= 1.0) {
      const pct = p > 0 ? ((c - p) / p) * 100 : 999;
      anomalies.push(`Anomaly: ${orderedChaos[i].experiment_type} recovery increased by ${pct.toFixed(0)}% (${p.toFixed(2)}s to ${c.toFixed(2)}s). Indicates degradation under repeated stress.`);
    }
  }
  for (let i = 1; i < intensityRecoverySeries.length; i += 1) {
    if (intensityRecoverySeries[i] + 0.05 < intensityRecoverySeries[i - 1]) {
      anomalies.push(`Intensity trend anomaly: Lv ${intensityLevels[i - 1]} avg ${intensityRecoverySeries[i - 1].toFixed(2)}s > Lv ${intensityLevels[i]} avg ${intensityRecoverySeries[i].toFixed(2)}s`);
    }
  }

  const categorizeCommand = (cmd, threatType) => {
    const x = String(cmd || '').toLowerCase();
    const tt = String(threatType || '').toLowerCase();
    if (x.includes('dd ') || x.includes('fallocate') || x.includes('shred') || tt.includes('integrity') || tt.includes('disk')) return 'DISK';
    if (x.includes('while true') || x.includes('yes ') || x.includes('sqrt') || tt.includes('cpu')) return 'CPU';
    if (x.includes('pkill') || x.includes('kill ') || tt.includes('privilege')) return 'PROC';
    if (tt.includes('memory')) return 'MEM';
    return 'GEN';
  };
  const normalizeCommandPattern = (cmd) =>
    String(cmd || '')
      .toLowerCase()
      .replace(/\d+/g, '<n>')
      .replace(/\/tmp\/[^\s]+/g, '/tmp/<file>')
      .replace(/\s+/g, ' ')
      .trim();
  const topFailingCommands = Object.entries(chaosData.reduce((acc, r) => {
    const cmd = String(r.raw_input || '').trim();
    if (!cmd) return acc;
    const category = categorizeCommand(cmd, r.threat_type);
    const key = `${category}:${normalizeCommandPattern(cmd)}`;
    if (!acc[key]) {
      acc[key] = { t: 0, f: 0, category, sample: cmd, variants: new Set() };
    }
    acc[key].t += 1;
    if (r.result === 'Vulnerable') acc[key].f += 1;
    acc[key].variants.add(cmd);
    return acc;
  }, {})).map(([key, s]) => ({
    key,
    category: s.category,
    command: s.sample,
    variants: s.variants.size,
    rate: s.t ? s.f / s.t : 0,
    f: s.f,
  })).sort((a, b) => b.rate - a.rate || b.f - a.f).slice(0, 6);

  const impactScores = Object.entries(chaosData.reduce((a, r) => {
    const k = r.threat_type || 'Unknown'; if (!a[k]) a[k] = { t: 0, f: 0, r: 0, i: 0 };
    a[k].t += 1; if (r.result === 'Vulnerable') a[k].f += 1; a[k].r += Number(r.recovery_time_secs || 0); a[k].i += Number(r.intensity_level || 1); return a;
  }, {})).map(([k, s]) => ({ threat: k, score: Math.round(((s.f / Math.max(1, s.t)) * (s.r / Math.max(1, s.t)) * (s.i / Math.max(1, s.t))) * 100) })).sort((a, b) => b.score - a.score).slice(0, 6);
  const explorationReport = learningInsights.report || [];
  const configMemory = learningInsights.config_memory || [];

  const selectedSession = sessions.find((s) => s.session_id === selectedSessionId) || sessions[0];
  const sessionTimeline = threats.filter((t) => selectedSession && t.session_id === selectedSession.session_id).map((t) => {
    const run = chaosData.filter((r) => r.threat_id === t.threat_id).sort((a, b) => Number(a.experiment_id) - Number(b.experiment_id)).pop();
    return { t, run };
  });

  const drawerRuns = selectedThreat ? chaosData.filter((r) => r.threat_id === selectedThreat.threat_id).sort((a, b) => Number(a.experiment_id) - Number(b.experiment_id)) : [];
  const drawerLatest = drawerRuns[drawerRuns.length - 1];
  const topFailingCommand = topFailingCommands[0];
  const topImpact = impactScores[0];
  const explain = (t, cmd) => {
    const x = String(t || '').toLowerCase(), c = String(cmd || '').toLowerCase();
    if (x.includes('privilege')) return 'Privilege escalation may disable protections and destabilize services.';
    if (x.includes('integrity')) return 'Integrity-impacting commands can overwrite/destroy system state.';
    if (x.includes('cpu')) return 'Pattern indicates sustained compute exhaustion pressure.';
    if (c.includes('dd ') || c.includes('fallocate')) return 'High write volume can saturate disk I/O and delay recovery.';
    return 'Command behavior matches a high-risk attack pattern under stress testing.';
  };
  const whyVuln = (r) => {
    if (!r) return 'No run yet.';
    const bits = [];
    if (Number(r.cpu_peak || 0) > 500) bits.push(`CPU ${r.cpu_peak}%`);
    if (Number(r.recovery_time_secs || 0) > 8) bits.push(`recovery ${r.recovery_time_secs}s`);
    if (r.metric_source === 'fallback') bits.push('fallback metrics source');
    if (Number(r.intensity_level || 0) >= 6 && r.result === 'Vulnerable') bits.push('failed at max intensity');
    return bits.length ? bits.join(', ') : 'No threshold breach detected.';
  };
  const aiInsightHeadline = topRisk
    ? `${topRisk.threat_type.replaceAll('_', ' ')} is currently highest risk at ${(Number(topRisk.failure_rate || 0) * 100).toFixed(0)}% failure rate.`
    : 'Insufficient risk data to rank threats yet.';
  const aiInsightActions = [
    topFailingCommand ? `Constrain command pattern: "${topFailingCommand.command.slice(0, 36)}..." (${(topFailingCommand.rate * 100).toFixed(0)}% failure).` : 'Capture more failed command samples.',
    topImpact ? `Prioritize hardening for ${topImpact.threat.replaceAll('_', ' ')} (impact score ${topImpact.score}).` : 'No impact leader yet.',
    anomalies.length ? `Investigate ${anomalies.length} anomaly signal(s), especially recovery spikes and intensity trend drops.` : 'No major anomaly detected in current window.',
  ];
  const configSettingsText = (cfg) => {
    if (!cfg) return '-';
    const s = cfg.settings || {};
    const parts = [];
    if (cfg.type === 'cpu_stress') {
      if (s.threads) parts.push(`threads=${s.threads}`);
      if (cfg.variant) parts.push(`variant=${cfg.variant}`);
      if (s.variant_combination) parts.push('combo=cpu+vm');
    } else if (cfg.type === 'memory_stress') {
      if (s.memory_mb) parts.push(`memory=${s.memory_mb}MB`);
    } else if (cfg.type === 'disk_io') {
      if (s.disk_intensity) parts.push(`hdd-workers=${s.disk_intensity}`);
    } else if (cfg.type === 'process_disruption') {
      if (s.target_service) parts.push(`target=${s.target_service}`);
      if (s.forks) parts.push(`forks=${s.forks}`);
    }
    parts.push(`duration=${cfg.duration}s`);
    return parts.join(', ');
  };

  return (
    <>
    <div className="dashboard-container">
      <div className="panel" style={{ borderRadius: 0, borderTop: 0, borderBottom: 0, borderLeft: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 32 }}><Shield color="var(--accent-cyan)" size={30} /><h2 style={{ fontSize: '1.1rem', letterSpacing: '1px' }}>CHAOS<span style={{ color: 'var(--accent-purple)' }}>ENGINE</span></h2></div>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <button className={`nav-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}><Activity size={18} /> Overview</button>
          <button className={`nav-btn ${activeTab === 'sessions' ? 'active' : ''}`} onClick={() => setActiveTab('sessions')}><Server size={18} /> Sessions</button>
          <button className={`nav-btn ${activeTab === 'activity' ? 'active' : ''}`} onClick={() => setActiveTab('activity')}><Activity size={18} /> Activity</button>
          <button className={`nav-btn ${activeTab === 'threats' ? 'active' : ''}`} onClick={() => setActiveTab('threats')}><Terminal size={18} /> Threat Feed</button>
          <button className={`nav-btn ${activeTab === 'chaos' ? 'active' : ''}`} onClick={() => setActiveTab('chaos')}><Zap size={18} /> Chaos & Risk</button>
        </nav>
      </div>

      <div style={{ padding: 32, overflowY: 'auto' }}>
        <div className="panel" style={{ marginBottom: 20, borderColor: systemRisk === 'HIGH' ? 'var(--danger)' : systemRisk === 'MEDIUM' ? 'var(--warning)' : 'var(--success)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ fontWeight: 700 }}>{`SYSTEM RISK: ${systemRisk}`}</div>
            <div>Top Threat: <strong>{topRisk ? topRisk.threat_type.replaceAll('_', ' ') : '-'}</strong></div>
            <div title="Current top threat failure rate">Failure Rate: <strong>{failureRatePct}%</strong></div>
            <div title="Health score from failures, recovery, intensity">Health Score: <strong>{healthScore}%</strong></div>
          </div>
        </div>
        {activeTab !== 'overview' && (
          <div className="panel" style={{ marginBottom: 20 }}>
            {activeTab === 'sessions' && (
              <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: 10 }}>
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search session id / source IP" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }} />
                <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }}>
                  <option value="all">All Status</option>
                  <option value="active">Active</option>
                  <option value="closed">Closed</option>
                  <option value="timeout">Timeout</option>
                </select>
              </div>
            )}
            {activeTab === 'activity' && (
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 10 }}>
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search command / threat / result" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }} />
                <select value={activitySessionFilter} onChange={(e) => setActivitySessionFilter(e.target.value || 'all')} style={{ background: 'rgba(18,20,34,0.95)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }}>
                  <option value="all" style={{ background: '#101522', color: '#e6edf3' }}>All Sessions</option>
                  {sessions.map((s) => <option key={s.session_id} value={s.session_id} style={{ background: '#101522', color: '#e6edf3' }}>{s.session_id}</option>)}
                </select>
              </div>
            )}
            {activeTab === 'threats' && (
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 10 }}>
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search command / class / severity" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }} />
                <select value={filterType} onChange={(e) => setFilterType(e.target.value)} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }}><option value="all">All Threat Types</option>{uniqueThreatTypes.map((tt) => <option key={tt} value={tt}>{tt.replaceAll('_', ' ')}</option>)}</select>
                <select value={filterSource} onChange={(e) => setFilterSource(e.target.value)} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }}>
                  <option value="all">All Sources</option>
                  <option value="ai">AI Model</option>
                  <option value="rule">Rule Engine</option>
                </select>
              </div>
            )}
            {activeTab === 'chaos' && (
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: 10 }}>
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search command / threat / experiment" style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }} />
                <select value={filterType} onChange={(e) => setFilterType(e.target.value)} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }}><option value="all">All Threat Types</option>{uniqueThreatTypes.map((tt) => <option key={tt} value={tt}>{tt.replaceAll('_', ' ')}</option>)}</select>
                <select value={filterResult} onChange={(e) => setFilterResult(e.target.value)} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }}><option value="all">All Results</option><option value="Vulnerable">Vulnerable</option><option value="Resilient">Resilient</option></select>
                <select value={filterIntensity} onChange={(e) => setFilterIntensity(e.target.value)} style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border-glass)', color: 'var(--text-primary)', padding: 10, borderRadius: 8 }}><option value="all">All Intensities</option><option value="1">Lv 1</option><option value="2">Lv 2</option><option value="3">Lv 3</option><option value="4">Lv 4</option><option value="5">Lv 5</option><option value="6">Lv 6</option></select>
              </div>
            )}
          </div>
        )}
        {apiError && <div className="panel" style={{ marginBottom: 20, borderColor: 'var(--danger)' }}><span style={{ color: 'var(--danger)', fontWeight: 600 }}>{apiError}</span></div>}

        {activeTab === 'overview' && <div>
          <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>System Overview</h1>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20, marginBottom: 20 }}><div className="panel"><div style={{ color: 'var(--text-secondary)' }}>Sessions</div><div className="stat-value">{overview.total_sessions}</div></div><div className="panel"><div style={{ color: 'var(--text-secondary)' }}>Threats</div><div className="stat-value">{overview.total_threats}</div></div><div className="panel"><div style={{ color: 'var(--text-secondary)' }}>Vulnerable Runs</div><div className="stat-value">{overview.vulnerable_runs}</div></div></div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div className="panel"><h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Detection Source Mix</h3><p>Rule Engine: <strong>{sourceBreakdown.rule}</strong></p><p>AI Model: <strong>{sourceBreakdown.ai}</strong></p></div>
            <div className="panel"><h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Top Threat Classes</h3>{topThreatClasses.map(([n, c]) => <p key={n}>{n.replaceAll('_', ' ')}: <strong>{c}</strong></p>)}</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginTop: 20 }}>
            <div className="panel"><h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Recovery Trend</h3>{renderLineChart(linePts(recoverySeries), 'var(--accent-cyan)', 'Recovery (s)', 'Run Order', `${Math.max(...recoverySeries, 0).toFixed(2)}s`, '0s')}</div>
            <div className="panel"><h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Failure Trend (Rolling {FAILURE_WINDOW} Runs)</h3>{renderLineChart(linePts(failureSeries), 'var(--danger)', 'Failure Rate %', 'Run Order', '100%', '0%')}</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 20, marginTop: 20 }}>
            <div className="panel"><h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Intensity to Avg Recovery Trend</h3>{renderLineChart(linePts(intensityRecoverySeries), 'var(--warning)', 'Avg Recovery (s)', 'Intensity Bucket', `${Math.max(...intensityRecoverySeries, 0).toFixed(2)}s`, '0s')}<p style={{ marginTop: 8, color: 'var(--text-secondary)' }}>{intensityLevels.length ? intensityLevels.map((lvl, i) => `Lv ${lvl}: ${intensityRecoverySeries[i].toFixed(2)}s`).join(' | ') : 'No intensity trend data yet.'}</p></div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginTop: 20 }}>
            <div className="panel">
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Top Failing Commands</h3>
              {topFailingCommands.map((c, i) => (
                <div key={c.key} style={{ marginBottom: 10 }}>
                  <p>
                    {i + 1}. <span className="badge medium" style={{ marginRight: 8 }}>{c.category}</span>
                    <span className="code-font" style={{ cursor: 'pointer' }} onClick={() => setExpandedTopCommand(expandedTopCommand === c.key ? null : c.key)}>
                      {expandedTopCommand === c.key ? c.command : `${c.command.slice(0, 36)}...`}
                    </span> - {(c.rate * 100).toFixed(0)}%
                  </p>
                  <p style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{`${c.variants} variant(s)`}</p>
                </div>
              ))}
              {topFailingCommands.length === 0 && <p>No failing command groups yet.</p>}
            </div>
            <div className="panel">
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Impact Score per Threat</h3>
              {impactScores.map((x) => {
                const maxScore = Math.max(...impactScores.map((s) => s.score), 1);
                const w = `${Math.max(6, (x.score / maxScore) * 100)}%`;
                return (
                  <div key={x.threat} style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>{x.threat.replaceAll('_', ' ')}</span>
                      <strong>{x.score}</strong>
                    </div>
                    <div style={{ height: 8, borderRadius: 6, background: 'rgba(255,255,255,0.08)', marginTop: 4 }}>
                      <div style={{ width: w, height: 8, borderRadius: 6, background: 'linear-gradient(90deg,var(--warning),var(--danger))' }} />
                    </div>
                  </div>
                );
              })}
              {impactScores.length === 0 && <p>No impact score data yet.</p>}
            </div>
            <div className="panel">
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Anomaly Detection</h3>
              {anomalies.slice(0, 5).map((a, i) => <p key={i} style={{ marginBottom: 8 }}>- {a}</p>)}
              {anomalies.length === 0 && <p>No unusual recovery spikes detected.</p>}
            </div>
            <div
              className="panel"
              onClick={() => setExpandAiInsight((v) => !v)}
              onMouseEnter={() => setExpandAiInsight(true)}
              onMouseLeave={() => setExpandAiInsight(false)}
              style={{ cursor: 'pointer' }}
            >
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>AI Insight {expandAiInsight ? '(Expanded)' : '(Hover/Click)'}</h3>
              <p>{aiInsightHeadline}</p>
              <p style={{ marginTop: 8, color: 'var(--text-secondary)' }}>{`Avg recovery ${avgRecovery.toFixed(2)}s, worst ${worstRecovery.toFixed(2)}s, failure ${(failRate * 100).toFixed(0)}%.`}</p>
              {expandAiInsight && (
                <>
                  <p style={{ marginTop: 8 }}>Recommended actions:</p>
                  {aiInsightActions.map((a, i) => <p key={i} style={{ color: 'var(--text-secondary)' }}>- {a}</p>)}
                </>
              )}
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginTop: 20 }}>
            <div className="panel">
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Exploration Report</h3>
              <p style={{ color: 'var(--text-secondary)', marginBottom: 10 }}>Lv = adaptive intensity level. Runtime settings used at that time are shown below.</p>
              {explorationReport.slice(0, 6).map((x) => (
                <div key={x.threat_type} style={{ marginBottom: 12, paddingBottom: 10, borderBottom: '1px dashed var(--border-glass)' }}>
                  <p><strong>{x.threat_type.replaceAll('_', ' ')}</strong> ({x.runs} runs)</p>
                  <p style={{ color: 'var(--text-secondary)' }}>
                    Best: {x.best_config.type} Lv{x.best_config.intensity} ({x.best_config.duration}s)
                    {x.best_config.variant ? `:${x.best_config.variant}` : ''} | Score {x.best_config.score}
                  </p>
                  <p style={{ color: 'var(--text-secondary)' }}>Settings: {configSettingsText(x.best_config)}</p>
                  <p style={{ color: 'var(--text-secondary)' }}>
                    Worst: {x.worst_config.type} Lv{x.worst_config.intensity} ({x.worst_config.duration}s)
                    {x.worst_config.variant ? `:${x.worst_config.variant}` : ''} | Score {x.worst_config.score}
                  </p>
                  <p style={{ color: 'var(--text-secondary)' }}>Settings: {configSettingsText(x.worst_config)}</p>
                  <p style={{ color: 'var(--text-secondary)' }}>
                    Threshold: {x.threshold ?? '-'} | Max Instability: {Number(x.max_instability || 0).toFixed(2)}
                  </p>
                </div>
              ))}
              {explorationReport.length === 0 && <p>No exploration learning data yet.</p>}
            </div>
            <div className="panel">
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Config Memory</h3>
              <table>
                <thead>
                  <tr>
                    <th>Threat</th>
                    <th>Config</th>
                    <th>Runs</th>
                    <th>Avg Score</th>
                    <th>Last3</th>
                    <th>Trend</th>
                  </tr>
                </thead>
                <tbody>
                  {configMemory.slice(0, 8).map((c) => (
                    <tr key={`${c.threat_type}-${c.experiment_type}-${c.intensity}-${c.duration}-${c.variant}`}>
                      <td>{c.threat_type.replaceAll('_', ' ')}</td>
                      <td className="code-font">{`${c.experiment_type} Lv${c.intensity}/${c.duration}s${c.variant ? `:${c.variant}` : ''}`}</td>
                      <td>{c.runs}</td>
                      <td>{Number(c.avg_score || 0).toFixed(2)}</td>
                      <td>{(c.last3_scores || []).join(', ') || '-'}</td>
                      <td><span className={`badge ${c.trend === 'degrading' ? 'high' : c.trend === 'improving' ? 'low' : 'medium'}`}>{c.trend}</span></td>
                    </tr>
                  ))}
                  {configMemory.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center' }}>No config memory yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>}

        {activeTab === 'sessions' && <div>
          <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>Session Activity</h1>
          <div className="panel"><table><thead><tr><th>Session ID</th><th>Source IP</th><th>Start Time</th><th>Commands</th><th>Status</th><th></th></tr></thead><tbody>{filteredSessions.map((s) => <tr key={s.session_id} style={{ cursor: 'pointer', outline: selectedSessionId === s.session_id ? '1px solid var(--accent-cyan)' : 'none' }} onClick={() => { setSelectedSessionId(s.session_id); fetchSessionDetail(s.session_id); }}><td className="code-font">{s.session_id}</td><td>{s.source_ip}</td><td>{s.start_time}</td><td>{s.total_commands}</td><td><span className={`badge ${s.status === 'active' ? 'medium' : 'low'}`}>{s.status}</span></td><td><span style={{ color: 'var(--accent-cyan)', fontSize: 12 }}>Investigate →</span></td></tr>)}{filteredSessions.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center' }}>No sessions match current filter.</td></tr>}</tbody></table></div>
          <div className="panel" style={{ marginTop: 20 }}><h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Session Drilldown Timeline</h3><table><thead><tr><th>Command</th><th>Threat</th><th>Experiment</th><th>Result</th><th>Recovery</th></tr></thead><tbody>{sessionTimeline.map((x) => <tr key={x.t.threat_id}><td className="code-font">{`> ${x.t.raw_input}`}</td><td>{x.t.threat_type.replaceAll('_', ' ')}</td><td className="code-font">{x.run ? x.run.experiment_type : '-'}</td><td>{x.run ? <span className={`badge ${x.run.result === 'Resilient' ? 'low' : 'high'}`}>{x.run.result}</span> : '-'}</td><td title="Time to return near baseline">{x.run ? `${x.run.recovery_time_secs}s` : '-'}</td></tr>)}{sessionTimeline.length === 0 && <tr><td colSpan="5" style={{ textAlign: 'center' }}>No threats for selected session.</td></tr>}</tbody></table></div>
        </div>}

        {activeTab === 'activity' && <div>
          <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>Session Command Activity</h1>
          <div className="panel">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Session</th>
                  <th>Command</th>
                  <th>Classification</th>
                  <th>Mapped Test</th>
                  <th>Outcome</th>
                </tr>
              </thead>
                <tbody>
                  {filteredActivity.map((x) => (
                  <tr key={x.command_id} style={{ cursor: 'pointer', outline: selectedActivity?.command_id === x.command_id ? '1px solid var(--accent-cyan)' : 'none' }} onClick={() => setSelectedActivity(x)}>
                    <td>{x.timestamp}</td>
                    <td className="code-font">{x.session_id}</td>
                    <td className="code-font">{`> ${activityCommandText(x.raw_input) || x.raw_input}`}</td>
                    <td>
                      {x.threat_id ? (
                        <span>
                          {x.threat_type.replaceAll('_', ' ')}
                          {x.severity ? ` (${x.severity})` : ''}
                        </span>
                      ) : (
                        <span className="badge low">No Threat</span>
                      )}
                    </td>
                    <td className="code-font">{x.experiment_type || '-'}</td>
                    <td>
                      {x.result ? (
                        <span className={`badge ${x.result === 'Resilient' ? 'low' : 'high'}`}>
                          {x.result}{x.intensity_level ? ` (Lv ${x.intensity_level})` : ''}{x.recovery_time_secs != null ? `, ${x.recovery_time_secs}s` : ''}
                        </span>
                      ) : (
                        <span>-</span>
                      )}
                    </td>
                  </tr>
                ))}
                {filteredActivity.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center' }}>No activity for this filter yet.</td></tr>}
              </tbody>
            </table>
          </div>
          {selectedActivity && (
            <div className="panel" style={{ marginTop: 20 }}>
              <h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Command Detail</h3>
              <p><strong>Time:</strong> {selectedActivity.timestamp}</p>
              <p><strong>Session:</strong> <span className="code-font">{selectedActivity.session_id}</span></p>
              <p><strong>Command:</strong> <span className="code-font">{activityCommandText(selectedActivity.raw_input) || selectedActivity.raw_input}</span></p>
              <p><strong>Parsed:</strong> <span className="code-font">{selectedActivity.parsed_command || '-'}</span></p>
              <p><strong>Response Type:</strong> {selectedActivity.response_type || '-'}</p>
              <p><strong>Threat:</strong> {selectedActivity.threat_id ? `${selectedActivity.threat_type.replaceAll('_', ' ')} (${selectedActivity.severity || 'Low'})` : 'No Threat'}</p>
              <p><strong>Confidence:</strong> {Number(selectedActivity.confidence || 0).toFixed(2)}</p>
              <p><strong>Source:</strong> {selectedActivity.source || '-'}</p>
              <p><strong>Mapped Test:</strong> <span className="code-font">{selectedActivity.experiment_type || '-'}</span></p>
              <p><strong>Latest Outcome:</strong> {selectedActivity.result ? `${selectedActivity.result}${selectedActivity.intensity_level ? ` (Lv ${selectedActivity.intensity_level})` : ''}${selectedActivity.recovery_time_secs != null ? `, ${selectedActivity.recovery_time_secs}s` : ''}` : '-'}</p>
              <h4 style={{ marginTop: 14, marginBottom: 8, color: 'var(--text-secondary)' }}>Related Chaos Runs</h4>
              {selectedActivityRuns.map((r) => (
                <p key={r.experiment_id} className="code-font">{`#${r.experiment_id} ${r.experiment_type} Lv ${r.intensity_level} -> ${r.result} (${r.recovery_time_secs}s)`}</p>
              ))}
              {selectedActivityRuns.length === 0 && <p>No chaos runs linked to this command.</p>}
            </div>
          )}
        </div>}

        {activeTab === 'threats' && <div>
          <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>Live Threat Feed</h1>
          <div className="panel"><table><thead><tr><th>Class</th><th>Severity</th><th>Confidence</th><th>Mapped Test</th><th>Raw Command</th><th>Source</th></tr></thead><tbody>{filteredThreats.map((t) => <tr key={t.threat_id} style={{ cursor: 'pointer' }} onClick={() => setSelectedThreat(t)}><td style={{ fontWeight: 600 }}>{t.threat_type.replaceAll('_', ' ')}</td><td><span className={`badge ${String(t.severity || '').toLowerCase()}`}>{t.severity}</span></td><td>{Number(t.confidence || 0).toFixed(2)}</td><td className="code-font">{t.mapped_experiment_type || t.experiment_type}</td><td className="code-font">{`> ${t.raw_input}`}</td><td>{t.source === 'ai' ? 'AI Model' : 'Rule Engine'}</td></tr>)}{filteredThreats.length === 0 && <tr><td colSpan="6" style={{ textAlign: 'center' }}>Listening on port 2222...</td></tr>}</tbody></table></div>
        </div>}

        {activeTab === 'chaos' && <div>
          <h1 style={{ marginBottom: 24, fontWeight: 300, fontSize: '2rem' }}>Chaos & Risk</h1>
          <div className="panel"><table><thead><tr><th>Experiment ID</th><th>Threat Ref</th><th>Type</th><th title="100%=one core">CPU Peak</th><th>Metric Src</th><th>Target</th><th>Down (s)</th><th>Restarts</th><th title="Return to baseline">Recovery (s)</th><th>Result</th><th>Re-Test</th></tr></thead><tbody>{filteredChaos.map((r) => <tr key={r.experiment_id}><td>{r.experiment_id}</td><td className="code-font">#{r.threat_id}</td><td className="code-font">{`${r.experiment_type}${r.experiment_type === 'cpu_stress' && r.cpu_variant ? `:${r.cpu_variant}` : ''} (Lv ${r.intensity_level})`}</td><td>{r.cpu_peak}%</td><td>{r.metric_source || ((r.notes || '').includes('MetricSource=docker') ? 'docker' : 'fallback')}</td><td>{r.experiment_type === 'process_disruption' ? (r.target_service || 'generic') : 'N/A'}</td><td>{r.experiment_type === 'process_disruption' ? (r.service_down_time != null ? (r.service_down_time + 's') : '0s') : 'N/A'}</td><td>{r.experiment_type === 'process_disruption' ? (r.restart_attempts != null ? r.restart_attempts : 0) : 'N/A'}</td><td>{r.recovery_time_secs}s</td><td><span className={`badge ${r.result === 'Resilient' ? 'low' : 'high'}`}>{r.result}</span></td><td>{r.is_retest ? 'Yes' : 'No'}</td></tr>)}{filteredChaos.length === 0 && <tr><td colSpan="11" style={{ textAlign: 'center' }}>No adaptive runs recorded yet.</td></tr>}</tbody></table></div>
          <div className="panel" style={{ marginTop: 20 }}><h3 style={{ marginBottom: 12, color: 'var(--text-secondary)' }}>Critical Threat Section</h3><table><thead><tr><th>Threat</th><th>Experiment</th><th>Intensity</th><th>Recovery</th><th>Command</th></tr></thead><tbody>{criticalThreats.map((c) => <tr key={c.experiment_id}><td>{c.threat_type.replaceAll('_', ' ')}</td><td className="code-font">{c.experiment_type}</td><td>Lv {c.intensity_level}</td><td>{c.recovery_time_secs}s</td><td className="code-font">{`> ${c.raw_input}`}</td></tr>)}{criticalThreats.length === 0 && <tr><td colSpan="5" style={{ textAlign: 'center' }}>No critical threats detected at max intensity yet.</td></tr>}</tbody></table></div>
        </div>}
      </div>

      {selectedThreat && (
        <div style={{ position: 'fixed', top: 0, right: 0, width: 420, height: '100vh', background: 'rgba(8,10,20,0.97)', borderLeft: '1px solid var(--border-glass)', padding: 16, overflowY: 'auto', zIndex: 50 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h3>Deep Analysis</h3>
            <button className="nav-btn" onClick={() => setSelectedThreat(null)}>Close</button>
          </div>
          <div className="panel" style={{ padding: 14 }}>
            <p><strong>Command:</strong> <span className="code-font">{selectedThreat.raw_input}</span></p>
            <p><strong>Category:</strong> {selectedThreat.threat_type.replaceAll('_', ' ')}</p>
            <p><strong>Mapped Test:</strong> <span className="code-font">{selectedThreat.mapped_experiment_type || selectedThreat.experiment_type}</span></p>
            <p><strong>Source:</strong> {selectedThreat.source === 'ai' ? 'AI Model' : 'Rule Engine'}</p>
            <p style={{ marginTop: 8 }}><strong>AI Explanation:</strong> {explain(selectedThreat.threat_type, selectedThreat.raw_input)}</p>
            <p><strong>Observed behavior:</strong> {drawerLatest ? `${drawerLatest.result} at Lv ${drawerLatest.intensity_level}` : 'No run yet'}</p>
            <p><strong>Why vulnerable:</strong> {whyVuln(drawerLatest)}</p>
          </div>
          <div className="panel" style={{ padding: 14, marginTop: 12 }}>
            <h4 style={{ marginBottom: 8 }}>Execution Timeline</h4>
            {drawerRuns.map((r) => <p key={r.experiment_id}>{`Lv ${r.intensity_level} to Recovery ${r.recovery_time_secs}s to ${r.result}`}</p>)}
            {drawerRuns.length === 0 && <p>No execution runs yet.</p>}
          </div>
          <div className="panel" style={{ padding: 14, marginTop: 12 }}>
            <h4 style={{ marginBottom: 8 }}>Experiment Replay</h4>
            <p>1. Command received</p>
            <p>2. Classified as {selectedThreat.threat_type.replaceAll('_', ' ')}</p>
            <p>3. Experiment started {drawerLatest ? `${drawerLatest.experiment_type} Lv ${drawerLatest.intensity_level}` : '-'}</p>
            <p>4. System stressed {drawerLatest ? `${drawerLatest.cpu_peak}% CPU peak` : '-'}</p>
            <p>5. Recovery measured {drawerLatest ? `${drawerLatest.recovery_time_secs}s` : '-'}</p>
          </div>
        </div>
      )}
      {selectedActivity && activeTab === 'activity' && (
        <div style={{ position: 'fixed', top: 0, right: 0, width: 440, height: '100vh', background: 'rgba(8,10,20,0.98)', borderLeft: '1px solid var(--border-glass)', padding: 16, overflowY: 'auto', zIndex: 60 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <h3>Activity Detail</h3>
            <button className="nav-btn" onClick={() => setSelectedActivity(null)}>Close</button>
          </div>
          <div className="panel" style={{ padding: 14 }}>
            <p><strong>Time:</strong> {selectedActivity.timestamp}</p>
            <p><strong>Session:</strong> <span className="code-font">{selectedActivity.session_id}</span></p>
            <p><strong>Command:</strong> <span className="code-font">{activityCommandText(selectedActivity.raw_input) || selectedActivity.raw_input}</span></p>
            <p><strong>Parsed:</strong> <span className="code-font">{selectedActivity.parsed_command || '-'}</span></p>
            <p><strong>Response Type:</strong> {selectedActivity.response_type || '-'}</p>
            <p><strong>Threat:</strong> {selectedActivity.threat_id ? `${selectedActivity.threat_type.replaceAll('_', ' ')} (${selectedActivity.severity || 'Low'})` : 'No Threat'}</p>
            <p><strong>Confidence:</strong> {Number(selectedActivity.confidence || 0).toFixed(2)}</p>
            <p><strong>Source:</strong> {selectedActivity.source || '-'}</p>
            <p><strong>Mapped Test:</strong> <span className="code-font">{selectedActivity.experiment_type || '-'}</span></p>
            <p><strong>Latest Outcome:</strong> {selectedActivity.result ? `${selectedActivity.result}${selectedActivity.intensity_level ? ` (Lv ${selectedActivity.intensity_level})` : ''}${selectedActivity.recovery_time_secs != null ? `, ${selectedActivity.recovery_time_secs}s` : ''}` : '-'}</p>
          </div>
          <div className="panel" style={{ padding: 14, marginTop: 12 }}>
            <h4 style={{ marginBottom: 8 }}>Related Chaos Runs</h4>
            {selectedActivityRuns.map((r) => (
              <p key={r.experiment_id} className="code-font">{`#${r.experiment_id} ${r.experiment_type} Lv ${r.intensity_level} -> ${r.result} (${r.recovery_time_secs}s)`}</p>
            ))}
            {selectedActivityRuns.length === 0 && <p>No chaos runs linked to this command.</p>}
          </div>
        </div>
      )}
    </div>

      {/* ── Session Investigation Modal ── */}
      {selectedSessionDetail && (
        <div style={{ position: 'fixed', top: 0, right: 0, width: 540, height: '100vh', background: 'rgba(6,8,18,0.98)', borderLeft: '1px solid var(--border-glass)', padding: 0, overflowY: 'auto', zIndex: 70, display: 'flex', flexDirection: 'column' }}>
          {/* Header */}
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-glass)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(0,0,0,0.4)', position: 'sticky', top: 0, zIndex: 1 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', letterSpacing: 1 }}>Session Investigation</h3>
              <span className="code-font" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{selectedSessionDetail.session?.session_id}</span>
            </div>
            <button className="nav-btn" onClick={() => setSelectedSessionDetail(null)}>✕ Close</button>
          </div>

          <div style={{ padding: '16px 20px', flex: 1 }}>
            {sessionDetailLoading ? (
              <p style={{ color: 'var(--text-secondary)' }}>Loading session data...</p>
            ) : selectedSessionDetail.error ? (
              <p style={{ color: 'var(--danger)' }}>{selectedSessionDetail.error}</p>
            ) : (
              <>
                {/* Verdict Banner */}
                {(() => {
                  const verdict = selectedSessionDetail.summary?.verdict;
                  const color = verdict === 'Suspicious' ? 'var(--danger)' : verdict === 'Monitored' ? 'var(--warning)' : 'var(--success)';
                  return (
                    <div style={{ background: `${color}22`, border: `1px solid ${color}`, borderRadius: 10, padding: '12px 16px', marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, fontSize: '1.1rem', color }}>Verdict: {verdict}</span>
                      <div style={{ textAlign: 'right', fontSize: 12, color: 'var(--text-secondary)' }}>
                        <div>🛡 Resilient: <strong style={{ color: 'var(--success)' }}>{selectedSessionDetail.summary?.resilient_count}</strong></div>
                        <div>⚠ Vulnerable: <strong style={{ color: 'var(--danger)' }}>{selectedSessionDetail.summary?.vulnerable_count}</strong></div>
                      </div>
                    </div>
                  );
                })()}

                {/* Session Metadata */}
                <div className="panel" style={{ marginBottom: 14, padding: 14 }}>
                  <h4 style={{ marginBottom: 10, color: 'var(--text-secondary)', fontSize: 12, letterSpacing: 1, textTransform: 'uppercase' }}>Session Metadata</h4>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 13 }}>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Source IP</span><br /><strong>{selectedSessionDetail.session?.source_ip}</strong></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Status</span><br /><span className={`badge ${selectedSessionDetail.session?.status === 'active' ? 'medium' : 'low'}`}>{selectedSessionDetail.session?.status}</span></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Logged In</span><br /><strong style={{ fontSize: 11 }}>{selectedSessionDetail.session?.start_time || '-'}</strong></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Logged Out</span><br /><strong style={{ fontSize: 11 }}>{selectedSessionDetail.session?.end_time || 'Still Active'}</strong></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Duration</span><br /><strong>{selectedSessionDetail.session?.duration_secs != null ? `${selectedSessionDetail.session.duration_secs}s` : '-'}</strong></div>
                    <div><span style={{ color: 'var(--text-secondary)' }}>Total Commands</span><br /><strong>{selectedSessionDetail.summary?.total_commands}</strong></div>
                  </div>
                  {selectedSessionDetail.summary?.threat_types?.length > 0 && (
                    <div style={{ marginTop: 10 }}>
                      <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Threat Types Seen: </span>
                      {selectedSessionDetail.summary.threat_types.map(tt => (
                        <span key={tt} className="badge high" style={{ marginRight: 4, marginTop: 4, display: 'inline-block' }}>{tt.replaceAll('_', ' ')}</span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Command Timeline */}
                <h4 style={{ marginBottom: 10, color: 'var(--text-secondary)', fontSize: 12, letterSpacing: 1, textTransform: 'uppercase' }}>Command Timeline</h4>
                {(selectedSessionDetail.commands || []).map((cmd, idx) => (
                  <div key={cmd.command_id} style={{ marginBottom: 10, borderRadius: 8, border: `1px solid ${cmd.chaos_result === 'Vulnerable' ? 'rgba(255,80,80,0.35)' : cmd.chaos_result === 'Resilient' ? 'rgba(0,255,160,0.2)' : 'var(--border-glass)'}`, background: 'rgba(255,255,255,0.02)', padding: '10px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>#{idx + 1} · {cmd.timestamp}</span>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {cmd.threat_type !== 'None' && <span className="badge high" style={{ fontSize: 10 }}>{cmd.threat_type.replaceAll('_', ' ')}</span>}
                        {cmd.chaos_result && <span className={`badge ${cmd.chaos_result === 'Resilient' ? 'low' : 'high'}`} style={{ fontSize: 10 }}>{cmd.chaos_result}</span>}
                        {!cmd.chaos_result && cmd.threat_type === 'None' && <span className="badge low" style={{ fontSize: 10 }}>Normal</span>}
                      </div>
                    </div>
                    <div className="code-font" style={{ fontSize: 13, marginBottom: 4 }}>&gt; {cmd.raw_input || '-'}</div>
                    {cmd.threat_type !== 'None' && (
                      <div style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                        <span>Severity: <strong style={{ color: cmd.severity === 'High' || cmd.severity === 'Critical' ? 'var(--danger)' : 'var(--warning)' }}>{cmd.severity}</strong></span>
                        <span>Confidence: <strong>{(cmd.confidence * 100).toFixed(0)}%</strong></span>
                        <span>Source: <strong>{cmd.source}</strong></span>
                        {cmd.experiment_type && <span>Test: <strong className="code-font">{cmd.experiment_type}</strong></span>}
                        {cmd.chaos_result && <span>CPU Peak: <strong>{cmd.cpu_peak}%</strong></span>}
                        {cmd.chaos_result && <span>Recovery: <strong>{cmd.recovery_time_secs}s</strong></span>}
                        {cmd.intensity_level && <span>Intensity: <strong>Lv {cmd.intensity_level}</strong></span>}
                      </div>
                    )}
                  </div>
                ))}
                {(!selectedSessionDetail.commands || selectedSessionDetail.commands.length === 0) && (
                  <p style={{ color: 'var(--text-secondary)' }}>No commands recorded for this session.</p>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}
