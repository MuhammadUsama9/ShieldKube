import React, { useState, useEffect, useRef } from 'react'
import {
    PieChart, Pie, Cell, ResponsiveContainer, Tooltip as ReTooltip,
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend as ReLegend,
    Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
    LineChart, Line
} from 'recharts'

const API_BASE = "http://localhost:8000"
const COLORS = {
    Runtime: '#ef4444',
    IAM: '#f97316',
    Network: '#3b82f6',
    Images: '#eab308',
    Host: '#a855f7',
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#22c55e'
}

function App() {
    const [summary, setSummary] = useState(null)
    const [pods, setPods] = useState([])
    const [policies, setPolicies] = useState([])
    const [rbac, setRbac] = useState([])
    const [heatmap, setHeatmap] = useState([])
    const [radarData, setRadarData] = useState([])
    const [inventory, setInventory] = useState([])
    const [vulnerabilities, setVulnerabilities] = useState({ pods: [], nodes: [], volumes: [], replica_sets: [], deployments: [], infrastructure: [] })
    const [trends, setTrends] = useState([])
    const [compliance, setCompliance] = useState([])
    const [metrics, setMetrics] = useState({ pods: [], nodes: [] })
    const [events, setEvents] = useState([])
    const [secrets, setSecrets] = useState([])
    const [logs, setLogs] = useState([])
    const [loading, setLoading] = useState(true)
    const [activeTab, setActiveTab] = useState('pods')
    const [activeSubTab, setActiveSubTab] = useState('Workloads') // For Inventory
    const [activeVulnTab, setActiveVulnTab] = useState('pods') // For Trivy
    const [search, setSearch] = useState('')
    const [selectedFix, setSelectedFix] = useState(null)
    const [filterNamespace, setFilterNamespace] = useState(null)
    const [notification, setNotification] = useState(null)



    const fetchData = async () => {
        try {
            const [sumRes, podsRes, polRes, rbacRes, heatRes, radarRes, invRes, vulnRes, trendsRes, compRes, metricsRes, evRes, secRes, logRes] = await Promise.all([
                fetch(`${API_BASE}/api/summary`),
                fetch(`${API_BASE}/api/pods`),
                fetch(`${API_BASE}/api/network-policies`),
                fetch(`${API_BASE}/api/rbac`),
                fetch(`${API_BASE}/api/heatmap`),
                fetch(`${API_BASE}/api/radar`),
                fetch(`${API_BASE}/api/inventory`),
                fetch(`${API_BASE}/api/vulnerabilities`),
                fetch(`${API_BASE}/api/trends`),
                fetch(`${API_BASE}/api/compliance`),
                fetch(`${API_BASE}/api/metrics`),
                fetch(`${API_BASE}/api/events`),
                fetch(`${API_BASE}/api/secrets`),
                fetch(`${API_BASE}/api/logs`)
            ])

            setSummary(await sumRes.json())
            setPods(await podsRes.json())
            setPolicies(await polRes.json())
            setRbac(await rbacRes.json())
            setHeatmap(await heatRes.json())
            setRadarData(await radarRes.json())
            setInventory(await invRes.json())
            setVulnerabilities(await vulnRes.json())
            setTrends(await trendsRes.json())
            setCompliance(await compRes.json())
            setMetrics(await metricsRes.json())
            setEvents(await evRes.json())
            setSecrets(await secRes.json())
            setLogs(await logRes.json())
        } catch (err) {
            console.error("Data fetch error:", err)
        } finally {
            setLoading(false)
        }
    }

    const handleRemediate = async (target) => {
        try {
            setNotification({ type: 'info', msg: `Initiating remediation for ${target.name || 'resource'}...` })
            const response = await fetch(`${API_BASE}/api/remediate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    kind: target.kind || (activeTab === 'pods' ? 'Pod' : 'Deployment'),
                    name: target.name || target.target,
                    namespace: target.namespace || 'default',
                    patch: target.patch || '{"spec": {"template": {"spec": {"securityContext": {"runAsNonRoot": true}}}}}'
                })
            })
            const result = await response.json()
            if (result.status === 'success') {
                setNotification({ type: 'success', msg: result.msg })
                setSelectedFix(null)
                fetchData() // Refresh data after fix
            } else {
                setNotification({ type: 'error', msg: `Failure: ${result.msg}` })
            }
        } catch (err) {
            setNotification({ type: 'error', msg: `Network Error: ${err.message}` })
        }
        setTimeout(() => setNotification(null), 5000)
    }

    const handleExport = () => {
        try {
            const allFindings = []

            // Map Pods
            pods.forEach(p => p.risks.forEach(r => allFindings.push({
                Type: 'Pod Configuration', Target: p.name, Namespace: p.namespace, Issue: r.type, CIS: r.cis, Severity: p.severity
            })))

            // Map RBAC
            rbac.forEach(r => r.risks.forEach(risk => allFindings.push({
                Type: 'RBAC', Target: r.name, Namespace: r.namespace, Issue: risk.type, CIS: risk.cis, Severity: r.severity
            })))

            // Map Policies
            policies.forEach(p => p.risks.forEach(r => allFindings.push({
                Type: 'Network Policy', Target: p.name, Namespace: p.namespace, Issue: r.type, CIS: r.cis, Severity: p.severity
            })))

            // Map CVEs
            Object.values(vulnerabilities).flat().forEach(v => allFindings.push({
                Type: 'Vulnerability', Target: v.target, Namespace: v.namespace || 'Cluster', Issue: v.id || v.title, CIS: 'N/A', Severity: v.severity
            }))

            if (allFindings.length === 0) {
                setNotification({ type: 'info', msg: "No findings to export." })
                return
            }

            const headers = Object.keys(allFindings[0]).join(',')
            const rows = allFindings.map(f => Object.values(f).map(v => `"${v}"`).join(',')).join('\n')
            const csvContent = "data:text/csv;charset=utf-8," + headers + "\n" + rows

            const encodedUri = encodeURI(csvContent)
            const link = document.createElement("a")
            link.setAttribute("href", encodedUri)
            link.setAttribute("download", `guardian_audit_${new Date().toISOString().split('T')[0]}.csv`)
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)

            setNotification({ type: 'success', msg: "Audit CSV exported successfully!" })
        } catch (err) {
            console.error("Export error:", err)
            setNotification({ type: 'error', msg: "Export failed." })
        }
    }

    useEffect(() => {
        fetchData()
        const interval = setInterval(fetchData, 8000)
        return () => clearInterval(interval)
    }, [])

    const consoleRef = useRef(null)

    useEffect(() => {
        if (!loading && logs.length > 0 && consoleRef.current) {
            const container = consoleRef.current
            container.scrollTo({
                top: container.scrollHeight,
                behavior: 'smooth'
            })
        }
    }, [logs, loading])

    const getFilteredData = () => {
        let data = []
        if (activeTab === 'pods') data = pods
        else if (activeTab === 'policies') data = policies
        else if (activeTab === 'rbac') data = rbac
        else if (activeTab === 'inventory') data = inventory.filter(i => i.group === activeSubTab)
        else if (activeTab === 'vulnerabilities') data = vulnerabilities[activeVulnTab] || []
        else if (activeTab === 'secrets') data = secrets

        if (filterNamespace) {
            data = data.filter(item => item.namespace === filterNamespace || item.namespace === "Global" || item.namespace === "Cluster-wide")
        }

        return data.filter(item => {
            const name = item.name || item.target || item.image || "";
            return name.toLowerCase().includes(search.toLowerCase())
        })
    }

    const namespaces = Array.from(new Set(inventory.map(i => i.namespace).filter(n => n && n !== "Global" && n !== "Cluster-wide")))

    const getScoreColor = (score) => {
        if (score > 80) return COLORS.Low
        if (score > 50) return COLORS.Medium
        return COLORS.Critical
    }

    const getTopPriorities = () => {
        const priorities = []
        // Priority 1: Critical CVEs
        Object.values(vulnerabilities).flat().filter(v => v.severity === 'Critical').slice(0, 2).forEach(v => {
            priorities.push({ type: 'CVE', label: v.id, target: v.target, sev: 'critical' })
        })
        // Priority 2: Privileged Pods
        pods.filter(p => p.severity === 'Critical').slice(0, 1).forEach(p => {
            priorities.push({ type: 'Runtime', label: 'Privileged Container', target: p.name, sev: 'critical' })
        })
        // Priority 3: RBAC Wildcards
        rbac.filter(r => r.severity === 'High').slice(0, 1).forEach(r => {
            priorities.push({ type: 'IAM', label: 'Wildcard Permissions', target: r.name, sev: 'high' })
        })
        return priorities.slice(0, 3)
    }

    if (loading && !summary) return <div className="dashboard-container"><h1>Calibrating Guardian Radar...</h1></div>

    return (
        <div className="dashboard-container">
            {/* Simulation Modal */}
            {selectedFix && (
                <div className="fix-modal-overlay" onClick={() => setSelectedFix(null)}>
                    <div className="fix-modal glass-card" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Remediation Blueprint</h3>
                            <button className="close-btn" onClick={() => setSelectedFix(null)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p><strong>Intelligence:</strong> Apply this patch to resolve <b>{selectedFix.type || selectedFix.id}</b>.</p>
                            {selectedFix.mitre && (
                                <div className="mitre-strip">
                                    <span className="mitre-label">MITRE ATT&CK</span>
                                    <span className="mitre-tactic">{selectedFix.mitre.tactic}</span>
                                    <span className="mitre-id">{selectedFix.mitre.id}</span>
                                </div>
                            )}
                            <div className="yaml-box">
                                <pre>{selectedFix.patch || `Remediation Plan:\n1. Pull patched image\n2. Update ${selectedFix.target} spec\n3. Roll out update`}</pre>
                            </div>
                            <div className="modal-actions">
                                <button className="glass-button secondary">Copy Patch</button>
                                <button className="glass-button primary" onClick={() => handleRemediate(selectedFix)}>Execute Fix (Authorized)</button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Notification Toast */}
            {notification && (
                <div className={`notification-toast ${notification.type}`}>
                    <span className="toast-icon">{notification.type === 'success' ? '✓' : '⚠'}</span>
                    {notification.msg}
                </div>
            )}

            {/* Header */}
            <header className="enterprise-header">
                <div className="header-branding">
                    <h1>Guardian Enterprise <span className="version-tag">v7.2</span></h1>
                    <div className="status-badge"><span className="pulse-dot"></span> Full-Spectrum Defense Active</div>
                </div>

                {summary && (
                    <div className="global-posture-card glass-card">
                        <div className="score-ring-container">
                            <div className="score-label">Posture Rating</div>
                            <div className="score-value" style={{ color: getScoreColor(summary.security_score) }}>{summary.security_score}%</div>
                            <div className="score-progress-bg"><div className="score-progress-fill" style={{ width: `${summary.security_score}%`, background: getScoreColor(summary.security_score) }}></div></div>
                        </div>
                        <div className="header-actions">
                            <button className="glass-button secondary" onClick={handleExport}>Export Audit</button>
                            <button className="glass-button primary" onClick={() => setActiveTab('vulnerabilities')}>Start CVE Remediation</button>
                        </div>
                    </div>
                )}
            </header>

            {/* Dashboard Grid (Charts) */}
            <div className="dashboard-visuals-grid">
                <div className="glass-card chart-item">
                    <h3>Risk Category Radar</h3>
                    <ResponsiveContainer width="100%" height={260}>
                        <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                            <PolarGrid stroke="rgba(255,255,255,0.1)" />
                            <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                            <PolarRadiusAxis angle={30} domain={[0, 15]} tick={false} axisLine={false} />
                            <Radar name="Risks" dataKey="A" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.5} />
                            <ReTooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b' }} />
                        </RadarChart>
                    </ResponsiveContainer>
                </div>
                <div className="glass-card chart-item">
                    <h3>Security Score Trend</h3>
                    <ResponsiveContainer width="100%" height={260}>
                        <LineChart data={trends}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                            <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                            <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                            <ReTooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b' }} />
                            <ReLegend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                            <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={3} dot={{ fill: '#3b82f6', r: 4 }} activeDot={{ r: 6 }} name="Posture Score" />
                            <Line type="monotone" dataKey="criticals" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444', r: 3 }} name="Critical Risks" />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
                <div className="glass-card chart-item">
                    <h3>Namespace Distribution</h3>
                    <ResponsiveContainer width="100%" height={260}>
                        <BarChart data={heatmap}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                            <XAxis dataKey="namespace" stroke="#64748b" fontSize={11} />
                            <YAxis stroke="#64748b" fontSize={11} />
                            <ReTooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ background: '#0f172a', border: '1px solid #1e293b' }} />
                            <Bar
                                dataKey="total"
                                fill="#6366f1"
                                radius={[4, 4, 0, 0]}
                                onClick={(d) => { setFilterNamespace(d.namespace); setActiveTab('pods') }}
                                style={{ cursor: 'pointer' }}
                            />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Main Stats */}
            {summary && (
                <div className="metrics-grid">
                    {[
                        { label: 'Infrastructure CVEs', value: summary.total_vulnerabilities, color: COLORS.High },
                        { label: 'Sensitive RBAC', value: rbac.length, color: COLORS.Network },
                        { label: 'Managed Assets', value: inventory.length, color: COLORS.Images },
                        { label: 'Network Isolation', value: policies.length > 0 ? 'Active' : 'Unprotected', color: policies.length > 0 ? COLORS.Low : COLORS.Critical }
                    ].map((m, i) => (
                        <div key={i} className="glass-card compact-metric">
                            <div className="metric-header">
                                <span className="metric-label">{m.label}</span>
                                <div className="metric-val" style={{ color: m.color }}>{m.value}</div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Tabs */}
            <div className="tabs-container">
                <div className="tabs-list">
                    {['pods', 'policies', 'rbac', 'inventory', 'vulnerabilities', 'compliance', 'monitoring', 'events', 'secrets'].map(t => (
                        <button key={t} onClick={() => { setActiveTab(t); if (t !== 'pods' && t !== 'inventory' && t !== 'vulnerabilities' && t !== 'secrets') setFilterNamespace(null) }} className={`tab-item ${activeTab === t ? 'active' : ''}`}>
                            {t.toUpperCase()}
                        </button>
                    ))}
                </div>
                <div className="controls-group" style={{ display: 'flex', gap: '1rem' }}>
                    {(activeTab === 'pods' || activeTab === 'inventory' || activeTab === 'vulnerabilities') && (
                        <select
                            className="glass-select"
                            value={filterNamespace || ""}
                            onChange={(e) => setFilterNamespace(e.target.value || null)}
                        >
                            <option value="">All Namespaces</option>
                            {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
                        </select>
                    )}
                    <div className="search-wrapper">
                        <input type="text" placeholder={`Query ${activeTab}...`} value={search} onChange={e => setSearch(e.target.value)} />
                    </div>
                </div>
            </div>

            {/* Primary Data Table */}
            <div className="main-content-grid">
                <div className="glass-card visual-section">
                    {activeTab === 'compliance' ? (
                        <div className="compliance-grid">
                            {compliance.map((c, idx) => (
                                <div key={idx} className="glass-card compliance-card">
                                    <div className="compliance-card-header">
                                        <div className="comp-brand">
                                            <h3>{c.framework}</h3>
                                            <p>{c.description}</p>
                                        </div>
                                        <div className="comp-pct" style={{ color: getScoreColor(c.score) }}>{c.score}%</div>
                                    </div>
                                    <div className="controls-mapping">
                                        {c.controls.map((ctrl, cidx) => (
                                            <div key={cidx} className="control-row">
                                                <div className="control-id-tag">{ctrl.id}</div>
                                                <div className="control-main">
                                                    <div className="control-title-bar">
                                                        <span className="control-name-text">{ctrl.name}</span>
                                                        <span className={`severity-tag ${ctrl.status.toLowerCase()}`}>{ctrl.status}</span>
                                                    </div>
                                                    <div className="control-finding-text">{ctrl.finding}</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : activeTab === 'monitoring' ? (
                        <div className="monitoring-view">
                            <div className="metrics-summary-row">
                                <div className="glass-card metric-card">
                                    <h4>Node Utilization</h4>
                                    <ResponsiveContainer width="100%" height={200}>
                                        <BarChart data={metrics.nodes}>
                                            <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                                            <YAxis unit="%" stroke="#64748b" fontSize={10} />
                                            <ReTooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b' }} />
                                            <Bar dataKey="cpu_usage" fill="#3b82f6" name="CPU Usage %" radius={[4, 4, 0, 0]} />
                                            <Bar dataKey="mem_usage" fill="#a855f7" name="Mem Usage %" radius={[4, 4, 0, 0]} />
                                        </BarChart>
                                    </ResponsiveContainer>
                                </div>
                                <div className="glass-card metric-card">
                                    <h4>Pod hotspots (CPU %)</h4>
                                    <ResponsiveContainer width="100%" height={200}>
                                        <PieChart>
                                            <Pie data={metrics.pods} dataKey="cpu_usage" nameKey="name" cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5}>
                                                {metrics.pods.map((entry, index) => <Cell key={index} fill={index % 2 === 0 ? '#3b82f6' : '#6366f1'} />)}
                                            </Pie>
                                            <ReTooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b' }} />
                                        </PieChart>
                                    </ResponsiveContainer>
                                </div>
                            </div>
                            <table className="ent-table">
                                <thead><tr><th>Pod</th><th>Namespace</th><th>CPU Utilization</th><th>Memory Utilization</th></tr></thead>
                                <tbody>
                                    {metrics.pods.map((p, idx) => (
                                        <tr key={idx}>
                                            <td>{p.name}</td>
                                            <td>{p.namespace}</td>
                                            <td>
                                                <div className="progress-bar-container">
                                                    <div className="progress-bar-fill" style={{ width: `${p.cpu_usage}%`, background: p.cpu_usage > 80 ? '#ef4444' : '#3b82f6' }}></div>
                                                    <span className="progress-text">{p.cpu}</span>
                                                </div>
                                            </td>
                                            <td>
                                                <div className="progress-bar-container">
                                                    <div className="progress-bar-fill" style={{ width: `${p.mem_usage}%`, background: p.mem_usage > 80 ? '#ef4444' : '#a855f7' }}></div>
                                                    <span className="progress-text">{p.memory}</span>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>

                            <h4 style={{marginTop: '2rem', marginBottom: '1rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.9rem', letterSpacing: '0.05em'}}>Cluster Nodes</h4>
                            <table className="ent-table">
                                <thead><tr><th>Node</th><th>CPU Scale</th><th>Memory Scale</th><th>CPU Utilization</th><th>Memory Utilization</th></tr></thead>
                                <tbody>
                                    {metrics.nodes.map((n, idx) => (
                                        <tr key={idx}>
                                            <td>{n.name}</td>
                                            <td>{n.cpu}</td>
                                            <td>{n.memory}</td>
                                            <td>
                                                <div className="progress-bar-container">
                                                    <div className="progress-bar-fill" style={{ width: `${n.cpu_usage}%`, background: n.cpu_usage > 80 ? '#ef4444' : '#3b82f6' }}></div>
                                                    <span className="progress-text">{n.cpu_usage}%</span>
                                                </div>
                                            </td>
                                            <td>
                                                <div className="progress-bar-container">
                                                    <div className="progress-bar-fill" style={{ width: `${n.mem_usage}%`, background: n.mem_usage > 80 ? '#ef4444' : '#a855f7' }}></div>
                                                    <span className="progress-text">{n.mem_usage}%</span>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : activeTab === 'inventory' ? (
                        <>
                            <div className="sub-tabs-list">
                                {['Workloads', 'Infrastructure', 'Network', 'Configuration'].map(st => (
                                    <button key={st} onClick={() => setActiveSubTab(st)} className={`sub-tab-item ${activeSubTab === st ? 'active' : ''}`}>{st}</button>
                                ))}
                            </div>
                            <table className="ent-table">
                                <thead><tr><th>Asset Name</th><th>Namespace</th><th>Kind</th></tr></thead>
                                <tbody>
                                    {getFilteredData().map((i, idx) => (
                                        <tr key={idx}><td>{i.name}</td><td>{i.namespace}</td><td><span className="cis-tag">{i.kind}</span></td></tr>
                                    ))}
                                </tbody>
                            </table>
                        </>
                    ) : activeTab === 'vulnerabilities' ? (
                        <>
                            <div className="sub-tabs-list">
                                {['pods', 'nodes', 'volumes', 'replica_sets', 'deployments', 'infrastructure'].map(vt => (
                                    <button key={vt} onClick={() => setActiveVulnTab(vt)} className={`sub-tab-item ${activeVulnTab === vt ? 'active' : ''}`}>
                                        {vt.replace('_', ' ')} ({vulnerabilities[vt]?.length || 0})
                                    </button>
                                ))}
                            </div>
                            <table className="ent-table">
                                <thead><tr><th>Target</th><th>CVE / ID</th><th>Severity</th><th>Action</th></tr></thead>
                                <tbody>
                                    {getFilteredData().map((v, idx) => (
                                        <tr key={idx}>
                                            <td><div className="asset-name">{v.target}</div><div className="asset-meta">{v.image || 'Infrastructure'}</div></td>
                                            <td><span className="v-tag">{v.id || v.cve_id}</span></td>
                                            <td><div className={`severity-tag ${v.severity.toLowerCase()}`}>{v.severity}</div></td>
                                            <td><button className="fix-btn" onClick={() => setSelectedFix(v)}>Fix</button></td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </>
                    ) : activeTab === 'events' ? (
                        <table className="ent-table">
                            <thead><tr><th>Time</th><th>Type</th><th>Reason</th><th>Object</th><th>Message</th><th>Count</th></tr></thead>
                            <tbody>
                                {events.filter(e => (e.message || '').toLowerCase().includes(search.toLowerCase()) || (e.object || '').toLowerCase().includes(search.toLowerCase())).map((e, idx) => (
                                    <tr key={idx}>
                                        <td style={{whiteSpace:'nowrap', fontSize:'0.8rem'}}>{e.time ? e.time.split('.')[0].replace('T', ' ').replace('+00:00', '') : 'N/A'}</td>
                                        <td><div className={`severity-tag ${e.type === 'Warning' ? 'high' : 'low'}`}>{e.type || 'Normal'}</div></td>
                                        <td>{e.reason || '—'}</td>
                                        <td><div className="asset-name">{e.object || 'Unknown'}</div><div className="asset-meta">{e.namespace}</div></td>
                                        <td style={{fontSize:'0.85rem', color:'var(--text-secondary)'}}>{e.message || ''}</td>
                                        <td>{e.count}</td>
                                    </tr>
                                ))}
                                {events.length === 0 && <tr><td colSpan="6" style={{textAlign:'center', padding:'2rem', color:'var(--text-secondary)'}}>No events detected.</td></tr>}
                            </tbody>
                        </table>
                    ) : activeTab === 'secrets' ? (
                        <table className="ent-table">
                            <thead><tr><th>Entity</th><th>Kind</th><th>Keys Exposing Risk</th><th>Status</th></tr></thead>
                            <tbody>
                                {getFilteredData().map((s, idx) => (
                                    <tr key={idx}>
                                        <td><div className="asset-name">{s.name}</div><div className="asset-meta">{s.namespace}</div></td>
                                        <td><span className="cis-tag">{s.kind}</span></td>
                                        <td><div style={{fontSize:'0.8rem', color:'var(--text-secondary)', maxWidth:'200px', wordWrap:'break-word'}}>{s.keys.join(', ') || 'None'}</div></td>
                                        <td>
                                            {s.risks.length > 0 ? s.risks.map((risk, ridx) => (
                                                <div key={ridx} className={`risk-pill`} style={{borderColor: risk.severity === 'Critical' ? 'var(--risk-critical)' : 'var(--risk-medium)'}}>
                                                    <span className="risk-text" style={{color: risk.severity === 'Critical' ? 'var(--risk-critical)' : 'var(--risk-medium)'}}>{risk.type}</span>
                                                </div>
                                            )) : <span className="secure-text">✓ Verified</span>}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <table className="ent-table">
                            <thead><tr><th>Resource</th><th>Status</th><th>Security Findings</th></tr></thead>
                            <tbody>
                                {getFilteredData().map((item, idx) => (
                                    <tr key={idx}>
                                        <td><div className="asset-name">{item.name}</div><div className="asset-meta">{item.namespace}</div></td>
                                        <td><div className={`severity-tag ${item.severity.toLowerCase()}`}>{item.severity}</div></td>
                                        <td>
                                            {item.risks.map((risk, ridx) => (
                                                <div key={ridx} className="risk-pill" onClick={() => setSelectedFix(risk)}>
                                                    <span className="cis-code">{risk.cis}</span>
                                                    <span className="risk-text">{risk.type}</span>
                                                </div>
                                            ))}
                                            {item.risks.length === 0 && <span className="secure-text">✓ Secure</span>}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>

                <div className="glass-card console-section">
                    <div className="console-header">Strategic Priorities</div>
                    <div className="priorities-list section-spacer">
                        {getTopPriorities().map((p, i) => (
                            <div key={i} className={`priority-item ${p.sev}`}>
                                <div className="priority-meta">
                                    <span className="priority-type">{p.type}</span>
                                    <span className="priority-target">{p.target}</span>
                                </div>
                                <div className="priority-label">{p.label}</div>
                            </div>
                        ))}
                        {getTopPriorities().length === 0 && <div className="secure-msg">✦ Cluster Baseline Secure</div>}
                    </div>

                    <div className="console-header">Enterprise Intelligence Log</div>
                    <div className="console-terminal" ref={consoleRef}>
                        {logs.map((l, i) => (
                            <div key={i} className={`log-entry ${l.level}`}>
                                <span className="log-time">[{l.timestamp}]</span>
                                <span className="log-msg" dangerouslySetInnerHTML={{ __html: l.msg }} />
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}

export default App
