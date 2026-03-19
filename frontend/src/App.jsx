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
    Host: '#8b5cf6',
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#10b981'
}

function App() {
    const [clusters, setClusters] = useState([])
    const [activeCluster, setActiveCluster] = useState('local')
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
    
    // New UX: Dashboard as default home view
    const [activeTab, setActiveTab] = useState('dashboard')
    const [activeSubTab, setActiveSubTab] = useState('Workloads') 
    const [activeVulnTab, setActiveVulnTab] = useState('pods') 
    const [search, setSearch] = useState('')
    const [selectedFix, setSelectedFix] = useState(null)
    const [filterNamespace, setFilterNamespace] = useState(null)
    const [notification, setNotification] = useState(null)
    
    const [showAddCluster, setShowAddCluster] = useState(false)
    const [newClusterName, setNewClusterName] = useState('')
    const [publicUrl, setPublicUrl] = useState('')
    const [installClusterId] = useState(`cluster-${Math.random().toString(36).substring(2, 8)}`)

    const generateInstallCommand = () => {
        const baseUrl = publicUrl.trim() || window.location.origin;
        const name = encodeURIComponent(newClusterName.trim() || "Remote Cluster");
        return `kubectl apply -f "${baseUrl}/api/agent/install?cluster_id=${installClusterId}&cluster_name=${name}"`;
    }

    const fetchData = async () => {
        try {
            const [clusRes, sumRes, podsRes, polRes, rbacRes, heatRes, radarRes, invRes, vulnRes, trendsRes, compRes, metricsRes, evRes, secRes, logRes] = await Promise.all([
                fetch(`${API_BASE}/api/clusters`),
                fetch(`${API_BASE}/api/summary?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/pods?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/network-policies?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/rbac?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/heatmap?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/radar?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/inventory?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/vulnerabilities?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/trends?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/compliance?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/metrics?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/events?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/secrets?cluster_id=${activeCluster}`),
                fetch(`${API_BASE}/api/logs?cluster_id=${activeCluster}`)
            ])

            setClusters(await clusRes.json())
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
                    cluster_id: activeCluster,
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
                fetchData()
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
            pods.forEach(p => p.risks.forEach(r => allFindings.push({ Type: 'Pod Configuration', Target: p.name, Namespace: p.namespace, Issue: r.type, CIS: r.cis, Severity: p.severity })))
            rbac.forEach(r => r.risks.forEach(risk => allFindings.push({ Type: 'RBAC', Target: r.name, Namespace: r.namespace, Issue: risk.type, CIS: risk.cis, Severity: r.severity })))
            policies.forEach(p => p.risks.forEach(r => allFindings.push({ Type: 'Network Policy', Target: p.name, Namespace: p.namespace, Issue: r.type, CIS: r.cis, Severity: p.severity })))
            Object.values(vulnerabilities).flat().forEach(v => allFindings.push({ Type: 'Vulnerability', Target: v.target, Namespace: v.namespace || 'Cluster', Issue: v.id || v.title, CIS: 'N/A', Severity: v.severity }))

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
            link.setAttribute("download", `shieldkube_audit_${new Date().toISOString().split('T')[0]}.csv`)
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)

            setNotification({ type: 'success', msg: "Audit CSV exported successfully!" })
        } catch (err) {
            setNotification({ type: 'error', msg: "Export failed." })
        }
    }

    useEffect(() => {
        fetchData()
        const interval = setInterval(fetchData, 8000)
        return () => clearInterval(interval)
    }, [activeCluster])

    const consoleRef = useRef(null)
    useEffect(() => {
        if (!loading && logs.length > 0 && consoleRef.current) {
            const container = consoleRef.current
            container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' })
        }
    }, [logs, loading, activeTab])

    const getFilteredData = () => {
        let data = []
        if (activeTab === 'pods') data = pods
        else if (activeTab === 'policies') data = policies
        else if (activeTab === 'rbac') data = rbac
        else if (activeTab === 'inventory') data = inventory.filter(i => i.group === activeSubTab)
        else if (activeTab === 'vulnerabilities') data = vulnerabilities[activeVulnTab] || []
        else if (activeTab === 'secrets') data = secrets

        if (filterNamespace) data = data.filter(item => item.namespace === filterNamespace || item.namespace === "Global" || item.namespace === "Cluster-wide")
        return data.filter(item => (item.name || item.target || item.image || "").toLowerCase().includes(search.toLowerCase()))
    }

    const namespaces = Array.from(new Set(inventory.map(i => i.namespace).filter(n => n && n !== "Global" && n !== "Cluster-wide")))
    const getScoreColor = (score) => {
        if (score > 80) return COLORS.Low
        if (score > 50) return COLORS.Medium
        return COLORS.Critical
    }

    const getTopPriorities = () => {
        const priorities = []
        Object.values(vulnerabilities).flat().filter(v => v.severity === 'Critical' || v.severity === 'High').slice(0, 2).forEach(v => {
            priorities.push({ type: 'CVE', label: v.id, target: v.target, sev: 'critical' })
        })
        pods.filter(p => p.severity === 'Critical').slice(0, 1).forEach(p => {
            priorities.push({ type: 'Runtime', label: 'Privileged Container', target: p.name, sev: 'critical' })
        })
        rbac.filter(r => r.severity === 'High').slice(0, 1).forEach(r => {
            priorities.push({ type: 'IAM', label: 'Wildcard Permissions', target: r.name, sev: 'high' })
        })
        return priorities.slice(0, 4)
    }

    if (loading && !summary) return <div style={{display:'flex', alignItems:'center', justifyContent:'center', height:'100vh'}}><h1>Calibrating Kube Engine...</h1></div>

    const renderModals = () => (
        <>
            {selectedFix && (
                <div className="drawer-overlay" onClick={() => setSelectedFix(null)}>
                    <div className="right-drawer" onClick={e => e.stopPropagation()}>
                        <div className="drawer-header">
                            <div>
                                <h3>Remediation Blueprint</h3>
                                <p>{selectedFix.target}</p>
                            </div>
                            <button className="drawer-close" onClick={() => setSelectedFix(null)}>×</button>
                        </div>
                        <div className="drawer-body">
                            <p style={{marginTop:0}}><strong>Intelligence:</strong> Apply this patch to resolve <b style={{color: 'var(--risk-crit)'}}>{selectedFix.type || selectedFix.id}</b>.</p>
                            <div className="yaml-box">
                                <pre>{selectedFix.patch || `Remediation Plan:\n1. Pull patched image\n2. Update ${selectedFix.target} spec\n3. Roll out update`}</pre>
                            </div>
                        </div>
                        <div className="drawer-footer">
                            <button className="glass-button secondary">Copy Patch</button>
                            <button className="glass-button primary" onClick={() => handleRemediate(selectedFix)}>Deploy Fix</button>
                        </div>
                    </div>
                </div>
            )}
            {showAddCluster && (
                <div className="fix-modal-overlay" onClick={() => setShowAddCluster(false)}>
                    <div className="fix-modal glass-card" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Connect Remote Cluster</h3>
                            <button className="close-btn" onClick={() => setShowAddCluster(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>Run the command below on any machine that has <code>kubectl</code> access to the target cluster. The agent will auto-install and start sending security data back to ShieldKube.</p>
                            <div style={{margin: '1rem 0'}}>
                                <label style={{fontSize: '0.9rem', color: '#94a3b8', display: 'block', marginBottom: '0.5rem'}}>🌐 ShieldKube Public URL <span style={{color: '#ef4444'}}>*</span></label>
                                <input type="text" value={publicUrl} onChange={(e) => setPublicUrl(e.target.value)} placeholder="e.g. http://203.0.113.5:8000" className="glass-select" style={{width: '100%', border: `1px solid ${publicUrl.trim() ? 'rgba(34,197,94,0.5)' : 'rgba(239,68,68,0.5)'}`}} />
                                <p style={{fontSize: '0.78rem', color: '#64748b', marginTop: '0.3rem'}}>⚠️ Must be reachable from the remote cluster — <strong>not localhost</strong>.</p>
                            </div>
                            <div style={{margin: '1rem 0'}}>
                                <label style={{fontSize: '0.9rem', color: '#94a3b8', display: 'block', marginBottom: '0.5rem'}}>Cluster Name:</label>
                                <input type="text" value={newClusterName} onChange={(e) => setNewClusterName(e.target.value)} placeholder="e.g. AWS Production Ops" className="glass-select" style={{width: '100%'}} />
                            </div>
                            <div className="yaml-box" style={{marginTop: '1rem'}}><pre style={{whiteSpace: 'pre-wrap', wordBreak: 'break-all'}}>{generateInstallCommand()}</pre></div>
                            <div className="modal-actions" style={{marginTop: '1.5rem'}}>
                                <button className="glass-button primary" onClick={() => { navigator.clipboard.writeText(generateInstallCommand()); setNotification({type: 'success', msg: 'Command copied!'}); setShowAddCluster(false); }}>Copy Command</button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
            {notification && (
                <div className={`notification-toast ${notification.type}`}>
                    <span className="toast-icon">{notification.type === 'success' ? '✓' : '⚠'}</span>
                    {notification.msg}
                </div>
            )}
        </>
    )

    // Calculate percentage circumference for SVG rating circle
    const circumference = 2 * Math.PI * 50;
    const strokeDashoffset = summary ? circumference - (summary.security_score / 100) * circumference : circumference;

    return (
        <div className="app-layout">
            {renderModals()}

            {/* Premium Sidebar Component */}
            <aside className="sidebar">
                <div className="brand-header">
                    <div className="logo-icon"><span>SK</span></div>
                    <div>
                        <h1>ShieldKube</h1>
                        <span className="version-tag">Enterprise v7.2</span>
                    </div>
                </div>

                <div className="nav-menu">
                    <div style={{fontSize:'0.65rem', fontWeight:700, color:'var(--text-secondary)', padding:'1rem 0.5rem 0.5rem', textTransform:'uppercase', letterSpacing:'0.1em'}}>Overview</div>
                    <button onClick={() => { setActiveTab('dashboard'); setFilterNamespace(null); setSearch(''); }} className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}>
                        <span className="nav-icon">◱</span> Dashboard
                    </button>
                    
                    <div style={{fontSize:'0.65rem', fontWeight:700, color:'var(--text-secondary)', padding:'1rem 0.5rem 0.5rem', textTransform:'uppercase', letterSpacing:'0.1em'}}>Security Posture</div>
                    {['pods', 'policies', 'rbac', 'vulnerabilities', 'compliance', 'secrets'].map(t => (
                        <button key={t} onClick={() => { setActiveTab(t); if(!['pods','inventory','vulnerabilities','secrets'].includes(t)) setFilterNamespace(null); }} className={`nav-item ${activeTab === t ? 'active' : ''}`}>
                            <span className="nav-icon">⬡</span> {t.charAt(0).toUpperCase() + t.slice(1).replace('_', ' ')}
                        </button>
                    ))}

                    <div style={{fontSize:'0.65rem', fontWeight:700, color:'var(--text-secondary)', padding:'1rem 0.5rem 0.5rem', textTransform:'uppercase', letterSpacing:'0.1em'}}>Operations</div>
                    {['inventory', 'monitoring', 'events', 'logs'].map(t => (
                        <button key={t} onClick={() => { setActiveTab(t); setFilterNamespace(null); }} className={`nav-item ${activeTab === t ? 'active' : ''}`}>
                            <span className="nav-icon">◉</span> {t.charAt(0).toUpperCase() + t.slice(1)}
                        </button>
                    ))}
                </div>
            </aside>

            {/* Main Content Area */}
            <main className="main-area">
                {/* Horizontal Top Bar */}
                <header className="top-bar">
                    <div className="flex-gap">
                        <div className="page-title">{activeTab.replace('_', ' ')}</div>
                        <div className="status-badge"><span className="pulse-dot"></span> Defense Active</div>
                    </div>
                    
                    <div className="flex-gap">
                        {['pods', 'inventory', 'vulnerabilities'].includes(activeTab) && (
                            <select className="glass-select" value={filterNamespace || ""} onChange={(e) => setFilterNamespace(e.target.value || null)}>
                                <option value="">All Namespaces</option>
                                {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
                            </select>
                        )}
                        {activeTab !== 'dashboard' && activeTab !== 'compliance' && activeTab !== 'monitoring' && (
                            <div className="search-wrapper">
                                <input type="text" placeholder={`Search ${activeTab}...`} value={search} onChange={e => setSearch(e.target.value)} />
                                <span className="search-hint">⌘K</span>
                            </div>
                        )}
                        
                        {clusters.length > 0 && (
                            <>
                                <select className="glass-select" value={activeCluster} onChange={e => { setActiveCluster(e.target.value); setLoading(true); }}>
                                    {clusters.map(c => <option key={c.id} value={c.id}>{c.name} {c.status === 'Offline' ? '(Offline)' : ''}</option>)}
                                </select>
                                <button className="glass-button secondary" onClick={() => setShowAddCluster(true)}>＋ Add Cluster</button>
                            </>
                        )}
                    </div>
                </header>

                {/* Dashboard / Content */}
                <div className="content-wrapper">
                    
                    {activeTab === 'dashboard' && summary && (
                        <>
                            {/* Hero Card */}
                            <div className="global-posture-card glass-card">
                                <div className="hero-left">
                                    <svg viewBox="0 0 120 120" className="circular-chart">
                                        <g transform="translate(60,60)">
                                            <circle r="50" className="circle-bg" />
                                            <circle r="50" className="circle" strokeDasharray={circumference} strokeDashoffset={strokeDashoffset} stroke={getScoreColor(summary.security_score)} transform="rotate(-90)" />
                                            <text x="0" y="5" className="percentage">{summary.security_score}%</text>
                                        </g>
                                    </svg>
                                    <div className="hero-text">
                                        <h2>Global Posture Rating</h2>
                                        <p>Cluster identity and isolation integrity.</p>
                                    </div>
                                </div>
                                <div className="flex-gap">
                                    <button className="glass-button secondary" onClick={handleExport}>⭳ Export Report</button>
                                    <button className="glass-button primary" onClick={() => setActiveTab('vulnerabilities')}>Start Remediation</button>
                                </div>
                            </div>

                            {/* Metrics Strip */}
                            <div className="metrics-grid">
                                {[
                                    { label: 'Infrastructure CVEs', value: summary.total_vulnerabilities, color: COLORS.High },
                                    { label: 'Sensitive RBAC', value: rbac.length, color: COLORS.Network },
                                    { label: 'Managed Assets', value: inventory.length, color: COLORS.Images },
                                    { label: 'Network Isolation', value: policies.length > 0 ? 'Active' : 'Missing', color: policies.length > 0 ? COLORS.Low : COLORS.Critical }
                                ].map((m, i) => (
                                    <div key={i} className="glass-card compact-metric">
                                        <div className="metric-header">
                                            <span className="metric-label">{m.label}</span>
                                            <div className="metric-val" style={{ color: m.color }}>{m.value}</div>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {/* Charts */}
                            <div className="dashboard-visuals-grid">
                                <div className="glass-card chart-item">
                                    <h3>Security Score Trend</h3>
                                    <ResponsiveContainer width="100%" height={260}>
                                        <LineChart data={trends}>
                                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                                            <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                                            <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                                            <ReTooltip contentStyle={{ background: '#09090b', border: '1px solid #27272a', borderRadius: '8px' }} />
                                            <ReLegend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                                            <Line type="monotone" dataKey="score" stroke="#0ea5e9" strokeWidth={3} dot={{ fill: '#0ea5e9', r: 4 }} activeDot={{ r: 6 }} name="Posture Score" />
                                            <Line type="monotone" dataKey="criticals" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444', r: 3 }} name="Critical Risks" />
                                        </LineChart>
                                    </ResponsiveContainer>
                                </div>
                                <div className="glass-card chart-item">
                                    <h3>Risk Category Radar</h3>
                                    <ResponsiveContainer width="100%" height={260}>
                                        <RadarChart cx="50%" cy="50%" outerRadius="75%" data={radarData}>
                                            <PolarGrid stroke="rgba(255,255,255,0.1)" />
                                            <PolarAngleAxis dataKey="subject" tick={{ fill: '#a1a1aa', fontSize: 11 }} />
                                            <PolarRadiusAxis angle={30} domain={[0, 15]} tick={false} axisLine={false} />
                                            <Radar name="Risks" dataKey="A" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.4} />
                                            <ReTooltip contentStyle={{ background: '#09090b', border: '1px solid #27272a', borderRadius: '8px' }} />
                                        </RadarChart>
                                    </ResponsiveContainer>
                                </div>
                                <div className="glass-card chart-item">
                                    <h3>Namespace Vulnerabilities</h3>
                                    <ResponsiveContainer width="100%" height={260}>
                                        <BarChart data={heatmap}>
                                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                                            <XAxis dataKey="namespace" stroke="#64748b" fontSize={11} />
                                            <YAxis stroke="#64748b" fontSize={11} />
                                            <ReTooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ background: '#09090b', border: '1px solid #27272a', borderRadius: '8px' }} />
                                            <Bar dataKey="total" fill="#0ea5e9" radius={[4, 4, 0, 0]} onClick={(d) => { setFilterNamespace(d.namespace); setActiveTab('pods') }} style={{ cursor: 'pointer' }} />
                                        </BarChart>
                                    </ResponsiveContainer>
                                </div>
                            </div>
                        </>
                    )}

                    {/* Content Views */}
                    {activeTab !== 'dashboard' && (
                        <div className="main-content-grid" style={{ gridTemplateColumns: (activeTab === 'compliance' || activeTab === 'monitoring') ? '1fr' : '1fr 350px' }}>
                            <div className="glass-card visual-section" style={{ minHeight: '600px'}}>
                                
                                {activeTab === 'compliance' && (
                                    <div className="compliance-grid">
                                        {compliance.map((c, idx) => (
                                            <div key={idx} className="glass-card compliance-card" style={{background: 'rgba(255,255,255,0.02)'}}>
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
                                )}

                                {activeTab === 'monitoring' && (
                                    <div className="monitoring-view">
                                        <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2rem'}}>
                                            <div className="glass-card metric-card" style={{background: 'rgba(255,255,255,0.02)'}}>
                                                <h4 style={{marginBottom:'1rem', fontSize:'0.85rem', color:'var(--text-secondary)', textTransform:'uppercase'}}>Node Utilization</h4>
                                                <ResponsiveContainer width="100%" height={220}>
                                                    <BarChart data={metrics.nodes}>
                                                        <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                                                        <YAxis unit="%" stroke="#64748b" fontSize={10} />
                                                        <ReTooltip contentStyle={{ background: '#09090b', border: '1px solid #27272a', borderRadius:'8px' }} />
                                                        <Bar dataKey="cpu_usage" fill="#0ea5e9" name="CPU Usage %" radius={[4, 4, 0, 0]} />
                                                        <Bar dataKey="mem_usage" fill="#8b5cf6" name="Mem Usage %" radius={[4, 4, 0, 0]} />
                                                    </BarChart>
                                                </ResponsiveContainer>
                                            </div>
                                            <div className="glass-card metric-card" style={{background: 'rgba(255,255,255,0.02)'}}>
                                                <h4 style={{marginBottom:'1rem', fontSize:'0.85rem', color:'var(--text-secondary)', textTransform:'uppercase'}}>Pod CPU Distribution</h4>
                                                <ResponsiveContainer width="100%" height={220}>
                                                    <PieChart>
                                                        <Pie data={metrics.pods} dataKey="cpu_usage" nameKey="name" cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5}>
                                                            {metrics.pods.map((_, index) => <Cell key={index} fill={index % 2 === 0 ? '#0ea5e9' : '#8b5cf6'} />)}
                                                        </Pie>
                                                        <ReTooltip contentStyle={{ background: '#09090b', border: '1px solid #27272a', borderRadius:'8px' }} />
                                                    </PieChart>
                                                </ResponsiveContainer>
                                            </div>
                                        </div>
                                        
                                        <table className="ent-table">
                                            <thead><tr><th>Node</th><th>CPU Scale</th><th>Memory Scale</th><th>CPU Usage</th><th>Mem Usage</th></tr></thead>
                                            <tbody>
                                                {metrics.nodes.map((n, idx) => (
                                                    <tr key={idx}>
                                                        <td><div className="asset-name">{n.name}</div></td>
                                                        <td>{n.cpu}</td>
                                                        <td>{n.memory}</td>
                                                        <td><div className={`severity-tag ${n.cpu_usage > 80 ? 'critical' : 'low'}`}>{n.cpu_usage}%</div></td>
                                                        <td><div className={`severity-tag ${n.mem_usage > 80 ? 'critical' : 'low'}`}>{n.mem_usage}%</div></td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>

                                        <h4 style={{marginTop:'3rem', marginBottom:'1rem', fontSize:'0.85rem', color:'var(--text-secondary)', textTransform:'uppercase'}}>Active Pod Telemetry</h4>
                                        <table className="ent-table">
                                            <thead><tr><th>Pod Identity</th><th>Live CPU Utilization</th><th>Live Memory Utilization</th></tr></thead>
                                            <tbody>
                                                {metrics.pods.map((p, idx) => (
                                                    <tr key={idx}>
                                                        <td>
                                                            <div className="asset-name" style={{fontSize: '0.9rem'}}>{p.name}</div>
                                                            <div className="asset-meta"><span className="ns-pill">{p.namespace}</span></div>
                                                        </td>
                                                        <td>
                                                            <div style={{display:'flex', alignItems:'center', gap:'0.75rem'}}>
                                                                <span style={{fontFamily:'Outfit', fontWeight:700, width:'40px', fontSize:'0.9rem'}}>{p.cpu_usage}%</span>
                                                                <div className="inline-gauge-container"><div className="inline-gauge-fill" style={{width: `${p.cpu_usage}%`, background: p.cpu_usage > 80 ? 'var(--risk-crit)' : 'var(--accent-cyan)'}}></div></div>
                                                            </div>
                                                        </td>
                                                        <td>
                                                            <div style={{display:'flex', alignItems:'center', gap:'0.75rem'}}>
                                                                <span style={{fontFamily:'Outfit', fontWeight:700, width:'40px', fontSize:'0.9rem'}}>{p.mem_usage}%</span>
                                                                <div className="inline-gauge-container"><div className="inline-gauge-fill" style={{width: `${p.mem_usage}%`, background: p.mem_usage > 80 ? 'var(--risk-crit)' : 'var(--accent-purple)'}}></div></div>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}

                                {activeTab === 'inventory' && (
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
                                                    <tr key={idx}>
                                                        <td><div className="asset-name">{i.name}</div></td>
                                                        <td>{i.namespace}</td>
                                                        <td><span className="cis-code" style={{border:'none'}}>{i.kind}</span></td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </>
                                )}

                                {activeTab === 'vulnerabilities' && (
                                    <>
                                        <div className="sub-tabs-list">
                                            {['pods', 'nodes', 'volumes', 'replica_sets', 'deployments', 'infrastructure'].map(vt => (
                                                <button key={vt} onClick={() => setActiveVulnTab(vt)} className={`sub-tab-item ${activeVulnTab === vt ? 'active' : ''}`}>
                                                    {vt.replace('_', ' ')} ({vulnerabilities[vt]?.length || 0})
                                                </button>
                                            ))}
                                        </div>
                                        <table className="ent-table">
                                            <thead><tr><th>Target Segment</th><th>CVE Signature</th><th>Severity</th><th>Action</th></tr></thead>
                                            <tbody>
                                                {getFilteredData().map((v, idx) => (
                                                    <tr key={idx}>
                                                        <td><div className="asset-name">{v.target}</div><div className="asset-meta">{v.image || 'Infrastructure'}</div></td>
                                                        <td><span className="v-tag" style={{fontFamily:'Fira Code, monospace', color:'var(--accent-cyan)'}}>{v.id || v.cve_id}</span></td>
                                                        <td><div className={`severity-tag ${v.severity.toLowerCase()}`}>{v.severity}</div></td>
                                                        <td><button className="fix-btn" onClick={() => setSelectedFix(v)}>Remediate</button></td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </>
                                )}

                                {activeTab === 'events' && (
                                    <table className="ent-table">
                                        <thead><tr><th>Timestamp</th><th>Type</th><th>Object</th><th>Message</th></tr></thead>
                                        <tbody>
                                            {events.filter(e => (e.message || '').toLowerCase().includes(search.toLowerCase()) || (e.object || '').toLowerCase().includes(search.toLowerCase())).map((e, idx) => (
                                                <tr key={idx}>
                                                    <td style={{whiteSpace:'nowrap', fontSize:'0.8rem'}}>{e.time ? e.time.split('.')[0].replace('T', ' ').replace('+00:00', '') : 'N/A'}</td>
                                                    <td><div className={`severity-tag ${e.type === 'Warning' ? 'high' : 'low'}`}>{e.type || 'Normal'}</div></td>
                                                    <td><div className="asset-name">{e.object || 'Unknown'}</div><div className="asset-meta">{e.namespace}</div></td>
                                                    <td style={{fontSize:'0.85rem', color:'var(--text-secondary)'}}>{e.message || ''}</td>
                                                </tr>
                                            ))}
                                            {events.length === 0 && <tr><td colSpan="4" style={{textAlign:'center', padding:'2rem', color:'var(--text-secondary)'}}>No events detected.</td></tr>}
                                        </tbody>
                                    </table>
                                )}

                                {activeTab === 'secrets' && (
                                    <table className="ent-table">
                                        <thead><tr><th>Entity</th><th>Keys Exposing Risk</th><th>Status</th></tr></thead>
                                        <tbody>
                                            {getFilteredData().map((s, idx) => (
                                                <tr key={idx}>
                                                    <td><div className="asset-name">{s.name}</div><div className="asset-meta">{s.namespace} • <span style={{color:'var(--accent-purple)'}}>{s.kind}</span></div></td>
                                                    <td><div style={{fontSize:'0.8rem', color:'var(--text-secondary)', maxWidth:'250px', wordWrap:'break-word'}}>{s.keys.join(', ') || 'None'}</div></td>
                                                    <td>
                                                        {s.risks.length > 0 ? s.risks.map((risk, ridx) => (
                                                            <div key={ridx} className={`severity-tag ${risk.severity.toLowerCase()}`} style={{margin:'2px'}}>
                                                                {risk.type}
                                                            </div>
                                                        )) : <span className="severity-tag low">✓ Verified Secure</span>}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}

                                {/* Fallback for pods, policies, rbac, logs where lists apply similarly */}
                                {['pods', 'policies', 'rbac', 'logs'].includes(activeTab) && (
                                    <table className="ent-table">
                                        <thead><tr><th>Resource</th><th>Risk Status</th><th>Security Findings</th></tr></thead>
                                        <tbody>
                                            {getFilteredData().map((item, idx) => (
                                                <tr key={idx}>
                                                    <td><div className="asset-name">{item.name}</div><div className="asset-meta">{item.namespace}</div></td>
                                                    <td><div className={`severity-tag ${item.severity?.toLowerCase() || 'low'}`}>{item.severity || 'Secure'}</div></td>
                                                    <td>
                                                        {item.risks?.map((risk, ridx) => (
                                                            <div key={ridx} className="risk-pill" onClick={() => setSelectedFix(risk)}>
                                                                <span className="cis-code">{risk.cis}</span>
                                                                <span className="risk-text">{risk.type}</span>
                                                            </div>
                                                        ))}
                                                        {(!item.risks || item.risks.length === 0) && <span className="severity-tag low" style={{background:'transparent', padding:0}}>✓ Secure Posture</span>}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}
                            </div>

                            {/* Persistent Right Side Console (Only when not full-width view) */}
                            {activeTab !== 'compliance' && activeTab !== 'monitoring' && (
                                <div className="console-section">
                                    <div className="console-header">Strategic Priorities</div>
                                    <div style={{marginBottom: '1rem'}}>
                                        {getTopPriorities().map((p, i) => (
                                            <div key={i} className={`priority-item ${p.sev}`}>
                                                <div className="priority-meta">
                                                    <span className="priority-type">{p.type}</span>
                                                    <span className="priority-target">{p.target}</span>
                                                </div>
                                                <div className="priority-label">{p.label}</div>
                                            </div>
                                        ))}
                                        {getTopPriorities().length === 0 && <div className="severity-tag low" style={{display:'block', textAlign:'center', padding:'1rem'}}>✦ Cluster Baseline Secure</div>}
                                    </div>

                                    <div className="console-header">Enterprise Intelligence Log</div>
                                    <div className="console-terminal" ref={consoleRef}>
                                        {logs.map((l, i) => (
                                            <div key={i} className={`log-entry ${l.level}`}>
                                                <span className="log-time">[{l.timestamp}]</span>
                                                <span className="log-msg" dangerouslySetInnerHTML={{ __html: l.msg }} />
                                            </div>
                                        ))}
                                        {logs.length === 0 && <span style={{color:'var(--text-muted)'}}>Awaiting telemetry stream...</span>}
                                    </div>
                                </div>
                            )}

                        </div>
                    )}
                </div>
            </main>
        </div>
    )
}

export default App
