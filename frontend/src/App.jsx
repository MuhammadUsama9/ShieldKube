import React, { useState, useEffect, useRef } from 'react'
import {
    PieChart, Pie, Cell, ResponsiveContainer, Tooltip as ReTooltip,
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend as ReLegend,
    Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
    LineChart, Line
} from 'recharts'

const API_BASE = `${window.location.protocol}//${window.location.hostname}:8000`
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
    const [topology, setTopology] = useState({ nodes: [], links: [] })
    const [rbacGraph, setRbacGraph] = useState({ nodes: [], links: [] })
    const [advisories, setAdvisories] = useState([])

    const sidebarItems = [
        { id: 'dashboard', label: 'Dashboard', icon: '📊' },
        { id: 'inventory', label: 'Inventory', icon: '📦' },
        { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🛡️' },
        { id: 'compliance', label: 'Compliance', icon: '📋' },
        { id: 'network', label: 'Network Map', icon: '🕸️' },
        { id: 'rbac', label: 'RBAC Vision', icon: '🕸️' },
        { id: 'advisories', label: 'Advisories', icon: '💡' },
        { id: 'monitoring', label: 'Monitoring', icon: '📈' },
        { id: 'events', label: 'Events', icon: '🔔' },
        { id: 'agent', label: 'Agent Install', icon: '🚀' }
    ]
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
        return `kubectl apply -f "${baseUrl}/api/agent/install?cluster_id=${installClusterId}&cluster_name=${name}&base_url=${encodeURIComponent(baseUrl)}"`;
    }

    const [error, setError] = useState(null);

    const fetchData = async () => {
        setLoading(true);
        setError(null);
        
        const fetchResource = async (path, setter, defaultValue) => {
            try {
                const response = await fetch(`${API_BASE}${path}`);
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data = await response.json();
                setter(data);
            } catch (err) {
                console.error(`Error fetching ${path}:`, err);
                if (defaultValue !== undefined) setter(defaultValue);
            }
        };

        try {
            // Priority 1: Bootstrap critical data in one go
            const bootResponse = await fetch(`${API_BASE}/api/dashboard/bootstrap/${activeCluster}`);
            if (bootResponse.ok) {
                const bootData = await bootResponse.json();
                setClusters(bootData.clusters || []);
                setSummary(bootData.summary);
                setPods(bootData.pods || []);
                setVulnerabilities(bootData.vulnerabilities || { pods: [], nodes: [], volumes: [], replica_sets: [], deployments: [], infrastructure: [] });
                setRadarData(bootData.radar || []);
            } else {
                throw new Error(`Bootstrap failed: ${bootResponse.statusText}`);
            }

            // Priority 2: Non-blocking supplemental data (Fire and forget)
            Promise.all([
                fetchResource(`/api/network-policies?cluster_id=${activeCluster}`, setPolicies, []),
                fetchResource(`/api/rbac?cluster_id=${activeCluster}`, setRbac, []),
                fetchResource(`/api/heatmap?cluster_id=${activeCluster}`, setHeatmap, []),
                fetchResource(`/api/inventory?cluster_id=${activeCluster}`, setInventory, []),
                fetchResource(`/api/trends?cluster_id=${activeCluster}`, setTrends, []),
                fetchResource(`/api/compliance?cluster_id=${activeCluster}`, setCompliance, []),
                fetchResource(`/api/metrics?cluster_id=${activeCluster}`, setMetrics, { pods: [], nodes: [] }),
                fetchResource(`/api/events?cluster_id=${activeCluster}`, setEvents, []),
                fetchResource(`/api/secrets?cluster_id=${activeCluster}`, setSecrets, []),
                fetchResource(`/api/logs?cluster_id=${activeCluster}`, setLogs, []),
                fetchResource(`/api/topology?cluster_id=${activeCluster}`, setTopology, { nodes: [], links: [] }),
                fetchResource(`/api/rbac/graph?cluster_id=${activeCluster}`, setRbacGraph, { nodes: [], links: [] }),
                fetchResource(`/api/advisories?cluster_id=${activeCluster}`, setAdvisories, [])
            ]);
        } catch (err) {
            console.error("Critical fetch error:", err);
            setError(err.message || "Network Error: Could not connect to ShieldKube Backend.");
        } finally {
            setLoading(false);
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

    const handleRemoveCluster = async (id) => {
        try {
            await fetch(`${API_BASE}/api/clusters/${id}`, { method: 'DELETE' })
            setNotification({ type: 'success', msg: 'Cluster disconnected remotely.' })
            setActiveCluster('local')
            fetchData()
        } catch (err) {
            setNotification({ type: 'error', msg: `Disconnect failed: ${err.message}` })
        }
    }

    useEffect(() => {
        fetchData()
        const interval = setInterval(fetchData, 8000)
        return () => clearInterval(interval)
    }, [activeCluster])

    // UI Components
    const SeverityBadge = ({ level }) => {
        const lv = level?.toLowerCase() || 'low';
        return <span className={`severity-tag ${lv}`}>{level || 'Low'}</span>;
    };

    const StatusBadge = ({ pods }) => {
        const hasCritical = pods.some(p => p.severity === 'Critical');
        const hasHigh = pods.some(p => p.severity === 'High');
        if (hasCritical) return <div className="status-badge" style={{color: 'var(--risk-crit)', background: 'rgba(244,63,94,0.1)', borderColor: 'rgba(244,63,94,0.2)'}}><span className="pulse-dot" style={{background: 'var(--risk-crit)'}}></span>Action Required</div>;
        if (hasHigh) return <div className="status-badge" style={{color: 'var(--risk-high)', background: 'rgba(251,146,60,0.1)', borderColor: 'rgba(251,146,60,0.2)'}}><span className="pulse-dot" style={{background: 'var(--risk-high)'}}></span>Attention Needed</div>;
        return <div className="status-badge"><span className="pulse-dot"></span>System Healthy</div>;
    };

    const MiniGauge = ({ val, color }) => (
        <div className="inline-gauge-container">
            <div className="inline-gauge-fill" style={{ width: `${val}%`, background: color }}></div>
        </div>
    );

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

    if (loading && !summary) {
        return (
            <div style={{display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:'100vh', background:'#0f172a', color:'white', fontFamily:'sans-serif'}}>
                <div style={{fontSize:'2rem', fontWeight:'bold', marginBottom:'20px', animation:'pulse 2s infinite'}}>ShieldKube Enterprise</div>
                <div style={{fontSize:'1.2rem', color:'#94a3b8'}}>Calibrating Kube Engine...</div>
                
                {error && (
                    <div style={{marginTop:'40px', padding:'20px', background:'#1e293b', borderRadius:'10px', border:'1px solid #334155', maxWidth:'500px', textAlign:'center'}}>
                        <div style={{color:'#f87171', marginBottom:'20px', fontWeight:'bold'}}>Connectivity Issue Detected</div>
                        <div style={{color:'#94a3b8', fontSize:'0.9rem', marginBottom:'30px'}}>{error}</div>
                        <div style={{display:'flex', gap:'15px', justifyContent:'center'}}>
                            <button onClick={fetchData} style={{padding:'10px 20px', background:'#3b82f6', border:'none', borderRadius:'6px', color:'white', cursor:'pointer', fontWeight:'bold'}}>Retry Connection</button>
                            <button onClick={() => {
                                setSummary({
                                    total_pods: 0, total_policies: 0, total_rbac: 0, total_vulnerabilities: 0, total_risks: 0, 
                                    security_score: 100, severity_distribution: { Critical: 0, High: 0, Medium: 0, Low: 0 }
                                });
                                setLoading(false);
                            }} style={{padding:'10px 20px', background:'#475569', border:'none', borderRadius:'6px', color:'white', cursor:'pointer'}}>Launch Simulation</button>
                        </div>
                    </div>
                )}
            </div>
        )
    }

    // ──────────────────────────────────────────────────────────────────────────
    // MONITORING – Premium Redesign
    // ──────────────────────────────────────────────────────────────────────────
    const renderMonitoring = () => {
        const totalPods   = metrics.pods.length
        const healthyPods = metrics.pods.filter(p => p.cpu_usage < 70 && p.mem_usage < 70).length
        const warnPods    = metrics.pods.filter(p => (p.cpu_usage >= 70 && p.cpu_usage < 90) || (p.mem_usage >= 70 && p.mem_usage < 90)).length
        const critPods    = metrics.pods.filter(p => p.cpu_usage >= 90 || p.mem_usage >= 90).length
        const avgCpu      = totalPods > 0 ? Math.round(metrics.pods.reduce((a, p) => a + p.cpu_usage, 0) / totalPods) : 0
        const avgMem      = totalPods > 0 ? Math.round(metrics.pods.reduce((a, p) => a + p.mem_usage, 0) / totalPods) : 0

        const clusterOk   = critPods === 0 && warnPods < 3
        const clusterColor = critPods > 0 ? '#ef4444' : warnPods > 0 ? '#f97316' : '#22c55e'
        const clusterLabel = critPods > 0 ? 'Action Required' : warnPods > 0 ? 'Degraded Performance' : 'All Systems Operational'

        const pctColor = v => v >= 90 ? '#ef4444' : v >= 70 ? '#f97316' : '#22c55e'
        const pctLabel = v => v >= 90 ? 'Critical' : v >= 70 ? 'Warning' : 'Healthy'

        // SVG circular gauge helper
        const CircleGauge = ({ pct, color, label, sublabel, size = 110 }) => {
            const r = size / 2 - 10
            const circ = 2 * Math.PI * r
            const dash = (pct / 100) * circ
            return (
                <div style={{display:'flex', flexDirection:'column', alignItems:'center', gap:'0.5rem'}}>
                    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{transform:'rotate(-90deg)'}}>
                        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10"/>
                        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth="10"
                            strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
                            style={{transition:'stroke-dasharray 1s ease'}}/>
                        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central"
                            style={{fill:'#fff', fontSize:'18px', fontWeight:800, fontFamily:'Outfit', transform:'rotate(90deg)', transformOrigin:'center'}}>
                            {pct}%
                        </text>
                    </svg>
                    <div style={{textAlign:'center'}}>
                        <div style={{fontWeight:700, fontSize:'0.85rem'}}>{label}</div>
                        <div style={{fontSize:'0.72rem', color:'var(--text-secondary)', marginTop:'2px'}}>{sublabel}</div>
                    </div>
                </div>
            )
        }

        const noMetrics = metrics.pods.length === 0 && metrics.nodes.length === 0

        return (
        <div style={{display:'flex', flexDirection:'column', gap:'1.5rem'}}>

            {/* ── Overall Cluster Health Banner ── */}
            <div style={{
                borderRadius:'16px', padding:'1.25rem 1.75rem',
                background: `linear-gradient(135deg, ${clusterColor}15 0%, ${clusterColor}05 100%)`,
                border:`1px solid ${clusterColor}40`,
                display:'flex', alignItems:'center', justifyContent:'space-between'
            }}>
                <div style={{display:'flex', alignItems:'center', gap:'1rem'}}>
                    <div style={{
                        width:'48px', height:'48px', borderRadius:'50%',
                        background:`${clusterColor}20`, display:'flex', alignItems:'center', justifyContent:'center',
                        fontSize:'1.5rem', border:`2px solid ${clusterColor}60`
                    }}>
                        {critPods > 0 ? '🚨' : warnPods > 0 ? '⚠️' : '✅'}
                    </div>
                    <div>
                        <div style={{fontWeight:800, fontSize:'1.15rem', color:clusterColor}}>{clusterLabel}</div>
                        <div style={{fontSize:'0.8rem', color:'var(--text-secondary)', marginTop:'3px'}}>
                            Cluster is being monitored · Last updated just now
                        </div>
                    </div>
                </div>
                <div style={{display:'flex', gap:'2rem', textAlign:'center'}}>
                    {[
                        {v: healthyPods, l: 'Healthy Pods', c: '#22c55e'},
                        {v: warnPods,    l: 'Degraded',     c: '#f97316'},
                        {v: critPods,    l: 'Critical',      c: '#ef4444'},
                    ].map(({v,l,c}) => (
                        <div key={l}>
                            <div style={{fontSize:'1.75rem', fontWeight:900, fontFamily:'Outfit', color:c, lineHeight:1}}>{v}</div>
                            <div style={{fontSize:'0.72rem', color:'var(--text-secondary)', marginTop:'4px', textTransform:'uppercase', letterSpacing:'0.06em'}}>{l}</div>
                        </div>
                    ))}
                </div>
            </div>

            {noMetrics ? (
                /* ── No Metrics State ── */
                <div className="glass-card" style={{padding:'4rem', textAlign:'center'}}>
                    <div style={{fontSize:'3rem', marginBottom:'1rem'}}>📡</div>
                    <div style={{fontWeight:700, fontSize:'1.1rem', marginBottom:'0.5rem'}}>Metrics Server Not Installed</div>
                    <div style={{fontSize:'0.875rem', color:'var(--text-secondary)', maxWidth:'420px', margin:'0 auto 1.5rem'}}>
                        To enable real-time CPU and memory tracking for your pods and nodes, install the Kubernetes Metrics Server.
                    </div>
                    <div style={{
                        background:'rgba(14,165,233,0.08)', border:'1px solid rgba(14,165,233,0.3)',
                        borderRadius:'10px', padding:'0.875rem 1.25rem', fontFamily:'monospace',
                        fontSize:'0.8rem', color:'#38bdf8', maxWidth:'500px', margin:'0 auto', textAlign:'left'
                    }}>
                        kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
                    </div>
                </div>
            ) : (
                <>
                {/* ── Cluster-Wide Gauge Ring ── */}
                <div className="glass-card" style={{padding:'2rem', display:'flex', flexDirection:'column', alignItems:'center', gap:'2rem'}}>
                    <div>
                        <div style={{textAlign:'center', fontWeight:700, fontSize:'0.75rem', textTransform:'uppercase', letterSpacing:'0.1em', color:'var(--text-secondary)', marginBottom:'0.25rem'}}>
                            Cluster-Wide Average Resource Usage
                        </div>
                        <div style={{textAlign:'center', fontSize:'0.8rem', color:'var(--text-secondary)', opacity:0.6}}>
                            Based on {totalPods} active pods
                        </div>
                    </div>
                    <div style={{display:'flex', gap:'4rem', justifyContent:'center', flexWrap:'wrap'}}>
                        <CircleGauge pct={avgCpu} color={pctColor(avgCpu)} label="CPU Usage" sublabel={`Avg across ${totalPods} pods`} size={130}/>
                        <CircleGauge pct={avgMem} color={pctColor(avgMem)} label="Memory Usage" sublabel={`Avg across ${totalPods} pods`} size={130}/>
                        {metrics.nodes.length > 0 && (
                            <CircleGauge
                                pct={Math.round(metrics.nodes.reduce((a,n) => a+n.cpu_usage,0) / metrics.nodes.length)}
                                color="#0ea5e9" label="Node CPU" sublabel={`Avg across ${metrics.nodes.length} nodes`} size={130}/>
                        )}
                        {metrics.nodes.length > 0 && (
                            <CircleGauge
                                pct={Math.round(metrics.nodes.reduce((a,n) => a+n.mem_usage,0) / metrics.nodes.length)}
                                color="#8b5cf6" label="Node Memory" sublabel={`Avg across ${metrics.nodes.length} nodes`} size={130}/>
                        )}
                    </div>
                </div>

                {/* ── Node Health Cards ── */}
                {metrics.nodes.length > 0 && (
                    <div>
                        <div style={{fontSize:'0.75rem', fontWeight:700, textTransform:'uppercase', letterSpacing:'0.1em', color:'var(--text-secondary)', marginBottom:'0.75rem'}}>
                            🖥️ Node Health · {metrics.nodes.length} nodes
                        </div>
                        <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(280px, 1fr))', gap:'1rem'}}>
                            {metrics.nodes.map((node, i) => {
                                const worst = Math.max(node.cpu_usage, node.mem_usage)
                                const nc = pctColor(worst)
                                return (
                                    <div key={i} style={{
                                        borderRadius:'14px', padding:'1.25rem',
                                        background:'rgba(255,255,255,0.02)',
                                        border:`1px solid rgba(255,255,255,0.07)`,
                                        borderTop:`3px solid ${nc}`,
                                        position:'relative', overflow:'hidden'
                                    }}>
                                        {/* Glow */}
                                        <div style={{position:'absolute', top:0, left:0, right:0, height:'40px',
                                            background:`linear-gradient(to bottom, ${nc}10, transparent)`, pointerEvents:'none'}}/>
                                        <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:'1.25rem'}}>
                                            <div>
                                                <div style={{fontWeight:800, fontSize:'0.95rem', marginBottom:'3px'}}>{node.name}</div>
                                                <div style={{fontSize:'0.72rem', color:'var(--text-secondary)'}}>
                                                    {node.roles || 'worker'} · {node.status || 'Ready'}
                                                </div>
                                            </div>
                                            <div style={{
                                                padding:'4px 10px', borderRadius:'20px', fontSize:'0.72rem', fontWeight:700,
                                                background:`${nc}20`, color:nc, border:`1px solid ${nc}40`
                                            }}>
                                                {pctLabel(worst)}
                                            </div>
                                        </div>
                                        {[
                                            {label:'CPU', val:node.cpu_usage, detail:node.cpu, color:pctColor(node.cpu_usage)},
                                            {label:'Memory', val:node.mem_usage, detail:node.memory, color:'#8b5cf6'},
                                        ].map(({label, val, detail, color}) => (
                                            <div key={label} style={{marginBottom:'0.65rem'}}>
                                                <div style={{display:'flex', justifyContent:'space-between', marginBottom:'5px', fontSize:'0.78rem'}}>
                                                    <span style={{color:'var(--text-secondary)'}}>{label} <span style={{color:'rgba(255,255,255,0.3)', fontSize:'0.7rem'}}>· {detail}</span></span>
                                                    <span style={{fontWeight:800, color, fontFamily:'Outfit'}}>{val}%</span>
                                                </div>
                                                <div style={{height:'7px', borderRadius:'99px', background:'rgba(255,255,255,0.06)', overflow:'hidden'}}>
                                                    <div style={{
                                                        height:'100%', borderRadius:'99px', width:`${val}%`,
                                                        background:`linear-gradient(90deg, ${color}99, ${color})`,
                                                        boxShadow:`0 0 8px ${color}60`, transition:'width 1s ease'
                                                    }}/>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                )}

                {/* ── Pod List ── */}
                <div>
                    <div style={{fontSize:'0.75rem', fontWeight:700, textTransform:'uppercase', letterSpacing:'0.1em', color:'var(--text-secondary)', marginBottom:'0.75rem'}}>
                        📦 Pod Telemetry · {totalPods} active pods
                    </div>
                    <div style={{display:'flex', flexDirection:'column', gap:'0.5rem'}}>
                        {metrics.pods.map((p, i) => {
                            const worst = Math.max(p.cpu_usage, p.mem_usage)
                            const pc = pctColor(worst)
                            return (
                                <div key={i} style={{
                                    borderRadius:'12px', padding:'0.875rem 1.25rem',
                                    background:'rgba(255,255,255,0.02)',
                                    border:'1px solid rgba(255,255,255,0.06)',
                                    display:'grid', gridTemplateColumns:'1fr auto 200px 200px 90px',
                                    alignItems:'center', gap:'1.5rem'
                                }}>
                                    {/* Pod Name */}
                                    <div>
                                        <div style={{fontWeight:600, fontSize:'0.88rem', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', maxWidth:'220px'}}>{p.name}</div>
                                    </div>
                                    {/* Namespace tag */}
                                    <span style={{fontSize:'0.7rem', padding:'2px 8px', borderRadius:'99px',
                                        background:'rgba(14,165,233,0.1)', color:'#38bdf8', whiteSpace:'nowrap',
                                        border:'1px solid rgba(14,165,233,0.2)'}}>
                                        {p.namespace}
                                    </span>
                                    {/* CPU bar */}
                                    <div>
                                        <div style={{display:'flex', justifyContent:'space-between', fontSize:'0.72rem', marginBottom:'4px'}}>
                                            <span style={{color:'var(--text-secondary)'}}>CPU</span>
                                            <span style={{fontWeight:700, color:pctColor(p.cpu_usage), fontFamily:'Outfit'}}>{p.cpu_usage}%</span>
                                        </div>
                                        <div style={{height:'5px', borderRadius:'99px', background:'rgba(255,255,255,0.06)'}}>
                                            <div style={{height:'100%', borderRadius:'99px', width:`${p.cpu_usage}%`,
                                                background:`linear-gradient(90deg, ${pctColor(p.cpu_usage)}80, ${pctColor(p.cpu_usage)})`,
                                                transition:'width 0.8s ease'}}/>
                                        </div>
                                    </div>
                                    {/* Memory bar */}
                                    <div>
                                        <div style={{display:'flex', justifyContent:'space-between', fontSize:'0.72rem', marginBottom:'4px'}}>
                                            <span style={{color:'var(--text-secondary)'}}>Memory</span>
                                            <span style={{fontWeight:700, color:pctColor(p.mem_usage), fontFamily:'Outfit'}}>{p.mem_usage}%</span>
                                        </div>
                                        <div style={{height:'5px', borderRadius:'99px', background:'rgba(255,255,255,0.06)'}}>
                                            <div style={{height:'100%', borderRadius:'99px', width:`${p.mem_usage}%`,
                                                background:'linear-gradient(90deg, #7c3aed, #8b5cf6)',
                                                transition:'width 0.8s ease'}}/>
                                        </div>
                                    </div>
                                    {/* Status pill */}
                                    <div style={{textAlign:'right'}}>
                                        <span style={{fontSize:'0.72rem', padding:'4px 10px', borderRadius:'99px', fontWeight:700,
                                            background:`${pc}15`, color:pc, border:`1px solid ${pc}35`}}>
                                            {pctLabel(worst)}
                                        </span>
                                    </div>
                                </div>
                            )
                        })}
                    </div>
                </div>
                </>
            )}
        </div>
    )


}



    const renderNetworkMap = () => (
        <div className="glass-card" style={{height:'600px', display:'flex', flexDirection:'column', padding:'0', overflow:'hidden'}}>
            <div style={{padding:'20px', borderBottom:'1px solid rgba(255,255,255,0.05)', display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                <div>
                    <h3 style={{margin:0}}>Network Topology Map</h3>
                    <p style={{fontSize:'0.8rem', color:'var(--text-secondary)', margin:'5px 0 0'}}>Visualizing service relationships and isolation</p>
                </div>
                <div style={{display:'flex', gap:'10px'}}>
                    <div className="severity-tag low">Intra-Namespace</div>
                    <div className="severity-tag high">Cross-Namespace</div>
                </div>
            </div>
            <div style={{flex:1, position:'relative', background:'radial-gradient(circle at center, rgba(30,41,59,0.5) 0%, transparent 80%)'}}>
                <svg width="100%" height="100%" viewBox="0 0 800 500">
                    <defs>
                        <marker id="arrow" viewBox="0 0 10 10" refX="25" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.2)" />
                        </marker>
                    </defs>
                    {topology.links.map((link, i) => {
                        const s = topology.nodes.find(n => n.id === link.source);
                        const t = topology.nodes.find(n => n.id === link.target);
                        if(!s || !t) return null;
                        const idxS = topology.nodes.indexOf(s);
                        const idxT = topology.nodes.indexOf(t);
                        const x1 = 100 + (idxS % 5) * 150;
                        const y1 = 100 + Math.floor(idxS / 5) * 120;
                        const x2 = 100 + (idxT % 5) * 150;
                        const y2 = 100 + Math.floor(idxT / 5) * 120;
                        return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(255,255,255,0.1)" strokeWidth="1" markerEnd="url(#arrow)" />
                    })}
                    {topology.nodes.map((node, i) => {
                        const x = 100 + (i % 5) * 150;
                        const y = 100 + Math.floor(i / 5) * 120;
                        return (
                            <g key={i} transform={`translate(${x},${y})`}>
                                <circle r="25" fill={node.isolated ? 'rgba(34,197,94,0.1)' : 'rgba(59,130,246,0.1)'} stroke={node.isolated ? '#22c55e' : '#3b82f6'} strokeWidth="2" />
                                <text y="40" textAnchor="middle" fill="#fff" fontSize="10">{node.id}</text>
                                <text y="52" textAnchor="middle" fill="var(--text-secondary)" fontSize="8">{node.namespace}</text>
                            </g>
                        );
                    })}
                </svg>
            </div>
        </div>
    )

    const renderRBACGraph = () => (
        <div className="glass-card" style={{height:'600px', display:'flex', flexDirection:'column', padding:'0', overflow:'hidden'}}>
             <div style={{padding:'20px', borderBottom:'1px solid rgba(255,255,255,0.05)'}}>
                <h3 style={{margin:0}}>RBAC Permission Vision</h3>
                <p style={{fontSize:'0.8rem', color:'var(--text-secondary)', margin:'5px 0 0'}}>Relationship graph of Subject ⮕ Role</p>
            </div>
            <div style={{flex:1, position:'relative'}}>
               <svg width="100%" height="100%" viewBox="0 0 800 500">
                    {rbacGraph.links.map((link, i) => {
                        const s = rbacGraph.nodes.find(n => n.id === link.source);
                        const t = rbacGraph.nodes.find(n => n.id === link.target);
                        if(!s || !t) return null;
                        const idxS = rbacGraph.nodes.indexOf(s);
                        const idxT = rbacGraph.nodes.indexOf(t);
                        const x1 = 150;
                        const y1 = 50 + idxS * 40;
                        const x2 = 550;
                        const y2 = 50 + idxT * 80;
                        return <path key={i} d={`M ${x1} ${y1} C ${x1+200} ${y1}, ${x2-200} ${y2}, ${x2} ${y2}`} fill="none" stroke="rgba(139, 92, 246, 0.2)" strokeWidth="1.5" />
                    })}
                    {rbacGraph.nodes.map((node, i) => {
                        const isSubject = node.type === 'subject';
                        const x = isSubject ? 150 : 550;
                        const y = 50 + (isSubject ? i * 40 : (i-rbacGraph.nodes.filter(n=>n.type==='subject').length) * 80);
                        return (
                            <g key={i} transform={`translate(${x},${y})`}>
                                <rect x="-100" y="-15" width="200" height="30" rx="15" fill={isSubject ? 'rgba(139,92,246,0.1)' : 'rgba(236,72,153,0.1)'} stroke={isSubject ? '#8b5cf6' : '#ec4899'} />
                                <text textAnchor="middle" dy="5" fill="#fff" fontSize="11">{node.id}</text>
                            </g>
                        );
                    })}
               </svg>
            </div>
        </div>
    )

    const renderAdvisories = () => (
        <div style={{display:'flex', flexDirection:'column', gap:'20px'}}>
             <div className="section-header">
                <div>
                    <div className="section-title">Security Advisories</div>
                    <div className="section-subtitle">Prioritized remediation steps for active risks</div>
                </div>
            </div>
            {advisories.map((adv, i) => (
                <div key={adv.id} className="glass-card" style={{display:'flex', gap:'25px', padding:'25px'}}>
                    <div style={{width:'60px', height:'60px', borderRadius:'12px', background: adv.severity === 'Critical' ? 'rgba(239,68,68,0.1)' : 'rgba(249,115,22,0.1)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:'1.5rem'}}>
                        {adv.severity === 'Critical' ? '🛑' : '⚠️'}
                    </div>
                    <div style={{flex:1}}>
                        <div style={{display:'flex', justifyContent:'space-between', marginBottom:'10px'}}>
                            <h3 style={{margin:0, color: adv.severity === 'Critical' ? '#ef4444' : '#f97316'}}>{adv.title}</h3>
                            <div className={`severity-tag ${adv.severity.toLowerCase()}`}>{adv.severity}</div>
                        </div>
                        <p style={{margin:'0 0 15px', color:'var(--text-secondary)'}}><strong>Target:</strong> {adv.target} — {adv.finding}</p>
                        <div className="yaml-box" style={{padding:'15px', fontSize:'0.85rem', color:'var(--accent-cyan)'}}>
                            <div style={{marginBottom:'5px', fontWeight:'bold', color:'var(--text-secondary)'}}>Recommended Fix:</div>
                            {adv.remediation}
                        </div>
                    </div>
                    <div style={{display:'flex', alignItems:'center'}}>
                        <button className="glass-button primary" style={{padding:'10px 20px'}}>Apply Fix</button>
                    </div>
                </div>
            ))}
            {advisories.length === 0 && (
                <div className="glass-card" style={{padding:'50px', textAlign:'center'}}>
                    <div style={{fontSize:'3rem', marginBottom:'20px'}}>🎉</div>
                    <h3>No Critical Advisories</h3>
                    <p style={{color:'var(--text-secondary)'}}>Your environment currently meets the established baseline security standards.</p>
                </div>
            )}
        </div>
    )

    const renderCompliance = () => (
        <div style={{display:'flex', flexDirection:'column', gap:'30px'}}>
            <div className="section-header">
                <div style={{display:'flex', alignItems:'center', gap:'15px'}}>
                    <div style={{fontSize:'2rem'}}>📋</div>
                    <div>
                        <div className="section-title">CIS Kubernetes Benchmarks</div>
                        <div className="section-subtitle">Automated security auditing via ShieldKube-Go Engine</div>
                    </div>
                </div>
                <div className="glass-card" style={{padding:'10px 20px', display:'flex', alignItems:'center', gap:'15px', background:'rgba(59, 130, 246, 0.1)'}}>
                    <div style={{fontSize:'0.8rem', color:'var(--text-secondary)'}}>Global Score</div>
                    <div style={{fontSize:'1.5rem', fontWeight:'bold', color:'var(--accent-blue)'}}>
                        {compliance.length > 0 ? Math.round(compliance.reduce((acc, curr) => acc + curr.score, 0) / compliance.length) : 'N/A'}%
                    </div>
                </div>
            </div>

            {compliance.map((framework, idx) => (
                <div key={idx} className="glass-card" style={{padding:'0', overflow:'hidden', border:'1px solid rgba(255,255,255,0.05)'}}>
                    <div style={{padding:'20px 25px', background:'rgba(255,255,255,0.02)', borderBottom:'1px solid rgba(255,255,255,0.05)', display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                        <div>
                            <div style={{fontSize:'1.1rem', fontWeight:'bold', marginBottom:'4px'}}>{framework.framework}</div>
                            <div style={{fontSize:'0.85rem', color:'var(--text-secondary)'}}>{framework.description}</div>
                        </div>
                        <div style={{textAlign:'right'}}>
                            <div style={{fontSize:'1.2rem', fontWeight:'bold'}}>{framework.score}%</div>
                            <div style={{fontSize:'0.75rem', color:'var(--text-secondary)'}}>Compliance Level</div>
                        </div>
                    </div>
                    <table className="ent-table">
                        <thead>
                            <tr>
                                <th style={{width:'80px'}}>ID</th>
                                <th>Security Control</th>
                                <th style={{width:'120px'}}>Status</th>
                                <th>Recommendation / Finding</th>
                            </tr>
                        </thead>
                        <tbody>
                            {framework.controls.map((control, cidx) => (
                                <tr key={cidx}>
                                    <td style={{fontSize:'0.8rem', fontWeight:'bold', color:'var(--accent-blue)'}}>{control.id}</td>
                                    <td style={{fontSize:'0.9rem'}}>{control.name}</td>
                                    <td>
                                        <div className={`severity-tag ${control.status === 'Passed' ? 'low' : control.status === 'Warning' ? 'medium' : 'high'}`}>
                                            {control.status}
                                        </div>
                                    </td>
                                    <td style={{fontSize:'0.8rem', color:'var(--text-secondary)', fontStyle:'italic'}}>{control.finding}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            ))}

            {compliance.length === 0 && !loading && (
                <div className="glass-card" style={{padding:'50px', textAlign:'center'}}>
                    <div style={{fontSize:'3rem', marginBottom:'20px'}}>🔍</div>
                    <div style={{fontSize:'1.2rem', fontWeight:'bold', marginBottom:'10px'}}>Go Engine Deep Scan Pending</div>
                    <div style={{fontSize:'0.9rem', color:'var(--text-secondary)', maxWidth:'400px', margin:'0 auto'}}>
                        The ShieldKube-Go security engine is required for CIS Benchmarks. 
                        Please ensure the `backend-go` container is running and syncing data.
                    </div>
                </div>
            )}
        </div>
    )

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
                        {clusters.some(c => c.id === installClusterId || (c.id.startsWith('cluster-') && !c.is_local)) ? (
                            <div className="modal-body" style={{textAlign: 'center', padding: '2rem 0'}}>
                                <div style={{fontSize: '3rem', color: 'var(--accent-cyan)', marginBottom: '1rem'}}>✓</div>
                                <h3 style={{margin: '0.5rem 0'}}>Agent Successfully Connected</h3>
                                <p style={{color: 'var(--text-secondary)'}}>Secure telemetry stream established. ShieldKube is now ingesting environment metrics and vulnerability profiles.</p>
                                <div className="modal-actions" style={{justifyContent: 'center', marginTop: '2rem'}}>
                                    <button className="glass-button primary" onClick={() => { 
                                        const cid = clusters.find(c => c.id === installClusterId || (c.id.startsWith('cluster-') && !c.is_local))?.id;
                                        if (cid) setActiveCluster(cid);
                                        setShowAddCluster(false); 
                                    }}>View Dashboard</button>
                                </div>
                            </div>
                        ) : (
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
                                <div className="modal-actions" style={{marginTop: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                                    <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.85rem'}}>
                                        <span className="pulse-dot" style={{background: 'var(--accent-blue)', animationDuration: '2s'}}></span>
                                        Awaiting connection setup...
                                    </div>
                                    <button className="glass-button primary" onClick={() => { navigator.clipboard.writeText(generateInstallCommand()); setNotification({type: 'success', msg: 'Command copied!'}); }}>Copy Command</button>
                                </div>
                            </div>
                        )}
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
                    {['pods', 'network', 'rbac', 'vulnerabilities', 'compliance', 'secrets', 'advisories'].map(t => (
                        <button key={t} onClick={() => { setActiveTab(t); setFilterNamespace(null); }} className={`nav-item ${activeTab === t ? 'active' : ''}`}>
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
                        <div className="page-title" style={{background: 'linear-gradient(to right, #fff, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', fontSize: '1.75rem'}}>{activeTab.replace('_', ' ')}</div>
                        <StatusBadge pods={pods} />
                    </div>
                    
                    <div className="flex-gap">
                        {['pods', 'inventory', 'vulnerabilities', 'secrets'].includes(activeTab) && (
                            <select className="glass-select" value={filterNamespace || ""} onChange={(e) => setFilterNamespace(e.target.value || null)}>
                                <option value="">All Namespaces</option>
                                {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
                            </select>
                        )}
                        {activeTab !== 'dashboard' && activeTab !== 'compliance' && activeTab !== 'monitoring' && (
                            <div className="search-wrapper">
                                <span style={{position:'absolute', left:'0.75rem', opacity:0.5}}>🔍</span>
                                <input type="text" placeholder={`Search ${activeTab}...`} value={search} onChange={e => setSearch(e.target.value)} style={{paddingLeft: '2.2rem'}} />
                                <span className="search-hint">⌘K</span>
                            </div>
                        )}
                        
                        <div style={{height: '24px', width: '1px', background: 'var(--border-subtle)', margin: '0 0.5rem'}}></div>

                        {clusters.length > 0 && (
                            <>
                                <select className="glass-select" value={activeCluster} onChange={e => { setActiveCluster(e.target.value); setLoading(true); }} style={{borderColor: clusters.find(c => c.id === activeCluster)?.status === 'Offline' ? 'var(--risk-crit)' : 'var(--border-subtle)'}}>
                                    {clusters.map(c => <option key={c.id} value={c.id}>{c.status === 'Offline' ? '⚠ ' : '◍ '}{c.name}</option>)}
                                </select>
                                {activeCluster !== 'local' && (
                                    <button className="glass-button secondary" style={{color: 'var(--risk-crit)', border: '1px solid rgba(244, 63, 94, 0.2)'}} onClick={() => handleRemoveCluster(activeCluster)}>Disconnect</button>
                                )}
                                <button className="glass-button primary" onClick={() => setShowAddCluster(true)}>＋ Add Cluster</button>
                            </>
                        )}
                    </div>
                </header>

                {/* Dashboard / Content */}
                <div className="content-wrapper">
                    
                    {activeTab === 'compliance' && renderCompliance()}

                    {activeTab === 'dashboard' && summary && (
                        <>
                            {/* Hero Card */}
                            <div className="global-posture-card glass-card">
                                <div className="hero-left">
                                    <div className="circular-chart-container" style={{position: 'relative', width: '120px', height: '120px'}}>
                                        <svg viewBox="0 0 120 120" className="circular-chart">
                                            <g transform="translate(60,60)">
                                                <circle r="50" className="circle-bg" />
                                                <circle r="50" className="circle" 
                                                    strokeDasharray={circumference} 
                                                    strokeDashoffset={strokeDashoffset} 
                                                    stroke={summary.security_score > 80 ? 'var(--risk-low)' : summary.security_score > 50 ? 'var(--risk-med)' : 'var(--risk-crit)'} 
                                                    transform="rotate(-90)" 
                                                />
                                                <text x="0" y="5" className="percentage" style={{fontSize: '24px'}}>{summary.security_score}%</text>
                                            </g>
                                        </svg>
                                    </div>
                                    <div className="hero-text">
                                        <h2>{summary.security_score > 80 ? 'Optimal Security' : summary.security_score > 50 ? 'Moderate Posture' : 'High Risk'}</h2>
                                        <p>Global Security Health Index for <strong>{clusters.find(c => c.id === activeCluster)?.name}</strong></p>
                                    </div>
                                </div>
                                <div className="hero-right" style={{textAlign: 'right'}}>
                                    <div style={{fontSize: '0.7rem', opacity: 0.6, textTransform: 'uppercase', letterSpacing: '0.1em'}}>Current Cluster</div>
                                    <div style={{fontSize: '1.25rem', fontWeight: 800, fontFamily: 'Outfit'}}>{clusters.find(c => c.id === activeCluster)?.name}</div>
                                    <div style={{fontSize: '0.75rem', marginTop: '0.4rem', color: clusters.find(c => c.id === activeCluster)?.status === 'Offline' ? 'var(--risk-crit)' : 'var(--risk-low)'}}>
                                        {clusters.find(c => c.id === activeCluster)?.status === 'Offline' ? '● Disconnected' : '● Live Sync Active'}
                                    </div>
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
                        <div className="main-content-grid" style={{ gridTemplateColumns: (['compliance', 'monitoring', 'network', 'rbac', 'advisories'].includes(activeTab)) ? '1fr' : '1fr 350px' }}>
                            <div className="glass-card visual-section" style={{ minHeight: '600px'}}>
                                
                                {activeTab === 'network' && renderNetworkMap()}
                                {activeTab === 'rbac' && renderRBACGraph()}
                                {activeTab === 'advisories' && renderAdvisories()}
                                {activeTab === 'compliance' && renderCompliance()}
                                {activeTab === "monitoring" && renderMonitoring()}
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
                                                        <td>
                                                            <div className="asset-name">{v.target}</div>
                                                            <div className="asset-meta">{v.image || 'Infrastructure'}</div>
                                                        </td>
                                                        <td>
                                                            <span className="v-tag" style={{fontFamily:'Fira Code, monospace', color:'var(--accent-cyan)', fontWeight: 700}}>
                                                                {v.id || v.cve_id}
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <SeverityBadge level={v.severity} />
                                                        </td>
                                                        <td>
                                                            <button className="glass-button secondary" style={{fontSize: '0.75rem', padding: '0.3rem 0.8rem'}} onClick={() => setSelectedFix(v)}>
                                                               Remediate
                                                            </button>
                                                        </td>
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
                                                    <td>
                                                        <div className="asset-name">{item.name}</div>
                                                        <div className="asset-meta">
                                                            <span className="ns-pill">{item.namespace}</span>
                                                            {item.kind && <span style={{opacity: 0.6}}> • {item.kind}</span>}
                                                        </div>
                                                    </td>
                                                    <td style={{minWidth: '140px'}}>
                                                        <SeverityBadge level={item.severity} />
                                                        {item.severity && item.severity !== 'Secure' && (
                                                           <MiniGauge val={item.severity === 'Critical' ? 100 : item.severity === 'High' ? 75 : item.severity === 'Medium' ? 50 : 25} color={COLORS[item.severity]} />
                                                        )}
                                                    </td>
                                                    <td>
                                                        <div style={{display: 'flex', flexWrap: 'wrap', gap: '6px'}}>
                                                           {item.risks?.map((risk, ridx) => (
                                                               <div key={ridx} className="risk-pill" onClick={() => setSelectedFix(risk)}>
                                                                   <span className="cis-code">{risk.cis}</span>
                                                                   <span className="risk-text">{risk.type}</span>
                                                               </div>
                                                           ))}
                                                           {(!item.risks || item.risks.length === 0) && (
                                                               <div style={{color: 'var(--risk-low)', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '4px', opacity: 0.8}}>
                                                                   <span style={{fontSize: '1.1rem'}}>✓</span> Secure Posture Baseline
                                                               </div>
                                                           )}
                                                        </div>
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
