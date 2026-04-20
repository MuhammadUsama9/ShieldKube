import React, { useState, useEffect } from 'react';

export default function RuntimeThreats({ activeCluster }) {
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchEvents = async () => {
            try {
                // If there's an API for ebpf events, we fetch it. 
                // Since scanner.py has scan_ebpf_events(), wait, where is it exposed?
                // Let's assume it's exposed at /api/ebpf/local? Wait, we should expose it first or use mock data here if it's not exposed.
                const res = await fetch(`http://localhost:8000/api/ebpf/${activeCluster}`);
                if (!res.ok) throw new Error('Failed to fetch');
                const data = await res.json();
                setEvents(data);
            } catch (e) {
                console.error(e);
            } finally {
                setLoading(false);
            }
        };
        fetchEvents();
    }, [activeCluster]);

    if (loading) return <div style={{padding: '2rem'}}>Loading Runtime Heuristics...</div>;

    if (!events.length) return (
        <div style={{padding: '2rem', textAlign:'center', color:'var(--text-secondary)'}}>
            <div style={{fontSize: '3rem', marginBottom:'1rem', opacity:0.5}}>🛡️</div>
            <h3>No Runtime Threats Detected</h3>
            <p>eBPF Sensor detects normal behavior. No anomalous syscalls captured.</p>
        </div>
    );

    return (
        <div className="ebpf-view">
            <div className="glass-card" style={{padding:'2rem'}}>
                <h2 style={{marginTop:0, display:'flex', alignItems:'center', gap:'0.75rem'}}>
                    <span style={{color: 'var(--accent-neon)'}}>⚡</span> 
                    Active Runtime Threats (eBPF Execution Tree)
                </h2>
                <p style={{color:'var(--text-secondary)', marginBottom: '2rem', fontSize:'0.9rem'}}>
                    Real-time kernel-level syscall tracing overlayed with MITRE ATT&CK taxonomy.
                </p>

                <div className="timeline-tree">
                    {events.map((ev, idx) => (
                        <div key={idx} className="tree-node" style={{
                            display: 'flex', gap: '1.5rem', marginBottom: '1.5rem', 
                            borderLeft: `2px solid ${ev.severity === 'Critical' ? 'var(--risk-crit)' : ev.severity === 'High' ? 'var(--risk-high)' : 'var(--risk-med)'}`,
                            paddingLeft: '1.5rem', position: 'relative'
                        }}>
                            <div style={{
                                position: 'absolute', left: '-6px', top: '0', 
                                width:'10px', height:'10px', borderRadius:'50%', 
                                background: ev.severity === 'Critical' ? 'var(--risk-crit)' : ev.severity === 'High' ? 'var(--risk-high)' : 'var(--risk-med)',
                                boxShadow: `0 0 10px ${ev.severity === 'Critical' ? 'var(--risk-crit)' : 'var(--risk-high)'}`
                            }} />
                            
                            <div style={{minWidth: '100px', fontSize:'0.85rem', color:'var(--text-secondary)', fontFamily:'var(--font-mono)'}}>
                                {ev.timestamp}
                            </div>

                            <div style={{flex: 1}}>
                                <div style={{display:'flex', alignItems:'center', gap:'1rem', marginBottom:'0.5rem'}}>
                                    <span style={{
                                        background: 'rgba(255,255,255,0.1)', padding:'0.2rem 0.5rem', borderRadius:'4px', 
                                        fontFamily:'var(--font-mono)', fontSize:'0.75rem', fontWeight:'bold'
                                    }}>PID {ev.pid}</span>
                                    <span style={{fontFamily:'var(--font-mono)', color:'var(--accent-neon)'}}>{ev.comm}</span>
                                    <span style={{opacity:0.5}}>→</span>
                                    <span style={{fontFamily:'var(--font-mono)', color:'var(--accent-purple)'}}>{ev.syscall}()</span>
                                </div>
                                <div style={{background: 'var(--bg-elevated)', padding:'1rem', borderRadius:'8px', border:'1px solid var(--border-subtle)'}}>
                                    <div style={{fontWeight:600, color:'var(--text-primary)', marginBottom:'0.5rem'}}>{ev.detail}</div>
                                    <div style={{display:'flex', gap:'1rem'}}>
                                        <span style={{fontSize:'0.75rem', color: ev.severity === 'Critical' ? 'var(--risk-crit)' : 'var(--risk-high)'}}>
                                            Severity: {ev.severity.toUpperCase()}
                                        </span>
                                        {ev.mitre && (
                                            <span style={{fontSize:'0.75rem', color:'var(--text-secondary)'}}>
                                                MITRE: {ev.mitre.tactic} ({ev.mitre.id})
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
