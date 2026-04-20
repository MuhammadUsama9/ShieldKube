import React, { useState, useEffect, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

export default function NetworkTopology({ activeCluster }) {
    const [graphData, setGraphData] = useState({ nodes: [], links: [] });
    const [loading, setLoading] = useState(true);
    const fgRef = useRef();

    useEffect(() => {
        // Fetch graph data from backend
        const fetchTopology = async () => {
            try {
                const res = await fetch(`http://localhost:8000/api/topology/${activeCluster}`);
                if (!res.ok) throw new Error('Failed to fetch');
                const data = await res.json();
                
                const pods = data.pods || [];
                
                // Map pods to nodes
                const nodes = pods.map((p, i) => ({
                    id: p.name,
                    name: p.name,
                    namespace: p.namespace,
                    val: p.severity === 'Critical' ? 4 : p.severity === 'High' ? 3 : 2,
                    color: p.severity === 'Critical' ? '#ef4444' : p.severity === 'High' ? '#f97316' : '#22c55e',
                    isolated: false // default assuming not isolated unless policies exist
                }));

                // Add a "cluster" root node
                nodes.push({
                    id: 'cluster-root', name: activeCluster, namespace: 'system', val: 7, color: '#3b82f6', isRoot: true
                });

                const links = [];
                pods.forEach(p => {
                    links.push({
                        source: p.name,
                        target: 'cluster-root',
                        color: 'rgba(56, 189, 248, 0.4)'
                    });
                    
                    // Faux random intra-pod communication links
                    if (Math.random() > 0.5) {
                        const randomTarget = pods[Math.floor(Math.random() * pods.length)];
                        if (randomTarget.name !== p.name) {
                            links.push({
                                source: p.name,
                                target: randomTarget.name,
                                color: (p.severity === 'Critical' || randomTarget.severity === 'Critical') ? 'rgba(239, 68, 68, 0.6)' : 'rgba(148, 163, 184, 0.2)'
                            });
                        }
                    }
                });

                setGraphData({ nodes, links });
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };

        fetchTopology();
    }, [activeCluster]);

    if (loading) return <div style={{padding:'2rem'}}>Loading Spatial Topology...</div>;

    return (
        <div style={{height: '100%', display:'flex', flexDirection:'column', background:'var(--bg-main)', position:'relative', borderRadius: '12px', overflow:'hidden', border: '1px solid var(--border-subtle)'}}>
            
            {/* Visual overlay title */}
            <div style={{position:'absolute', top:0, left:0, padding:'1.5rem', zIndex: 10, pointerEvents:'none'}}>
                <h2 style={{margin:0, display:'flex', alignItems:'center', gap:'0.75rem'}}>
                    <span style={{color:'var(--accent-blue)'}}>⬡</span> 
                    Network Topology Isolation Map
                </h2>
                <p style={{margin:0, marginTop:'0.5rem', color:'var(--text-secondary)', fontSize:'0.85rem'}}>
                    Interactive live-map of cluster workloads and intra-namespace traversal boundaries.
                </p>
                <div style={{display:'flex', gap:'1rem', marginTop:'1rem'}}>
                    <span style={{fontSize:'0.75rem', background:'rgba(239,68,68,0.1)', color:'#ef4444', padding:'0.2rem 0.5rem', borderRadius:'4px', border:'1px solid rgba(239,68,68,0.2)'}}>● Critical Host</span>
                    <span style={{fontSize:'0.75rem', background:'rgba(34,197,94,0.1)', color:'#22c55e', padding:'0.2rem 0.5rem', borderRadius:'4px', border:'1px solid rgba(34,197,94,0.2)'}}>● Secured Namespace</span>
                </div>
            </div>

            <div style={{flex: 1}}>
                <ForceGraph2D
                    ref={fgRef}
                    graphData={graphData}
                    nodeRelSize={6}
                    linkColor="color"
                    linkDirectionalParticles={1}
                    linkDirectionalParticleSpeed={d => d.color.includes('239') ? 0.01 : 0.005}
                    backgroundColor="#010308"
                    nodeCanvasObject={(node, ctx, globalScale) => {
                        const label = node.name;
                        const fontSize = 12/globalScale;
                        ctx.font = `${fontSize}px Inter, sans-serif`;
                        
                        // Draw Node Pulse Glow
                        if (node.color === '#ef4444') {
                            ctx.beginPath();
                            ctx.arc(node.x, node.y, node.val * 2.5, 0, 2 * Math.PI, false);
                            ctx.fillStyle = 'rgba(239, 68, 68, 0.2)';
                            ctx.fill();
                        }
                        
                        // Node Core
                        ctx.beginPath();
                        ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
                        ctx.fillStyle = node.color;
                        ctx.fill();
                        
                        // Node Text
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
                        ctx.fillText(label, node.x, node.y + node.val + 2 + fontSize);
                    }}
                    onNodeDragEnd={node => {
                        node.fx = node.x;
                        node.fy = node.y;
                    }}
                />
            </div>
            
            {/* Control Strip */}
            <div style={{position:'absolute', bottom:0, width:'100%', textAlign:'right', padding:'1rem', pointerEvents:'none'}}>
                <button className="glass-button secondary" style={{pointerEvents:'auto'}} onClick={() => {
                    fgRef.current.zoomToFit(400);
                }}>⌖ Recenter View</button>
            </div>
        </div>
    );
}
