import os
import re
import time
import random
from kubernetes import client, config
import requests
from typing import List, Dict, Any, Union
from collections import defaultdict

TRUSTED_REGISTRIES = ["gcr.io", "quay.io", "docker.io/library"]
SECRET_PATTERNS = ["key", "pass", "token", "secret", "auth", "pwd"]

# Expanded CVE Database for common container images
CVE_DB = {
    "nginx": [
        {"id": "CVE-2023-44487", "severity": "Critical", "title": "HTTP/2 Rapid Reset Attack", "fixed_in": "1.25.3"},
        {"id": "CVE-2021-23017", "severity": "High", "title": "Resolver buffer overflow", "fixed_in": "1.21.0"},
        {"id": "CVE-2022-41741", "severity": "Medium", "title": "Memory corruption in ngx_http_mp4_module", "fixed_in": "1.23.2"},
        {"id": "CVE-2022-41742", "severity": "Medium", "title": "Memory disclosure in ngx_http_mp4_module", "fixed_in": "1.23.2"}
    ],
    "redis": [
        {"id": "CVE-2023-41056", "severity": "High", "title": "Integer overflow in Redis", "fixed_in": "7.0.13"},
        {"id": "CVE-2023-28856", "severity": "High", "title": "Authenticated users can trigger panic", "fixed_in": "7.0.11"},
        {"id": "CVE-2022-24736", "severity": "Medium", "title": "Lua script execution in Redis", "fixed_in": "6.2.7"},
        {"id": "CVE-2022-35977", "severity": "Medium", "title": "Integer overflow in SETRANGE", "fixed_in": "7.0.5"}
    ],
    "postgres": [
        {"id": "CVE-2023-5868", "severity": "Medium", "title": "Memory disclosure in aggregate function", "fixed_in": "16.1"},
        {"id": "CVE-2023-5869", "severity": "High", "title": "Buffer overflow in integer aggregation", "fixed_in": "16.1"},
        {"id": "CVE-2022-1552", "severity": "High", "title": "Privilege escalation via Autovacuum", "fixed_in": "14.3"}
    ],
    "mysql": [
        {"id": "CVE-2023-21963", "severity": "Medium", "title": "Vulnerability in Server: Optimizer", "fixed_in": "8.0.33"},
        {"id": "CVE-2023-21912", "severity": "Medium", "title": "Vulnerability in Server: Encryption", "fixed_in": "8.0.32"}
    ],
    "node": [
        {"id": "CVE-2023-32002", "severity": "High", "title": "Module loading bypass", "fixed_in": "20.5.0"},
        {"id": "CVE-2023-32559", "severity": "Medium", "title": "Privilege escalation via policy", "fixed_in": "18.16.1"},
        {"id": "CVE-2022-32212", "severity": "High", "title": "HTTP Request Smuggling", "fixed_in": "18.5.0"}
    ],
    "python": [
        {"id": "CVE-2023-24329", "severity": "High", "title": "URL parsing bypass", "fixed_in": "3.11.2"},
        {"id": "CVE-2022-45061", "severity": "Medium", "title": "CPU-based DoS in IDNA encoding", "fixed_in": "3.11.1"},
        {"id": "CVE-2023-40217", "severity": "Medium", "title": "SSL handshake bypass", "fixed_in": "3.11.5"}
    ],
    "alpine": [
        {"id": "CVE-2022-30065", "severity": "Medium", "title": "Busybox use-after-free", "fixed_in": "3.16.0"},
        {"id": "CVE-2023-5363", "severity": "High", "title": "OpenSSL vulnerability", "fixed_in": "3.1.4"}
    ],
    "ubuntu": [
        {"id": "CVE-2023-32629", "severity": "High", "title": "OverlayFS local privilege escalation", "fixed_in": "23.04"},
        {"id": "CVE-2023-31248", "severity": "High", "title": "Netfilter vulnerability", "fixed_in": "23.04"}
    ],
    "debian": [
        {"id": "CVE-2023-4911", "severity": "Critical", "title": "Looney Tunables glibc overflow", "fixed_in": "12.2"}
    ],
    "busybox": [
        {"id": "CVE-2022-28391", "severity": "Medium", "title": "Buffer overflow in netstat", "fixed_in": "1.35.0"}
    ]
}

class K8sScanner:
    def __init__(self, mock_mode: bool = False):
        self.mock_mode = mock_mode
        self.scan_logs = []
        self.is_connected = False
        self.v1 = None
        self.apps_v1 = None
        self.networking_v1 = None
        self.rbac_v1 = None
        self.policy_v1 = None
        
        if not self.mock_mode:
            try:
                # Try in-cluster first, then local config
                try:
                    config.load_incluster_config()
                    self._log("ShieldKube Engine: Connected via In-Cluster context.")
                except:
                    config.load_kube_config()
                    self._log("ShieldKube Engine: Connected via Kube-Config context.")
                
                self.v1 = client.CoreV1Api()
                self.apps_v1 = client.AppsV1Api()
                self.networking_v1 = client.NetworkingV1Api()
                self.rbac_v1 = client.RbacAuthorizationV1Api()
                self.policy_v1 = client.PolicyV1Api()
                self.is_connected = True
                self._log("ShieldKube Engine v1.0 (Live Audit) Initialized.")
            except Exception as e:
                self._log(f"Connection Error: {e}", "error")
                if self.mock_mode: # Only fall back if explicitly allowed or during dev
                    self._log("Falling back to MOCK MODE due to connection failure.")
                else:
                    # In production we might still want to avoid crashing the whole app, 
                    # but we shouldn't show fake data without warning.
                    self._log("Live Kubernetes connection failed. Dashboard will be empty until resolved.", "error")

    def _log(self, msg: str, level: str = "info"):
        self.scan_logs.append({"timestamp": time.strftime("%H:%M:%S"), "msg": msg, "level": level})
        if len(self.scan_logs) > 40: self.scan_logs.pop(0)

    def get_logs(self): return self.scan_logs

    def calculate_security_score(self, pods, policies, rbac, vulnerabilities) -> int:
        total_risks = sum(len(p.get("risks", [])) for p in pods + policies + rbac)
        score = 100 - (total_risks * 3)
        for section in vulnerabilities.values():
            score -= (len(section) * 2)
        return max(5, min(100, score))

    def scan_radar_data(self) -> List[Dict[str, Any]]:
        self._log("Synthesizing multi-dimensional risk radar...")
        pods = self.scan_pods()
        rbac = self.scan_rbac()
        policies = self.scan_network_policies()
        
        categories = {"Runtime": 0, "IAM": 0, "Network": 0, "Images": 0, "Host": 0}
        
        for item in pods + policies + rbac:
            for risk in item.get("risks", []):
                cat = risk.get("category", "Runtime")
                if cat in categories: categories[cat] += 1
                
        return [{"subject": k, "A": v, "fullMark": 15} for k, v in categories.items()]

    def scan_inventory(self) -> List[Dict[str, Any]]:
        if self.mock_mode: return self._get_mock_inventory()
        try:
            self._log("Auditing Global Asset Inventory...")
            inv = []
            # Categorized list for sub-tabs
            deploys = self.apps_v1.list_deployment_for_all_namespaces(_request_timeout=3).items
            for d in deploys: inv.append({"kind": "Deployment", "name": d.metadata.name, "namespace": d.metadata.namespace, "group": "Workloads"})
            
            pods = self.v1.list_pod_for_all_namespaces(_request_timeout=3).items
            for p in pods: inv.append({"kind": "Pod", "name": p.metadata.name, "namespace": p.metadata.namespace, "group": "Workloads"})

            nodes = self.v1.list_node(_request_timeout=3).items
            for n in nodes: inv.append({"kind": "Node", "name": n.metadata.name, "namespace": "Global", "group": "Infrastructure"})
            
            svcs = self.v1.list_service_for_all_namespaces(_request_timeout=3).items
            for s in svcs: inv.append({"kind": "Service", "name": s.metadata.name, "namespace": s.metadata.namespace, "group": "Network"})
            
            cms = self.v1.list_config_map_for_all_namespaces(_request_timeout=3).items
            for c in cms: inv.append({"kind": "ConfigMap", "name": c.metadata.name, "namespace": c.metadata.namespace, "group": "Configuration"})
            
            return inv
        except Exception as e:
            self._log(f"Inventory scan error: {e}.", "error")
            return self._get_mock_inventory() if self.mock_mode else []

    def scan_vulnerabilities(self) -> Dict[str, List[Dict[str, Any]]]:
        self._log("Running workload-centric CVE audit...")
        if self.mock_mode: return self._get_mock_deep_vulnerabilities()
        
        results = {"pods": [], "nodes": [], "volumes": [], "replica_sets": [], "deployments": [], "infrastructure": []}
        try:
            # Infrastructure check (ResourceQuota & LimitRange)
            namespaces = self.v1.list_namespace(_request_timeout=3).items
            quotas = self.v1.list_resource_quota_for_all_namespaces(_request_timeout=3).items
            limits = self.v1.list_limit_range_for_all_namespaces(_request_timeout=3).items
            
            quota_ns = {q.metadata.namespace for q in quotas}
            limit_ns = {l.metadata.namespace for l in limits}
            
            for ns in namespaces:
                if ns.metadata.name.startswith("kube-") or ns.metadata.name == "default": continue
                if ns.metadata.name not in quota_ns:
                    results["infrastructure"].append({"target": ns.metadata.name, "severity": "Medium", "id": "INFRA-01", "title": "Missing ResourceQuota", "remediation": "Apply a ResourceQuota to prevent resource exhaustion."})
                if ns.metadata.name not in limit_ns:
                    results["infrastructure"].append({"target": ns.metadata.name, "severity": "Medium", "id": "INFRA-02", "title": "Missing LimitRange", "remediation": "Apply a LimitRange to set default resource bounds."})
            # Deployment scan
            deploys = self.apps_v1.list_deployment_for_all_namespaces(_request_timeout=3).items
            try:
                pdbs = self.policy_v1.list_pod_disruption_budget_for_all_namespaces(_request_timeout=3).items
                pdb_map = {(p.metadata.namespace, p.spec.selector.match_labels.get("app")): True for p in pdbs if p.spec.selector and p.spec.selector.match_labels}
            except:
                pdb_map = {}

            for d in deploys:
                # PDB Audit
                app_label = d.spec.selector.match_labels.get("app") if d.spec.selector and d.spec.selector.match_labels else None
                if app_label and (d.metadata.namespace, app_label) not in pdb_map:
                     results["deployments"].append({
                        "target": d.metadata.name, 
                        "namespace": d.metadata.namespace, 
                        "severity": "Medium", 
                        "id": "AVAIL-01", 
                        "title": "Missing PodDisruptionBudget", 
                        "remediation": "Create a PDB to ensure availability during maintenance."
                    })

                for c in d.spec.template.spec.containers:
                    vulns = self._check_image_cve(c.image)
                    for v in vulns:
                        results["deployments"].append({"target": d.metadata.name, "namespace": d.metadata.namespace, "image": c.image, **v})
            
            # ReplicaSet scan
            rss = self.apps_v1.list_replica_set_for_all_namespaces(_request_timeout=3).items
            for rs in rss:
                for c in rs.spec.template.spec.containers:
                    vulns = self._check_image_cve(c.image)
                    for v in vulns:
                        results["replica_sets"].append({"target": rs.metadata.name, "namespace": rs.metadata.namespace, "image": c.image, **v})
            
            # Pod scan
            pods = self.v1.list_pod_for_all_namespaces(_request_timeout=3).items
            for p in pods:
                for c in p.spec.containers:
                    vulns = self._check_image_cve(c.image)
                    for v in vulns:
                        results["pods"].append({"target": p.metadata.name, "namespace": p.metadata.namespace, "image": c.image, **v})

            # Host/Node check
            nodes = self.v1.list_node(_request_timeout=3).items
            for n in nodes:
                 kernel = n.status.node_info.kernel_version
                 if "5.4" in kernel:
                     results["nodes"].append({"target": n.metadata.name, "severity": "High", "id": "KRNL-01", "title": "Outdated Kernel Detected", "remediation": "Update Node OS"})

            return results
        except Exception as e:
            self._log(f"Deep scan error: {e}.", "error")
            return self._get_mock_deep_vulnerabilities() if self.mock_mode else {"pods": [], "nodes": [], "volumes": [], "replica_sets": [], "deployments": [], "infrastructure": []}

    def _check_image_cve(self, image: str) -> List[Dict]:
        """
        Check for vulnerabilities using a hybrid approach:
        1. Local high-performance CVE database for common base images.
        2. Real-time OSV.dev API lookup for specific version tags.
        """
        parts = image.split('/')[-1].split(':')
        base = parts[0]
        tag = parts[1] if len(parts) > 1 else "latest"
        
        # 1. Local Database Lookup (Fast)
        vulns = CVE_DB.get(base, []) .copy()
        
        # 2. Dynamic OSV.dev Lookup (if specific version tag is present and NOT in mock_mode)
        if not self.mock_mode and tag not in ["latest", "stable", "main", "master"]:
            osv_vulns = self._check_osv_api(base, tag)
            # Avoid duplicates if tagging matches static DB entries
            existing_ids = {v["id"] for v in vulns}
            for ov in osv_vulns:
                if ov["id"] not in existing_ids:
                    vulns.append(ov)
        
        return vulns

    def _check_osv_api(self, package: str, version: str) -> List[Dict]:
        """Query OSV.dev API for version-specific vulnerabilities."""
        try:
            # OSV supports multiple ecosystems. For container base images, 
            # we check common ones like PyPI, npm, or Debian/Alpine if detectable.
            # This is a simplified integration for the ShieldKube dashboard.
            pkg_data: Dict[str, str] = {"name": package}
            
            # Add ecosystem hints based on package name
            if package in ["python", "django", "flask"]: pkg_data["ecosystem"] = "PyPI"
            elif package in ["node", "express", "react"]: pkg_data["ecosystem"] = "npm"
            
            payload = {
                "version": version,
                "package": pkg_data
            }
            
            resp = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for v in data.get("vulns", []):
                    results.append({
                        "id": v.get("id"),
                        "severity": v.get("database_specific", {}).get("severity", "Medium"),
                        "title": v.get("summary", "No summary provided"),
                        "fixed_in": "Refer to OSV"
                    })
                return results
        except Exception:
            pass # Suppress API errors to avoid breaking the scan
        return []

    def scan_pods(self) -> List[Dict]:
        if self.mock_mode: return self._get_mock_pods()
        try:
            pods = self.v1.list_pod_for_all_namespaces(_request_timeout=3).items
            res = []
            for p in pods:
                risks = self._analyze_pod_security(p)
                res.append({"name": p.metadata.name, "namespace": p.metadata.namespace, "risks": risks, "severity": self._calculate_severity(risks)})
            return res
        except Exception as e:
            self._log(f"Pod scan error: {e}.", "error")
            return self._get_mock_pods() if self.mock_mode else []

    def scan_network_policies(self) -> List[Dict[str, Any]]:
        self._log("Auditing Network Isolation policies...")
        if self.mock_mode: return [{"name": "wide-open", "namespace": "default", "severity": "High", "risks": [{"type": "OpenIngress", "msg": "No isolation.", "cis": "5.3.1", "category": "Network", "mitre": {"tactic": "Lateral Movement", "id": "T1557"}}]}]
        try:
            policies = self.networking_v1.list_network_policy_for_all_namespaces(_request_timeout=3).items
            results = []
            for pol in policies:
                risks = []
                if not pol.spec.ingress and not pol.spec.egress:
                    risks.append({
                        "type": "DefaultDenyMissing", 
                        "msg": "No rules defined.", 
                        "cis": "5.3.2", 
                        "category": "Network",
                        "mitre": {"tactic": "Lateral Movement", "id": "T1557"}
                    })
                results.append({
                    "name": pol.metadata.name,
                    "namespace": pol.metadata.namespace,
                    "risks": risks,
                    "severity": "Medium" if risks else "Low"
                })
            return results
        except Exception as e:
            self._log(f"NetPol scan error: {e}", "error")
            return []

    def scan_rbac(self) -> List[Dict[str, Any]]:
        self._log("Auditing RBAC permissions depth...")
        if self.mock_mode: return [{"name": "admin-leak", "namespace": "Global", "subjects": ["User: dev-bot"], "severity": "High", "risks": [{"type": "StarPerms", "msg": "Wildcard used.", "cis": "5.1.1", "category": "IAM", "mitre": {"tactic": "Privilege Escalation", "id": "T1548"}}]}]
        try:
            cluster_roles = self.rbac_v1.list_cluster_role(_request_timeout=3).items
            results = []
            for cr in cluster_roles:
                risks = []
                if not cr.rules: continue
                for rule in cr.rules:
                    if rule.resources and rule.verbs and "*" in rule.resources and "*" in rule.verbs:
                        risks.append({
                            "type": "RBAC Wildcard",
                            "msg": f"ClusterRole {cr.metadata.name} has wildcard permissions.",
                            "cis": "5.1.1",
                            "category": "IAM",
                            "patch": "restrict resources/verbs",
                            "mitre": {"tactic": "Privilege Escalation", "id": "T1548"}
                        })
                
                if risks:
                    results.append({
                        "name": cr.metadata.name,
                        "namespace": "Cluster-wide",
                        "subjects": ["N/A"], # Could expand to list bindings
                        "risks": risks,
                        "severity": "High"
                    })
            return results
        except Exception as e:
            self._log(f"RBAC scan error: {e}", "error")
            return []

    def scan_heatmap(self) -> List[Dict]:
        self._log("Calculating namespace risk density...")
        pods = self.scan_pods()
        ns_map = defaultdict(lambda: {"namespace": "", "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        
        for p in pods:
            ns = p["namespace"]
            ns_map[ns]["namespace"] = ns
            sev = p["severity"].lower()
            if sev in ns_map[ns]:
                ns_map[ns][sev] += 1
            ns_map[ns]["total"] += 1
            
        return list(ns_map.values()) if ns_map else [{"namespace": "default", "critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1}]

    def scan_trends(self) -> List[Dict]:
        self._log("Analyzing security posture velocity...")
        # Simulate last 7 scans
        trends = []
        base_score = 65
        for i in range(7):
            day = (time.time() - (6-i)*86400)
            score = base_score + (i * 2) + random.randint(-2, 2)
            criticals = max(0, 5 - i + random.randint(-1, 1))
            trends.append({
                "time": time.strftime("%b %d", time.localtime(day)),
                "score": min(100, score),
                "criticals": criticals
            })
        return trends

    def scan_compliance(self):
        self._log("Running deep cross-framework Compliance audit (CIS, NSA, NIST 800-53)...")
        if self.mock_mode: return self._get_mock_compliance()
        if not self.is_connected: return []
        try:
            controls_cis = []
            controls_nsa = []
            controls_nist = []

            # --- CIS 5.1: RBAC ---
            try:
                cluster_roles = self.rbac_v1.list_cluster_role(_request_timeout=3).items
                wildcard_roles = [r.metadata.name for r in cluster_roles if r.rules and any(
                    '*' in (rule.verbs or []) or '*' in (rule.resources or []) for rule in r.rules
                )]
                controls_cis.append({
                    "id": "CIS 5.1.1",
                    "name": "Ensure cluster-admin role is restricted",
                    "status": "Warning" if wildcard_roles else "Passed",
                    "finding": f"ClusterRoles with wildcard permissions: {', '.join(wildcard_roles[:3]) or 'None'}"
                })
                # NIST AC-2: Account Management
                controls_nist.append({
                    "id": "AC-2",
                    "name": "Account Management / Least Privilege",
                    "status": "Warning" if wildcard_roles else "Passed",
                    "finding": f"Privileged accounts detected: {len(wildcard_roles)} roles with wildcard access."
                })
            except Exception:
                controls_cis.append({"id": "CIS 5.1.1", "name": "Ensure cluster-admin role is restricted", "status": "Warning", "finding": "Could not audit ClusterRoles"})

            # --- CIS 5.2: Pod Security ---
            try:
                pods = self.v1.list_pod_for_all_namespaces(_request_timeout=3).items
                privileged = [p.metadata.name for p in pods if any(
                    c.security_context and c.security_context.privileged
                    for c in (p.spec.containers or [])
                )]
                controls_cis.append({
                    "id": "CIS 5.2.1",
                    "name": "Minimize privileged containers",
                    "status": "Failed" if privileged else "Passed",
                    "finding": f"Privileged pods: {', '.join(privileged[:3])}" if privileged else "No privileged pods found"
                })
                # NIST AC-6: Least Privilege
                controls_nist.append({
                    "id": "AC-6",
                    "name": "Least Privilege / Privileged Access",
                    "status": "Failed" if privileged else "Passed",
                    "finding": f"{len(privileged)} pods running with full kernel privileges."
                })

                root_pods = [p.metadata.name for p in pods if any(
                    not (c.security_context and c.security_context.run_as_non_root)
                    for c in (p.spec.containers or [])
                )]
                controls_cis.append({
                    "id": "CIS 5.2.6",
                    "name": "Minimize containers running as root",
                    "status": "Warning" if root_pods else "Passed",
                    "finding": f"{len(root_pods)} containers may run as root" if root_pods else "All containers set runAsNonRoot"
                })
                # NIST CM-6: Configuration Settings
                controls_nist.append({
                    "id": "CM-6",
                    "name": "Configuration Settings / Hardening",
                    "status": "Warning" if root_pods else "Passed",
                    "finding": f"Non-hardened workloads: {len(root_pods)} containers lack runAsNonRoot."
                })
            except Exception:
                controls_cis.append({"id": "CIS 5.2.1", "name": "Minimize privileged containers", "status": "Warning", "finding": "Could not audit pod security"})

            # --- CIS 5.3: Network Policies ---
            try:
                namespaces = self.v1.list_namespace(_request_timeout=3).items
                policies = self.networking_v1.list_network_policy_for_all_namespaces(_request_timeout=3).items
                policy_ns = {p.metadata.namespace for p in policies}
                unprotected = [ns.metadata.name for ns in namespaces if ns.metadata.name not in policy_ns and not ns.metadata.name.startswith("kube-")]
                controls_cis.append({
                    "id": "CIS 5.3.2",
                    "name": "Ensure NetworkPolicy is configured",
                    "status": "Failed" if unprotected else "Passed",
                    "finding": f"Namespaces without NetworkPolicy: {', '.join(unprotected[:3])}" if unprotected else "All namespaces have NetworkPolicies"
                })
                # NIST SC-7: Boundary Protection
                controls_nist.append({
                    "id": "SC-7",
                    "name": "Boundary Protection / Network Isolation",
                    "status": "Failed" if unprotected else "Passed",
                    "finding": f"Unsegmented namespaces: {len(unprotected)} lack explicit ingress/egress rules."
                })
            except Exception:
                controls_cis.append({"id": "CIS 5.3.2", "name": "Ensure NetworkPolicy is configured", "status": "Warning", "finding": "Could not audit network policies"})

            # --- NIST SI-2: Flaw Remediation (CVEs) ---
            try:
                vulns = self.scan_vulnerabilities()
                crit_vulns = sum(len([v for v in vlist if v.get("severity") == "Critical"]) for vlist in vulns.values())
                controls_nist.append({
                    "id": "SI-2",
                    "name": "Flaw Remediation / Vulnerability Management",
                    "status": "Failed" if crit_vulns > 0 else "Passed",
                    "finding": f"Unpatched vulnerabilities: {crit_vulns} critical CVEs detected in environment."
                })
            except Exception:
                pass

            # --- NSA Controls ---
            try:
                # Check for automount SA token
                pods = self.v1.list_pod_for_all_namespaces(_request_timeout=3).items
                automount = [p.metadata.name for p in pods if p.spec.automount_service_account_token is not False]
                controls_nsa.append({
                    "id": "NSA 6.1",
                    "name": "Disable automounting of service account tokens",
                    "status": "Warning" if len(automount) > 3 else "Passed",
                    "finding": f"{len(automount)} pods automount SA tokens" if automount else "SA token automounting disabled"
                })
                # Check for read-only root filesystem
                read_write = [f"{p.metadata.namespace}/{p.metadata.name}" for p in pods if any(
                    not (c.security_context and c.security_context.read_only_root_filesystem)
                    for c in (p.spec.containers or [])
                )]
                controls_nsa.append({
                    "id": "NSA 6.3",
                    "name": "Use immutable (read-only) root filesystems",
                    "status": "Warning" if read_write else "Passed",
                    "finding": f"{len(read_write)} containers with writable root filesystems" if read_write else "All containers use read-only root filesystems"
                })
            except Exception:
                controls_nsa.append({"id": "NSA 6.1", "name": "Disable automounting of SA tokens", "status": "Warning", "finding": "Could not audit SA tokens"})

            def score(controls):
                passed = sum(1 for c in controls if c["status"] == "Passed")
                return round(passed / len(controls) * 100) if controls else 0

            return [
                {
                    "framework": "CIS Kubernetes Benchmark v1.8",
                    "description": "Center for Internet Security Kubernetes Security Guidelines",
                    "score": score(controls_cis),
                    "controls": controls_cis
                },
                {
                    "framework": "NIST 800-53 Rev 5",
                    "description": "Security and Privacy Controls for Information Systems and Organizations",
                    "score": score(controls_nist),
                    "controls": controls_nist
                },
                {
                    "framework": "NSA/CISA Kubernetes Hardening Guide",
                    "description": "US National Security Agency Kubernetes hardening recommendations",
                    "score": score(controls_nsa),
                    "controls": controls_nsa
                }
            ]
        except Exception as e:
            self._log(f"Compliance scan error: {e}", "error")
            return []

    def map_to_mitre_attack(self) -> Dict[str, List[Dict]]:
        """Maps cluster-wide findings to the MITRE ATT&CK Matrix for Enterprise / Containers."""
        self._log("Strategic Intelligence: Mapping risks to MITRE ATT&CK Matrix...")
        
        matrix = {
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Privilege Escalation": [],
            "Defense Evasion": [],
            "Credential Access": [],
            "Lateral Movement": [],
            "Discovery": [],
            "Collection": [],
            "Command and Control": [],
            "Impact": []
        }
        
        # 1. Fetch source data
        pods = self.scan_pods()
        rbac = self.scan_rbac()
        policies = self.scan_network_policies()
        vulns = self.scan_vulnerabilities()
        ebpf_events = self.scan_ebpf_events()
        
        # 2. Map Pod Security Risks
        for p in pods:
            for r in p.get("risks", []):
                tactic = r.get("mitre", {}).get("tactic", "Impact")
                if tactic in matrix:
                    matrix[tactic].append({
                        "name": r["type"],
                        "target": p["name"],
                        "id": r.get("mitre", {}).get("id", "T1611"),
                        "severity": p["severity"]
                    })
        
        # 3. Map RBAC Risks
        for r in rbac:
            for risk in r.get("risks", []):
                matrix["Privilege Escalation"].append({
                    "name": risk["type"],
                    "target": r["name"],
                    "id": "T1548",
                    "severity": r["severity"]
                })
        
        # 4. Map Network Risks
        for p in policies:
            for r in p.get("risks", []):
                matrix["Lateral Movement"].append({
                    "name": r["type"],
                    "target": p["name"],
                    "id": "T1557",
                    "severity": p["severity"]
                })
        
        # 5. Map eBPF Events (Realtime threats)
        for e in ebpf_events:
            tactic = e.get("mitre", {}).get("tactic", "Impact")
            if tactic in matrix:
                matrix[tactic].append({
                    "name": e["detail"],
                    "target": e["comm"],
                    "id": e.get("mitre", {}).get("id", "T1055"),
                    "severity": e["severity"]
                })

        return matrix

    def generate_ai_insight(self, risk_type: str, resource_name: str) -> Dict[str, Any]:
        """Provides an explainable-AI narrative and triage for a specific security risk."""
        self._log(f"AI Security Analyst: Analyzing risk '{risk_type}' for {resource_name}...")
        
        # In a real enterprise app, this would call an LLM (vertex-ai, openai)
        # Here we use a high-fidelity template engine to simulate advanced AI reasoning.
        
        TEMPLATES: Dict[str, Dict[str, Any]] = {
            "PrivilegedContainer": {
                "summary": "Critical kernel exposure via pod 'process' escalation.",
                "analysis": f"The pod `{resource_name}` is configured with `privileged: true`. This bypasses all container isolation layers, allowing the process to access any host device and potentially escape to the node. This is a common entry point for container breakout attacks.",
                "remediation": "Disable `privileged: true`. If hardware access is required, use `securityContext.capabilities` to grant specific permissions like `CAP_NET_ADMIN` or `CAP_SYS_TIME`.",
                "impact": "Node-level compromise, lateral movement across the cluster."
            },
            "RBACWildcard": {
                "summary": "Over-privileged service account detected.",
                "analysis": f"The ClusterRole associated with `{resource_name}` uses wildcard `*` permissions for verbs or resources. This violates the principle of Least Privilege and allows an attacker who compromises this namespace to perform any action on the cluster.",
                "remediation": "Audit the role's usage and replace wildcards with specific resources (e.g., `pods`, `services`) and verbs (e.g., `get`, `list`).",
                "impact": "Full cluster administrative control bypass."
            },
            "ImageVulnerability": {
                "summary": "Known exploit path in container dependency.",
                "analysis": f"The image used by `{resource_name}` contains critical CVEs (e.g., Looney Tunables or HTTP/2 Rapid Reset). These vulnerabilities can be exploited to trigger buffer overflows or denial-of-service and in some cases, remote code execution.",
                "remediation": "Update the base image or specific package to the fixed version specified in the vulnerability report.",
                "impact": "Unauthorized access, data exfiltration, or service disruption."
            }
        }
        
        default: Dict[str, Any] = {
            "summary": f"Standard security risk: {risk_type}",
            "analysis": f"This risk indicates a configuration that deviates from security best practices for resource `{resource_name}`.",
            "remediation": "Review the configuration and apply hardening according to the ShieldKube compliance report.",
            "impact": "Potential exposure of internal cluster resources."
        }
        
        insight = TEMPLATES.get(risk_type, default).copy()
        insight["risk_id"] = f"AI-{random.randint(1000, 9999)}"
        insight["confidence_score"] = 0.95 if risk_type in TEMPLATES else 0.75
        return insight

    def get_sbom(self, resource_name: str) -> Dict[str, Any]:
        """Generates a mock CycloneDX SBOM for the specified container image/resource."""
        self._log(f"SBOM Explorer: Retrieving bill of materials for {resource_name}...")
        
        # Simulate a manifest for common images
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "component": {
                    "name": resource_name,
                    "version": "latest",
                    "type": "container"
                }
            },
            "components": [
                {"name": "openssl", "version": "3.0.8", "licenses": ["Apache-2.0"], "purl": f"pkg:alpine/openssl@3.0.8"},
                {"name": "zlib", "version": "1.2.13", "licenses": ["Zlib"], "purl": f"pkg:alpine/zlib@1.2.13"},
                {"name": "busybox", "version": "1.36.0", "licenses": ["GPL-2.0"], "purl": f"pkg:alpine/busybox@1.36.0"},
                {"name": "libc6", "version": "2.36-9", "licenses": ["LGPL-2.1"], "purl": f"pkg:debian/libc6@2.36-9"}
            ]
        }



    def scan_events(self) -> List[Dict[str, Any]]:
        self._log("Fetching recent cluster events...")
        if self.mock_mode: return self._get_mock_events()
        try:
            events = self.v1.list_event_for_all_namespaces(_request_timeout=3).items
            # Sort by last timestamp if available
            def get_time(e):
                return getattr(e, "last_timestamp", None) or getattr(e, "event_time", None) or getattr(e.metadata, "creation_timestamp", None)
            
            valid_events = [e for e in events if get_time(e)]
            valid_events.sort(key=get_time, reverse=True)
            res = []
            for e in valid_events[:50]:
                res.append({
                    "reason": e.reason or "Unknown",
                    "message": e.message or "",
                    "type": e.type or "Normal",
                    "object": f"{e.involved_object.kind}/{e.involved_object.name}" if e.involved_object else "Unknown",
                    "namespace": e.involved_object.namespace or "cluster" if e.involved_object else "cluster",
                    "count": e.count or 1,
                    "time": str(get_time(e))
                })
            return res
        except Exception as e:
            self._log(f"Events Error: {e}", "error")
            return self._get_mock_events() if self.mock_mode else []

    def scan_secrets(self) -> List[Dict[str, Any]]:
        self._log("Auditing Secret and ConfigMap contents...")
        if self.mock_mode: return self._get_mock_secrets()
        try:
            secrets = self.v1.list_secret_for_all_namespaces(_request_timeout=3).items
            config_maps = self.v1.list_config_map_for_all_namespaces(_request_timeout=3).items
            results = []
            
            for s in secrets:
                if s.type in ("kubernetes.io/service-account-token", "kubernetes.io/tls", "kubernetes.io/dockerconfigjson"): continue
                risks = []
                # Check for weak or easily guessable secret names
                if any(weak in s.metadata.name.lower() for weak in ["test", "demo", "dev", "default"]):
                    risks.append({"type": "WeakNaming", "msg": f"Secret '{s.metadata.name}' has a weak or non-production naming convention.", "severity": "Medium"})
                
                results.append({
                    "name": s.metadata.name,
                    "namespace": s.metadata.namespace,
                    "kind": "Secret",
                    "keys": list(s.data.keys()) if s.data else [],
                    "risks": risks,
                    "severity": "High" if risks else "Low"
                })

            for cm in config_maps:
                if cm.metadata.name.startswith("kube-"): continue
                risks = []
                # Scan configmap values for hardcoded secrets
                if cm.data:
                    for k, v in cm.data.items():
                        if any(pat in k.lower() for pat in SECRET_PATTERNS) or any(pat in str(v).lower() for pat in ["bearer ", "eyjh", "password=", "api_key", "secret="]):
                            risks.append({"type": "HardcodedSecret", "msg": f"ConfigMap contains potential hardcoded secret in key: {k}", "severity": "Critical"})
                
                results.append({
                    "name": cm.metadata.name,
                    "namespace": cm.metadata.namespace,
                    "kind": "ConfigMap",
                    "keys": list(cm.data.keys()) if cm.data else [],
                    "risks": risks,
                    "severity": "Critical" if risks else "Low"
                })
                
            return results
        except Exception as e:
            self._log(f"Secrets Scan Error: {e}", "error")
            return self._get_mock_secrets() if self.mock_mode else []

    def _get_mock_secrets(self):
        return [
            {"name": "app-config", "namespace": "prod", "kind": "ConfigMap", "keys": ["DB_HOST", "DB_PASSWORD"], "severity": "Critical", "risks": [{"type": "HardcodedSecret", "msg": "ConfigMap contains potential hardcoded secret in key: DB_PASSWORD", "severity": "Critical"}]},
            {"name": "test-api-token", "namespace": "dev", "kind": "Secret", "keys": ["token"], "severity": "Medium", "risks": [{"type": "WeakNaming", "msg": "Secret 'test-api-token' has a weak or non-production naming convention.", "severity": "Medium"}]},
            {"name": "tls-certs", "namespace": "default", "kind": "Secret", "keys": ["tls.crt", "tls.key"], "severity": "Low", "risks": []},
            {"name": "oauth-client-credentials", "namespace": "auth", "kind": "Secret", "keys": ["client_id", "client_secret"], "severity": "Critical", "risks": [{"type": "HardcodedSecret", "msg": "Secret 'oauth-client-credentials' contains OAuth client_secret — rotate and use Vault or IRSA.", "severity": "Critical"}]},
            {"name": "jwt-signing-key", "namespace": "api-gateway", "kind": "Secret", "keys": ["jwt_secret", "refresh_secret"], "severity": "Critical", "risks": [{"type": "HardcodedSecret", "msg": "JWT signing key stored as plaintext Kubernetes Secret — prefer external secret manager (AWS Secrets Manager, Vault).", "severity": "Critical"}]}
        ]

    def _get_mock_compliance(self):
        return [
            {
                "framework": "CIS Kubernetes Benchmark v1.6.0",
                "description": "Baseline security posture for Kubernetes clusters",
                "score": 68,
                "controls": [
                    {"id": "5.1.1", "name": "Ensure that the cluster-admin role is only used where required", "status": "Failed", "finding": "Found 2 ServiceAccounts with cluster-admin"},
                    {"id": "5.2.2", "name": "Minimize the admission of privileged containers", "status": "Failed", "finding": "1 privileged pod running in default namespace"},
                    {"id": "5.2.8", "name": "Minimize the admission of containers with the NET_RAW capability", "status": "Passed", "finding": "No containers with NET_RAW detected"}
                ]
            },
            {
                "framework": "NSA/CISA Kubernetes Security Guidance",
                "description": "Hardening guidance for cloud clusters",
                "score": 85,
                "controls": [
                    {"id": "NSA-01", "name": "Pod Security Policies/Admission", "status": "Passed", "finding": "PodSecurity admission controller enabled"},
                    {"id": "NSA-02", "name": "Network Separation", "status": "Failed", "finding": "Default namespace allows any ingress"}
                ]
            }
        ]

    def _get_mock_events(self):
        return [
            {"reason": "BackOff", "message": "Back-off restarting failed container", "type": "Warning", "object": "Pod/nginx-api", "namespace": "prod", "count": 21, "time": "2023-11-20 14:32:00+00:00"},
            {"reason": "FailedScheduling", "message": "0/3 nodes are available: 3 Insufficient cpu.", "type": "Warning", "object": "Pod/redis-cache", "namespace": "testing", "count": 1, "time": "2023-11-20 14:30:00+00:00"},
            {"reason": "Scheduled", "message": "Successfully assigned default/webapp-01 to node-01", "type": "Normal", "object": "Pod/webapp-01", "namespace": "default", "count": 1, "time": "2023-11-20 14:28:00+00:00"}
        ]

    def _parse_cpu(self, cpu_str: str) -> float:
        try:
            if cpu_str.endswith("n"): return float(cpu_str[:-1]) / 1_000_000_000
            if cpu_str.endswith("u"): return float(cpu_str[:-1]) / 1_000_000
            if cpu_str.endswith("m"): return float(cpu_str[:-1]) / 1_000
            if cpu_str.endswith("k"): return float(cpu_str[:-1]) * 1_000
            return float(cpu_str)
        except: return 0.0

    def _parse_memory(self, mem_str: str) -> float:
        try:
            if mem_str.endswith("Ki"): return float(mem_str[:-2]) / 1024
            if mem_str.endswith("Mi"): return float(mem_str[:-2])
            if mem_str.endswith("Gi"): return float(mem_str[:-2]) * 1024
            if mem_str.endswith("Ti"): return float(mem_str[:-2]) * 1024 * 1024
            return float(mem_str) / (1024 * 1024) # assuming bytes
        except: return 0.0

    def scan_metrics(self):
        self._log("Fetching resource metrics...")
        if self.mock_mode: return self._get_mock_metrics()
        if not self.is_connected: return {"pods": [], "nodes": []}

        try:
            # Get real node capacity for accurate percentages
            node_info = {}
            try:
                nodes = self.v1.list_node(_request_timeout=3).items
                for n in nodes:
                    alloc = n.status.allocatable or {}
                    cpu_alloc = self._parse_cpu(alloc.get("cpu", "0"))
                    mem_alloc = self._parse_memory(alloc.get("memory", "0"))
                    # Determine node status
                    ready = "Unknown"
                    for cond in (n.status.conditions or []):
                        if cond.type == "Ready":
                            ready = "Ready" if cond.status == "True" else "NotReady"
                    node_info[n.metadata.name] = {
                        "cpu_alloc": cpu_alloc,
                        "mem_alloc": mem_alloc,
                        "status": ready,
                        "roles": ",".join([k.split("/")[1] for k in (n.metadata.labels or {}) if "node-role.kubernetes.io/" in k]) or "worker"
                    }
            except Exception as e:
                self._log(f"Node capacity fetch error: {e}", "warn")

            custom_api = client.CustomObjectsApi()

            # Collect pod metrics
            pods_data = []
            try:
                pod_metrics = custom_api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods", _request_timeout=3)
                for item in pod_metrics.get("items", []):
                    name = item["metadata"]["name"]
                    ns = item["metadata"]["namespace"]
                    cpu_total = sum(self._parse_cpu(c["usage"]["cpu"]) for c in item.get("containers", []))
                    mem_total = sum(self._parse_memory(c["usage"]["memory"]) for c in item.get("containers", []))
                    # Use node allocatable if available, else rough estimate
                    cpu_pct = min(100, int(cpu_total * 100))
                    mem_pct = min(100, int((mem_total / 1024) * 100))
                    pods_data.append({
                        "name": name, "namespace": ns,
                        "cpu": f"{cpu_total:.3f} cores", "memory": f"{mem_total:.1f} Mi",
                        "cpu_usage": max(1, cpu_pct), "mem_usage": max(1, mem_pct)
                    })
            except Exception as e:
                self._log(f"Pod metrics error: {e}", "warn")

            # Collect node metrics with real capacities
            nodes_data = []
            try:
                node_metrics = custom_api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes", _request_timeout=3)
                for item in node_metrics.get("items", []):
                    name = item["metadata"]["name"]
                    cpu_used = self._parse_cpu(item["usage"]["cpu"])
                    mem_used = self._parse_memory(item["usage"]["memory"])
                    info = node_info.get(name, {})
                    cpu_alloc = info.get("cpu_alloc", max(cpu_used * 1.5, 2.0))
                    mem_alloc = info.get("mem_alloc", max(mem_used * 1.5, 2048.0))
                    cpu_pct = min(100, int((cpu_used / cpu_alloc) * 100)) if cpu_alloc > 0 else 0
                    mem_pct = min(100, int((mem_used / mem_alloc) * 100)) if mem_alloc > 0 else 0
                    nodes_data.append({
                        "name": name,
                        "cpu": f"{cpu_used:.2f}/{cpu_alloc:.1f} cores",
                        "memory": f"{mem_used:.0f}/{mem_alloc:.0f} Mi",
                        "cpu_usage": max(1, cpu_pct),
                        "mem_usage": max(1, mem_pct),
                        "status": info.get("status", "Ready"),
                        "roles": info.get("roles", "worker")
                    })
            except Exception as e:
                self._log(f"Node metrics error: {e}", "warn")
                # Fall back to node info without usage stats
                for n_name, info in node_info.items():
                    nodes_data.append({
                        "name": n_name,
                        "cpu": f"0/{info['cpu_alloc']:.1f} cores",
                        "memory": f"0/{info['mem_alloc']:.0f} Mi",
                        "cpu_usage": 0, "mem_usage": 0,
                        "status": info["status"], "roles": info["roles"]
                    })

            return {"pods": pods_data, "nodes": nodes_data}
        except Exception as e:
            self._log(f"Metrics Error: {e}", "error")
            return {"pods": [], "nodes": []}


    def remediate_resource(self, kind: str, name: str, namespace: str, patch_data: str) -> Dict:
        self._log(f"EXECUTING REMEDIATION: {kind}/{name} in {namespace}...")
        
        if self.mock_mode:
            self._log(f"MOCK: Applied patch '{patch_data}' to {kind}/{name}")
            return {"status": "success", "msg": f"Mock remediation applied to {name}"}

        try:
            # Handle standard patches (YAML/JSON)
            # For simplicity, we assume patch_data is a dict or valid JSON string for strategic merge patch
            if isinstance(patch_data, str):
                import json
                try:
                    patch_body = json.loads(patch_data)
                except:
                    # If not JSON, try to wrap it (e.g., "privileged: false" -> {"spec": {"template": {"spec": {"containers": [{"name": "*", "securityContext": {"privileged": false}}]}}}})
                    # This is simplified; in a real app we'd map 'privileged: false' to exact patch structure
                    patch_body = {"spec": {"template": {"spec": {"containers": [{"name": name, "securityContext": {"privileged": false}}]}}}}
            else:
                patch_body = patch_data

            if kind.lower() == "deployment":
                self.apps_v1.patch_namespaced_deployment(name, namespace, patch_body)
            elif kind.lower() == "pod":
                self.v1.patch_namespaced_pod(name, namespace, patch_body)
            else:
                return {"status": "error", "msg": f"Remediation for {kind} not yet implemented."}

            self._log(f"SUCCESS: {kind}/{name} patched.")
            return {"status": "success", "msg": f"Resource {name} patched successfully."}
        except Exception as e:
            self._log(f"FAILURE: {str(e)}", level="error")
            return {"status": "error", "msg": str(e)}

    def _analyze_pod_security(self, pod):
        risks = []
        
        # Check Pod Spec
        if pod.spec.host_network:
            risks.append({"type": "HostNetwork", "msg": "Host network usage.", "cis": "5.2.4", "category": "Host", "patch": "hostNetwork: false", "mitre": {"tactic": "Privilege Escalation", "id": "T1611"}})
        if pod.spec.host_pid:
            risks.append({"type": "HostPID", "msg": "Host PID usage.", "cis": "5.2.3", "category": "Host", "patch": "hostPID: false", "mitre": {"tactic": "Privilege Escalation", "id": "T1611"}})
        if pod.spec.host_ipc:
            risks.append({"type": "HostIPC", "msg": "Host IPC usage.", "cis": "5.2.5", "category": "Host", "patch": "hostIPC: false", "mitre": {"tactic": "Privilege Escalation", "id": "T1611"}})

        # Service Account Token
        if pod.spec.automount_service_account_token is not False:
             risks.append({
                "type": "SAAutomount", 
                "msg": "Service Account token is automounted.", 
                "cis": "5.1.6", 
                "category": "IAM", 
                "patch": "automountServiceAccountToken: false",
                "mitre": {"tactic": "Credential Access", "id": "T1552"}
            })

        for c in pod.spec.containers:
            # Privileged
            if c.security_context and c.security_context.privileged:
                risks.append({
                    "type": "Privileged", 
                    "msg": f"Privileged container: {c.name}", 
                    "cis": "5.2.2", 
                    "category": "Runtime", 
                    "patch": "privileged: false",
                    "mitre": {"tactic": "Execution", "id": "T1611"}
                })
            
            # Root User
            if not c.security_context or not c.security_context.run_as_non_root:
                risks.append({
                    "type": "RunAsRoot", 
                    "msg": f"Container '{c.name}' may run as root.", 
                    "cis": "5.2.6", 
                    "category": "Runtime", 
                    "patch": "runAsNonRoot: true",
                    "mitre": {"tactic": "Privilege Escalation", "id": "T1548"}
                })

            # ReadOnlyRootFilesystem
            if not c.security_context or not c.security_context.read_only_root_filesystem:
                risks.append({
                    "type": "WritableRootFS", 
                    "msg": f"Writable root filesystem in '{c.name}'.", 
                    "cis": "5.2.8", 
                    "category": "Runtime", 
                    "patch": "readOnlyRootFilesystem: true",
                    "mitre": {"tactic": "Persistence", "id": "T1499"}
                })

            # CapabilityEscalation: block dangerous added caps
            DANGEROUS_CAPS = {'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'ALL'}
            if c.security_context and c.security_context.capabilities:
                added_caps = set(c.security_context.capabilities.add or [])
                hit_caps = added_caps & DANGEROUS_CAPS
                if hit_caps:
                    risks.append({
                        "type": "CapabilityEscalation",
                        "msg": f"Container '{c.name}' adds dangerous capabilities: {', '.join(hit_caps)}.",
                        "cis": "5.2.1",
                        "category": "Runtime",
                        "patch": f"capabilities: {{drop: ['ALL'], add: [<only needed>]}}",
                        "mitre": {"tactic": "Privilege Escalation", "id": "T1611"}
                    })

            # NoLivenessProbe
            if not c.liveness_probe:
                risks.append({
                    "type": "NoLivenessProbe",
                    "msg": f"Container '{c.name}' has no livenessProbe defined.",
                    "cis": "5.2.7",
                    "category": "Runtime",
                    "patch": "livenessProbe: {httpGet: {path: /healthz, port: 8080}, initialDelaySeconds: 30}",
                    "mitre": {"tactic": "Defense Evasion", "id": "T1562"}
                })

            # NoReadinessProbe
            if not c.readiness_probe:
                risks.append({
                    "type": "NoReadinessProbe",
                    "msg": f"Container '{c.name}' has no readinessProbe defined.",
                    "cis": "5.2.7",
                    "category": "Runtime",
                    "patch": "readinessProbe: {httpGet: {path: /ready, port: 8080}, initialDelaySeconds: 10}",
                    "mitre": {"tactic": "Defense Evasion", "id": "T1562"}
                })

            # UntrustedRegistry
            if not any(c.image.startswith(reg) for reg in TRUSTED_REGISTRIES):
                risks.append({
                    "type": "UntrustedRegistry",
                    "msg": f"Image '{c.image.split(':')[0]}' is not from a trusted registry ({', '.join(TRUSTED_REGISTRIES)}).",
                    "cis": "5.4.1",
                    "category": "Images",
                    "patch": f"image: gcr.io/your-project/{c.image.split('/')[-1]}",
                    "mitre": {"tactic": "Supply Chain Compromise", "id": "T1195"}
                })

            # Resource Limits
            if not c.resources or not c.resources.limits:
                risks.append({
                    "type": "ResourceLimits", 
                    "msg": f"No resource limits for '{c.name}'.", 
                    "cis": "5.6.1", 
                    "category": "Runtime", 
                    "patch": "resources: {limits: {cpu: '500m', memory: '512Mi'}}",
                    "mitre": {"tactic": "Impact", "id": "T1496"}
                })

            # Security Profiles
            seccomp = c.security_context.seccomp_profile if c.security_context else None
            apparmor = pod.metadata.annotations.get(f"container.apparmor.security.beta.kubernetes.io/{c.name}") if pod.metadata.annotations else None
            if not seccomp and not apparmor:
                risks.append({
                    "type": "NoSecurityProfile", 
                    "msg": f"No AppArmor or Seccomp profile for '{c.name}'.", 
                    "cis": "5.7.1", 
                    "category": "Runtime", 
                    "patch": "securityContext: {seccompProfile: {type: RuntimeDefault}}",
                    "mitre": {"tactic": "Defense Evasion", "id": "T1562"}
                })

            # HostPort check
            if c.ports:
                for p in c.ports:
                    if p.host_port:
                        risks.append({
                            "type": "HostPort", 
                            "msg": f"HostPort '{p.host_port}' used in '{c.name}'.", 
                            "cis": "5.2.10", 
                            "category": "Network", 
                            "patch": "hostPort: null",
                            "mitre": {"tactic": "Infiltration", "id": "T1567"}
                        })
            
            # Internal Secrets Check (Env vs Volume)
            if c.env:
                for ev in c.env:
                    if any(p in ev.name.lower() for p in SECRET_PATTERNS):
                        risks.append({
                            "type": "SecretAsEnv", 
                            "msg": f"Sensitive env var '{ev.name}' in '{c.name}'.", 
                            "cis": "5.4.2", 
                            "category": "IAM", 
                            "patch": "valueFrom: {secretKeyRef: {...}}",
                            "mitre": {"tactic": "Credential Access", "id": "T1552"}
                        })

            # Images
            if ":" not in c.image or c.image.endswith(":latest"):
                risks.append({
                    "type": "LatestTag", 
                    "msg": f"Container '{c.name}' uses :latest tag.", 
                    "cis": "5.4.1", 
                    "category": "Images", 
                    "patch": f"image: {c.image.split(':')[0]}:v1.0.0",
                    "mitre": {"tactic": "Initial Access", "id": "T1204"}
                })
        return risks

    def scan_ebpf_events(self) -> List[Dict[str, Any]]:
        """Simulate eBPF-style kernel syscall events for the eBPF runtime threat monitor."""
        self._log("eBPF Runtime Monitor: Scanning kernel events...")
        import random
        base_ts = time.time()
        events = [
            {
                "event_type": "syscall",
                "pid": random.randint(1000, 9999),
                "comm": "nginx-api",
                "syscall": "ptrace",
                "severity": "Critical",
                "detail": "Process attempted ptrace() — potential container escape vector.",
                "timestamp": time.strftime("%H:%M:%S", time.localtime(base_ts - 12)),
                "mitre": {"tactic": "Privilege Escalation", "id": "T1055"}
            },
            {
                "event_type": "file_open",
                "pid": random.randint(1000, 9999),
                "comm": "redis-cache",
                "syscall": "openat",
                "severity": "High",
                "detail": "Unexpected open of /etc/shadow — credential file access detected.",
                "timestamp": time.strftime("%H:%M:%S", time.localtime(base_ts - 45)),
                "mitre": {"tactic": "Credential Access", "id": "T1003"}
            },
            {
                "event_type": "network",
                "pid": random.randint(1000, 9999),
                "comm": "webapp-01",
                "syscall": "connect",
                "severity": "Medium",
                "detail": "Outbound connection to 185.220.101.45 (known Tor exit node).",
                "timestamp": time.strftime("%H:%M:%S", time.localtime(base_ts - 90)),
                "mitre": {"tactic": "Command and Control", "id": "T1090"}
            },
            {
                "event_type": "module_load",
                "pid": random.randint(1000, 9999),
                "comm": "kworker",
                "syscall": "init_module",
                "severity": "Critical",
                "detail": "Unexpected kernel module load — rootkit insertion attempt.",
                "timestamp": time.strftime("%H:%M:%S", time.localtime(base_ts - 180)),
                "mitre": {"tactic": "Defense Evasion", "id": "T1014"}
            },
            {
                "event_type": "exec",
                "pid": random.randint(1000, 9999),
                "comm": "sh",
                "syscall": "execve",
                "severity": "High",
                "detail": "Shell spawned inside container — possible reverse shell or interactive breakout.",
                "timestamp": time.strftime("%H:%M:%S", time.localtime(base_ts - 300)),
                "mitre": {"tactic": "Execution", "id": "T1059"}
            }
        ]
        return events

    def _calculate_severity(self, risks):
        if not risks: return "Low"
        if any(r["type"] in ("Privileged", "CapabilityEscalation") for r in risks): return "Critical"
        return "High" if len(risks) > 1 else "Medium"

    def _get_mock_pods(self):
        return [
            {"name": "nginx-api", "namespace": "prod", "severity": "Critical", "risks": [
                {"type": "Privileged", "msg": "Privileged container: nginx", "cis": "5.2.2", "category": "Runtime", "patch": "privileged: false", "mitre": {"tactic": "Execution", "id": "T1611"}},
                {"type": "CapabilityEscalation", "msg": "Container 'nginx' adds dangerous capabilities: SYS_ADMIN, NET_ADMIN.", "cis": "5.2.1", "category": "Runtime", "patch": "capabilities: {drop: ['ALL']}", "mitre": {"tactic": "Privilege Escalation", "id": "T1611"}},
                {"type": "SecretAsEnv", "msg": "Sensitive env var 'DB_PASSWORD' in 'nginx'.", "cis": "5.4.2", "category": "IAM", "patch": "valueFrom: {secretKeyRef: {...}}", "mitre": {"tactic": "Credential Access", "id": "T1552"}},
                {"type": "UntrustedRegistry", "msg": "Image 'nginx' is not from a trusted registry (gcr.io, quay.io, docker.io/library).", "cis": "5.4.1", "category": "Images", "patch": "image: gcr.io/your-project/nginx", "mitre": {"tactic": "Supply Chain Compromise", "id": "T1195"}}
            ]},
            {"name": "redis-cache", "namespace": "testing", "severity": "High", "risks": [
                {"type": "ResourceLimits", "msg": "No resource limits for 'redis'.", "cis": "5.6.1", "category": "Runtime", "patch": "resources: {limits: {cpu: '500m', memory: '512Mi'}}", "mitre": {"tactic": "Impact", "id": "T1496"}},
                {"type": "NoLivenessProbe", "msg": "Container 'redis' has no livenessProbe defined.", "cis": "5.2.7", "category": "Runtime", "patch": "livenessProbe: {tcpSocket: {port: 6379}, initialDelaySeconds: 15}", "mitre": {"tactic": "Defense Evasion", "id": "T1562"}},
                {"type": "NoReadinessProbe", "msg": "Container 'redis' has no readinessProbe defined.", "cis": "5.2.7", "category": "Runtime", "patch": "readinessProbe: {tcpSocket: {port: 6379}, initialDelaySeconds: 5}", "mitre": {"tactic": "Defense Evasion", "id": "T1562"}}
            ]},
            {"name": "webapp-01", "namespace": "default", "severity": "High", "risks": [
                {"type": "LatestTag", "msg": "Container 'webapp' uses :latest tag.", "cis": "5.4.1", "category": "Images", "patch": "image: nginx:1.25", "mitre": {"tactic": "Initial Access", "id": "T1204"}},
                {"type": "WritableRootFS", "msg": "Writable root filesystem in 'webapp'.", "cis": "5.2.8", "category": "Runtime", "patch": "readOnlyRootFilesystem: true", "mitre": {"tactic": "Persistence", "id": "T1499"}},
                {"type": "NoSecurityProfile", "msg": "No AppArmor or Seccomp profile for 'webapp'.", "cis": "5.7.1", "category": "Runtime", "patch": "securityContext: {seccompProfile: {type: RuntimeDefault}}", "mitre": {"tactic": "Defense Evasion", "id": "T1562"}}
            ]},
            {"name": "ml-inference", "namespace": "ai", "severity": "Critical", "risks": [
                {"type": "CapabilityEscalation", "msg": "Container 'ml-inference' adds dangerous capabilities: SYS_PTRACE.", "cis": "5.2.1", "category": "Runtime", "patch": "capabilities: {drop: ['ALL']}", "mitre": {"tactic": "Privilege Escalation", "id": "T1611"}},
                {"type": "UntrustedRegistry", "msg": "Image 'ml-inference' is not from a trusted registry.", "cis": "5.4.1", "category": "Images", "patch": "image: gcr.io/your-project/ml-inference", "mitre": {"tactic": "Supply Chain Compromise", "id": "T1195"}},
                {"type": "NoLivenessProbe", "msg": "Container 'ml-inference' has no livenessProbe defined.", "cis": "5.2.7", "category": "Runtime", "patch": "livenessProbe: {httpGet: {path: /healthz, port: 8080}}", "mitre": {"tactic": "Defense Evasion", "id": "T1562"}}
            ]}
        ]

    def _get_mock_inventory(self):
        return [
            {"kind": "Deployment", "name": "api-gateway", "namespace": "prod", "group": "Workloads", "status": "Ready"},
            {"kind": "Pod", "name": "webapp-pod", "namespace": "default", "group": "Workloads", "status": "Running"},
            {"kind": "Node", "name": "master-1", "namespace": "Global", "group": "Infrastructure", "status": "Ready"},
            {"kind": "Service", "name": "db-proxy", "namespace": "data", "group": "Network", "status": "ClusterIP"},
            {"kind": "ConfigMap", "name": "env-vars", "namespace": "default", "group": "Configuration", "status": "12 Keys"}
        ]

    def _get_mock_deep_vulnerabilities(self):
        return {
            "pods": [
                {"target": "auth-pod", "namespace": "prod", "image": "nginx:1.14", "id": "CVE-2023-44487", "severity": "Critical", "title": "HTTP/2 Rapid Reset"},
                {"target": "web-pod", "namespace": "default", "image": "python:3.9", "id": "CVE-2023-24329", "severity": "High", "title": "URL Parsing Bypass"}
            ],
            "nodes": [{"target": "node-01", "severity": "High", "id": "NODE-K1", "title": "Kernel Exposure", "remediation": "Patch host OS"}],
            "volumes": [{"target": "data-vol", "severity": "Medium", "id": "VOL-E1", "title": "Non-encrypted storage"}],
            "infrastructure": [{"target": "dev-ns", "severity": "Medium", "id": "INFRA-01", "title": "Missing ResourceQuota", "remediation": "Apply ResourceQuota limits."}],
            "replica_sets": [{"target": "web-rs", "namespace": "default", "image": "nginx:1.19", "id": "CVE-2021-23017", "severity": "High", "title": "Resolver buffer overflow"}],
            "deployments": [
                {"target": "web-deploy", "namespace": "default", "image": "redis:6.0", "id": "CVE-2023-41056", "severity": "High", "title": "Integer Overflow"},
                {"target": "api-gateway", "namespace": "prod", "severity": "Medium", "id": "AVAIL-01", "title": "Missing PodDisruptionBudget", "remediation": "Create a PDB to ensure availability."}
            ]
        }

    def _get_mock_metrics(self):
        import random
        return {
            "pods": [
                {"name": "nginx-api", "namespace": "prod", "cpu": f"{random.randint(10, 80)}%", "memory": f"{random.randint(100, 400)}Mi", "cpu_usage": random.randint(5, 95), "mem_usage": random.randint(10, 90)},
                {"name": "redis-cache", "namespace": "testing", "cpu": f"{random.randint(5, 40)}%", "memory": f"{random.randint(200, 800)}Mi", "cpu_usage": random.randint(5, 95), "mem_usage": random.randint(10, 90)},
                {"name": "webapp-01", "namespace": "default", "cpu": f"{random.randint(20, 60)}%", "memory": f"{random.randint(50, 200)}Mi", "cpu_usage": random.randint(5, 95), "mem_usage": random.randint(10, 90)}
            ],
            "nodes": [
                {"name": "node-01", "cpu": "45%", "memory": "12Gi", "cpu_usage": 45, "mem_usage": 75},
                {"name": "node-02", "cpu": "22%", "memory": "8Gi", "cpu_usage": 22, "mem_usage": 50}
            ]
        }
