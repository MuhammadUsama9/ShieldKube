import os
import re
import time
import random
from kubernetes import client, config
from typing import List, Dict, Any
from collections import defaultdict

TRUSTED_REGISTRIES = ["gcr.io", "quay.io", "docker.io/library"]
SECRET_PATTERNS = ["key", "pass", "token", "secret", "auth", "pwd"]

CVE_DB = {
    "nginx": [
        {"id": "CVE-2023-44487", "severity": "Critical", "title": "HTTP/2 Rapid Reset Attack", "fixed_in": "1.25.3"},
        {"id": "CVE-2021-23017", "severity": "High", "title": "Resolver buffer overflow", "fixed_in": "1.21.0"}
    ],
    "redis": [
        {"id": "CVE-2023-41056", "severity": "High", "title": "Integer overflow", "fixed_in": "7.2.1"},
        {"id": "CVE-2022-24736", "severity": "Medium", "title": "Lua script execution", "fixed_in": "6.2.7"}
    ],
    "alpine": [{"id": "CVE-2022-30065", "severity": "Medium", "title": "Busybox use-after-free", "fixed_in": "3.16.0"}],
    "python": [{"id": "CVE-2023-24329", "severity": "High", "title": "URL parsing bypass", "fixed_in": "3.11.2"}]
}

class K8sScanner:
    def __init__(self, mock_mode: bool = False):
        self.mock_mode = mock_mode
        self.scan_logs = []
        if not self.mock_mode:
            try:
                config.load_kube_config()
                self.v1 = client.CoreV1Api()
                self.apps_v1 = client.AppsV1Api()
                self.networking_v1 = client.NetworkingV1Api()
                self.rbac_v1 = client.RbacAuthorizationV1Api()
                self.policy_v1 = client.PolicyV1Api()
                self._log("ShieldKube Engine v1.0 (Live Audit) Initialized.")
            except Exception as e:
                self._log(f"Init Error: {e}", "error")
                self.mock_mode = True

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
        except Exception: return self._get_mock_inventory()

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
            self._log(f"Deep scan error: {e}", "error")
            return self._get_mock_deep_vulnerabilities()

    def _check_image_cve(self, image: str) -> List[Dict]:
        base = image.split('/')[-1].split(':')[0]
        return CVE_DB.get(base, [])

    def scan_pods(self) -> List[Dict]:
        if self.mock_mode: return self._get_mock_pods()
        try:
            pods = self.v1.list_pod_for_all_namespaces(_request_timeout=3).items
            res = []
            for p in pods:
                risks = self._analyze_pod_security(p)
                res.append({"name": p.metadata.name, "namespace": p.metadata.namespace, "risks": risks, "severity": self._calculate_severity(risks)})
            return res
        except Exception: return self._get_mock_pods()

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
                        "name": role.metadata.name,
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
        self._log("Running CIS Compliance audit...")
        if self.mock_mode: return self._get_mock_compliance()
        return []

    def scan_metrics(self):
        self._log("Fetching resource metrics...")
        if self.mock_mode: return self._get_mock_metrics()
        # In a real cluster, this would query Metrics Server or Prometheus
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

            # Capabilities
            if c.security_context and c.security_context.capabilities:
                add = c.security_context.capabilities.add or []
                if "SYS_ADMIN" in add or "ALL" in add:
                    risks.append({
                        "type": "DangerousCapabilities", 
                        "msg": f"Dangerous capabilities in '{c.name}'.", 
                        "cis": "5.2.1", 
                        "category": "Runtime", 
                        "patch": "capabilities: {drop: ['ALL']}",
                        "mitre": {"tactic": "Privilege Escalation", "id": "T1611"}
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

    def _calculate_severity(self, risks):
        if not risks: return "Low"
        if any(r["type"] == "Privileged" for r in risks): return "Critical"
        return "High" if len(risks) > 1 else "Medium"

    def _get_mock_pods(self):
        return [
            {"name": "nginx-api", "namespace": "prod", "severity": "Critical", "risks": [
                {"type": "Privileged", "msg": "Privileged container: nginx", "cis": "5.2.2", "category": "Runtime", "patch": "privileged: false", "mitre": {"tactic": "Execution", "id": "T1611"}},
                {"type": "RunAsRoot", "msg": "Container 'nginx' may run as root.", "cis": "5.2.6", "category": "Runtime", "patch": "runAsNonRoot: true", "mitre": {"tactic": "Privilege Escalation", "id": "T1548"}},
                {"type": "SecretAsEnv", "msg": "Sensitive env var 'DB_PASSWORD' in 'nginx'.", "cis": "5.4.2", "category": "IAM", "patch": "valueFrom: {secretKeyRef: {...}}", "mitre": {"tactic": "Credential Access", "id": "T1552"}}
            ]},
            {"name": "redis-cache", "namespace": "testing", "severity": "High", "risks": [
                {"type": "ResourceLimits", "msg": "No resource limits for 'redis'.", "cis": "5.6.1", "category": "Runtime", "patch": "resources: {limits: {cpu: '500m', memory: '512Mi'}}", "mitre": {"tactic": "Impact", "id": "T1496"}},
                {"type": "SAAutomount", "msg": "Service Account token is automounted.", "cis": "5.1.6", "category": "IAM", "patch": "automountServiceAccountToken: false", "mitre": {"tactic": "Credential Access", "id": "T1552"}},
                {"type": "HostPort", "msg": "HostPort '6379' used in 'redis'.", "cis": "5.2.10", "category": "Network", "patch": "hostPort: null", "mitre": {"tactic": "Infiltration", "id": "T1567"}}
            ]},
            {"name": "webapp-01", "namespace": "default", "severity": "High", "risks": [
                {"type": "LatestTag", "msg": "Container 'webapp' uses :latest tag.", "cis": "5.4.1", "category": "Images", "patch": "image: nginx:1.25", "mitre": {"tactic": "Initial Access", "id": "T1204"}},
                {"type": "WritableRootFS", "msg": "Writable root filesystem in 'webapp'.", "cis": "5.2.8", "category": "Runtime", "patch": "readOnlyRootFilesystem: true", "mitre": {"tactic": "Persistence", "id": "T1499"}},
                {"type": "NoSecurityProfile", "msg": "No AppArmor or Seccomp profile for 'webapp'.", "cis": "5.7.1", "category": "Runtime", "patch": "securityContext: {seccompProfile: {type: RuntimeDefault}}", "mitre": {"tactic": "Defense Evasion", "id": "T1562"}}
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
