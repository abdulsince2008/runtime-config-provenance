from typing import List, Dict, Any, Optional, Tuple
from difflib import unified_diff

from .models import (
    PodEffectiveConfig, IaCManifest, ContainerConfig,
    DriftFinding, DriftReport
)


class ConfigComparator:
    SEVERITY_RULES = {
        "image": "critical",
        "command": "high",
        "args": "high",
        "env_vars": "medium",
        "config_maps": "medium",
        "secrets": "high",
        "working_dir": "low",
        "ports": "medium",
    }

    def __init__(self, iac_manifests: List[IaCManifest]):
        self.iac_manifests = iac_manifests
        self._index = self._build_index()

    def _build_index(self) -> Dict[Tuple[str, str], List[IaCManifest]]:
        index = {}
        for m in self.iac_manifests:
            key = (m.namespace, m.name)
            if key not in index:
                index[key] = []
            index[key].append(m)
        return index

    def find_matching_iac(self, pod: PodEffectiveConfig) -> Optional[IaCManifest]:
        key = (pod.namespace, pod.labels.get("app", ""))
        candidates = self._index.get(key, [])

        if not candidates:
            for m in self.iac_manifests:
                if m.namespace == pod.namespace:
                    return m
            return None

        best_match = None
        best_score = -1
        for candidate in candidates:
            score = self._similarity_score(pod, candidate)
            if score > best_score:
                best_score = score
                best_match = candidate

        return best_match

    def _similarity_score(self, pod: PodEffectiveConfig, iac: IaCManifest) -> int:
        score = 0
        pod_containers = {c.name: c for c in pod.containers}
        iac_containers = {c.name: c for c in iac.containers}

        for name in set(pod_containers.keys()) | set(iac_containers.keys()):
            if name in pod_containers and name in iac_containers:
                if pod_containers[name].hash() == iac_containers[name].hash():
                    score += 100
                else:
                    score += 50
            elif name in pod_containers:
                score += 10
            elif name in iac_containers:
                score += 10

        return score

    def compare(self, pod: PodEffectiveConfig, iac: Optional[IaCManifest]) -> DriftReport:
        if not iac:
            return DriftReport(
                pod_name=pod.pod_name,
                namespace=pod.namespace,
                runtime_hash=pod.overall_hash(),
                iac_hash="",
                matched_iac_source=None,
                findings=[DriftFinding(
                    pod_name=pod.pod_name,
                    namespace=pod.namespace,
                    container_name="",
                    drift_type="no_iac_match",
                    field_path="",
                    iac_value=None,
                    runtime_value="No matching IaC manifest found",
                    severity="critical"
                )]
            )

        runtime_hash = pod.overall_hash()
        iac_hash = iac.hash

        findings = []
        pod_containers = {c.name: c for c in pod.containers}
        iac_containers = {c.name: c for c in iac.containers}

        all_container_names = set(pod_containers.keys()) | set(iac_containers.keys())

        for name in all_container_names:
            rc = pod_containers.get(name)
            ic = iac_containers.get(name)

            if rc and not ic:
                findings.append(DriftFinding(
                    pod_name=pod.pod_name,
                    namespace=pod.namespace,
                    container_name=name,
                    drift_type="extra_container",
                    field_path="container",
                    iac_value=None,
                    runtime_value=f"Container '{name}' exists in runtime but not in IaC",
                    severity="high"
                ))
                continue

            if ic and not rc:
                findings.append(DriftFinding(
                    pod_name=pod.pod_name,
                    namespace=pod.namespace,
                    container_name=name,
                    drift_type="missing_container",
                    field_path="container",
                    iac_value=f"Container '{name}' defined in IaC",
                    runtime_value=None,
                    severity="high"
                ))
                continue

            if rc and ic:
                findings.extend(self._compare_containers(pod.pod_name, pod.namespace, name, rc, ic))

        return DriftReport(
            pod_name=pod.pod_name,
            namespace=pod.namespace,
            runtime_hash=runtime_hash,
            iac_hash=iac_hash,
            matched_iac_source=iac.source_path,
            findings=findings
        )

    def _compare_containers(
        self, pod_name: str, namespace: str, container_name: str,
        runtime: ContainerConfig, iac: ContainerConfig
    ) -> List[DriftFinding]:
        findings = []

        if runtime.image != iac.image:
            findings.append(DriftFinding(
                pod_name=pod_name,
                namespace=namespace,
                container_name=container_name,
                drift_type="image_mismatch",
                field_path="image",
                iac_value=iac.image,
                runtime_value=runtime.image,
                severity=self.SEVERITY_RULES["image"]
            ))

        if runtime.command != iac.command:
            findings.append(DriftFinding(
                pod_name=pod_name,
                namespace=namespace,
                container_name=container_name,
                drift_type="command_mismatch",
                field_path="command",
                iac_value=iac.command,
                runtime_value=runtime.command,
                severity=self.SEVERITY_RULES["command"]
            ))

        if runtime.args != iac.args:
            findings.append(DriftFinding(
                pod_name=pod_name,
                namespace=namespace,
                container_name=container_name,
                drift_type="args_mismatch",
                field_path="args",
                iac_value=iac.args,
                runtime_value=runtime.args,
                severity=self.SEVERITY_RULES["args"]
            ))

        if runtime.working_dir != iac.working_dir:
            findings.append(DriftFinding(
                pod_name=pod_name,
                namespace=namespace,
                container_name=container_name,
                drift_type="working_dir_mismatch",
                field_path="workingDir",
                iac_value=iac.working_dir,
                runtime_value=runtime.working_dir,
                severity=self.SEVERITY_RULES["working_dir"]
            ))

        findings.extend(self._compare_dict(
            pod_name, namespace, container_name,
            "env_vars", runtime.env_vars, iac.env_vars,
            self.SEVERITY_RULES["env_vars"]
        ))

        findings.extend(self._compare_nested_dict(
            pod_name, namespace, container_name,
            "config_maps", runtime.config_maps, iac.config_maps,
            self.SEVERITY_RULES["config_maps"]
        ))

        findings.extend(self._compare_nested_dict(
            pod_name, namespace, container_name,
            "secrets", runtime.secrets, iac.secrets,
            self.SEVERITY_RULES["secrets"]
        ))

        findings.extend(self._compare_ports(
            pod_name, namespace, container_name,
            runtime.ports, iac.ports
        ))

        return findings

    def _compare_dict(
        self, pod_name: str, namespace: str, container_name: str,
        field_type: str, runtime: Dict[str, Any], iac: Dict[str, Any],
        severity: str
    ) -> List[DriftFinding]:
        findings = []
        all_keys = set(runtime.keys()) | set(iac.keys())

        for key in all_keys:
            if key not in runtime:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type=f"{field_type}_missing",
                    field_path=f"{field_type}.{key}",
                    iac_value=iac[key],
                    runtime_value=None,
                    severity=severity
                ))
            elif key not in iac:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type=f"{field_type}_extra",
                    field_path=f"{field_type}.{key}",
                    iac_value=None,
                    runtime_value=runtime[key],
                    severity=severity
                ))
            elif runtime[key] != iac[key]:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type=f"{field_type}_mismatch",
                    field_path=f"{field_type}.{key}",
                    iac_value=iac[key],
                    runtime_value=runtime[key],
                    severity=severity
                ))

        return findings

    def _compare_nested_dict(
        self, pod_name: str, namespace: str, container_name: str,
        field_type: str, runtime: Dict[str, Dict[str, Any]], iac: Dict[str, Dict[str, Any]],
        severity: str
    ) -> List[DriftFinding]:
        findings = []
        all_mounts = set(runtime.keys()) | set(iac.keys())

        for mount_name in all_mounts:
            if mount_name not in runtime:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type=f"{field_type}_mount_missing",
                    field_path=f"{field_type}.{mount_name}",
                    iac_value=iac[mount_name],
                    runtime_value=None,
                    severity=severity
                ))
            elif mount_name not in iac:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type=f"{field_type}_mount_extra",
                    field_path=f"{field_type}.{mount_name}",
                    iac_value=None,
                    runtime_value=runtime[mount_name],
                    severity=severity
                ))
            else:
                rt_keys = set(runtime[mount_name].keys())
                iac_keys = set(iac[mount_name].keys())
                all_keys = rt_keys | iac_keys

                for key in all_keys:
                    if key not in runtime[mount_name]:
                        findings.append(DriftFinding(
                            pod_name=pod_name,
                            namespace=namespace,
                            container_name=container_name,
                            drift_type=f"{field_type}_key_missing",
                            field_path=f"{field_type}.{mount_name}.{key}",
                            iac_value=iac[mount_name][key],
                            runtime_value=None,
                            severity=severity
                        ))
                    elif key not in iac[mount_name]:
                        findings.append(DriftFinding(
                            pod_name=pod_name,
                            namespace=namespace,
                            container_name=container_name,
                            drift_type=f"{field_type}_key_extra",
                            field_path=f"{field_type}.{mount_name}.{key}",
                            iac_value=None,
                            runtime_value=runtime[mount_name][key],
                            severity=severity
                        ))
                    elif runtime[mount_name][key] != iac[mount_name][key]:
                        findings.append(DriftFinding(
                            pod_name=pod_name,
                            namespace=namespace,
                            container_name=container_name,
                            drift_type=f"{field_type}_key_mismatch",
                            field_path=f"{field_type}.{mount_name}.{key}",
                            iac_value=iac[mount_name][key],
                            runtime_value=runtime[mount_name][key],
                            severity=severity
                        ))

        return findings

    def _compare_ports(
        self, pod_name: str, namespace: str, container_name: str,
        runtime: List[Dict[str, Any]], iac: List[Dict[str, Any]]
    ) -> List[DriftFinding]:
        findings = []
        rt_ports = {p["containerPort"]: p for p in runtime}
        iac_ports = {p["containerPort"]: p for p in iac}
        all_ports = set(rt_ports.keys()) | set(iac_ports.keys())

        for port in all_ports:
            if port not in rt_ports:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type="port_missing",
                    field_path=f"ports.{port}",
                    iac_value=iac_ports[port],
                    runtime_value=None,
                    severity=self.SEVERITY_RULES["ports"]
                ))
            elif port not in iac_ports:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type="port_extra",
                    field_path=f"ports.{port}",
                    iac_value=None,
                    runtime_value=rt_ports[port],
                    severity=self.SEVERITY_RULES["ports"]
                ))
            elif rt_ports[port] != iac_ports[port]:
                findings.append(DriftFinding(
                    pod_name=pod_name,
                    namespace=namespace,
                    container_name=container_name,
                    drift_type="port_mismatch",
                    field_path=f"ports.{port}",
                    iac_value=iac_ports[port],
                    runtime_value=rt_ports[port],
                    severity=self.SEVERITY_RULES["ports"]
                ))

        return findings


def generate_diff(iac_value: Any, runtime_value: Any, field_path: str) -> str:
    iac_str = str(iac_value) if iac_value is not None else "<missing>"
    runtime_str = str(runtime_value) if runtime_value is not None else "<missing>"
    return "\n".join(unified_diff(
        [iac_str], [runtime_str],
        fromfile=f"IaC ({field_path})", tofile=f"Runtime ({field_path})",
        lineterm=""
    ))