from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import hashlib
import json


@dataclass
class ContainerConfig:
    name: str
    image: str
    env_vars: Dict[str, str] = field(default_factory=dict)
    config_maps: Dict[str, Dict[str, str]] = field(default_factory=dict)
    secrets: Dict[str, Dict[str, str]] = field(default_factory=dict)
    command: List[str] = field(default_factory=list)
    args: List[str] = field(default_factory=list)
    working_dir: str = ""
    ports: List[Dict[str, Any]] = field(default_factory=list)

    def to_hashable(self) -> str:
        data = {
            "name": self.name,
            "image": self.image,
            "env_vars": dict(sorted(self.env_vars.items())),
            "config_maps": {k: dict(sorted(v.items())) for k, v in sorted(self.config_maps.items())},
            "secrets": {k: dict(sorted(v.items())) for k, v in sorted(self.secrets.items())},
            "command": self.command,
            "args": self.args,
            "working_dir": self.working_dir,
            "ports": sorted(self.ports, key=lambda x: x.get("containerPort", 0)),
        }
        return json.dumps(data, sort_keys=True)

    def hash(self) -> str:
        return hashlib.sha256(self.to_hashable().encode()).hexdigest()[:16]


@dataclass
class PodEffectiveConfig:
    namespace: str
    pod_name: str
    containers: List[ContainerConfig]
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    service_account: str = ""
    node_name: str = ""
    captured_at: datetime = field(default_factory=datetime.utcnow)

    def overall_hash(self) -> str:
        combined = "".join(sorted(c.hash() for c in self.containers))
        return hashlib.sha256(combined.encode()).hexdigest()[:16]


@dataclass
class IaCManifest:
    source_path: str
    kind: str
    namespace: str
    name: str
    containers: List[ContainerConfig]
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            combined = "".join(sorted(c.hash() for c in self.containers))
            self.hash = hashlib.sha256(combined.encode()).hexdigest()[:16]


@dataclass
class DriftFinding:
    pod_name: str
    namespace: str
    container_name: str
    drift_type: str
    field_path: str
    iac_value: Any
    runtime_value: Any
    severity: str = "medium"


@dataclass
class DriftReport:
    pod_name: str
    namespace: str
    runtime_hash: str
    iac_hash: str
    matched_iac_source: Optional[str]
    findings: List[DriftFinding] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def has_drift(self) -> bool:
        return len(self.findings) > 0

    @property
    def drift_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")