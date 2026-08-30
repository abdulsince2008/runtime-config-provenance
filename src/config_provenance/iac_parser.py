from typing import List, Dict, Any, Optional
from pathlib import Path
import yaml
import base64

from .models import ContainerConfig, IaCManifest


class IaCParser:
    def __init__(self, manifest_dirs: List[str]):
        self.manifest_dirs = [Path(d) for d in manifest_dirs]
        self._config_maps: Dict[tuple, Dict[str, str]] = {}
        self._secrets: Dict[tuple, Dict[str, str]] = {}

    def parse_all(self) -> List[IaCManifest]:
        # First pass: collect all ConfigMaps and Secrets
        self._collect_config_maps_and_secrets()

        # Second pass: parse workloads
        manifests = []
        for manifest_dir in self.manifest_dirs:
            if not manifest_dir.exists():
                continue
            for yaml_file in manifest_dir.rglob("*.yaml"):
                manifests.extend(self._parse_file(yaml_file))
            for yml_file in manifest_dir.rglob("*.yml"):
                manifests.extend(self._parse_file(yml_file))
        return manifests

    def _collect_config_maps_and_secrets(self):
        for manifest_dir in self.manifest_dirs:
            if not manifest_dir.exists():
                continue
            for yaml_file in manifest_dir.rglob("*.yaml"):
                self._parse_config_map_and_secret(yaml_file)
            for yml_file in manifest_dir.rglob("*.yml"):
                self._parse_config_map_and_secret(yml_file)

    def _parse_config_map_and_secret(self, file_path: Path):
        try:
            with open(file_path, 'r') as f:
                docs = list(yaml.safe_load_all(f))
        except Exception:
            return

        for doc in docs:
            if not doc or not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "")
            namespace = metadata.get("namespace", "default")
            key = (namespace, name)

            if kind == "ConfigMap":
                data = doc.get("data", {})
                if data:
                    self._config_maps[key] = data
            elif kind == "Secret":
                data = doc.get("data", {})
                string_data = doc.get("stringData", {})
                decoded = {}
                for k, v in data.items():
                    try:
                        decoded[k] = base64.b64decode(v).decode()
                    except Exception:
                        decoded[k] = v
                decoded.update(string_data)
                if decoded:
                    self._secrets[key] = decoded

    def _parse_file(self, file_path: Path) -> List[IaCManifest]:
        manifests = []
        try:
            with open(file_path, 'r') as f:
                docs = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return manifests

        for doc in docs:
            if not doc or not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            if kind not in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "ReplicaSet"):
                continue

            metadata = doc.get("metadata", {})
            name = metadata.get("name", "")
            namespace = metadata.get("namespace", "default")

            spec = doc.get("spec", {})
            template_spec = None

            if kind == "Pod":
                template_spec = spec
            else:
                template = spec.get("template", {})
                template_spec = template.get("spec", {})

            if not template_spec:
                continue

            containers = self._extract_containers(template_spec, namespace)
            if not containers:
                continue

            manifest = IaCManifest(
                source_path=str(file_path),
                kind=kind,
                namespace=namespace,
                name=name,
                containers=containers
            )
            manifests.append(manifest)

        return manifests

    def _extract_containers(self, pod_spec: Dict[str, Any], namespace: str) -> List[ContainerConfig]:
        containers = []
        for container in pod_spec.get("containers", []):
            env_vars = {}
            config_maps = {}
            secrets = {}

            # Direct env vars
            for env_var in container.get("env", []):
                if "value" in env_var:
                    env_vars[env_var["name"]] = env_var["value"]
                elif "valueFrom" in env_var:
                    vf = env_var["valueFrom"]
                    if "configMapKeyRef" in vf:
                        cm_name = vf["configMapKeyRef"]["name"]
                        key = vf["configMapKeyRef"]["key"]
                        cm_data = self._config_maps.get((namespace, cm_name), {})
                        if key in cm_data:
                            env_vars[env_var["name"]] = cm_data[key]
                    elif "secretKeyRef" in vf:
                        sec_name = vf["secretKeyRef"]["name"]
                        key = vf["secretKeyRef"]["key"]
                        sec_data = self._secrets.get((namespace, sec_name), {})
                        if key in sec_data:
                            env_vars[env_var["name"]] = sec_data[key]

            # envFrom
            for env_from in container.get("envFrom", []):
                if "configMapRef" in env_from:
                    cm_name = env_from["configMapRef"]["name"]
                    cm_data = self._config_maps.get((namespace, cm_name), {})
                    if cm_data:
                        config_maps[cm_name] = cm_data
                        env_vars.update(cm_data)
                elif "secretRef" in env_from:
                    sec_name = env_from["secretRef"]["name"]
                    sec_data = self._secrets.get((namespace, sec_name), {})
                    if sec_data:
                        secrets[sec_name] = sec_data
                        env_vars.update(sec_data)

            # Volume mounts
            for vm in container.get("volumeMounts", []):
                for vol in pod_spec.get("volumes", []):
                    if vol.get("name") == vm.get("name"):
                        if "configMap" in vol:
                            cm_name = vol["configMap"]["name"]
                            cm_data = self._config_maps.get((namespace, cm_name), {})
                            if cm_data:
                                config_maps[cm_name] = cm_data
                        elif "secret" in vol:
                            sec_name = vol["secret"]["secretName"]
                            sec_data = self._secrets.get((namespace, sec_name), {})
                            if sec_data:
                                secrets[sec_name] = sec_data

            containers.append(ContainerConfig(
                name=container.get("name", ""),
                image=container.get("image", ""),
                env_vars=env_vars,
                config_maps=config_maps,
                secrets=secrets,
                command=list(container.get("command", [])),
                args=list(container.get("args", [])),
                working_dir=container.get("workingDir", ""),
                ports=[{"containerPort": p.get("containerPort"), "protocol": p.get("protocol", "TCP")} for p in container.get("ports", [])]
            ))

        return containers


class MockRuntimeProvider:
    def __init__(self, sample_pods: List[Dict[str, Any]]):
        self.sample_pods = sample_pods

    def get_pods(self, namespace: str, label_selector: Optional[str] = None) -> List[Any]:
        from .models import PodEffectiveConfig, ContainerConfig
        result = []
        for pod_data in self.sample_pods:
            if pod_data.get("namespace") != namespace:
                continue
            if label_selector:
                labels = pod_data.get("labels", {})
                match = True
                for kv in label_selector.split(","):
                    k, v = kv.split("=")
                    if labels.get(k) != v:
                        match = False
                        break
                if not match:
                    continue

            containers = []
            for c in pod_data.get("containers", []):
                containers.append(ContainerConfig(
                    name=c["name"],
                    image=c["image"],
                    env_vars=c.get("env_vars", {}),
                    config_maps=c.get("config_maps", {}),
                    secrets=c.get("secrets", {}),
                    command=c.get("command", []),
                    args=c.get("args", []),
                    working_dir=c.get("working_dir", ""),
                    ports=c.get("ports", []),
                ))
            result.append(PodEffectiveConfig(
                namespace=pod_data["namespace"],
                pod_name=pod_data["name"],
                containers=containers,
                labels=pod_data.get("labels", {}),
                annotations=pod_data.get("annotations", {}),
                service_account=pod_data.get("service_account", ""),
                node_name=pod_data.get("node_name", ""),
            ))
        return result