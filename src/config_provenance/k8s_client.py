from typing import List, Optional, Dict, Any
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from .models import ContainerConfig, PodEffectiveConfig


class K8sClient:
    def __init__(self, kubeconfig_path: Optional[str] = None, context: Optional[str] = None):
        self.kubeconfig_path = kubeconfig_path
        self.context = context
        self._core_v1: Optional[client.CoreV1Api] = None
        self._apps_v1: Optional[client.AppsV1Api] = None

    def _get_core_v1(self) -> client.CoreV1Api:
        if self._core_v1 is None:
            if self.kubeconfig_path:
                config.load_kube_config(config_file=self.kubeconfig_path, context=self.context)
            else:
                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config(context=self.context)
            self._core_v1 = client.CoreV1Api()
        return self._core_v1

    def _get_apps_v1(self) -> client.AppsV1Api:
        if self._apps_v1 is None:
            if self.kubeconfig_path:
                config.load_kube_config(config_file=self.kubeconfig_path, context=self.context)
            else:
                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config(context=self.context)
            self._apps_v1 = client.AppsV1Api()
        return self._apps_v1

    def list_pods(self, namespace: str, label_selector: Optional[str] = None) -> List[client.V1Pod]:
        core_v1 = self._get_core_v1()
        try:
            resp = core_v1.list_namespaced_pod(namespace, label_selector=label_selector)
            return resp.items
        except ApiException as e:
            if e.status == 404:
                return []
            raise

    def get_pod(self, namespace: str, name: str) -> Optional[client.V1Pod]:
        core_v1 = self._get_core_v1()
        try:
            return core_v1.read_namespaced_pod(name, namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def get_config_map(self, namespace: str, name: str) -> Optional[client.V1ConfigMap]:
        core_v1 = self._get_core_v1()
        try:
            return core_v1.read_namespaced_config_map(name, namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def get_secret(self, namespace: str, name: str) -> Optional[client.V1Secret]:
        core_v1 = self._get_core_v1()
        try:
            return core_v1.read_namespaced_secret(name, namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def list_deployments(self, namespace: str, label_selector: Optional[str] = None) -> List[client.V1Deployment]:
        apps_v1 = self._get_apps_v1()
        try:
            resp = apps_v1.list_namespaced_deployment(namespace, label_selector=label_selector)
            return resp.items
        except ApiException as e:
            if e.status == 404:
                return []
            raise

    def get_deployment(self, namespace: str, name: str) -> Optional[client.V1Deployment]:
        apps_v1 = self._get_apps_v1()
        try:
            return apps_v1.read_namespaced_deployment(name, namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def extract_pod_effective_config(self, pod: client.V1Pod) -> PodEffectiveConfig:
        containers = []
        for container in pod.spec.containers:
            env_vars = {}
            config_maps = {}
            secrets = {}

            if container.env:
                for env_var in container.env:
                    if env_var.value is not None:
                        env_vars[env_var.name] = env_var.value
                    elif env_var.value_from:
                        if env_var.value_from.config_map_key_ref:
                            cm_name = env_var.value_from.config_map_key_ref.name
                            key = env_var.value_from.config_map_key_ref.key
                            cm = self.get_config_map(pod.metadata.namespace, cm_name)
                            if cm and cm.data and key in cm.data:
                                env_vars[env_var.name] = cm.data[key]
                        elif env_var.value_from.secret_key_ref:
                            sec_name = env_var.value_from.secret_key_ref.name
                            key = env_var.value_from.secret_key_ref.key
                            sec = self.get_secret(pod.metadata.namespace, sec_name)
                            if sec and sec.data and key in sec.data:
                                import base64
                                env_vars[env_var.name] = base64.b64decode(sec.data[key]).decode()

            if container.env_from:
                for env_from in container.env_from:
                    if env_from.config_map_ref:
                        cm = self.get_config_map(pod.metadata.namespace, env_from.config_map_ref.name)
                        if cm and cm.data:
                            config_maps[env_from.config_map_ref.name] = cm.data
                    elif env_from.secret_ref:
                        sec = self.get_secret(pod.metadata.namespace, env_from.secret_ref.name)
                        if sec and sec.data:
                            import base64
                            secrets[env_from.secret_ref.name] = {
                                k: base64.b64decode(v).decode() for k, v in sec.data.items()
                            }

            if container.volume_mounts:
                for vm in container.volume_mounts:
                    for vol in pod.spec.volumes or []:
                        if vol.name == vm.name:
                            if vol.config_map:
                                cm = self.get_config_map(pod.metadata.namespace, vol.config_map.name)
                                if cm and cm.data:
                                    config_maps[vol.config_map.name] = cm.data
                            elif vol.secret:
                                sec = self.get_secret(pod.metadata.namespace, vol.secret.secret_name)
                                if sec and sec.data:
                                    import base64
                                    secrets[vol.secret.secret_name] = {
                                        k: base64.b64decode(v).decode() for k, v in sec.data.items()
                                    }

            containers.append(ContainerConfig(
                name=container.name,
                image=container.image,
                env_vars=env_vars,
                config_maps=config_maps,
                secrets=secrets,
                command=list(container.command) if container.command else [],
                args=list(container.args) if container.args else [],
                working_dir=container.working_dir or "",
                ports=[{"containerPort": p.container_port, "protocol": p.protocol} for p in (container.ports or [])]
            ))

        return PodEffectiveConfig(
            namespace=pod.metadata.namespace,
            pod_name=pod.metadata.name,
            containers=containers,
            labels=dict(pod.metadata.labels) if pod.metadata.labels else {},
            annotations=dict(pod.metadata.annotations) if pod.metadata.annotations else {},
            service_account=pod.spec.service_account_name or "",
            node_name=pod.spec.node_name or "",
        )