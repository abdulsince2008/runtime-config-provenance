import sys
import json
from pathlib import Path
from typing import Optional, List
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.syntax import Syntax

from .k8s_client import K8sClient
from .iac_parser import IaCParser, MockRuntimeProvider
from .comparator import ConfigComparator, generate_diff
from .models import DriftReport, DriftFinding, PodEffectiveConfig


console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Runtime Config Provenance Tool - Detect config drift between running pods and IaC manifests."""
    pass


@cli.command()
@click.option("--namespace", "-n", default="default", help="Kubernetes namespace to scan")
@click.option("--label-selector", "-l", default="", help="Label selector for pods (e.g., app=myapp)")
@click.option("--manifest-dir", "-m", multiple=True, help="Directory containing IaC manifests (YAML)")
@click.option("--kubeconfig", "-k", default=None, help="Path to kubeconfig file")
@click.option("--context", "-c", default=None, help="Kubeconfig context to use")
@click.option("--output", "-o", type=click.Choice(["table", "json", "tree"]), default="table", help="Output format")
@click.option("--demo/--no-demo", default=False, help="Run in demo mode with sample data")
@click.option("--fail-on-drift", is_flag=True, help="Exit with code 1 if drift detected")
def scan(namespace: str, label_selector: str, manifest_dir: tuple, kubeconfig: str, context: str,
         output: str, demo: bool, fail_on_drift: bool):
    """Scan running pods and compare against IaC manifests."""
    label_selector = label_selector if label_selector else None

    if demo:
        run_demo_scan(namespace, output, fail_on_drift)
        return

    if not manifest_dir:
        console.print("[red]Error: --manifest-dir is required (or use --demo)[/red]")
        sys.exit(1)

    console.print(f"[blue]Scanning namespace:[/blue] {namespace}")
    console.print(f"[blue]IaC manifest dirs:[/blue] {', '.join(manifest_dir)}")

    try:
        k8s = K8sClient(kubeconfig_path=kubeconfig, context=context)
    except Exception as e:
        console.print(f"[red]Failed to initialize K8s client:[/red] {e}")
        sys.exit(1)

    try:
        pods = k8s.list_pods(namespace, label_selector)
    except Exception as e:
        console.print(f"[red]Failed to list pods:[/red] {e}")
        sys.exit(1)

    if not pods:
        console.print("[yellow]No pods found matching criteria[/yellow]")
        sys.exit(0)

    console.print(f"[green]Found {len(pods)} pod(s)[/green]")

    parser = IaCParser(list(manifest_dir))
    iac_manifests = parser.parse_all()
    console.print(f"[green]Parsed {len(iac_manifests)} IaC manifest(s)[/green]")

    if not iac_manifests:
        console.print("[yellow]Warning: No valid IaC manifests found[/yellow]")

    comparator = ConfigComparator(iac_manifests)

    reports = []
    for pod in pods:
        effective_config = k8s.extract_pod_effective_config(pod)
        matching_iac = comparator.find_matching_iac(effective_config)
        report = comparator.compare(effective_config, matching_iac)
        reports.append(report)

    output_results(reports, output)

    if fail_on_drift and any(r.has_drift for r in reports):
        sys.exit(1)


def run_demo_scan(namespace: str, output: str, fail_on_drift: bool):
    """Run scan with built-in demo data."""
    console.print("[blue]Running in DEMO mode with sample data[/blue]\n")

    sample_pods = [
        {
            "namespace": "production",
            "name": "web-app-7d4b8c9f5-xk2z9",
            "labels": {"app": "web-app", "version": "v2.1.0"},
            "annotations": {},
            "service_account": "web-app-sa",
            "node_name": "node-3",
            "containers": [
                {
                    "name": "web",
                    "image": "myorg/web-app:v2.1.0",
                    "env_vars": {
                        "ENVIRONMENT": "production",
                        "LOG_LEVEL": "info",
                        "DATABASE_URL": "postgres://prod-db:5432/app",
                        "FEATURE_NEW_UI": "true",
                        "MAX_CONNECTIONS": "100",
                        "config.yaml": "server:\n  port: 8080\n  timeout: 30s\nfeature_flags:\n  new_ui: true\n  beta_api: false\n",
                        "api_key": "sk_live_abc123",
                        "db_password": "prod_password_123"
                    },
                    "config_maps": {
                        "web-app-config": {
                            "config.yaml": "server:\n  port: 8080\n  timeout: 30s\nfeature_flags:\n  new_ui: true\n  beta_api: false\n"
                        }
                    },
                    "secrets": {
                        "web-app-secrets": {
                            "api_key": "sk_live_abc123",
                            "db_password": "prod_password_123"
                        }
                    },
                    "command": [],
                    "args": [],
                    "working_dir": "/app",
                    "ports": [{"containerPort": 8080, "protocol": "TCP"}]
                },
                {
                    "name": "sidecar",
                    "image": "myorg/log-sidecar:v1.2.0",
                    "env_vars": {
                        "LOG_DESTINATION": "elasticsearch",
                        "LOG_LEVEL": "debug"
                    },
                    "config_maps": {},
                    "secrets": {},
                    "command": ["/sidecar"],
                    "args": ["--config", "/etc/sidecar/config.yaml"],
                    "working_dir": "/",
                    "ports": []
                }
            ]
        },
        {
            "namespace": "production",
            "name": "api-service-6f8b9c7d4-mn5p2",
            "labels": {"app": "api-service", "version": "v1.5.3"},
            "annotations": {},
            "service_account": "api-sa",
            "node_name": "node-1",
            "containers": [
                {
                    "name": "api",
                    "image": "myorg/api-service:v1.5.3",
                    "env_vars": {
                        "ENVIRONMENT": "production",
                        "LOG_LEVEL": "warn",
                        "DATABASE_URL": "postgres://prod-db:5432/api",
                        "CACHE_TTL": "300",
                        "RATE_LIMIT": "1000",
                        "settings.json": '{"rate_limit": 1000, "cache_ttl": 300, "timeout": "5s"}',
                        "jwt_secret": "super_secret_jwt_key",
                        "encryption_key": "enc_key_456"
                    },
                    "config_maps": {
                        "api-config": {
                            "settings.json": '{"rate_limit": 1000, "cache_ttl": 300, "timeout": "5s"}'
                        }
                    },
                    "secrets": {
                        "api-secrets": {
                            "jwt_secret": "super_secret_jwt_key",
                            "encryption_key": "enc_key_456"
                        }
                    },
                    "command": [],
                    "args": [],
                    "working_dir": "/app",
                    "ports": [{"containerPort": 8000, "protocol": "TCP"}]
                }
            ]
        }
    ]

    mock_provider = MockRuntimeProvider(sample_pods)
    pods = mock_provider.get_pods(namespace)

    manifest_dir = Path(__file__).parent.parent.parent / "sample_manifests"
    parser = IaCParser([str(manifest_dir)])
    iac_manifests = parser.parse_all()
    console.print(f"[green]Parsed {len(iac_manifests)} IaC manifest(s) from sample_manifests/[/green]\n")

    comparator = ConfigComparator(iac_manifests)
    reports = []

    for pod in pods:
        matching_iac = comparator.find_matching_iac(pod)
        report = comparator.compare(pod, matching_iac)
        reports.append(report)

    output_results(reports, output)

    if fail_on_drift and any(r.has_drift for r in reports):
        sys.exit(1)


def output_results(reports: List[DriftReport], output_format: str):
    if output_format == "json":
        output_json(reports)
    elif output_format == "tree":
        output_tree(reports)
    else:
        output_table(reports)


def output_table(reports: List[DriftReport]):
    summary_table = Table(title="Drift Scan Summary")
    summary_table.add_column("Pod", style="cyan")
    summary_table.add_column("Namespace", style="blue")
    summary_table.add_column("Runtime Hash", style="magenta")
    summary_table.add_column("IaC Hash", style="green")
    summary_table.add_column("Matched IaC", style="yellow")
    summary_table.add_column("Drift", style="red")
    summary_table.add_column("Critical", style="bold red")
    summary_table.add_column("High", style="red")
    summary_table.add_column("Medium", style="yellow")
    summary_table.add_column("Low", style="green")

    for r in reports:
        matched = r.matched_iac_source.split("/")[-1] if r.matched_iac_source else "N/A"
        drift_status = "YES" if r.has_drift else "NO"
        summary_table.add_row(
            r.pod_name, r.namespace, r.runtime_hash, r.iac_hash,
            matched, drift_status,
            str(r.critical_count), str(r.high_count),
            str(r.medium_count), str(r.low_count)
        )

    console.print(summary_table)
    console.print()

    for report in reports:
        if not report.has_drift:
            console.print(f"[green]✓ {report.pod_name} - No drift detected[/green]")
            continue

        console.print(f"\n[bold red]Drift Details: {report.pod_name}[/bold red]")
        detail_table = Table(show_header=True, header_style="bold")
        detail_table.add_column("Container", style="cyan")
        detail_table.add_column("Type", style="magenta")
        detail_table.add_column("Field", style="yellow")
        detail_table.add_column("IaC Value", style="green", max_width=40)
        detail_table.add_column("Runtime Value", style="red", max_width=40)
        detail_table.add_column("Severity", style="bold")

        for finding in report.findings:
            iac_val = str(finding.iac_value) if finding.iac_value is not None else "<missing>"
            rt_val = str(finding.runtime_value) if finding.runtime_value is not None else "<missing>"
            if len(iac_val) > 40:
                iac_val = iac_val[:37] + "..."
            if len(rt_val) > 40:
                rt_val = rt_val[:37] + "..."

            severity_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green"
            }.get(finding.severity, "white")

            detail_table.add_row(
                finding.container_name,
                finding.drift_type,
                finding.field_path,
                iac_val,
                rt_val,
                f"[{severity_style}]{finding.severity.upper()}[/{severity_style}]"
            )

        console.print(detail_table)


def output_tree(reports: List[DriftReport]):
    tree = Tree("📊 [bold]Drift Scan Results[/bold]")

    for report in reports:
        status_icon = "🔴" if report.has_drift else "🟢"
        pod_node = tree.add(f"{status_icon} {report.pod_name} ({report.namespace})")
        pod_node.add(f"Runtime Hash: {report.runtime_hash}")
        pod_node.add(f"IaC Hash: {report.iac_hash}")
        pod_node.add(f"Matched IaC: {report.matched_iac_source or 'N/A'}")

        if report.has_drift:
            findings_node = pod_node.add(f"⚠️ {report.drift_count} finding(s)")
            for f in report.findings:
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
                finding_node = findings_node.add(f"{sev_icon} {f.container_name}: {f.drift_type} ({f.field_path})")
                finding_node.add(f"IaC: {f.iac_value}")
                finding_node.add(f"Runtime: {f.runtime_value}")

    console.print(tree)


def output_json(reports: List[DriftReport]):
    result = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_pods": len(reports),
            "pods_with_drift": sum(1 for r in reports if r.has_drift),
            "total_findings": sum(r.drift_count for r in reports),
            "by_severity": {
                "critical": sum(r.critical_count for r in reports),
                "high": sum(r.high_count for r in reports),
                "medium": sum(r.medium_count for r in reports),
                "low": sum(r.low_count for r in reports),
            }
        },
        "reports": []
    }

    for r in reports:
        report_data = {
            "pod_name": r.pod_name,
            "namespace": r.namespace,
            "runtime_hash": r.runtime_hash,
            "iac_hash": r.iac_hash,
            "matched_iac_source": r.matched_iac_source,
            "has_drift": r.has_drift,
            "findings": []
        }
        for f in r.findings:
            report_data["findings"].append({
                "container_name": f.container_name,
                "drift_type": f.drift_type,
                "field_path": f.field_path,
                "iac_value": f.iac_value,
                "runtime_value": f.runtime_value,
                "severity": f.severity
            })
        result["reports"].append(report_data)

    console.print(Syntax(json.dumps(result, indent=2, default=str), "json"))


@cli.command()
@click.option("--manifest-dir", "-m", required=True, help="Directory containing IaC manifests")
def validate(manifest_dir: str):
    """Validate IaC manifests can be parsed."""
    parser = IaCParser([manifest_dir])
    manifests = parser.parse_all()

    console.print(f"[green]Found {len(manifests)} valid manifest(s):[/green]")
    for m in manifests:
        console.print(f"  • {m.kind}/{m.name} ({m.namespace}) - {m.source_path}")
        for c in m.containers:
            console.print(f"    - Container: {c.name} ({c.image})")


@cli.command()
@click.option("--pod", "-p", required=True, help="Pod name (namespace/pod-name)")
def hash(pod: str):
    """Compute hash of a running pod's effective config (requires K8s access)."""
    if "/" not in pod:
        console.print("[red]Pod format must be namespace/pod-name[/red]")
        sys.exit(1)

    namespace, pod_name = pod.split("/", 1)

    try:
        k8s = K8sClient()
        k8s_pod = k8s.get_pod(namespace, pod_name)
        if not k8s_pod:
            console.print(f"[red]Pod {pod} not found[/red]")
            sys.exit(1)

        effective = k8s.extract_pod_effective_config(k8s_pod)
        console.print(f"Pod: {effective.pod_name}")
        console.print(f"Namespace: {effective.namespace}")
        console.print(f"Overall Hash: {effective.overall_hash()}")
        console.print("\nContainers:")
        for c in effective.containers:
            console.print(f"  {c.name}: {c.hash()} ({c.image})")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    cli()