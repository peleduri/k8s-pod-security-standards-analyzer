from kubernetes import client, config
import logging
from datetime import datetime
import json
import os
import time
import schedule
from logging.handlers import RotatingFileHandler

# Enhanced logging configuration
log_file = '/var/log/security-analysis.log'
handler = RotatingFileHandler(log_file, maxBytes=10485760, backupCount=5)  # 10MB per file, keep 5 files
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[handler]
)

def setup_kubernetes_client():
    try:
        config.load_incluster_config()
        return client.CoreV1Api()
    except Exception as e:
        logging.error(f"Failed to setup Kubernetes client: {e}")
        raise

def check_container_security(container):
    """Detailed container security analysis"""
    security_issues = []

    # Check security context
    if not container.security_context:
        security_issues.append("No security context defined")
    else:
        sc = container.security_context
        if not getattr(sc, 'run_as_non_root', True):
            security_issues.append("Container may run as root")
        if getattr(sc, 'privileged', False):
            security_issues.append("Container runs in privileged mode")
        if not getattr(sc, 'read_only_root_filesystem', False):
            security_issues.append("Root filesystem is writable")

    # # Check resource limits
    # if not container.resources:
    #     security_issues.append("No resource limits defined")
    # elif not container.resources.limits:
    #     security_issues.append("No resource limits set (only requests)")

    # # Check image pull policy
    # if container.image_pull_policy != 'Always':
    #     security_issues.append(f"Image pull policy is {container.image_pull_policy}, recommended: Always")

    # # Check if using latest tag
    # if container.image and ':latest' in container.image:
    #     security_issues.append("Using 'latest' tag - not recommended")

    return security_issues

def check_pod_security_level(pod):
    """Enhanced security level check with detailed analysis"""
    security_level = "restricted"
    security_details = {
        "issues": [],
        "recommendations": []
    }

    spec = pod.spec

    # Pod-level security context checks
    if spec.security_context:
        sc = spec.security_context
        if not getattr(sc, 'run_as_non_root', True):
            security_level = "privileged"
            security_details["issues"].append("Pod may run as root")
    else:
        security_details["recommendations"].append("Add pod-level security context")

    # Host namespace checks
    if getattr(spec, 'host_network', False):
        security_level = "privileged"
        security_details["issues"].append("Pod uses host network")
    if getattr(spec, 'host_pid', False):
        security_level = "privileged"
        security_details["issues"].append("Pod uses host PID namespace")
    if getattr(spec, 'host_ipc', False):
        security_level = "privileged"
        security_details["issues"].append("Pod uses host IPC namespace")

    # Container checks
    for container in spec.containers:
        container_issues = check_container_security(container)
        if container_issues:
            security_details["issues"].extend([f"Container {container.name}: {issue}"
                                               for issue in container_issues])

    # Volume checks
    if spec.volumes:
        for volume in spec.volumes:
            if getattr(volume, 'host_path', None):
                security_level = "privileged"
                security_details["issues"].append(f"Uses hostPath volume: {volume.host_path.path}")

    return security_level, security_details

def analyze_namespace_security(namespace, core_v1):
    """Analyze security context for a namespace with enhanced reporting"""
    try:
        pods = core_v1.list_namespaced_pod(namespace).items
        pod_analyses = []
        security_levels = []

        for pod in pods:
            security_level, details = check_pod_security_level(pod)
            security_levels.append(security_level)

            pod_analyses.append({
                "pod_name": pod.metadata.name,
                "security_level": security_level,
                "issues": details["issues"],
                "recommendations": details["recommendations"],
                "creation_timestamp": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None
            })

        # Determine recommended namespace level
        if "privileged" in security_levels:
            recommended_level = "privileged"
        elif "baseline" in security_levels:
            recommended_level = "baseline"
        else:
            recommended_level = "restricted"

        # Calculate statistics
        total_pods = len(pods)
        security_distribution = {
            "privileged": security_levels.count("privileged"),
            "baseline": security_levels.count("baseline"),
            "restricted": security_levels.count("restricted")
        }

        return {
            "namespace": namespace,
            "analysis_time": datetime.now().isoformat(),
            "recommended_security_level": recommended_level,
            "pod_count": total_pods,
            "security_distribution": security_distribution,
            "pod_analyses": pod_analyses,
            "summary": {
                "total_issues": sum(len(p["issues"]) for p in pod_analyses),
                "total_recommendations": sum(len(p["recommendations"]) for p in pod_analyses),
                "percentage_restricted": (security_distribution["restricted"] / total_pods * 100) if total_pods > 0 else 0
            }
        }

    except Exception as e:
        logging.error(f"Error analyzing namespace {namespace}: {e}")
        return None

def run_analysis():
    try:
        logging.info("Starting security analysis...")
        start_time = datetime.now()
        core_v1 = setup_kubernetes_client()

        namespaces = core_v1.list_namespace().items
        results = []

        for ns in namespaces:
            namespace = ns.metadata.name
            analysis = analyze_namespace_security(namespace, core_v1)
            if analysis:
                results.append(analysis)

                # Log detailed findings
                logging.info(f"\nNamespace: {namespace}")
                logging.info(f"Security Level: {analysis['recommended_security_level']}")
                logging.info(f"Pod Distribution: {json.dumps(analysis['security_distribution'], indent=2)}")

                if analysis['summary']['total_issues'] > 0:
                    logging.warning(f"Found {analysis['summary']['total_issues']} security issues")
                    for pod in analysis['pod_analyses']:
                        if pod['issues']:
                            logging.warning(f"Pod {pod['pod_name']} issues: {', '.join(pod['issues'])}")

        # Generate summary report
        total_pods = sum(r['pod_count'] for r in results)
        total_issues = sum(r['summary']['total_issues'] for r in results)

        execution_time = (datetime.now() - start_time).total_seconds()

        summary = {
            "analysis_time": start_time.isoformat(),
            "execution_time_seconds": execution_time,
            "total_namespaces": len(results),
            "total_pods": total_pods,
            "total_security_issues": total_issues,
            "cluster_security_status": "Alert" if total_issues > 0 else "Healthy"
        }

        logging.info("\nAnalysis Summary:")
        logging.info(json.dumps(summary, indent=2))

    except Exception as e:
        logging.error(f"Fatal error in security analysis: {e}")

def main():
    logging.info("Security analyzer starting up...")

    # Schedule multiple runs
    schedule.every().day.at("00:00").do(run_analysis)  # Daily at midnight
    schedule.every().day.at("12:00").do(run_analysis)  # Daily at noon

    # Run initial analysis
    run_analysis()

    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main()
