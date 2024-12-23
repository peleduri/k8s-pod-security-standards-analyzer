from kubernetes import client, config
import logging
from datetime import datetime
import json
import os
import time
import schedule

# Configure logging
logging.basicConfig(
    filename='/var/log/security-analysis.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def setup_kubernetes_client():
    try:
        # Load in-cluster configuration
        config.load_incluster_config()
        return client.CoreV1Api()
    except Exception as e:
        logging.error(f"Failed to setup Kubernetes client: {e}")
        raise

def check_pod_security_level(pod):
    """Determine security level based on pod spec"""
    security_level = "restricted"  # Start with most restrictive
    
    spec = pod.spec
    
    # Check security context at pod level
    if spec.security_context:
        if (getattr(spec.security_context, 'run_as_non_root', None) == False or
            getattr(spec.security_context, 'privileged', None) == True):
            return "privileged"
    
    for container in spec.containers:
        if container.security_context:
            # Check privileged mode
            if getattr(container.security_context, 'privileged', None):
                return "privileged"
            
            # Check capabilities
            if getattr(container.security_context, 'capabilities', None):
                caps = container.security_context.capabilities
                if caps.add:
                    security_level = "baseline"
            
            # Check host ports
            if container.ports:
                for port in container.ports:
                    if getattr(port, 'host_port', None):
                        return "privileged"
    
    # Check volumes
    if spec.volumes:
        for volume in spec.volumes:
            # Check for host path volumes
            if getattr(volume, 'host_path', None):
                return "privileged"
            # Check for privileged volume types
            if any(getattr(volume, attr, None) for attr in [
                'gcePersistentDisk', 'awsElasticBlockStore', 'azureDisk',
                'portworxVolume', 'scaleIO']):
                security_level = "baseline"
    
    return security_level

def analyze_namespace_security(namespace, core_v1):
    """Analyze security context for a namespace"""
    try:
        # Get all pods in namespace
        pods = core_v1.list_namespaced_pod(namespace).items
        
        # Track security levels for all pods
        security_levels = []
        pod_details = []
        
        for pod in pods:
            security_level = check_pod_security_level(pod)
            security_levels.append(security_level)
            
            pod_details.append({
                "pod_name": pod.metadata.name,
                "security_level": security_level
            })
        
        # Determine the highest (least restrictive) security level needed
        if "privileged" in security_levels:
            recommended_level = "privileged"
        elif "baseline" in security_levels:
            recommended_level = "baseline"
        else:
            recommended_level = "restricted"
        
        return {
            "namespace": namespace,
            "recommended_security_level": recommended_level,
            "pod_count": len(pods),
            "pod_details": pod_details,
            "analysis_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Error analyzing namespace {namespace}: {e}")
        return None

def run_analysis():
    try:
        logging.info("Starting security analysis...")
        core_v1 = setup_kubernetes_client()
        
        # Get all namespaces
        namespaces = core_v1.list_namespace().items
        
        results = []
        for ns in namespaces:
            namespace = ns.metadata.name
            analysis = analyze_namespace_security(namespace, core_v1)
            if analysis:
                results.append(analysis)
                logging.info(f"Namespace {namespace} analysis:")
                logging.info(json.dumps(analysis, indent=2))
        
        # Write summary to log
        logging.info(f"Analysis complete. Processed {len(results)} namespaces")
        
    except Exception as e:
        logging.error(f"Fatal error in security analysis: {e}")

def main():
    logging.info("Security analyzer starting up...")
    
    # Schedule the analysis to run daily at midnight
    schedule.every().day.at("00:00").do(run_analysis)
    
    # Run initial analysis
    run_analysis()
    
    # Keep the script running
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main()
