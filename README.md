# Kubernetes Pod Security Standards Analyzer

A specialized tool for analyzing Pod Security Standards (PSS) across Kubernetes namespaces, helping cluster administrators determine and enforce the appropriate security levels (Privileged/Baseline/Restricted) for their workloads.

## Watch the video


[![Watch the video](https://img.youtube.com/vi/RnNI8zkoCNI/maxresdefault.jpg)](https://youtu.be/RnNI8zkoCNI)


## Overview

This analyzer runs as a pod within your Kubernetes cluster and continuously evaluates the security requirements of workloads across all namespaces. It determines whether namespaces should run with Privileged, Baseline, or Restricted Pod Security Standards based on actual workload requirements.

## Features

- Automated detection of required Pod Security Standards levels
- Namespace-wide security assessment
- Daily security analysis reports
- Detailed pod-level security evaluation
- Log rotation for long-term operation
- Container-level security context analysis

## Prerequisites

- Kubernetes cluster (1.22+)
- kubectl CLI tool
- Docker/Podman (for building the container image)
- Python 3.9+

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/your-org/k8s-pod-security-standards-analyzer.git
cd k8s-pod-security-standards-analyzer
```

2. Build the container image:
```bash
docker build -t your-registry/k8s-pss-analyzer:latest .
docker push your-registry/k8s-pss-analyzer:latest
```

3. Deploy to your cluster:
```bash
kubectl create namespace security-monitoring
kubectl apply -f kubernetes/
```

## Security Analysis

The analyzer evaluates the following security aspects:

1. Pod Security Context:
   - Root vs non-root users
   - Privileged mode
   - Host namespaces

2. Container Security:
   - Security contexts
   - Resource limits
   - Image pull policies
   - Root filesystem access

3. Volume Mounts:
   - hostPath volumes
   - Privileged volume types

## Sample Output

Log format:
```
2024-12-23 10:00:00 - INFO - Starting security analysis...
2024-12-23 10:00:01 - INFO - Analyzing namespace: default
2024-12-23 10:00:01 - INFO - Security Level Required: restricted
2024-12-23 10:00:01 - INFO - Issues found: 2
2024-12-23 10:00:02 - INFO - Analysis complete
```

Analysis report:
```json
{
  "namespace": "example-namespace",
  "recommended_security_level": "restricted",
  "pod_count": 5,
  "security_distribution": {
    "privileged": 0,
    "baseline": 2,
    "restricted": 3
  }
}
```

## Future Configuration

environment variables:
```yaml
SCAN_INTERVAL: "24h"         # How often to run the analysis
LOG_LEVEL: "INFO"           # Logging verbosity
EXCLUDED_NAMESPACES: ""     # Comma-separated list of namespaces to exclude
```

## Architecture

The analyzer runs as a Kubernetes deployment with:
- Dedicated ServiceAccount with minimal RBAC permissions
- Daily scheduled analysis
- Log rotation for efficient storage
- Read-only access to cluster resources

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request


## Support

- Open an issue in the GitHub repository
- Provide logs and cluster version when reporting issues
- Check existing issues before creating new ones
