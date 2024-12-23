# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: security-analyzer
  namespace: security-monitoring
---
# clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-analyzer-role
rules:
  - apiGroups: [""]
    resources:
      - "namespaces"
      - "pods"
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch"]
---
# clusterrolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-analyzer-binding
subjects:
  - kind: ServiceAccount
    name: security-analyzer
    namespace: security-monitoring
roleRef:
  kind: ClusterRole
  name: security-analyzer-role
  apiGroup: rbac.authorization.k8s.io
---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-analyzer
  namespace: security-monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-analyzer
  template:
    metadata:
      labels:
        app: security-analyzer
    spec:
      automountServiceAccountToken: true
      serviceAccountName: security-analyzer
      containers:
        - name: security-analyzer
          image: uripld/k8s-pod-security-standards-analyzer:0.3
          imagePullPolicy: Always
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"
              cpu: "200m"
          volumeMounts:
            - name: logs
              mountPath: /var/log
      volumes:
        - name: logs
          emptyDir: {}
