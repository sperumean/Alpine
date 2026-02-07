#!/bin/bash
#==============================================================================
# Kubernetes / KubeVirt Audit & Hardening
# Target: mead (.16) - KubeVirt + K8S
#
# Usage:
#   ./k8s-audit.sh              # Full K8S + system audit
#   ./k8s-audit.sh --snapshot   # Save K8S state
#   ./k8s-audit.sh --diff       # Compare to snapshot
#   ./k8s-audit.sh --harden     # Apply K8S hardening
#==============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

MODE="audit"
SNAPSHOT_DIR="/root/wrccdc-k8s-snapshot"
LOG_FILE="/root/wrccdc-k8s-audit-$(date +%Y%m%d-%H%M%S).log"

case "$1" in
    --snapshot) MODE="snapshot" ;;
    --diff)     MODE="diff" ;;
    --harden)   MODE="harden" ;;
    --help|-h)  echo "Usage: $0 [--snapshot|--diff|--harden]"; exit 0 ;;
esac

log()    { echo -e "$1" | tee -a "$LOG_FILE"; }
header() { log "\n${CYAN}══════════════════════════════════════════════════════════${NC}"; log "${CYAN}  ${BOLD}$1${NC}"; log "${CYAN}══════════════════════════════════════════════════════════${NC}"; }
pass()   { log "  ${GREEN}[PASS]${NC} $1"; }
warn()   { log "  ${YELLOW}[WARN]${NC} $1"; }
fail()   { log "  ${RED}[FAIL]${NC} $1"; }
info()   { log "  ${BLUE}[INFO]${NC} $1"; }

# Check for kubectl
if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl not found. Is this the right box?"
    echo "Falling back to system-only audit. Use linux-audit.sh instead."
    exit 1
fi

#==============================================================================
# SNAPSHOT
#==============================================================================
do_snapshot() {
    header "SAVING K8S SNAPSHOT"
    mkdir -p "$SNAPSHOT_DIR"

    kubectl get nodes -o wide > "$SNAPSHOT_DIR/nodes.txt" 2>/dev/null
    kubectl get pods --all-namespaces -o wide > "$SNAPSHOT_DIR/pods.txt" 2>/dev/null
    kubectl get svc --all-namespaces -o wide > "$SNAPSHOT_DIR/services.txt" 2>/dev/null
    kubectl get deployments --all-namespaces > "$SNAPSHOT_DIR/deployments.txt" 2>/dev/null
    kubectl get daemonsets --all-namespaces > "$SNAPSHOT_DIR/daemonsets.txt" 2>/dev/null
    kubectl get secrets --all-namespaces > "$SNAPSHOT_DIR/secrets.txt" 2>/dev/null
    kubectl get configmaps --all-namespaces > "$SNAPSHOT_DIR/configmaps.txt" 2>/dev/null
    kubectl get serviceaccounts --all-namespaces > "$SNAPSHOT_DIR/serviceaccounts.txt" 2>/dev/null
    kubectl get clusterroles > "$SNAPSHOT_DIR/clusterroles.txt" 2>/dev/null
    kubectl get clusterrolebindings > "$SNAPSHOT_DIR/clusterrolebindings.txt" 2>/dev/null
    kubectl get rolebindings --all-namespaces > "$SNAPSHOT_DIR/rolebindings.txt" 2>/dev/null
    kubectl get networkpolicies --all-namespaces > "$SNAPSHOT_DIR/netpolicies.txt" 2>/dev/null
    kubectl get ingress --all-namespaces > "$SNAPSHOT_DIR/ingress.txt" 2>/dev/null
    kubectl get pv > "$SNAPSHOT_DIR/pv.txt" 2>/dev/null
    kubectl get pvc --all-namespaces > "$SNAPSHOT_DIR/pvc.txt" 2>/dev/null

    # KubeVirt
    kubectl get vmi --all-namespaces > "$SNAPSHOT_DIR/kubevirt-vms.txt" 2>/dev/null
    kubectl get vm --all-namespaces > "$SNAPSHOT_DIR/kubevirt-vmdefs.txt" 2>/dev/null

    # Full YAML dump of critical resources
    kubectl get pods --all-namespaces -o yaml > "$SNAPSHOT_DIR/pods-full.yaml" 2>/dev/null
    kubectl get svc --all-namespaces -o yaml > "$SNAPSHOT_DIR/services-full.yaml" 2>/dev/null

    info "K8S snapshot saved to $SNAPSHOT_DIR"
}

#==============================================================================
# DIFF
#==============================================================================
do_diff() {
    header "COMPARING K8S STATE TO SNAPSHOT"
    [ ! -d "$SNAPSHOT_DIR" ] && { fail "No snapshot! Run --snapshot first."; exit 1; }

    CHANGES=0

    diff_k8s() {
        LABEL="$1"; CMD="$2"; SNAP="$3"
        [ ! -f "$SNAP" ] && return
        eval "$CMD" > /tmp/_k8s_current.txt 2>/dev/null
        if ! diff -q "$SNAP" /tmp/_k8s_current.txt >/dev/null 2>&1; then
            fail "$LABEL CHANGED!"
            diff --color "$SNAP" /tmp/_k8s_current.txt 2>/dev/null || diff "$SNAP" /tmp/_k8s_current.txt
            CHANGES=$((CHANGES + 1))
        else
            pass "$LABEL unchanged"
        fi
    }

    diff_k8s "Pods" "kubectl get pods --all-namespaces -o wide" "$SNAPSHOT_DIR/pods.txt"
    diff_k8s "Services" "kubectl get svc --all-namespaces -o wide" "$SNAPSHOT_DIR/services.txt"
    diff_k8s "Deployments" "kubectl get deployments --all-namespaces" "$SNAPSHOT_DIR/deployments.txt"
    diff_k8s "DaemonSets" "kubectl get daemonsets --all-namespaces" "$SNAPSHOT_DIR/daemonsets.txt"
    diff_k8s "Secrets" "kubectl get secrets --all-namespaces" "$SNAPSHOT_DIR/secrets.txt"
    diff_k8s "ClusterRoles" "kubectl get clusterroles" "$SNAPSHOT_DIR/clusterroles.txt"
    diff_k8s "ClusterRoleBindings" "kubectl get clusterrolebindings" "$SNAPSHOT_DIR/clusterrolebindings.txt"
    diff_k8s "NetworkPolicies" "kubectl get networkpolicies --all-namespaces" "$SNAPSHOT_DIR/netpolicies.txt"
    diff_k8s "KubeVirt VMs" "kubectl get vmi --all-namespaces" "$SNAPSHOT_DIR/kubevirt-vms.txt"

    log ""
    [ $CHANGES -eq 0 ] && log "${GREEN}${BOLD}  No K8S changes detected.${NC}" || log "${RED}${BOLD}  $CHANGES K8S change(s)!${NC}"
}

#==============================================================================
# AUDIT
#==============================================================================

audit_cluster() {
    header "CLUSTER INFORMATION"

    info "Cluster info:"
    kubectl cluster-info 2>/dev/null | while read -r l; do log "    $l"; done

    info "Nodes:"
    kubectl get nodes -o wide 2>/dev/null | while read -r l; do log "    $l"; done

    info "K8S version:"
    kubectl version --short 2>/dev/null | while read -r l; do log "    $l"; done

    # Check if API server is exposed
    API_URL=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
    info "API server: $API_URL"
}

audit_pods() {
    header "PODS"

    info "All pods:"
    kubectl get pods --all-namespaces -o wide 2>/dev/null | while read -r l; do log "    $l"; done

    # Check for privileged pods
    info "Checking for privileged pods:"
    kubectl get pods --all-namespaces -o json 2>/dev/null | grep -B5 '"privileged": true' | while read -r l; do
        fail "Privileged container found: $l"
    done

    # Pods running as root
    info "Pods with hostNetwork/hostPID/hostIPC:"
    kubectl get pods --all-namespaces -o json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for pod in data.get('items', []):
        spec = pod.get('spec', {})
        name = pod['metadata']['name']
        ns = pod['metadata']['namespace']
        if spec.get('hostNetwork'): print(f'    [FAIL] {ns}/{name}: hostNetwork=true')
        if spec.get('hostPID'): print(f'    [FAIL] {ns}/{name}: hostPID=true')
        if spec.get('hostIPC'): print(f'    [FAIL] {ns}/{name}: hostIPC=true')
except: pass
" 2>/dev/null | while read -r l; do log "$l"; done

    # Pods not running
    info "Pods NOT running:"
    kubectl get pods --all-namespaces --field-selector=status.phase!=Running 2>/dev/null | while read -r l; do
        warn "$l"
    done
}

audit_services() {
    header "SERVICES"

    info "All services:"
    kubectl get svc --all-namespaces -o wide 2>/dev/null | while read -r l; do log "    $l"; done

    # NodePort services (exposed externally)
    info "NodePort services (externally accessible):"
    kubectl get svc --all-namespaces -o json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for svc in data.get('items', []):
        if svc['spec'].get('type') == 'NodePort':
            name = svc['metadata']['name']
            ns = svc['metadata']['namespace']
            for port in svc['spec'].get('ports', []):
                print(f'    {ns}/{name}: NodePort {port.get(\"nodePort\")} -> {port.get(\"port\")}')
except: pass
" 2>/dev/null | while read -r l; do warn "$l"; done

    # LoadBalancer services
    kubectl get svc --all-namespaces -o json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for svc in data.get('items', []):
        if svc['spec'].get('type') == 'LoadBalancer':
            print(f'    {svc[\"metadata\"][\"namespace\"]}/{svc[\"metadata\"][\"name\"]}: LoadBalancer')
except: pass
" 2>/dev/null | while read -r l; do warn "$l"; done
}

audit_rbac() {
    header "RBAC & ACCESS CONTROL"

    info "ClusterRoleBindings:"
    kubectl get clusterrolebindings -o wide 2>/dev/null | while read -r l; do log "    $l"; done

    # Check for overly permissive bindings
    info "Checking for cluster-admin bindings:"
    kubectl get clusterrolebindings -o json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for binding in data.get('items', []):
        role = binding.get('roleRef', {}).get('name', '')
        if role == 'cluster-admin':
            subjects = binding.get('subjects', [])
            for s in subjects:
                name = binding['metadata']['name']
                print(f'    [WARN] {name}: {s.get(\"kind\")} {s.get(\"name\")} has cluster-admin')
except: pass
" 2>/dev/null | while read -r l; do log "$l"; done

    info "ServiceAccounts:"
    kubectl get serviceaccounts --all-namespaces 2>/dev/null | while read -r l; do log "    $l"; done
}

audit_secrets() {
    header "SECRETS"

    info "All secrets (names only — NOT dumping values):"
    kubectl get secrets --all-namespaces 2>/dev/null | while read -r l; do log "    $l"; done

    # Check for secrets mounted in pods
    info "Secrets mounted in pods:"
    kubectl get pods --all-namespaces -o json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for pod in data.get('items', []):
        name = pod['metadata']['name']
        ns = pod['metadata']['namespace']
        for vol in pod['spec'].get('volumes', []):
            if vol.get('secret'):
                print(f'    {ns}/{name}: mounts secret {vol[\"secret\"][\"secretName\"]}')
except: pass
" 2>/dev/null | while read -r l; do log "$l"; done
}

audit_network_policies() {
    header "NETWORK POLICIES"

    POLICIES=$(kubectl get networkpolicies --all-namespaces 2>/dev/null)
    if echo "$POLICIES" | grep -q "No resources"; then
        warn "NO NETWORK POLICIES — all pod-to-pod traffic is allowed!"
    else
        info "Network policies:"
        echo "$POLICIES" | while read -r l; do log "    $l"; done
    fi
}

audit_kubevirt() {
    header "KUBEVIRT VIRTUAL MACHINES"

    # Check if KubeVirt is installed
    if ! kubectl get crd virtualmachineinstances.kubevirt.io >/dev/null 2>&1; then
        info "KubeVirt CRDs not found, skipping"
        return
    fi

    info "Virtual Machine Instances:"
    kubectl get vmi --all-namespaces -o wide 2>/dev/null | while read -r l; do log "    $l"; done

    info "Virtual Machine Definitions:"
    kubectl get vm --all-namespaces 2>/dev/null | while read -r l; do log "    $l"; done

    info "DataVolumes:"
    kubectl get dv --all-namespaces 2>/dev/null | while read -r l; do log "    $l"; done

    # KubeVirt version
    info "KubeVirt version:"
    kubectl get kubevirt -n kubevirt -o jsonpath='{.items[0].status.observedKubeVirtVersion}' 2>/dev/null | xargs -I{} log "    {}"
}

audit_ingress() {
    header "INGRESS"
    kubectl get ingress --all-namespaces 2>/dev/null | while read -r l; do log "    $l"; done
}

audit_configmaps() {
    header "CONFIGMAPS (non-system)"
    kubectl get configmaps --all-namespaces 2>/dev/null | grep -v "kube-system\|kube-public\|kube-node-lease" | while read -r l; do log "    $l"; done
}

audit_etcd() {
    header "ETCD SECURITY"

    # Check if etcd is running locally
    if pgrep etcd >/dev/null 2>&1; then
        info "etcd is running on this node"

        # Check etcd flags
        ETCD_CMD=$(ps aux | grep etcd | grep -v grep | head -1)
        echo "$ETCD_CMD" | grep -q "\-\-client-cert-auth=true" && pass "etcd client cert auth enabled" || warn "etcd client cert auth may not be enabled"
        echo "$ETCD_CMD" | grep -q "\-\-peer-client-cert-auth=true" && pass "etcd peer cert auth enabled" || warn "etcd peer cert auth may not be enabled"

        # Check if etcd data dir is accessible
        ETCD_DATA=$(echo "$ETCD_CMD" | grep -o "\-\-data-dir=[^ ]*" | cut -d= -f2)
        if [ -n "$ETCD_DATA" ]; then
            PERMS=$(stat -c "%a" "$ETCD_DATA" 2>/dev/null)
            info "etcd data dir: $ETCD_DATA (perms: $PERMS)"
        fi
    else
        info "etcd not running locally"
    fi
}

audit_container_runtime() {
    header "CONTAINER RUNTIME"

    if command -v docker >/dev/null 2>&1; then
        info "Docker version: $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
        info "Docker containers:"
        docker ps -a 2>/dev/null | while read -r l; do log "    $l"; done
    fi

    if command -v crictl >/dev/null 2>&1; then
        info "CRI containers:"
        crictl ps 2>/dev/null | while read -r l; do log "    $l"; done
    fi

    if command -v containerd >/dev/null 2>&1; then
        info "containerd version: $(containerd --version 2>/dev/null)"
    fi
}

#==============================================================================
# HARDENING
#==============================================================================

harden_k8s() {
    header "K8S HARDENING"

    # Create default-deny network policy for default namespace
    info "Creating default-deny network policy for default namespace:"
    cat << 'EOF' | kubectl apply -f - 2>/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
    pass "Default-deny network policy applied to default namespace"

    # Disable anonymous auth check
    info "Check API server anonymous auth (manual verification needed):"
    info "  Look for --anonymous-auth=false in API server config"

    # Remove default service account token automounting
    info "Consider disabling automountServiceAccountToken on default SA"

    warn "K8S hardening is environment-specific — review changes carefully!"
    warn "Don't break scored services!"
}

#==============================================================================
# MAIN
#==============================================================================

case "$MODE" in
    snapshot) do_snapshot ;;
    diff)     do_diff ;;
    audit|harden)
        log "${BOLD}WRCCDC 2026 - K8S/KubeVirt Audit | $(hostname) | $(date)${NC}"

        audit_cluster
        audit_pods
        audit_services
        audit_rbac
        audit_secrets
        audit_network_policies
        audit_kubevirt
        audit_ingress
        audit_configmaps
        audit_etcd
        audit_container_runtime

        [ "$MODE" = "harden" ] && harden_k8s

        header "SUMMARY"
        log "  Nodes:     $(kubectl get nodes --no-headers 2>/dev/null | wc -l)"
        log "  Pods:      $(kubectl get pods --all-namespaces --no-headers 2>/dev/null | wc -l)"
        log "  Services:  $(kubectl get svc --all-namespaces --no-headers 2>/dev/null | wc -l)"
        log "  Secrets:   $(kubectl get secrets --all-namespaces --no-headers 2>/dev/null | wc -l)"
        log "  VMs:       $(kubectl get vmi --all-namespaces --no-headers 2>/dev/null | wc -l)"
        log "  Log: $LOG_FILE"
        ;;
esac
