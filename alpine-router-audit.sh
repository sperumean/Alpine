#!/bin/sh
#==============================================================================
# 
# Target: (192.168.220.2) - Alpine Linux
# Author: Cyber Viking LLC
#
# Usage:
#   ./alpine-router-audit.sh              # Audit only (safe, no changes)
#   ./alpine-router-audit.sh --harden     # Audit + apply hardening
#   ./alpine-router-audit.sh --monitor    # Continuous monitoring mode
#   ./alpine-router-audit.sh --snapshot   # Save current state for diff later
#   ./alpine-router-audit.sh --diff       # Compare current state to snapshot
#
# IMPORTANT: This script is SAFE to run in audit mode. It makes NO changes
# unless --harden is explicitly passed. Even then, it backs up everything first.
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Config
MODE="audit"
BACKUP_DIR="/root/wrccdc-backup-$(date +%Y%m%d-%H%M%S)"
SNAPSHOT_DIR="/root/wrccdc-snapshot"
INTERNAL_NET="192.168.220.0/24"
ROUTER_IP="192.168.220.2"
LOG_FILE="/root/wrccdc-audit-$(date +%Y%m%d-%H%M%S).log"

# Parse args
case "$1" in
    --harden)  MODE="harden" ;;
    --monitor) MODE="monitor" ;;
    --snapshot) MODE="snapshot" ;;
    --diff)    MODE="diff" ;;
    --help|-h)
        echo "Usage: $0 [--harden|--monitor|--snapshot|--diff]"
        echo "  (no args)   Audit only - no changes made"
        echo "  --harden    Audit + apply hardening (backs up first)"
        echo "  --monitor   Continuous monitoring for red team changes"
        echo "  --snapshot  Save current state for later comparison"
        echo "  --diff      Compare current state against saved snapshot"
        exit 0
        ;;
esac

# Logging
log() {
    echo "$1" | tee -a "$LOG_FILE"
}

header() {
    log ""
    log "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    log "${CYAN}║${NC} ${BOLD}$1${NC}"
    log "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
}

pass() { log "  ${GREEN}[PASS]${NC} $1"; }
warn() { log "  ${YELLOW}[WARN]${NC} $1"; }
fail() { log "  ${RED}[FAIL]${NC} $1"; }
info() { log "  ${BLUE}[INFO]${NC} $1"; }

#==============================================================================
# SNAPSHOT MODE - Save current state for later comparison
#==============================================================================
do_snapshot() {
    header "SAVING SYSTEM SNAPSHOT"
    mkdir -p "$SNAPSHOT_DIR"

    # Save firewall rules
    if command -v nft >/dev/null 2>&1; then
        nft list ruleset > "$SNAPSHOT_DIR/nft-ruleset.txt" 2>/dev/null
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables-save > "$SNAPSHOT_DIR/iptables.txt" 2>/dev/null
    fi

    # Save key files
    cp /etc/passwd "$SNAPSHOT_DIR/passwd" 2>/dev/null
    cp /etc/shadow "$SNAPSHOT_DIR/shadow" 2>/dev/null
    cp /etc/group "$SNAPSHOT_DIR/group" 2>/dev/null
    cp /etc/hosts "$SNAPSHOT_DIR/hosts" 2>/dev/null
    cp /etc/ssh/sshd_config "$SNAPSHOT_DIR/sshd_config" 2>/dev/null
    cp /etc/resolv.conf "$SNAPSHOT_DIR/resolv.conf" 2>/dev/null

    # Save network config
    ip addr > "$SNAPSHOT_DIR/ip-addr.txt" 2>/dev/null
    ip route > "$SNAPSHOT_DIR/ip-route.txt" 2>/dev/null
    ss -tlnp > "$SNAPSHOT_DIR/listening-ports.txt" 2>/dev/null
    ps aux > "$SNAPSHOT_DIR/processes.txt" 2>/dev/null

    # Save cron
    ls -la /etc/crontabs/ > "$SNAPSHOT_DIR/crontabs-list.txt" 2>/dev/null
    cat /etc/crontabs/* > "$SNAPSHOT_DIR/crontabs-content.txt" 2>/dev/null
    ls -la /var/spool/cron/ > "$SNAPSHOT_DIR/spool-cron.txt" 2>/dev/null

    # Save running services
    rc-status --all > "$SNAPSHOT_DIR/services.txt" 2>/dev/null

    # Hash critical files for integrity checking
    find /etc -type f -name "*.conf" -exec sha256sum {} \; > "$SNAPSHOT_DIR/etc-hashes.txt" 2>/dev/null
    sha256sum /etc/passwd /etc/shadow /etc/group /etc/hosts 2>/dev/null >> "$SNAPSHOT_DIR/critical-hashes.txt"

    info "Snapshot saved to $SNAPSHOT_DIR"
    info "Run with --diff later to detect changes"
}

#==============================================================================
# DIFF MODE - Compare current state to snapshot
#==============================================================================
do_diff() {
    header "COMPARING CURRENT STATE TO SNAPSHOT"

    if [ ! -d "$SNAPSHOT_DIR" ]; then
        fail "No snapshot found! Run with --snapshot first."
        exit 1
    fi

    CHANGES=0

    # Check firewall rules
    if command -v nft >/dev/null 2>&1 && [ -f "$SNAPSHOT_DIR/nft-ruleset.txt" ]; then
        nft list ruleset > /tmp/nft-current.txt 2>/dev/null
        if ! diff -q "$SNAPSHOT_DIR/nft-ruleset.txt" /tmp/nft-current.txt >/dev/null 2>&1; then
            fail "NFT RULES CHANGED!"
            diff "$SNAPSHOT_DIR/nft-ruleset.txt" /tmp/nft-current.txt
            CHANGES=$((CHANGES + 1))
        else
            pass "nftables rules unchanged"
        fi
    fi

    if command -v iptables >/dev/null 2>&1 && [ -f "$SNAPSHOT_DIR/iptables.txt" ]; then
        iptables-save > /tmp/iptables-current.txt 2>/dev/null
        if ! diff -q "$SNAPSHOT_DIR/iptables.txt" /tmp/iptables-current.txt >/dev/null 2>&1; then
            fail "IPTABLES RULES CHANGED!"
            diff "$SNAPSHOT_DIR/iptables.txt" /tmp/iptables-current.txt
            CHANGES=$((CHANGES + 1))
        else
            pass "iptables rules unchanged"
        fi
    fi

    # Check users
    if [ -f "$SNAPSHOT_DIR/passwd" ]; then
        if ! diff -q /etc/passwd "$SNAPSHOT_DIR/passwd" >/dev/null 2>&1; then
            fail "USERS CHANGED!"
            diff "$SNAPSHOT_DIR/passwd" /etc/passwd
            CHANGES=$((CHANGES + 1))
        else
            pass "/etc/passwd unchanged"
        fi
    fi

    # Check listening ports
    ss -tlnp > /tmp/ports-current.txt 2>/dev/null
    if [ -f "$SNAPSHOT_DIR/listening-ports.txt" ]; then
        if ! diff -q "$SNAPSHOT_DIR/listening-ports.txt" /tmp/ports-current.txt >/dev/null 2>&1; then
            warn "LISTENING PORTS CHANGED!"
            diff "$SNAPSHOT_DIR/listening-ports.txt" /tmp/ports-current.txt
            CHANGES=$((CHANGES + 1))
        else
            pass "Listening ports unchanged"
        fi
    fi

    # Check routes
    ip route > /tmp/routes-current.txt 2>/dev/null
    if [ -f "$SNAPSHOT_DIR/ip-route.txt" ]; then
        if ! diff -q "$SNAPSHOT_DIR/ip-route.txt" /tmp/routes-current.txt >/dev/null 2>&1; then
            fail "ROUTES CHANGED!"
            diff "$SNAPSHOT_DIR/ip-route.txt" /tmp/routes-current.txt
            CHANGES=$((CHANGES + 1))
        else
            pass "Routes unchanged"
        fi
    fi

    # Check hosts file
    if [ -f "$SNAPSHOT_DIR/hosts" ]; then
        if ! diff -q /etc/hosts "$SNAPSHOT_DIR/hosts" >/dev/null 2>&1; then
            fail "HOSTS FILE CHANGED!"
            diff "$SNAPSHOT_DIR/hosts" /etc/hosts
            CHANGES=$((CHANGES + 1))
        else
            pass "/etc/hosts unchanged"
        fi
    fi

    # Check SSH config
    if [ -f "$SNAPSHOT_DIR/sshd_config" ]; then
        if ! diff -q /etc/ssh/sshd_config "$SNAPSHOT_DIR/sshd_config" >/dev/null 2>&1; then
            warn "SSH CONFIG CHANGED!"
            diff "$SNAPSHOT_DIR/sshd_config" /etc/ssh/sshd_config
            CHANGES=$((CHANGES + 1))
        else
            pass "sshd_config unchanged"
        fi
    fi

    # Check critical file hashes
    if [ -f "$SNAPSHOT_DIR/critical-hashes.txt" ]; then
        sha256sum /etc/passwd /etc/shadow /etc/group /etc/hosts 2>/dev/null > /tmp/hashes-current.txt
        if ! diff -q "$SNAPSHOT_DIR/critical-hashes.txt" /tmp/hashes-current.txt >/dev/null 2>&1; then
            fail "CRITICAL FILE HASHES CHANGED!"
            diff "$SNAPSHOT_DIR/critical-hashes.txt" /tmp/hashes-current.txt
            CHANGES=$((CHANGES + 1))
        else
            pass "Critical file hashes match"
        fi
    fi

    log ""
    if [ $CHANGES -eq 0 ]; then
        log "${GREEN}${BOLD}No changes detected. System matches snapshot.${NC}"
    else
        log "${RED}${BOLD}$CHANGES change(s) detected! Investigate immediately.${NC}"
    fi
}

#==============================================================================
# MONITOR MODE - Watch for red team changes in real time
#==============================================================================
do_monitor() {
    header "CONTINUOUS MONITORING - Ctrl+C to stop"
    info "Checking every 30 seconds for changes..."
    info "Run --snapshot first to establish baseline"
    log ""

    while true; do
        TIMESTAMP=$(date '+%H:%M:%S')
        ALERTS=""

        # Check firewall rule count
        if command -v nft >/dev/null 2>&1; then
            NFT_COUNT=$(nft list ruleset 2>/dev/null | wc -l)
        fi
        if command -v iptables >/dev/null 2>&1; then
            IPT_COUNT=$(iptables -L -n 2>/dev/null | wc -l)
        fi

        # Check user count
        USER_COUNT=$(wc -l < /etc/passwd)

        # Check listening ports
        PORT_COUNT=$(ss -tlnp 2>/dev/null | wc -l)

        # Check routes
        ROUTE_COUNT=$(ip route 2>/dev/null | wc -l)

        # Check for new processes
        PROC_COUNT=$(ps aux 2>/dev/null | wc -l)

        # Check active connections
        CONN_COUNT=$(ss -tn 2>/dev/null | grep -v "State" | wc -l)

        # Check for UID 0 accounts
        ROOT_ACCOUNTS=$(awk -F: '$3 == 0' /etc/passwd | wc -l)

        # Print status line
        printf "\r[%s] Users:%s Ports:%s Routes:%s Procs:%s Conns:%s Root:%s NFT:%s IPT:%s" \
            "$TIMESTAMP" "$USER_COUNT" "$PORT_COUNT" "$ROUTE_COUNT" \
            "$PROC_COUNT" "$CONN_COUNT" "$ROOT_ACCOUNTS" \
            "${NFT_COUNT:-n/a}" "${IPT_COUNT:-n/a}"

        # Alert on anomalies
        if [ "$ROOT_ACCOUNTS" -gt 1 ]; then
            echo ""
            fail "[$TIMESTAMP] MULTIPLE ROOT ACCOUNTS DETECTED!"
            awk -F: '$3 == 0 {print "    " $1}' /etc/passwd
        fi

        sleep 30
    done
}

#==============================================================================
# BACKUP (runs before hardening)
#==============================================================================
do_backup() {
    header "CREATING BACKUP"
    mkdir -p "$BACKUP_DIR"

    # Backup everything important
    cp -r /etc "$BACKUP_DIR/etc" 2>/dev/null
    if command -v nft >/dev/null 2>&1; then
        nft list ruleset > "$BACKUP_DIR/nft-ruleset-backup.txt" 2>/dev/null
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables-save > "$BACKUP_DIR/iptables-backup.txt" 2>/dev/null
    fi
    ip addr > "$BACKUP_DIR/ip-addr-backup.txt" 2>/dev/null
    ip route > "$BACKUP_DIR/ip-route-backup.txt" 2>/dev/null

    info "Full backup saved to $BACKUP_DIR"
    info "To restore firewall: nft -f $BACKUP_DIR/nft-ruleset-backup.txt"
    info "To restore iptables: iptables-restore < $BACKUP_DIR/iptables-backup.txt"
}

#==============================================================================
# AUDIT FUNCTIONS
#==============================================================================

audit_system_info() {
    header "SYSTEM INFORMATION"
    info "Hostname: $(hostname)"
    info "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    info "Kernel: $(uname -r)"
    info "Uptime: $(uptime)"
    info "Date: $(date)"
    info "Mode: $MODE"
}

audit_users() {
    header "USER ACCOUNTS"

    # Check for UID 0 accounts
    ROOT_USERS=$(awk -F: '$3 == 0' /etc/passwd)
    ROOT_COUNT=$(echo "$ROOT_USERS" | wc -l)
    if [ "$ROOT_COUNT" -gt 1 ]; then
        fail "Multiple UID 0 accounts found:"
        echo "$ROOT_USERS" | while read -r line; do
            log "    $line"
        done
    else
        pass "Only root has UID 0"
    fi

    # Check for accounts with login shells
    info "Accounts with login shells:"
    awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {printf "    %-20s UID:%-6s Shell:%s\n", $1, $3, $7}' /etc/passwd | tee -a "$LOG_FILE"

    # Check for empty passwords
    if [ -f /etc/shadow ]; then
        EMPTY_PW=$(awk -F: '($2 == "" || $2 == "!") && $1 != "*"' /etc/shadow)
        if [ -n "$EMPTY_PW" ]; then
            fail "Accounts with empty/no password:"
            echo "$EMPTY_PW" | while read -r line; do
                log "    $(echo "$line" | cut -d: -f1)"
            done
        else
            pass "No empty passwords found"
        fi
    fi

    # Check for unauthorized SSH keys
    info "Checking for SSH authorized_keys:"
    find / -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
        warn "Found: $keyfile"
        cat "$keyfile" | while read -r key; do
            log "    $key"
        done
    done

    # Check sudoers / doas
    if [ -f /etc/sudoers ]; then
        info "Sudoers file exists"
    fi
    if [ -f /etc/doas.conf ]; then
        info "doas.conf:"
        cat /etc/doas.conf | while read -r line; do
            log "    $line"
        done
    fi
}

audit_ssh() {
    header "SSH CONFIGURATION"

    SSHD_CONFIG="/etc/ssh/sshd_config"
    if [ ! -f "$SSHD_CONFIG" ]; then
        warn "sshd_config not found"
        return
    fi

    # Check key settings
    check_ssh_setting() {
        SETTING="$1"
        EXPECTED="$2"
        CURRENT=$(grep -i "^$SETTING" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | tail -1)
        if [ -z "$CURRENT" ]; then
            warn "$SETTING not explicitly set (using default)"
        elif [ "$CURRENT" = "$EXPECTED" ]; then
            pass "$SETTING = $CURRENT"
        else
            fail "$SETTING = $CURRENT (should be $EXPECTED)"
        fi
    }

    check_ssh_setting "PermitRootLogin" "no"
    check_ssh_setting "PasswordAuthentication" "yes"  # Need this for competition
    check_ssh_setting "PermitEmptyPasswords" "no"
    check_ssh_setting "X11Forwarding" "no"
    check_ssh_setting "MaxAuthTries" "3"
    check_ssh_setting "Protocol" "2"

    # Check SSH port
    SSH_PORT=$(grep -i "^Port" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
    if [ -z "$SSH_PORT" ]; then
        info "SSH Port: 22 (default)"
    else
        info "SSH Port: $SSH_PORT"
    fi

    # Check for suspicious SSH config includes
    if grep -qi "^Include\|^AuthorizedKeysFile\|^ForceCommand" "$SSHD_CONFIG" 2>/dev/null; then
        warn "Custom SSH directives found:"
        grep -i "^Include\|^AuthorizedKeysFile\|^ForceCommand" "$SSHD_CONFIG" | while read -r line; do
            log "    $line"
        done
    fi
}

audit_network() {
    header "NETWORK CONFIGURATION"

    # Interfaces
    info "Network interfaces:"
    ip -brief addr 2>/dev/null | while read -r line; do
        log "    $line"
    done

    # Routes
    info "Routing table:"
    ip route 2>/dev/null | while read -r line; do
        log "    $line"
    done

    # IP forwarding
    FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [ "$FWD" = "1" ]; then
        pass "IP forwarding enabled (required for router)"
    else
        fail "IP forwarding DISABLED — router won't forward traffic!"
    fi

    # Check NAT/netmap
    info "Checking NAT configuration:"
    if command -v nft >/dev/null 2>&1; then
        NFT_NAT=$(nft list ruleset 2>/dev/null | grep -i "nat\|masquerade\|netmap\|dnat\|snat")
        if [ -n "$NFT_NAT" ]; then
            pass "NAT rules found in nftables:"
            echo "$NFT_NAT" | while read -r line; do
                log "    $line"
            done
        else
            warn "No NAT rules found in nftables"
        fi
    fi
    if command -v iptables >/dev/null 2>&1; then
        IPT_NAT=$(iptables -t nat -L -n -v 2>/dev/null | grep -v "^Chain\|^$\|pkts")
        if [ -n "$IPT_NAT" ]; then
            pass "NAT rules found in iptables:"
            iptables -t nat -L -n -v 2>/dev/null | tee -a "$LOG_FILE"
        fi
    fi

    # DNS
    info "DNS configuration:"
    cat /etc/resolv.conf 2>/dev/null | grep -v "^#" | while read -r line; do
        log "    $line"
    done
}

audit_firewall() {
    header "FIREWALL RULES"

    # nftables
    if command -v nft >/dev/null 2>&1; then
        info "=== NFTABLES RULESET ==="
        NFT_RULES=$(nft list ruleset 2>/dev/null)
        if [ -n "$NFT_RULES" ]; then
            echo "$NFT_RULES" | tee -a "$LOG_FILE"
        else
            warn "nftables ruleset is EMPTY"
        fi
    fi

    # iptables
    if command -v iptables >/dev/null 2>&1; then
        info "=== IPTABLES RULES ==="
        info "Filter table:"
        iptables -L -n -v --line-numbers 2>/dev/null | tee -a "$LOG_FILE"
        info "NAT table:"
        iptables -t nat -L -n -v --line-numbers 2>/dev/null | tee -a "$LOG_FILE"
        info "Mangle table:"
        iptables -t mangle -L -n -v --line-numbers 2>/dev/null | tee -a "$LOG_FILE"
    fi

    # Check for DROP/REJECT rules that might block scoring
    info "Checking for potentially dangerous rules:"
    if command -v iptables >/dev/null 2>&1; then
        DROPS=$(iptables -L -n 2>/dev/null | grep -i "DROP\|REJECT" | grep -v "^Chain")
        if [ -n "$DROPS" ]; then
            warn "DROP/REJECT rules found (verify these don't block scoring):"
            echo "$DROPS" | while read -r line; do
                log "    $line"
            done
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        NFT_DROPS=$(nft list ruleset 2>/dev/null | grep -i "drop\|reject")
        if [ -n "$NFT_DROPS" ]; then
            warn "NFT drop/reject rules (verify these don't block scoring):"
            echo "$NFT_DROPS" | while read -r line; do
                log "    $line"
            done
        fi
    fi
}

audit_listening_ports() {
    header "LISTENING PORTS"

    info "TCP listeners:"
    ss -tlnp 2>/dev/null | while read -r line; do
        log "    $line"
    done

    info "UDP listeners:"
    ss -ulnp 2>/dev/null | while read -r line; do
        log "    $line"
    done

    # Check for suspicious ports
    SUSPECT_PORTS=$(ss -tlnp 2>/dev/null | grep -E ":(4444|5555|6666|7777|8888|9999|1337|31337|12345)" )
    if [ -n "$SUSPECT_PORTS" ]; then
        fail "Suspicious ports detected:"
        echo "$SUSPECT_PORTS" | while read -r line; do
            log "    $line"
        done
    else
        pass "No common backdoor ports detected"
    fi
}

audit_processes() {
    header "RUNNING PROCESSES"

    info "All processes:"
    ps aux 2>/dev/null | tee -a "$LOG_FILE"

    # Check for suspicious processes
    SUSPECT_PROCS=$(ps aux 2>/dev/null | grep -iE "nc -l|ncat|netcat|reverse|shell|meterpreter|beacon|c2|cobalt|empire|rat" | grep -v grep)
    if [ -n "$SUSPECT_PROCS" ]; then
        fail "Suspicious processes detected:"
        echo "$SUSPECT_PROCS" | while read -r line; do
            log "    $line"
        done
    else
        pass "No obvious suspicious processes"
    fi
}

audit_cron() {
    header "SCHEDULED TASKS"

    # Check system crontabs
    info "System crontabs (/etc/crontabs/):"
    ls -la /etc/crontabs/ 2>/dev/null | while read -r line; do
        log "    $line"
    done
    for f in /etc/crontabs/*; do
        if [ -f "$f" ]; then
            info "Contents of $f:"
            cat "$f" | while read -r line; do
                log "    $line"
            done
        fi
    done

    # Check periodic
    for period in 15min hourly daily weekly monthly; do
        if [ -d "/etc/periodic/$period" ]; then
            FILES=$(ls /etc/periodic/$period/ 2>/dev/null)
            if [ -n "$FILES" ]; then
                info "/etc/periodic/$period:"
                echo "$FILES" | while read -r line; do
                    log "    $line"
                done
            fi
        fi
    done

    # Check /var/spool/cron
    if [ -d "/var/spool/cron" ]; then
        info "/var/spool/cron:"
        ls -la /var/spool/cron/ 2>/dev/null | while read -r line; do
            log "    $line"
        done
    fi
}

audit_persistence() {
    header "PERSISTENCE MECHANISMS"

    # Check init scripts
    info "Init scripts (/etc/init.d/):"
    ls -la /etc/init.d/ 2>/dev/null | while read -r line; do
        log "    $line"
    done

    # Check enabled services
    info "Enabled services:"
    rc-status --all 2>/dev/null | tee -a "$LOG_FILE"

    # Check /etc/local.d (Alpine autostart)
    if [ -d "/etc/local.d" ]; then
        info "/etc/local.d/ scripts (run at boot):"
        ls -la /etc/local.d/ 2>/dev/null | while read -r line; do
            log "    $line"
        done
        for f in /etc/local.d/*.start; do
            if [ -f "$f" ]; then
                warn "Autostart script: $f"
                cat "$f" | while read -r line; do
                    log "    $line"
                done
            fi
        done
    fi

    # Check profile.d
    if [ -d "/etc/profile.d" ]; then
        info "/etc/profile.d/ scripts:"
        ls -la /etc/profile.d/ 2>/dev/null | while read -r line; do
            log "    $line"
        done
    fi

    # Check for modified binaries (common red team technique)
    info "Checking critical binary integrity:"
    for bin in /usr/sbin/sshd /usr/sbin/crond /sbin/iptables /sbin/nft; do
        if [ -f "$bin" ]; then
            HASH=$(sha256sum "$bin" 2>/dev/null | awk '{print $1}')
            info "$bin: $HASH"
        fi
    done

    # Check /tmp and /dev/shm for suspicious files
    info "Files in /tmp:"
    find /tmp -type f -ls 2>/dev/null | while read -r line; do
        log "    $line"
    done
    info "Files in /dev/shm:"
    find /dev/shm -type f -ls 2>/dev/null | while read -r line; do
        log "    $line"
    done
}

audit_files() {
    header "FILE SYSTEM CHECKS"

    # SUID binaries
    info "SUID binaries:"
    find / -perm -4000 -type f 2>/dev/null | while read -r line; do
        log "    $line"
    done

    # SGID binaries
    info "SGID binaries:"
    find / -perm -2000 -type f 2>/dev/null | while read -r line; do
        log "    $line"
    done

    # World-writable files in sensitive dirs
    info "World-writable files in /etc:"
    find /etc -perm -002 -type f 2>/dev/null | while read -r line; do
        warn "World-writable: $line"
    done

    # Recently modified files in /etc
    info "Files modified in /etc in last 24h:"
    find /etc -mtime -1 -type f 2>/dev/null | while read -r line; do
        log "    $line"
    done

    # Check hosts file
    info "/etc/hosts:"
    cat /etc/hosts 2>/dev/null | while read -r line; do
        log "    $line"
    done
}

audit_connectivity() {
    header "CONNECTIVITY CHECK"

    # Can we reach internal hosts?
    info "Pinging internal hosts:"
    for ip in 10 14 16 20 22 23 24 26 28 240; do
        TARGET="192.168.220.$ip"
        if ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1; then
            pass "  $TARGET reachable"
        else
            fail "  $TARGET UNREACHABLE"
        fi
    done

    # Check if scoring engine is reachable (common external target)
    info "Checking external connectivity:"
    if ping -c 1 -W 2 10.0.0.20 >/dev/null 2>&1; then
        pass "  10.0.0.20 (competition infra) reachable"
    else
        warn "  10.0.0.20 not reachable (may be expected)"
    fi
}

#==============================================================================
# HARDENING FUNCTIONS (only run with --harden)
#==============================================================================

harden_ssh() {
    header "HARDENING SSH"

    SSHD_CONFIG="/etc/ssh/sshd_config"
    if [ ! -f "$SSHD_CONFIG" ]; then
        warn "sshd_config not found, skipping"
        return
    fi

    # Apply secure settings
    apply_ssh_setting() {
        KEY="$1"
        VALUE="$2"
        if grep -q "^$KEY" "$SSHD_CONFIG"; then
            sed -i "s/^$KEY.*/$KEY $VALUE/" "$SSHD_CONFIG"
        elif grep -q "^#$KEY" "$SSHD_CONFIG"; then
            sed -i "s/^#$KEY.*/$KEY $VALUE/" "$SSHD_CONFIG"
        else
            echo "$KEY $VALUE" >> "$SSHD_CONFIG"
        fi
        info "Set $KEY = $VALUE"
    }

    apply_ssh_setting "PermitRootLogin" "no"
    apply_ssh_setting "PermitEmptyPasswords" "no"
    apply_ssh_setting "X11Forwarding" "no"
    apply_ssh_setting "MaxAuthTries" "3"
    apply_ssh_setting "ClientAliveInterval" "300"
    apply_ssh_setting "ClientAliveCountMax" "2"
    apply_ssh_setting "AllowTcpForwarding" "no"

    # Restart SSH
    if rc-service sshd restart >/dev/null 2>&1; then
        pass "SSH restarted with hardened config"
    elif service sshd restart >/dev/null 2>&1; then
        pass "SSH restarted with hardened config"
    else
        warn "Could not restart SSH — may need manual restart"
    fi
}

harden_users() {
    header "HARDENING USER ACCOUNTS"

    # Lock unnecessary accounts
    info "Locking system accounts that shouldn't have login:"
    awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ && $1 != "root" && $1 != "admin"' /etc/passwd | while IFS=: read -r user _ _ _ _ _ shell; do
        # Don't lock the admin account we need for competition
        warn "User with shell access: $user ($shell) — verify this is needed"
    done

    # Remove unauthorized SSH keys (be careful!)
    info "Review authorized_keys files manually before removing"
}

harden_services() {
    header "HARDENING SERVICES"

    # Disable unnecessary services
    UNNECESSARY="telnetd ftpd"
    for svc in $UNNECESSARY; do
        if rc-service "$svc" status >/dev/null 2>&1; then
            warn "Disabling $svc"
            rc-service "$svc" stop 2>/dev/null
            rc-update del "$svc" 2>/dev/null
        fi
    done

    # Make sure critical services are running
    CRITICAL="sshd networking"
    for svc in $CRITICAL; do
        if rc-service "$svc" status >/dev/null 2>&1; then
            pass "$svc is running"
        else
            warn "$svc not running — starting"
            rc-service "$svc" start 2>/dev/null
        fi
    done
}

harden_sysctl() {
    header "HARDENING SYSCTL"

    # IMPORTANT: Keep ip_forward enabled — this is a router!
    SYSCTL_FILE="/etc/sysctl.d/99-wrccdc-hardening.conf"

    cat > "$SYSCTL_FILE" << 'SYSEOF'
# WRCCDC Hardening - Keep ip_forward ON (this is a router!)
net.ipv4.ip_forward = 1

# Prevent source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects (prevent MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Ignore ICMP broadcast
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
SYSEOF

    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
    pass "Sysctl hardening applied (ip_forward still ON)"
}

#==============================================================================
# GENERATE SUMMARY
#==============================================================================

generate_summary() {
    header "AUDIT SUMMARY"

    log ""
    log "  ${BOLD}Quick Reference${NC}"
    log "  ─────────────────────────────────────────"
    log "  Hostname:        $(hostname)"
    log "  Internal IP:     $ROUTER_IP"
    log "  Internal Net:    $INTERNAL_NET"
    log "  IP Forward:      $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
    log "  Users w/ shell:  $(awk -F: '$7 !~ /nologin|false/' /etc/passwd | wc -l)"
    log "  UID 0 accounts:  $(awk -F: '$3 == 0' /etc/passwd | wc -l)"
    log "  Listening TCP:   $(ss -tln 2>/dev/null | grep -c LISTEN)"
    log "  Listening UDP:   $(ss -uln 2>/dev/null | grep -c UNCONN)"
    log "  Active conns:    $(ss -tn 2>/dev/null | grep -c ESTAB)"
    log "  ─────────────────────────────────────────"
    log ""
    log "  ${BOLD}Critical Reminders for WRCCDC:${NC}"
    log "  ${RED}• DO NOT block scoring engine traffic${NC}"
    log "  ${RED}• DO NOT disable IP forwarding${NC}"
    log "  ${RED}• DO NOT break NAT/netmap${NC}"
    log "  ${YELLOW}• Router reset costs 100 points${NC}"
    log "  ${YELLOW}• SLA violation: 50 pts (first 2hrs) / 25 pts (after)${NC}"
    log "  ${GREEN}• Always backup before changes${NC}"
    log "  ${GREEN}• Test connectivity after ANY firewall change${NC}"
    log ""
    log "  Full log saved to: $LOG_FILE"
}

#==============================================================================
# MAIN
#==============================================================================

case "$MODE" in
    snapshot)
        do_snapshot
        ;;
    diff)
        do_diff
        ;;
    monitor)
        do_monitor
        ;;
    audit|harden)
        log "${BOLD}WRCCDC 2026 - Alpine Router Audit${NC}"
        log "${BOLD}Mode: $MODE${NC}"
        log "${BOLD}Started: $(date)${NC}"
        log ""

        if [ "$MODE" = "harden" ]; then
            do_backup
        fi

        # Run all audits
        audit_system_info
        audit_users
        audit_ssh
        audit_network
        audit_firewall
        audit_listening_ports
        audit_processes
        audit_cron
        audit_persistence
        audit_files
        audit_connectivity

        # Run hardening if requested
        if [ "$MODE" = "harden" ]; then
            header "APPLYING HARDENING"
            warn "Hardening will modify system configuration"
            warn "Backup saved to $BACKUP_DIR"
            harden_ssh
            harden_users
            harden_services
            harden_sysctl
        fi

        generate_summary
        ;;
esac
