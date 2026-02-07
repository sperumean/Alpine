#!/bin/bash
#==============================================================================
# Universal Linux Audit & Hardening Script
# Targets: arrowhead(.10) mead(.16) stupidlake(.20) wikey(.23)
#          pychgynmygytgyn(.24) elsinore(.26) berryessa(.240)
# Supports: Debian, Rocky/RHEL, Void Linux, Alpine, Generic
#
# Usage:
#   ./linux-audit.sh                  # Audit only (safe)
#   ./linux-audit.sh --harden         # Audit + harden (backs up first)
#   ./linux-audit.sh --monitor        # Continuous red team detection
#   ./linux-audit.sh --snapshot       # Save baseline state
#   ./linux-audit.sh --diff           # Compare current to snapshot
#   ./linux-audit.sh --passwords      # Change all user passwords
#==============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

MODE="audit"
BACKUP_DIR="/root/wrccdc-backup-$(date +%Y%m%d-%H%M%S)"
SNAPSHOT_DIR="/root/wrccdc-snapshot"
LOG_FILE="/root/wrccdc-audit-$(date +%Y%m%d-%H%M%S).log"

case "$1" in
    --harden)    MODE="harden" ;;
    --monitor)   MODE="monitor" ;;
    --snapshot)  MODE="snapshot" ;;
    --diff)      MODE="diff" ;;
    --passwords) MODE="passwords" ;;
    --help|-h)   echo "Usage: $0 [--harden|--monitor|--snapshot|--diff|--passwords]"; exit 0 ;;
esac

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|kali) DISTRO="debian" ;;
            rocky|rhel|centos|fedora|almalinux) DISTRO="rhel" ;;
            void) DISTRO="void" ;;
            alpine) DISTRO="alpine" ;;
            *) DISTRO="unknown" ;;
        esac
    else DISTRO="unknown"; fi
}

detect_role() {
    ROLES=""
    command -v nginx >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1 && ROLES="$ROLES webserver"
    command -v mysql >/dev/null 2>&1 || command -v psql >/dev/null 2>&1 || command -v mongod >/dev/null 2>&1 && ROLES="$ROLES database"
    command -v postfix >/dev/null 2>&1 || command -v dovecot >/dev/null 2>&1 && ROLES="$ROLES mail"
    command -v kubectl >/dev/null 2>&1 || command -v kubelet >/dev/null 2>&1 && ROLES="$ROLES kubernetes"
    command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1 && ROLES="$ROLES containers"
    command -v smbd >/dev/null 2>&1 || [ -f /etc/samba/smb.conf ] && ROLES="$ROLES samba"
    [ -f /etc/exports ] && ROLES="$ROLES nfs"
    command -v named >/dev/null 2>&1 || command -v unbound >/dev/null 2>&1 && ROLES="$ROLES dns"
    command -v vsftpd >/dev/null 2>&1 || command -v proftpd >/dev/null 2>&1 && ROLES="$ROLES ftp"
    pgrep -f "modbus\|scada\|plc\|openplc" >/dev/null 2>&1 && ROLES="$ROLES ics"
}

log() { echo -e "$1" | tee -a "$LOG_FILE"; }
header() { log "\n${CYAN}══════════════════════════════════════════════════════════════${NC}\n${CYAN}  ${BOLD}$1${NC}\n${CYAN}══════════════════════════════════════════════════════════════${NC}"; }
pass() { log "  ${GREEN}[PASS]${NC} $1"; }
warn() { log "  ${YELLOW}[WARN]${NC} $1"; }
fail() { log "  ${RED}[FAIL]${NC} $1"; }
info() { log "  ${BLUE}[INFO]${NC} $1"; }

#==============================================================================
# SNAPSHOT / DIFF / MONITOR
#==============================================================================
do_snapshot() {
    header "SAVING SYSTEM SNAPSHOT"
    mkdir -p "$SNAPSHOT_DIR"
    cp /etc/passwd /etc/shadow /etc/group /etc/hosts /etc/resolv.conf "$SNAPSHOT_DIR/" 2>/dev/null
    cp /etc/ssh/sshd_config "$SNAPSHOT_DIR/" 2>/dev/null
    iptables-save > "$SNAPSHOT_DIR/iptables.txt" 2>/dev/null
    nft list ruleset > "$SNAPSHOT_DIR/nft-ruleset.txt" 2>/dev/null
    ip addr > "$SNAPSHOT_DIR/ip-addr.txt" 2>/dev/null
    ip route > "$SNAPSHOT_DIR/ip-route.txt" 2>/dev/null
    ss -tlnp > "$SNAPSHOT_DIR/listening-ports.txt" 2>/dev/null
    ps aux > "$SNAPSHOT_DIR/processes.txt" 2>/dev/null
    crontab -l > "$SNAPSHOT_DIR/crontab-root.txt" 2>/dev/null
    systemctl list-unit-files --type=service > "$SNAPSHOT_DIR/services.txt" 2>/dev/null
    sha256sum /etc/passwd /etc/shadow /etc/group /etc/hosts /etc/ssh/sshd_config /etc/resolv.conf 2>/dev/null > "$SNAPSHOT_DIR/critical-hashes.txt"
    info "Snapshot saved to $SNAPSHOT_DIR"
}

do_diff() {
    header "COMPARING TO SNAPSHOT"
    [ ! -d "$SNAPSHOT_DIR" ] && { fail "No snapshot! Run --snapshot first"; exit 1; }
    CHANGES=0
    for f in passwd shadow group hosts resolv.conf sshd_config; do
        SRC="/etc/$f"; [ "$f" = "sshd_config" ] && SRC="/etc/ssh/$f"
        [ -f "$SNAPSHOT_DIR/$f" ] && [ -f "$SRC" ] && {
            if ! diff -q "$SNAPSHOT_DIR/$f" "$SRC" >/dev/null 2>&1; then
                fail "$f CHANGED!"; diff "$SNAPSHOT_DIR/$f" "$SRC" | tee -a "$LOG_FILE"
                CHANGES=$((CHANGES + 1))
            else pass "$f unchanged"; fi
        }
    done
    # Check ports
    ss -tlnp > /tmp/ports-now.txt 2>/dev/null
    if [ -f "$SNAPSHOT_DIR/listening-ports.txt" ] && ! diff -q "$SNAPSHOT_DIR/listening-ports.txt" /tmp/ports-now.txt >/dev/null 2>&1; then
        fail "LISTENING PORTS CHANGED!"; diff "$SNAPSHOT_DIR/listening-ports.txt" /tmp/ports-now.txt | tee -a "$LOG_FILE"
        CHANGES=$((CHANGES + 1))
    else pass "Ports unchanged"; fi
    # Check routes
    ip route > /tmp/routes-now.txt 2>/dev/null
    if [ -f "$SNAPSHOT_DIR/ip-route.txt" ] && ! diff -q "$SNAPSHOT_DIR/ip-route.txt" /tmp/routes-now.txt >/dev/null 2>&1; then
        fail "ROUTES CHANGED!"; diff "$SNAPSHOT_DIR/ip-route.txt" /tmp/routes-now.txt | tee -a "$LOG_FILE"
        CHANGES=$((CHANGES + 1))
    else pass "Routes unchanged"; fi
    log ""
    [ $CHANGES -eq 0 ] && log "${GREEN}${BOLD}No changes detected.${NC}" || log "${RED}${BOLD}$CHANGES change(s) detected!${NC}"
}

do_monitor() {
    header "CONTINUOUS MONITORING - Ctrl+C to stop"
    BASE_USERS=$(wc -l < /etc/passwd); BASE_PORTS=$(ss -tln 2>/dev/null | grep -c LISTEN)
    BASE_ROUTES=$(ip route 2>/dev/null | wc -l); BASE_ROOT=$(awk -F: '$3==0' /etc/passwd | wc -l)
    while true; do
        TS=$(date '+%H:%M:%S')
        NOW_USERS=$(wc -l < /etc/passwd); NOW_PORTS=$(ss -tln 2>/dev/null | grep -c LISTEN)
        NOW_ROUTES=$(ip route 2>/dev/null | wc -l); NOW_CONNS=$(ss -tn 2>/dev/null | grep -c ESTAB)
        NOW_ROOT=$(awk -F: '$3==0' /etc/passwd | wc -l); NOW_PROCS=$(ps aux 2>/dev/null | wc -l)
        ALERT=""
        [ "$NOW_USERS" != "$BASE_USERS" ] && ALERT="${ALERT} ${RED}USERS:${NOW_USERS}(was${BASE_USERS})${NC}"
        [ "$NOW_PORTS" != "$BASE_PORTS" ] && ALERT="${ALERT} ${RED}PORTS:${NOW_PORTS}(was${BASE_PORTS})${NC}"
        [ "$NOW_ROOT" -gt 1 ] && ALERT="${ALERT} ${RED}UID0:${NOW_ROOT}!${NC}"
        [ -n "$ALERT" ] && echo -e "\n[${TS}] ${RED}ALERT:${NC}${ALERT}"
        printf "\r[%s] Users:%s Ports:%s Routes:%s Conns:%s Procs:%s Root:%s  " \
            "$TS" "$NOW_USERS" "$NOW_PORTS" "$NOW_ROUTES" "$NOW_CONNS" "$NOW_PROCS" "$NOW_ROOT"
        sleep 30
    done
}

#==============================================================================
# PASSWORD CHANGE
#==============================================================================
do_passwords() {
    header "BULK PASSWORD CHANGE"
    warn "SUBMIT PCRs IN QUOTIENT AFTER CHANGING!"
    warn "Orange team uses these creds — update via scoring engine!"
    log ""
    USERS=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd)
    echo "Change root password? (y/n): "; read -r CR
    if [ "$CR" = "y" ]; then
        echo "New root password: "; read -rs RP; echo "root:$RP" | chpasswd
        pass "Root password changed — ${YELLOW}SUBMIT PCR${NC}"
    fi
    echo "New password for all users (or 'individual'): "; read -rs BP
    if [ "$BP" = "individual" ]; then
        for u in $USERS; do
            echo "Password for $u: "; read -rs UP; echo "$u:$UP" | chpasswd; pass "Changed: $u"
        done
    else
        for u in $USERS; do echo "$u:$BP" | chpasswd; pass "Changed: $u"; done
    fi
    log "\n  ${YELLOW}${BOLD}>>> SUBMIT PCRs IN QUOTIENT FOR:${NC}"
    for u in root $USERS; do log "  ${YELLOW}    - $u${NC}"; done
}

#==============================================================================
# AUDIT FUNCTIONS
#==============================================================================
audit_system_info() {
    header "SYSTEM INFORMATION"
    detect_distro; detect_role
    info "Hostname:  $(hostname)"
    info "Distro:    $DISTRO"
    info "OS:        $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    info "Kernel:    $(uname -r)"
    info "Uptime:    $(uptime -p 2>/dev/null || uptime)"
    info "IPs:       $(ip -4 addr show 2>/dev/null | grep inet | grep -v 127.0.0.1 | awk '{print $2}' | tr '\n' ' ')"
    info "Roles:     ${ROLES:-none detected}"
}

audit_users() {
    header "USER ACCOUNTS"
    # UID 0
    RC=$(awk -F: '$3==0' /etc/passwd | wc -l)
    [ "$RC" -gt 1 ] && { fail "Multiple UID 0 accounts!"; awk -F: '$3==0{print "    "$0}' /etc/passwd | tee -a "$LOG_FILE"; } || pass "Only root has UID 0"
    # Login shells
    info "Accounts with login shells:"
    awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {printf "    %-20s UID:%-6s Home:%-20s Shell:%s\n",$1,$3,$6,$7}' /etc/passwd | tee -a "$LOG_FILE"
    # Empty passwords
    EP=$(awk -F: '($2=="" || $2=="!" || $2=="!!") && $1!="*"' /etc/shadow 2>/dev/null)
    [ -n "$EP" ] && { fail "Empty/locked passwords:"; echo "$EP" | awk -F: '{print "    "$1}' | tee -a "$LOG_FILE"; } || pass "No empty passwords"
    # SSH keys
    info "SSH authorized_keys:"
    find / -name "authorized_keys" -type f 2>/dev/null | while read -r f; do
        warn "Found: $f ($(wc -l < "$f") keys)"
        cat "$f" | while read -r k; do log "    ${k:0:80}..."; done
    done
    # Sudoers
    info "Sudo config:"
    grep -v "^#\|^$\|^Defaults" /etc/sudoers 2>/dev/null | while read -r l; do log "    $l"; done
    [ -d /etc/sudoers.d ] && for f in /etc/sudoers.d/*; do [ -f "$f" ] && { warn "Drop-in: $f"; cat "$f" | tee -a "$LOG_FILE"; }; done
    # Privileged groups
    info "Privileged groups:"
    for g in wheel sudo adm root docker; do
        M=$(getent group "$g" 2>/dev/null | cut -d: -f4); [ -n "$M" ] && info "  $g: $M"
    done
}

audit_ssh() {
    header "SSH CONFIGURATION"
    SC="/etc/ssh/sshd_config"; [ ! -f "$SC" ] && { warn "sshd_config not found"; return; }
    chk() {
        V=$(grep -i "^$1" "$SC" 2>/dev/null | awk '{print $2}' | tail -1)
        [ -z "$V" ] && warn "$1 not set" || { [ "$V" = "$2" ] && pass "$1 = $V" || fail "$1 = $V (want $2)"; }
    }
    chk "PermitRootLogin" "no"
    chk "PasswordAuthentication" "yes"
    chk "PermitEmptyPasswords" "no"
    chk "X11Forwarding" "no"
    chk "MaxAuthTries" "3"
    INC=$(grep -i "^Include\|^AuthorizedKeysCommand\|^ForceCommand" "$SC" 2>/dev/null)
    [ -n "$INC" ] && { warn "Custom directives:"; echo "$INC" | while read -r l; do log "    $l"; done; }
}

audit_network() {
    header "NETWORK"
    info "Interfaces:"; ip -brief addr 2>/dev/null | while read -r l; do log "    $l"; done
    info "Routes:"; ip route 2>/dev/null | while read -r l; do log "    $l"; done
    info "DNS:"; grep -v "^#\|^$" /etc/resolv.conf 2>/dev/null | while read -r l; do log "    $l"; done
    info "Hosts:"; grep -v "^#\|^$" /etc/hosts 2>/dev/null | while read -r l; do log "    $l"; done
    FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    info "IP forwarding: $FWD"
}

audit_firewall() {
    header "FIREWALL"
    if command -v iptables >/dev/null 2>&1; then
        info "=== IPTABLES ==="; for t in filter nat mangle; do
            info "Table: $t"; iptables -t "$t" -L -n -v --line-numbers 2>/dev/null | tee -a "$LOG_FILE"
        done
    fi
    command -v nft >/dev/null 2>&1 && { info "=== NFTABLES ==="; nft list ruleset 2>/dev/null | tee -a "$LOG_FILE"; }
    command -v ufw >/dev/null 2>&1 && { info "=== UFW ==="; ufw status verbose 2>/dev/null | tee -a "$LOG_FILE"; }
    command -v firewall-cmd >/dev/null 2>&1 && { info "=== FIREWALLD ==="; firewall-cmd --list-all 2>/dev/null | tee -a "$LOG_FILE"; }
}

audit_ports() {
    header "LISTENING PORTS"
    info "TCP:"; ss -tlnp 2>/dev/null | tee -a "$LOG_FILE"
    info "UDP:"; ss -ulnp 2>/dev/null | tee -a "$LOG_FILE"
    S=$(ss -tlnp 2>/dev/null | grep -E ":(4444|5555|6666|7777|8888|9999|1337|31337|12345|6969)")
    [ -n "$S" ] && { fail "Suspicious ports:"; echo "$S" | tee -a "$LOG_FILE"; } || pass "No common backdoor ports"
    info "Established connections:"; ss -tnp 2>/dev/null | grep ESTAB | tee -a "$LOG_FILE"
}

audit_processes() {
    header "PROCESSES"
    info "All running:"; ps auxf 2>/dev/null | tee -a "$LOG_FILE" || ps aux | tee -a "$LOG_FILE"
    S=$(ps aux 2>/dev/null | grep -iE "nc -l|ncat|netcat|socat.*listen|meterpreter|beacon|cobalt|empire|chisel|ligolo|sliver" | grep -v grep)
    [ -n "$S" ] && { fail "Suspicious:"; echo "$S" | tee -a "$LOG_FILE"; } || pass "No obvious suspicious processes"
}

audit_cron() {
    header "SCHEDULED TASKS"
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] && { info "$d/:"; ls -la "$d/" 2>/dev/null | tee -a "$LOG_FILE"
            for f in "$d"/*; do [ -f "$f" ] && { info "  $f:"; grep -v "^#\|^$" "$f" | tee -a "$LOG_FILE"; }; done
        }
    done
    info "Root crontab:"; crontab -l 2>/dev/null | tee -a "$LOG_FILE"
    [ -d /var/spool/cron/crontabs ] && { info "User crontabs:"; ls -la /var/spool/cron/crontabs/ 2>/dev/null | tee -a "$LOG_FILE"; }
    command -v systemctl >/dev/null 2>&1 && { info "Systemd timers:"; systemctl list-timers --all --no-pager 2>/dev/null | tee -a "$LOG_FILE"; }
}

audit_persistence() {
    header "PERSISTENCE"
    # Profile.d
    [ -d /etc/profile.d ] && { info "/etc/profile.d/:"; ls -la /etc/profile.d/ 2>/dev/null | tee -a "$LOG_FILE"; }
    # Bashrc backdoors
    info "Checking shell configs for backdoors:"
    for f in /etc/profile /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.bash_profile /root/.profile; do
        [ -f "$f" ] && {
            S=$(grep -iE "nc |ncat |bash -i|/dev/tcp|curl.*\||wget.*\||python.*socket|reverse|exec [0-9]" "$f" 2>/dev/null)
            [ -n "$S" ] && { fail "BACKDOOR in $f:"; echo "$S" | tee -a "$LOG_FILE"; }
        }
    done
    for hd in /home/*; do
        for f in "$hd/.bashrc" "$hd/.bash_profile" "$hd/.profile"; do
            [ -f "$f" ] && {
                S=$(grep -iE "nc |ncat |bash -i|/dev/tcp|curl.*\||wget.*\||python.*socket|reverse|exec [0-9]" "$f" 2>/dev/null)
                [ -n "$S" ] && { fail "BACKDOOR in $f:"; echo "$S" | tee -a "$LOG_FILE"; }
            }
        done
    done
    # Alias hijacking
    info "Command integrity:"
    for cmd in sudo su ssh scp passwd; do
        T=$(type "$cmd" 2>/dev/null)
        echo "$T" | grep -q "alias\|function" && fail "$cmd overridden: $T"
    done
    # LD_PRELOAD
    [ -f /etc/ld.so.preload ] && { fail "/etc/ld.so.preload exists!"; cat /etc/ld.so.preload | tee -a "$LOG_FILE"; }
    # Suspicious files
    info "Hidden files in /tmp:"; find /tmp -name ".*" -type f -ls 2>/dev/null | tee -a "$LOG_FILE"
    info "Scripts in /tmp:"; find /tmp -name "*.sh" -type f -ls 2>/dev/null | tee -a "$LOG_FILE"
    info "Files in /dev/shm:"; find /dev/shm -type f -ls 2>/dev/null | tee -a "$LOG_FILE"
}

audit_files() {
    header "FILE SYSTEM"
    info "SUID binaries:"; find / -perm -4000 -type f 2>/dev/null | tee -a "$LOG_FILE"
    info "World-writable in /etc:"; find /etc -perm -002 -type f 2>/dev/null | while read -r f; do warn "$f"; done
    info "Modified in /etc (24h):"; find /etc -mtime -1 -type f 2>/dev/null | tee -a "$LOG_FILE"
    # Webshell check
    for wr in /var/www /srv/http /usr/share/nginx; do
        [ -d "$wr" ] && {
            info "Webshell scan ($wr):"
            find "$wr" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" \) 2>/dev/null | while read -r f; do
                grep -lE "eval\(|base64_decode|system\(|passthru|shell_exec|exec\(" "$f" 2>/dev/null && fail "WEBSHELL: $f"
            done
        }
    done
}

audit_services() {
    header "SERVICE-SPECIFIC CHECKS"
    # Web
    echo "$ROLES" | grep -q "webserver" && {
        info "=== WEB SERVER ==="
        command -v nginx >/dev/null 2>&1 && { nginx -t 2>&1 | tee -a "$LOG_FILE"; }
        command -v apache2 >/dev/null 2>&1 && { apache2ctl -S 2>&1 | tee -a "$LOG_FILE"; }
        command -v httpd >/dev/null 2>&1 && { httpd -S 2>&1 | tee -a "$LOG_FILE"; }
        info "Web content:"; curl -s http://localhost 2>/dev/null | head -5 | tee -a "$LOG_FILE"
    }
    # Kubernetes
    echo "$ROLES" | grep -q "kubernetes" && {
        info "=== KUBERNETES ==="
        kubectl get nodes 2>/dev/null | tee -a "$LOG_FILE"
        kubectl get pods -A 2>/dev/null | tee -a "$LOG_FILE"
        kubectl get svc -A 2>/dev/null | tee -a "$LOG_FILE"
        info "Privileged pods:"; kubectl get pods -A -o json 2>/dev/null | grep -c "privileged" | tee -a "$LOG_FILE"
    }
    # Containers
    echo "$ROLES" | grep -q "containers" && {
        info "=== CONTAINERS ==="
        docker ps -a 2>/dev/null | tee -a "$LOG_FILE"
        docker images 2>/dev/null | tee -a "$LOG_FILE"
    }
    # Samba
    echo "$ROLES" | grep -q "samba" && {
        info "=== SAMBA ==="; testparm -s 2>/dev/null | tee -a "$LOG_FILE"
        pdbedit -L 2>/dev/null | tee -a "$LOG_FILE"
    }
    # NFS
    echo "$ROLES" | grep -q "nfs" && { info "=== NFS ==="; cat /etc/exports 2>/dev/null | tee -a "$LOG_FILE"; }
    # FTP
    echo "$ROLES" | grep -q "ftp" && { info "=== FTP ==="; grep -v "^#\|^$" /etc/vsftpd.conf 2>/dev/null | tee -a "$LOG_FILE"; }
}

audit_logs() {
    header "LOG INTEGRITY"
    for lf in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        if [ -f "$lf" ]; then
            SZ=$(stat -c%s "$lf" 2>/dev/null || stat -f%z "$lf" 2>/dev/null)
            [ "$SZ" -eq 0 ] 2>/dev/null && fail "$lf is EMPTY (log wipe!)" || pass "$lf ($(du -h "$lf" 2>/dev/null | awk '{print $1}'))"
        fi
    done
    command -v journalctl >/dev/null 2>&1 && { info "Journal: $(journalctl --disk-usage 2>/dev/null)"; }
    info "Recent failed logins:"
    grep -i "failed\|failure\|invalid" /var/log/auth.log /var/log/secure 2>/dev/null | tail -10 | tee -a "$LOG_FILE"
}

audit_connectivity() {
    header "CONNECTIVITY"
    for h in "2:ontario" "10:arrowhead" "14:tahoe" "16:mead" "20:stupidlake" "22:victoria" "23:wikey" "24:pychgynmygytgyn" "26:elsinore" "28:baikal" "240:berryessa"; do
        IP="192.168.220.$(echo "$h"|cut -d: -f1)"; N=$(echo "$h"|cut -d: -f2)
        ping -c1 -W1 "$IP" >/dev/null 2>&1 && pass "$IP ($N)" || fail "$IP ($N) UNREACHABLE"
    done
}

#==============================================================================
# HARDENING
#==============================================================================
harden_backup() {
    header "BACKUP"; mkdir -p "$BACKUP_DIR"
    cp -r /etc "$BACKUP_DIR/etc" 2>/dev/null
    iptables-save > "$BACKUP_DIR/iptables.txt" 2>/dev/null
    info "Backup: $BACKUP_DIR"
}

harden_ssh() {
    header "HARDENING SSH"
    SC="/etc/ssh/sshd_config"; [ ! -f "$SC" ] && return
    ss() { grep -q "^$1" "$SC" && sed -i "s/^$1.*/$1 $2/" "$SC" || { grep -q "^#$1" "$SC" && sed -i "s/^#$1.*/$1 $2/" "$SC" || echo "$1 $2" >> "$SC"; }; }
    ss "PermitRootLogin" "no"; ss "PermitEmptyPasswords" "no"; ss "X11Forwarding" "no"
    ss "MaxAuthTries" "3"; ss "ClientAliveInterval" "300"; ss "AllowTcpForwarding" "no"
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || rc-service sshd restart 2>/dev/null || sv restart sshd 2>/dev/null
    pass "SSH hardened"
}

harden_sysctl() {
    header "HARDENING SYSCTL"
    cat > /etc/sysctl.d/99-wrccdc.conf << 'EOF'
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
EOF
    sysctl -p /etc/sysctl.d/99-wrccdc.conf >/dev/null 2>&1; pass "Sysctl hardened"
}

harden_cleanup() {
    header "CLEANUP"
    for p in "nc -l" "ncat -l" "socat" "meterpreter" "beacon"; do
        PIDS=$(pgrep -f "$p" 2>/dev/null)
        [ -n "$PIDS" ] && { kill -9 $PIDS 2>/dev/null; warn "Killed $p"; }
    done
    find /tmp -name ".*" -type f -not -name ".X*" -delete 2>/dev/null
    find /dev/shm -type f -delete 2>/dev/null
    pass "Temp files cleaned"
}

generate_summary() {
    header "SUMMARY"
    log "  Hostname:       $(hostname)"
    log "  Distro:         $DISTRO"
    log "  Roles:          ${ROLES:-none}"
    log "  Users w/shell:  $(awk -F: '$7 !~ /nologin|false/' /etc/passwd | wc -l)"
    log "  UID 0 accounts: $(awk -F: '$3==0' /etc/passwd | wc -l)"
    log "  TCP listeners:  $(ss -tln 2>/dev/null | grep -c LISTEN)"
    log "  Connections:    $(ss -tn 2>/dev/null | grep -c ESTAB)"
    log ""
    log "  ${RED}SLAs: 50pts (before 11AM) / 25pts (after 11AM)${NC}"
    log "  ${YELLOW}Submit PCRs in Quotient after password changes!${NC}"
    log "  ${YELLOW}Orange team connects from 10.100.1XX.Y${NC}"
    log "  ${GREEN}File incident reports = 50% reduction in persistence penalties${NC}"
    log "  Log: $LOG_FILE"
}

#==============================================================================
# MAIN
#==============================================================================
detect_distro
case "$MODE" in
    snapshot)  do_snapshot ;;
    diff)      do_diff ;;
    monitor)   do_monitor ;;
    passwords) do_passwords ;;
    audit|harden)
        log "${BOLD}WRCCDC 2026 - Linux Audit ($(hostname)) - $MODE - $(date)${NC}"
        [ "$MODE" = "harden" ] && harden_backup
        audit_system_info; audit_users; audit_ssh; audit_network; audit_firewall
        audit_ports; audit_processes; audit_cron; audit_persistence; audit_files
        audit_services; audit_logs; audit_connectivity
        [ "$MODE" = "harden" ] && { harden_ssh; harden_sysctl; harden_cleanup; }
        generate_summary ;;
esac
