#!/usr/bin/env bash

# Proxy installer with no username/password (IP:PORT only)
# Supports: SOCKS5 (Dante), HTTP Proxy (Squid)
# Platform: Debian/Ubuntu/RedHat

set -euo pipefail

# Function: log
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Function: error_exit
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check for root
[[ $EUID -ne 0 ]] && error_exit "Must run as root"

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            OS="debian"
            PKG="apt-get"
            ;;
        centos|rhel|amzn|rocky|almalinux)
            OS="redhat"
            PKG="yum"
            ;;
        *)
            error_exit "Unsupported OS"
            ;;
    esac
else
    error_exit "Cannot detect OS"
fi

# Get public IP
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s https://icanhazip.com)
[[ -z "$PUBLIC_IP" ]] && error_exit "Could not detect public IP"

# Get default interface
EXT_IF=$(ip route | awk '/default/ {print $5; exit}')

# Install Dante SOCKS5 with no auth
install_socks5() {
    PORT=1080
    log "Installing SOCKS5 on port $PORT"
    
    if [[ "$OS" = "debian" ]]; then
        $PKG update -y && $PKG install -y dante-server
    else
        $PKG install -y dante-server
    fi

    cat > /etc/danted.conf <<EOF
logoutput: /var/log/danted.log
internal: 0.0.0.0 port = $PORT
external: $EXT_IF
method: none
user.privileged: root
user.notprivileged: nobody

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: connect disconnect error
    protocol: tcp udp
}
EOF

    systemctl restart danted
    systemctl enable danted
    log "SOCKS5 proxy ready: socks5://$PUBLIC_IP:$PORT"
}

# Install Squid HTTP proxy with no auth
install_squid() {
    PORT=3128
    log "Installing HTTP proxy on port $PORT"

    if [[ "$OS" = "debian" ]]; then
        $PKG update -y && $PKG install -y squid
    else
        $PKG install -y squid
    fi

    cat > /etc/squid/squid.conf <<EOF
http_port $PORT
http_access allow all
EOF

    systemctl restart squid
    systemctl enable squid
    log "HTTP proxy ready: http://$PUBLIC_IP:$PORT"
}

# Run installers
install_socks5
install_squid
