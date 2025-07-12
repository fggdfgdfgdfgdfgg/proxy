#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------
#       Script cài đặt SOCKS5, Shadowsocks và HTTP Proxy (Squid)
#       - Support Debian/Ubuntu/RedHat
#       - Random port 20000–40000; có thể chọn manual
# ------------------------------------------------------------------

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a /var/log/proxy-installer.log
}
error_exit() {
  log "ERROR: $1"; exit 1
}
check_root() {
  [[ $EUID -eq 0 ]] || error_exit "Phải chạy với root."
}
generate_password() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c16
}
generate_username() {
  echo "user_$(tr -dc 'a-z0-9' </dev/urandom | head -c8)"
}
validate_port() {
  local p=$1
  [[ "$p" =~ ^[0-9]+$ ]] && ((p>=1 && p<=65535)) && ! ss -tuln | grep -q ":$p " && return 0
  return 1
}
validate_username() {
  local u=$1
  [[ "$u" =~ ^[a-zA-Z0-9_-]{2,32}$ ]] && return 0
  return 1
}
prompt_choice() {
  echo "Chọn proxy cài đặt:"
  echo "  1) SOCKS5"
  echo "  2) Shadowsocks"
  echo "  3) HTTP Proxy"
  echo "  4) SOCKS5 + HTTP"
  echo "  5) Shadowsocks + HTTP"
  echo "  6) SOCKS5 + Shadowsocks"
  echo "  7) Cả 3"
  while true; do
    read -p "Chọn [1-7]: " CHOICE
    [[ "$CHOICE" =~ ^[1-7]$ ]] && break
  done
}
prompt_mode() {
  echo "Chế độ cấu hình:"
  echo "  1) Tự động (random)"
  echo "  2) Thủ công"
  while true; do
    read -p "Chọn [1-2]: " MODE
    [[ "$MODE" =~ ^[1-2]$ ]] && break
  done
}
get_manual_port_user_pass() {
  local defp=$1 defu=$2
  while true; do read -p "Port (mặc định $defp): " mp; mp=${mp:-$defp}; validate_port "$mp" && break; done
  while true; do read -p "User (mặc định ${2}user): " mu; mu=${mu:-${defu}user}; validate_username "$mu" && break; done
  read -p "Pass (enter để random): " mdp
  mdp=${mdp:-$(generate_password)}
  echo "$mp|$mu|$mdp"
}

install_packages() {
  if command -v apt-get >/dev/null; then
    apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  else
    yum install -y "$@"
  fi
}

detect_net() {
  EXT_IF=$(ip route | awk '/default/ {print $5; exit}') || EXT_IF=eth0
  PUBLIC_IP=$(curl -s https://api.ipify.org)
}

install_socks5() {
  log "Install SOCKS5..."
  if [[ "$MODE" == "1" ]]; then
    PORT=$(shuf -i20000-40000 -n1)
    while ss -tuln | grep -q ":$PORT "; do PORT=$(shuf -i20000-40000 -n1); done
    USER=$(generate_username); PASS=$(generate_password)
  else
    IFS="|" read PORT USER PASS <<< "$(get_manual_port_user_pass 1080 socks5)"
  fi
  install_packages dante-server
  useradd -M -N -s /usr/sbin/nologin "$USER" || true
  echo "$USER:$PASS" | chpasswd
  cat >/etc/danted.conf <<EOF
logoutput: syslog /var/log/danted.log
internal: 0.0.0.0 port = ${PORT}
external: ${EXT_IF}
method: pam
user.privileged: root
user.notprivileged: nobody
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 log: connect disconnect error }
socks pass   { from: 0.0.0.0/0 to: 0.0.0.0/0 command: bind connect udpassociate log: connect disconnect error protocol: tcp udp }
socks block  { from: 0.0.0.0/0 to: 127.0.0.0/8 }
socks block  { from: 0.0.0.0/0 to: 169.254.0.0/16 }
EOF
  systemctl enable --now danted
  ss -tuln | grep ":$PORT" >/dev/null || error_exit "SOCKS5 start lỗi"
  echo "socks5://${PUBLIC_IP}:${PORT}:${USER}:${PASS}"
}

install_shadowsocks() {
  log "Install Shadowsocks..."
  if [[ "$MODE" == "1" ]]; then
    PORT=$(shuf -i20000-40000 -n1)
    while ss -tuln | grep -q ":$PORT "; do PORT=$(shuf -i20000-40000 -n1); done
    PASS=$(generate_password); METHOD="aes-256-gcm"
  else
    IFS="|" read PORT USER PASS <<< "$(get_manual_port_user_pass 8388 ss)"
    METHOD="aes-256-gcm"
  fi
  install_packages shadowsocks-libev
  mkdir -p /etc/shadowsocks-libev
  cat >/etc/shadowsocks-libev/config.json <<EOF
{"server":"0.0.0.0","server_port":${PORT},"password":"${PASS}","method":"${METHOD}","timeout":300}
EOF
  systemctl enable --now shadowsocks-libev
  ss -tuln | grep ":$PORT" >/dev/null || error_exit "Shadowsocks start lỗi"
  echo "ss://${PUBLIC_IP}:${PORT}:${METHOD}:${PASS}"
}

install_squid() {
  log "Install HTTP Proxy..."
  if [[ "$MODE" == "1" ]]; then
    PORT=$(shuf -i20000-40000 -n1)
    while ss -tuln | grep -q ":$PORT "; do PORT=$(shuf -i20000-40000 -n1); done
    USER=$(generate_username); PASS=$(generate_password)
  else
    IFS="|" read PORT USER PASS <<< "$(get_manual_port_user_pass 3128 http)"
  fi
  install_packages squid apache2-utils
  htpasswd -cb /etc/squid/passwd "$USER" "$PASS"
  cat >/etc/squid/squid.conf <<EOF
http_port ${PORT}
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm proxy
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
http_access deny all
EOF
  chown proxy:proxy /etc/squid/passwd
  chmod 600 /etc/squid/passwd
  systemctl enable --now squid
  ss -tuln | grep ":$PORT" >/dev/null || error_exit "Squid start lỗi"
  echo "http://${USER}:${PASS}@${PUBLIC_IP}:${PORT}"
}

main() {
  check_root; detect_net
  prompt_choice; prompt_mode
  RESULT=()
  [[ "$CHOICE" =~ [14] ]] && RESULT+=( "$(install_socks5)" )
  [[ "$CHOICE" =~ [267] ]] && RESULT+=( "$(install_shadowsocks)" )
  [[ "$CHOICE" =~ [35] ]] && RESULT+=( "$(install_squid)" )
  echo; echo "✅ Completed! Các proxy đã tạo:"
  for r in "${RESULT[@]}"; do echo "   $r"; done
}
main "$@"
