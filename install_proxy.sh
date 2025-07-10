#!/bin/bash

# ==== CẤU HÌNH ====
USERNAME="giaiphapmmo79"
PASSWORD="giaiphapmmo79"
SOCKS5_PORT=1080
HTTP_PORT=3128
# ===================

echo "🚀 Bắt đầu cài đặt SOCKS5 (Dante) và HTTP Proxy (Squid)..."
sudo apt update -y

# =============================
# CÀI SOCKS5 PROXY (DANTE)
# =============================
echo "🧱 Cài Dante SOCKS5..."
sudo apt install -y dante-server

# Tạo file cấu hình cho Dante
cat <<EOF | sudo tee /etc/sockd.conf > /dev/null
logoutput: /var/log/sockd.log
internal: 0.0.0.0 port = $SOCKS5_PORT
external: eth0
method: username
user.privileged: root
user.notprivileged: nobody
client pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  log: connect disconnect error
}
socks pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  log: connect disconnect error
  command: connect
}
EOF

# Tạo user
echo "🔐 Tạo user SOCKS5..."
sudo useradd -m $USERNAME
echo "$USERNAME:$PASSWORD" | sudo chpasswd

# Khởi động lại dịch vụ
sudo systemctl restart sockd
sudo systemctl enable sockd

# =============================
# CÀI HTTP PROXY (SQUID)
# =============================
echo "🌐 Cài Squid HTTP proxy..."
sudo apt install -y squid apache2-utils

# Tạo user/pass cho Squid
sudo htpasswd -b -c /etc/squid/passwd $USERNAME $PASSWORD

# Sửa file cấu hình squid
SQUID_CONF="/etc/squid/squid.conf"
sudo cp $SQUID_CONF $SQUID_CONF.bak

cat <<EOF | sudo tee $SQUID_CONF > /dev/null
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm Proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_port $HTTP_PORT
cache deny all
access_log none
EOF

sudo systemctl restart squid
sudo systemctl enable squid

# =============================
# MỞ CỔNG FIREWALL (nếu có)
# =============================
if command -v ufw >/dev/null 2>&1; then
    echo "🔥 Mở cổng firewall..."
    sudo ufw allow 22
    sudo ufw allow $SOCKS5_PORT
    sudo ufw allow $HTTP_PORT
fi

echo ""
echo "✅ Cài đặt hoàn tất!"
echo "SOCKS5 proxy: IP_VPS_CUA_BAN:$SOCKS5_PORT"
echo "HTTP proxy : IP_VPS_CUA_BAN:$HTTP_PORT"
echo "Username   : $USERNAME"
echo "Password   : $PASSWORD"
