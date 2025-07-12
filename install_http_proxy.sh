#!/bin/bash
set -e

USERNAME="giaiphapmmo79"
PASSWORD="giaiphapmmo79"
PORT="8888"

# Cài Squid
apt update -y
apt install -y squid apache2-utils

# Tạo file mật khẩu
htpasswd -cb /etc/squid/passwd "$USERNAME" "$PASSWORD"

# Sao lưu config cũ
cp /etc/squid/squid.conf /etc/squid/squid.conf.bak

# Tạo config mới
cat > /etc/squid/squid.conf <<EOF
http_port $PORT
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
EOF

# Phân quyền
chmod 600 /etc/squid/passwd
chown proxy:proxy /etc/squid/passwd

# Khởi động lại Squid
systemctl restart squid
systemctl enable squid

echo "✅ HTTP Proxy đã sẵn sàng!"
echo "➡️  http://$USERNAME:$PASSWORD@$(curl -s ipv4.icanhazip.com):$PORT"
