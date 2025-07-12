#!/bin/bash
set -e

# Thông tin đăng nhập
USERNAME="giaiphapmmo79"
PASSWORD="giaiphapmmo79"

# Random port từ 2000–65000 (tránh trùng port hệ thống)
PORT=$((RANDOM % 63000 + 2000))

# Cài đặt Squid và apache2-utils nếu chưa có
apt update -y
apt install -y squid apache2-utils

# Tạo file mật khẩu Squid
htpasswd -cb /etc/squid/passwd "$USERNAME" "$PASSWORD"

# Sao lưu cấu hình gốc nếu chưa có
[ -f /etc/squid/squid.conf.bak ] || cp /etc/squid/squid.conf /etc/squid/squid.conf.bak

# Ghi cấu hình mới
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

# Mở port trên firewall (nếu dùng UFW)
if command -v ufw >/dev/null; then
    ufw allow "$PORT"/tcp || true
fi

# Mở port trên AWS (nếu cần) – bạn phải mở bằng tay trên AWS Security Group

# Khởi động Squid
systemctl restart squid
systemctl enable squid

# In thông tin proxy
IP=$(curl -s ipv4.icanhazip.com)
echo "✅ HTTP Proxy đã sẵn sàng!"
echo "➡️  Proxy: http://$USERNAME:$PASSWORD@$IP:$PORT"
