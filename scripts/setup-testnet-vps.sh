#!/bin/bash
# Soqucoin Testnet VPS Setup Script
# Run this on a fresh Ubuntu 22.04 droplet
# Usage: curl -sSL https://raw.githubusercontent.com/soqucoin/soqucoin/soqucoin-genesis/scripts/setup-testnet-vps.sh | bash

set -e

echo "=========================================="
echo "  Soqucoin Testnet VPS Setup"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Variables
SOQUCOIN_DIR="/opt/soqucoin"
RPC_PASSWORD=$(openssl rand -hex 16)

echo "[1/6] Updating system..."
apt-get update && apt-get upgrade -y

echo "[2/6] Installing dependencies..."
apt-get install -y git curl ufw fail2ban ca-certificates gnupg

echo "[3/6] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 18333/tcp comment 'Soqucoin P2P Testnet'
ufw allow 3333/tcp comment 'Stratum'
echo "y" | ufw enable

echo "[4/6] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
systemctl enable fail2ban && systemctl start fail2ban

echo "[5/6] Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

echo "[6/6] Deploying Soqucoin..."
git clone https://github.com/soqucoin/soqucoin.git "$SOQUCOIN_DIR"
cd "$SOQUCOIN_DIR/docker"

# Set a random RPC password
sed -i "s/change_this_password_in_production/$RPC_PASSWORD/g" soqucoin.conf

# Build and start
docker compose up -d --build

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "RPC Password: $RPC_PASSWORD"
echo "(Save this - you'll need it for RPC access)"
echo ""
echo "Check status: docker compose -f $SOQUCOIN_DIR/docker/docker-compose.yml ps"
echo "View logs:    docker compose -f $SOQUCOIN_DIR/docker/docker-compose.yml logs -f"
echo ""
echo "Stratum URL:  stratum+tcp://$(curl -s ifconfig.me):3333"
echo ""
echo "Next: Update DNS for testnet.soqu.org to point to this IP"
echo ""
