# VPS Testnet Deployment Guide

**Target**: `testnet.soqu.org:3333`  
**Node**: Dedicated VPS with soqucoind + stratum bridge  
**Updated**: 2025-12-15

---

## Pre-Migration Checklist

> [!IMPORTANT]
> These items should be verified before VPS deployment:

| Item | Status | Notes |
|------|--------|-------|
| CI passing | ✅ Green | All 11 checks pass |
| Docker infrastructure | ✅ Ready | Dockerfiles + compose in `docker/` |
| Testnet config | ✅ Ready | `docker/soqucoin.conf` |
| Stratum bridge | ✅ Ready | Dockerfile.bridge |
| DNS control | ⏳ Pending | Need access to `testnet.soqu.org` |

**Technical debt items that do NOT block VPS deployment:**
- RPC test skips (CI-only)
- Native CI smoke tests (CI-only)  
- CMake migration (post-mainnet)
- Pre-built binaries (post-testnet)

---

## VPS Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk | 50 GB SSD | 100 GB NVMe |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |

### Recommended Providers

| Provider | Plan | Price | Notes |
|----------|------|-------|-------|
| **Hetzner** | CX31 | ~€10/mo | Best value, German DC |
| **DigitalOcean** | Droplet 4GB | ~$24/mo | Simple UI |
| **Vultr** | VC2 4GB | ~$24/mo | Global locations |
| **AWS** | t3.medium | ~$30/mo | Enterprise grade |

---

## Step-by-Step VPS Setup

### Step 1: Provision VPS

1. Create Ubuntu 22.04 LTS server
2. Add your SSH public key during creation
3. Note the IP address

### Step 2: Initial Server Security

SSH into the VPS:
```bash
ssh root@YOUR_VPS_IP
```

Run these commands:
```bash
# Update system
apt update && apt upgrade -y

# Install essential tools
apt install -y git curl ufw fail2ban

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 18333/tcp comment 'Soqucoin P2P Testnet'
ufw allow 3333/tcp comment 'Stratum'
ufw enable

# Configure fail2ban
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
```

### Step 3: Install Docker

```bash
# Add Docker repository
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

### Step 4: Deploy Soqucoin

```bash
# Clone repository
git clone https://github.com/soqucoin/soqucoin.git /opt/soqucoin
cd /opt/soqucoin

# Update RPC password (IMPORTANT!)
nano docker/soqucoin.conf
# Change: rpcpassword=YOUR_SECURE_PASSWORD

# Build and start containers
cd docker
docker compose up -d --build

# Check logs
docker compose logs -f
```

### Step 5: Verify Deployment

```bash
# Check containers are running
docker compose ps

# Check node status
docker exec soqucoind soqucoin-cli -testnet getblockchaininfo

# Check stratum port
nc -zv localhost 3333
```

### Step 6: Configure DNS

Update DNS for `testnet.soqu.org`:
- Type: A
- Name: testnet
- Value: YOUR_VPS_IP
- TTL: 300 (for quick changes during testing)

---

## Connect L7 ASIC

Once DNS propagates:

1. **L7 Configuration**:
   - Pool URL: `stratum+tcp://testnet.soqu.org:3333`
   - Worker: `l7_testnet`
   - Password: `x`

2. **Verify Blocks**:
   ```bash
   docker exec soqucoind soqucoin-cli -testnet getblockcount
   ```

---

## Monitoring

### Basic Health Checks

```bash
# Node health
docker exec soqucoind soqucoin-cli -testnet getnetworkinfo

# Container status
docker compose ps

# Logs
docker compose logs --tail=100
```

### Recommended: Set up auto-restart check

```bash
# Add cron job to verify containers
(crontab -l 2>/dev/null; echo "*/5 * * * * cd /opt/soqucoin/docker && docker compose ps | grep -q 'Up' || docker compose up -d") | crontab -
```

---

## Troubleshooting

### Container won't start
```bash
docker compose logs soqucoind
# Check for config or permission errors
```

### L7 not connecting
```bash
# Verify stratum port is open
nc -zv YOUR_VPS_IP 3333

# Check firewall
ufw status
```

### Node not syncing
```bash
# Check peer connections
docker exec soqucoind soqucoin-cli -testnet getpeerinfo
```

---

## Security Reminders

- [ ] Change default RPC password in `soqucoin.conf`
- [ ] Never expose RPC port (18332) publicly
- [ ] Keep SSH key private
- [ ] Regularly update: `apt update && apt upgrade -y`
- [ ] Monitor logs for unusual activity
