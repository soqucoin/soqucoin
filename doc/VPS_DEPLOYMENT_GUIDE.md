# VPS Testnet Deployment Guide

**Target**: `testnet.soqu.org:3333`  
**Node**: Dedicated VPS with soqucoind + stratum bridge  
**Provider**: DigitalOcean  
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

---

## DigitalOcean Droplet Setup

### Recommended Droplet Specifications

| Use Case | Droplet Type | vCPUs | RAM | Disk | Price |
|----------|--------------|-------|-----|------|-------|
| **Testnet (Recommended)** | Basic Regular | 2 | 4 GB | 80 GB SSD | $24/mo |
| Testnet + Heavy Mining | Basic Regular | 4 | 8 GB | 160 GB SSD | $48/mo |
| Mainnet Production | Premium Intel | 4 | 8 GB | 160 GB NVMe | $84/mo |

> [!TIP]
> Start with the **4GB / 2 vCPU** droplet for testnet. You can resize later if needed.

### Step 1: Create Droplet

1. **Log in** to [cloud.digitalocean.com](https://cloud.digitalocean.com)

2. **Click "Create" → "Droplets"**

3. **Choose Region**: 
   - Recommended: **San Francisco** (SFO3) or **New York** (NYC3)
   - Choose closest to your L7 ASIC for lowest latency

4. **Choose Image**:
   - **Ubuntu 22.04 (LTS) x64** ← Select this

5. **Choose Size**:
   - Click **"Basic"**
   - Select **"Regular"** (not Premium)
   - Choose **$24/mo - 4 GB RAM / 2 CPUs / 80 GB SSD**

6. **Choose Authentication**:
   - Select **"SSH keys"** (strongly recommended)
   - Click **"New SSH Key"** if you don't have one added
   - Paste your public key (from `~/.ssh/id_rsa.pub` or similar)

7. **Additional Options** (Optional but recommended):
   - ✅ **Enable Monitoring** (free resource graphs)
   - ✅ **Enable Backups** (+$4.80/mo, weekly snapshots)

8. **Hostname**: 
   - Enter: `soqucoin-testnet`

9. **Click "Create Droplet"**

10. **Copy the IP address** once created

### Step 2: Add SSH Key (If Needed)

If you don't have an SSH key yet, create one on your Mac:

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "soqucoin-testnet" -f ~/.ssh/soqucoin_do

# Copy public key to clipboard
cat ~/.ssh/soqucoin_do.pub | pbcopy

# Paste this in DigitalOcean's "New SSH Key" dialog
```

### Step 3: Connect to Droplet

```bash
# Connect using your key
ssh -i ~/.ssh/soqucoin_do root@YOUR_DROPLET_IP

# Or if using default key
ssh root@YOUR_DROPLET_IP
```

---

## Server Configuration

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

---

## Automated Setup (One-Command)

After creating your droplet, you can run everything with a single command:

```bash
# SSH into your new droplet
ssh root@YOUR_DROPLET_IP

# Run automated setup script
curl -sSL https://raw.githubusercontent.com/soqucoin/soqucoin/soqucoin-genesis/scripts/setup-testnet-vps.sh | bash
```

This script automatically:
1. ✅ Updates the system
2. ✅ Configures UFW firewall
3. ✅ Installs fail2ban
4. ✅ Installs Docker
5. ✅ Clones the repository
6. ✅ Generates a secure RPC password
7. ✅ Builds and starts containers

**Script location**: `scripts/setup-testnet-vps.sh`

---

## Mainnet Scaling

When ready for mainnet, resize to **Premium Intel 4GB/8GB droplet**:

1. Power off droplet
2. Go to Droplet → Resize
3. Select new size
4. Power on

Or use DigitalOcean's **Kubernetes** for high-availability.
