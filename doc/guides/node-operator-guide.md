# Soqucoin Node Operator Guide

> **Version**: 2.0 | **Updated**: 2026-01-02
> **Network**: Testnet3 (Mainnet Q1 2026)
> **Consensus**: Scrypt PoW + AuxPoW

---

## Overview

This guide covers setting up and operating a Soqucoin full node. A full node validates all transactions and blocks, contributes to network decentralization, and is required for mining, running a pool, or operating services.

---

## 1. System Requirements

### Minimum Requirements

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| **CPU** | 2 cores | 4+ cores | Modern x86_64 or ARM64 |
| **RAM** | 4 GB | 8+ GB | More for higher RPC load |
| **Storage** | 50 GB | 200 GB SSD | NVMe preferred |
| **Network** | 10 Mbps | 100+ Mbps | Static IP for public nodes |
| **OS** | Ubuntu 22.04 | Ubuntu 24.04 LTS | Also: Debian 12, macOS 14+ |

### Raspberry Pi Considerations

Soqucoin can run on a Raspberry Pi 4 (8GB model) but with reduced performance:
- Initial sync: ~24-48 hours (vs ~1 hour on VPS)
- Block validation: ~2-3x slower
- Recommended: Use SSD over microSD card

---

## 2. Installation

### Option A: Build from Source (Recommended)

#### Prerequisites (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 libevent-dev libboost-system-dev libboost-filesystem-dev \
    libboost-test-dev libboost-thread-dev libdb++-dev libminiupnpc-dev \
    libzmq3-dev libssl-dev git
```

#### Build

```bash
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin
./autogen.sh
./configure --with-gui=no    # Remove flag if you want Qt wallet
make -j$(nproc)
sudo make install
```

### Option B: macOS

```bash
# Install Homebrew dependencies
brew install automake berkeley-db@4 boost openssl libevent miniupnpc protobuf qt zeromq

# Build
./autogen.sh
./configure --with-gui=no
make -j$(sysctl -n hw.logicalcpu)
```

---

## 3. Configuration

### Data Directory Locations

| OS | Default Path |
|----|--------------|
| Linux | `~/.soqucoin/` |
| macOS | `~/Library/Application Support/Soqucoin/` |
| Windows | `%APPDATA%\Soqucoin\` |

### Configuration File (`soqucoin.conf`)

Create `~/.soqucoin/soqucoin.conf`:

```ini
# ===================
# NETWORK
# ===================
# For testnet (remove for mainnet)
testnet=1

# Accept incoming connections
listen=1
server=1

# For public node (seed node), allow external connections
# For private node, set listen=0
maxconnections=125

# ===================
# RPC (Required for mining/services)
# ===================
rpcuser=soqurpc
rpcpassword=CHANGE_THIS_TO_SECURE_RANDOM_STRING
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
rpcport=44555

# High-performance settings (for mining pools)
rpcworkqueue=128
rpcthreads=8

# ===================
# AUXPOW / MERGED MINING
# ===================
# Allow both native Scrypt and AuxPoW blocks
fAllowLegacyBlocks=true

# ===================
# PERFORMANCE
# ===================
# Database cache (MB) - increase for faster sync
dbcache=512

# Prune blockchain to save disk (MB, 0=no prune)
# prune=5000

# Disable transaction index (saves disk)
# txindex=0
```

---

## 4. Running the Node

### Manual Start

```bash
# Start in background
soqucoind -daemon

# Check status
soqucoin-cli getblockchaininfo

# Stop gracefully
soqucoin-cli stop
```

### systemd Service (Production)

Create `/etc/systemd/system/soqucoind.service`:

```ini
[Unit]
Description=Soqucoin Full Node
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=soqucoin
Group=soqucoin

# Adjust paths as needed
ExecStart=/usr/local/bin/soqucoind -daemon -conf=/home/soqucoin/.soqucoin/soqucoin.conf -pid=/run/soqucoin/soqucoind.pid
ExecStop=/usr/local/bin/soqucoin-cli stop

# Restart on crash
Restart=always
RestartSec=10
StartLimitIntervalSec=0

# Runtime directory
RuntimeDirectory=soqucoin

# Security hardening
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable soqucoind
sudo systemctl start soqucoind
```

Check status:

```bash
sudo systemctl status soqucoind
journalctl -u soqucoind -f
```

---

## 5. Initial Sync

### Expected Sync Times

| Network | Blocks | Time (VPS) | Time (Pi 4) |
|---------|--------|------------|-------------|
| Testnet3 | ~1,500 | <5 min | ~30 min |
| Mainnet | TBD | TBD | TBD |

### Monitoring Sync Progress

```bash
# Check current height
soqucoin-cli getblockcount

# Check sync status
soqucoin-cli getblockchaininfo | jq '.verificationprogress'

# Watch debug log
tail -f ~/.soqucoin/testnet3/debug.log
```

---

## 6. Network Ports

### Mainnet

| Port | Protocol | Purpose | Public? |
|------|----------|---------|---------|
| 33388 | TCP | P2P connections | ✅ Yes (for public nodes) |
| 33389 | TCP | RPC interface | ❌ No (localhost only) |

### Testnet

| Port | Protocol | Purpose | Public? |
|------|----------|---------|---------|
| 44556 | TCP | Testnet P2P | ✅ Yes (for testnet nodes) |
| 44555 | TCP | Testnet RPC | ❌ No (localhost only) |

### Firewall Configuration (UFW)

**For Mainnet:**
```bash
sudo ufw allow 33388/tcp comment 'Soqucoin Mainnet P2P'
```

**For Testnet:**
```bash
sudo ufw allow 44556/tcp comment 'Soqucoin Testnet P2P'
```

> ⚠️ **Never expose RPC ports (33389/44555) to the public internet.**

```bash
# Enable firewall
sudo ufw enable
```

---

## 7. Monitoring and Maintenance

### Useful CLI Commands

```bash
# Network info
soqucoin-cli getnetworkinfo

# Peer connections
soqucoin-cli getpeerinfo | jq '.[].addr'

# Mempool status
soqucoin-cli getmempoolinfo

# Node uptime
soqucoin-cli uptime

# Current best block
soqucoin-cli getbestblockhash
```

### Prometheus Integration

Use `node_exporter` and custom RPC scraping for production monitoring:

```bash
# Check metrics
curl -s http://localhost:9100/metrics | grep node_cpu
```

### Log Rotation

Add to `/etc/logrotate.d/soqucoin`:

```
/home/soqucoin/.soqucoin/testnet3/debug.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
}
```

---

## 8. Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Cannot connect to server" | Node not running | Start with `soqucoind -daemon` |
| "Loading block index" | Node starting up | Wait for initialization |
| "Reorganizing blockchain" | Reorg in progress | Wait for completion |
| "AddToWallet called for" | Wallet processing | Normal during sync |
| "prev block not found" | Stale peer data | Delete `peers.dat`, restart |

### Diagnostic Steps

```bash
# 1. Check if process is running
pgrep -a soqucoind

# 2. Check RPC connectivity
soqucoin-cli getblockchaininfo

# 3. Check disk space
df -h ~/.soqucoin

# 4. Check memory
free -h

# 5. Check logs for errors
grep -i error ~/.soqucoin/testnet3/debug.log | tail -20
```

### Reset Blockchain (Last Resort)

```bash
# Stop node
soqucoin-cli stop

# Remove chain data (keeps wallet!)
rm -rf ~/.soqucoin/testnet3/blocks
rm -rf ~/.soqucoin/testnet3/chainstate

# Remove stale peer data
rm ~/.soqucoin/testnet3/peers.dat

# Restart
soqucoind -daemon
```

---

## 9. Security Best Practices

1. **Use dedicated user account**: Run `soqucoind` as non-root user
2. **Firewall**: Only expose P2P port, never RPC
3. **Strong RPC password**: Use 32+ character random string
4. **Regular updates**: Monitor GitHub for security releases
5. **Backup wallet**: Keep encrypted `wallet.dat` backup offline
6. **SSH hardening**: Disable password auth, use key-based SSH

---

## 10. Resources

- **Website**: https://soqu.org
- **GitHub**: https://github.com/soqucoin/soqucoin
- **Whitepaper**: https://soqu.org/whitepaper.html
- **Mining Guide**: [See mining-guide.md](mining-guide.md)
- **API Reference**: [See api-reference.md](api-reference.md)

---

*Last Updated: 2026-01-02*
*Prepared for Soqucoin Testnet3 / Mainnet Launch*
