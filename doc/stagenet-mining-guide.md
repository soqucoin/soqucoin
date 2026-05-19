# Soqucoin Stagenet Mining Guide

> **Network**: Stagenet (pre-mainnet testing environment)  
> **Algorithm**: Scrypt (Litecoin/Dogecoin compatible — AuxPoW merge-mining ready)  
> **Block time**: ~60 seconds  
> **Initial reward**: 500,000 SOQ/block (halving every 100,000 blocks)  
> **Pool**: `stratum+tcp://64.23.197.144:3333`  
> **Explorer**: Coming soon

---

## Quick Start

### 1. Point Your Miner at the Pool

The Soqucoin Stagenet pool runs a production-grade Stratum server. Any Scrypt-capable
ASIC or GPU miner can connect.

**Pool address**: `stratum+tcp://64.23.197.144:3333`

| Setting | Value |
|---------|-------|
| Algorithm | Scrypt |
| URL | `stratum+tcp://64.23.197.144:3333` |
| Worker | `<your_stagenet_address>.worker_name` |
| Password | `x` |

### 2. Get a Stagenet Address

To receive mining rewards, you need a Soqucoin stagenet address.

**Option A: Build from source** (see [BUILDING.md](../BUILDING.md))

```bash
# After building, generate a new address:
soqucoin-cli -stagenet getnewaddress "" bech32m
# Returns: ssq1p... (bech32m stagenet address)
```

**Option B: Use the Foundation pool address (testing only)**

If you just want to test connectivity, you can mine to the Foundation's
pool address. You won't receive the coins, but you can verify your
hardware works:

```
ssq1p23ssp9dsfcxzn33msmfzsk723rg24h9j8lrdn4qtaezcztjemd3smejtp7
```

### 3. Configure Your Miner

#### Bitmain Antminer L7 / L9

```
Pool 1 URL:      stratum+tcp://64.23.197.144:3333
Pool 1 Worker:   <your_address>.L7
Pool 1 Password: x
```

#### Goldshell Mini-DOGE / LT6

```
Pool 1 URL:      stratum+tcp://64.23.197.144:3333
Pool 1 Worker:   <your_address>.goldshell
Pool 1 Password: x
```

#### cgminer / bfgminer (GPU/CPU)

```bash
cgminer --scrypt -o stratum+tcp://64.23.197.144:3333 \
  -u <your_address>.gpu -p x
```

#### cpuminer (testing only — very slow)

```bash
minerd --algo=scrypt -o stratum+tcp://64.23.197.144:3333 \
  -u <your_address>.cpu -p x
```

---

## Running Your Own Stagenet Node

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4 GB |
| Disk | 10 GB SSD | 50 GB SSD |
| OS | Ubuntu 22.04+ / macOS 13+ | Ubuntu 24.04 LTS |
| Network | 10 Mbps | 100 Mbps |

### Build from Source

```bash
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin

# Install dependencies (Ubuntu)
sudo apt-get update
sudo apt-get install -y build-essential libtool autotools-dev automake \
  pkg-config bsdmainutils python3 libssl-dev libevent-dev libboost-all-dev \
  libdb-dev libdb++-dev libminiupnpc-dev libzmq3-dev

# Build
./autogen.sh
./configure --with-incompatible-bdb
make -j$(nproc)

# Install (optional)
sudo make install
```

### Configure

Create `~/.soqucoin/soqucoin.conf`:

```ini
# Soqucoin Stagenet Node Configuration
stagenet=1

# Network
port=28333
listen=1

# RPC (for local CLI access)
server=1
rpcuser=soqucoin
rpcpassword=<choose_a_strong_password>
rpcallowip=127.0.0.1

# ZMQ notifications (required for soq-solo-miner)
zmqpubhashblock=tcp://127.0.0.1:28334

# Seed nodes (Foundation-operated)
addnode=64.23.197.144:28333
addnode=143.110.229.69:28333

# Performance
dbcache=512
maxconnections=32
```

### Start the Node

```bash
soqucoind -daemon
# Check status:
soqucoin-cli -stagenet getblockchaininfo
# Check peers:
soqucoin-cli -stagenet getpeerinfo
```

### Solo Mining (without pool)

If you prefer to mine directly to your node (no pool), use the bundled
**soq-solo-miner** stratum proxy in `contrib/solo-miner/`:

```bash
# 1. Configure the solo miner
cd contrib/solo-miner
cp config.example.json config.json
# Edit config.json: set rpc_password and reward_to address

# 2. Start the solo miner
./soq-solo-miner-macos-arm64 config.json   # macOS
./soq-solo-miner-linux-x64 config.json     # Linux

# 3. Point your ASIC at stratum+tcp://localhost:3333
```

For CPU testing (very slow, development only):

```bash
soqucoin-cli -stagenet generatetoaddress 1 <your_address>
```

---

## Pool Architecture

The Soqucoin Stagenet Pool is a production-grade Go stratum server with:

- **Stratum v1** protocol (compatible with all Scrypt ASIC miners)
- **PPLNS** payout scheme (Pay Per Last N Shares)
- **PostgreSQL** backend for share persistence
- **AuxPoW** support (future: merged mining with Litecoin/Dogecoin parent chains)
- **API** on port 8080 for stats (coming soon)

### Pool Fee

**0%** — The stagenet pool operates at zero fee. This is a testing environment.

### Payouts

Payouts are processed every 10 minutes via PPLNS. Minimum payout: 1 SOQ.

---

## Network Details

| Parameter | Value |
|-----------|-------|
| Chain ID | `stagenet` |
| P2P Port | 28333 |
| RPC Port | 28332 |
| Address Prefix | `ssq1p...` (bech32m, Taproot) |
| PoW Algorithm | Scrypt |
| AuxPoW | Enabled (merge-mining ready) |
| Block Time | ~60 seconds |
| Initial Subsidy | 500,000 SOQ |
| Halving Interval | 100,000 blocks |
| Consensus Features | Dilithium signatures, USDSOQ opcodes, Lattice-BP++ privacy (BIP9-gated) |

### Seed Nodes

| Node | IP | Port | Role |
|------|----|------|------|
| Mining VPS | 64.23.197.144 | 28333 | Pool + Mining node |
| Services VPS | 143.110.229.69 | 28333 | Full validation node |

---

## Troubleshooting

### Miner shows "connection refused"
- Verify the pool is running: `nc -zv 64.23.197.144 3333`
- Check firewall: port 3333 must be open on your network

### Miner shows "unauthorized"
- Use format: `<address>.worker` for username
- Password can be anything (use `x`)

### Node won't sync
- Check seed nodes are reachable: `nc -zv 64.23.197.144 28333`
- Verify `stagenet=1` is in your config
- Try adding nodes manually: `soqucoin-cli -stagenet addnode 64.23.197.144:28333 add`

### Node crashes on startup
- Ensure at least 2 GB RAM available
- Check disk space: blockchain grows ~1 MB/day on stagenet
- Review `~/.soqucoin/stagenet/debug.log` for errors

---

## Important Notes

> **⚠️ Stagenet SOQ has no monetary value.** This is a testing network. Stagenet
> may be wiped (chain reset) at any time during development. Do not use stagenet
> for anything other than testing.

> **🛡️ Post-Quantum Security**: Stagenet runs the same consensus code as mainnet
> will at launch. Dilithium (ML-DSA-44) signatures, USDSOQ stablecoin opcodes,
> and Lattice-BP++ privacy primitives are all active and available for testing.

---

## Getting Help

- **Discord**: [Soqucoin Community](https://discord.gg/soqucoin)
- **GitHub Issues**: [soqucoin/soqucoin](https://github.com/soqucoin/soqucoin/issues)
- **Website**: [soqu.org](https://soqu.org)
