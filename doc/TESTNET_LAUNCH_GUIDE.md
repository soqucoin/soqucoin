# Testnet Launch Guide

**Status**: CI Green ✅ | Ready for Deployment  
**Updated**: 2025-12-15

---

## Quick Start

### Option A: Docker (Recommended)

```bash
# 1. Build containers
cd docker
docker compose build

# 2. Start testnet
docker compose up -d

# 3. Verify
docker compose logs -f soqucoind
curl localhost:18332/rest/chaininfo.json
```

### Option B: Native Build

```bash
# 1. Build
./autogen.sh
./configure --without-gui --enable-experimental
make -j$(nproc)

# 2. Start testnet
./src/soqucoind -testnet -daemon

# 3. Verify
./src/soqucoin-cli -testnet getblockchaininfo
```

---

## ASIC Mining (L7 Antminer)

1. **Start Stratum Bridge**:
   - Docker: Included in `docker compose up`
   - Native: `python3 stratum_bridge.py`

2. **Configure L7**:
   - URL: `stratum+tcp://YOUR_IP:3333`
   - Worker: `testnet`
   - Password: `x`

3. **Verify Mining**:
   ```bash
   ./src/soqucoin-cli -testnet getmininginfo
   ```

---

## Network Configuration

### Isolated Testnet (Solo Mining)
```ini
# soqucoin.conf
testnet=1
server=1
connect=0  # No peers
rpcuser=soqu
rpcpassword=YOUR_PASSWORD
```

### Multi-Node Testnet
```ini
# Node 1 (Mining Node)
testnet=1
server=1
listen=1
rpcuser=soqu
rpcpassword=YOUR_PASSWORD

# Node 2 (Sync Node)
testnet=1
connect=NODE1_IP
rpcuser=soqu
rpcpassword=YOUR_PASSWORD
```

---

## Testnet Validation Checklist

- [ ] Node starts and syncs
- [ ] Stratum bridge connects
- [ ] L7 ASIC mines blocks
- [ ] Dilithium transactions send/receive
- [ ] Multi-node synchronization
- [ ] 24+ hour stability

---

## Technical Debt

See [TESTNET_TECHNICAL_DEBT.md](TESTNET_TECHNICAL_DEBT.md) for:
- CI items skipped for testnet
- Consensus hacks to revert for mainnet
- Pre-mainnet requirements

---

## Ports

| Port | Purpose | Testnet |
|------|---------|---------|
| 18333 | P2P | ✅ |
| 18332 | RPC | ✅ |
| 3333 | Stratum | ✅ |

---

## Troubleshooting

### "No peers" warning
Expected in isolated mode. Use `connect=0` intentionally.

### RPC connection refused
Check `rpcbind=127.0.0.1` and `rpcallowip` settings.

### L7 not connecting
Verify stratum bridge is running on port 3333.
