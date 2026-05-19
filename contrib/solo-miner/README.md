# Soqucoin Solo Miner

A lightweight stratum proxy that connects to your local `soqucoind` node and lets you mine blocks directly — **all rewards go to your address**.

No database, no pool fees, no centralized infrastructure.

## Quick Start

### 1. Start your Soqucoin node

```bash
soqucoind -stagenet -daemon -server -rpcuser=soqucoin -rpcpassword=YOUR_PASSWORD -zmqpubhashblock=tcp://127.0.0.1:28334
```

### 2. Configure the solo miner

Copy `config.example.json` to `config.json` and edit:
- `rpc_password` — your soqucoind RPC password
- `reward_to` — your Soqucoin address (where block rewards go)

```bash
cp config.example.json config.json
nano config.json
```

### 3. Run the solo miner

```bash
./soq-solo-miner config.json
```

### 4. Point your miners

Connect your mining hardware to:
```
stratum+tcp://YOUR_IP:3333
```

Worker name format: `YOUR_ADDRESS.rigname`

## Configuration

| Field | Description |
|-------|-------------|
| `port` | Stratum port (default: 3333) |
| `pool_difficulty` | Share difficulty (adjust for your hashrate) |
| `rpc_url` | soqucoind RPC endpoint |
| `rpc_password` | soqucoind RPC password |
| `reward_to` | Your Soqucoin address |
| `block_notify_url` | ZMQ notification endpoint (must match soqucoind -zmqpubhashblock — use a different port than RPC) |

## Difficulty Guide

| Hashrate | Recommended `pool_difficulty` |
|----------|------------------------------|
| < 1 GH/s | 10000 |
| 1-10 GH/s | 50000 |
| 10-100 GH/s | 100000 |
| 100+ GH/s | 500000 |

## Found Blocks

When you find a block, it's automatically submitted to the network via your node. Found blocks are logged to:
- **Console** — immediate notification
- **found_blocks.json** — persistent log in the working directory

## Building from Source

Requires Go 1.23+:

```bash
cd contrib/solo-miner
go build -o soq-solo-miner .
```

Cross-compile for Linux:
```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o soq-solo-miner-linux-x64 .
```

## License

Same as Soqucoin Core — MIT License.
