# Running a Soqucoin node

Mainnet has run since **13 October 2026**. Running your own node takes four steps, from the download to the check that you're on the real chain. If you've never run a node before, start at the top and go in order.

You don't need a node to mine on SOQUPOOL or to hold SOQ in SoquShield. You run one to check the chain yourself instead of relying on anyone else's copy. We'd like a lot of you to do exactly that.

## Before anything else: stay safe

New chains attract scammers. Most of what goes wrong for new operators is somebody offering "help".

- Download only from the [GitHub releases page](https://github.com/soqucoin/soqucoin/releases), and check the checksum (step 1 shows how).
- Nobody on our team will DM you a download link, a config file or a list of peers. If someone does, it's a scam.
- Don't add `addnode=` or `connect=` lines that anyone gives you. Your node finds the network on its own through the seeds built into it. A stranger's peer list is the easiest way to get you onto a fake chain.
- Never share a seed phrase or a `wallet.dat` file with anyone, for any reason.

Our official channels are X [@soqucoin](https://x.com/soqucoin), Telegram [t.me/officialsoqucoin](https://t.me/officialsoqucoin) and this page.

## What you need

| Your computer | What to download |
|---|---|
| 64-bit Linux, x64 or ARM64: Ubuntu 22.04 or newer, Debian 12 or newer, Fedora, Raspberry Pi OS (Trixie) | The ready-made Linux build |
| An older Linux | Build from source ([see below](#building-from-source)) |
| macOS 15 (Sequoia) or newer, Apple silicon or Intel | The ready-made macOS build |
| 64-bit Windows | The ready-made Windows build |

The chain started on 13 October 2026 and is still small, so it won't use much for a long time. Our own stagenet nodes run in about 120 MB of memory. A machine with 2 GB of RAM and 20 GB of free disk has plenty of room, and that includes a small cloud server.

The current release is **2.6.1**. It schedules one consensus rule: from mainnet block **67,000**, expected about 26 November 2026, every block must carry the chain id `0x5351` in its version. Every block since block 1 already carries it, so nothing changes for a miner on a current node's templates. Every node operator must move to 2.6.0 or later before block 67,000: a node still on 2.5.x at that height would follow a block the network refuses if one appeared. Mainnet needs 2.5.1 or newer to start at all: block 1 carries the genesis migration, and only those releases know the rule for it, so an older release rejects block 1 and stops there.

## Step 1: Download and check it

### Linux

On an ARM64 machine, swap `linux-x64` for `linux-arm64` everywhere it appears below.

```bash
mkdir -p ~/soqucoin && cd ~/soqucoin
curl -LO https://github.com/soqucoin/soqucoin/releases/download/v2.6.1/soqucoin-v2.6.1-linux-x64.tar.gz
curl -LO https://github.com/soqucoin/soqucoin/releases/download/v2.6.1/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Look for `soqucoin-v2.6.1-linux-x64.tar.gz: OK`. Anything else means a bad download: delete the file and download it again. Don't run it.

Then unpack it. It needs no extra libraries.

```bash
tar xzf soqucoin-v2.6.1-linux-x64.tar.gz
```

That leaves two programs in `~/soqucoin`: `soqucoind` (the node) and `soqucoin-cli` (the tool you use to talk to it).

### macOS

On an Intel Mac, swap `macos-arm64` for `macos-x64` in both places.

```bash
mkdir -p ~/soqucoin && cd ~/soqucoin
curl -LO https://github.com/soqucoin/soqucoin/releases/download/v2.6.1/soqucoin-v2.6.1-macos-arm64.tar.gz
curl -LO https://github.com/soqucoin/soqucoin/releases/download/v2.6.1/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS
tar xzf soqucoin-v2.6.1-macos-arm64.tar.gz
```

Same check: look for `OK`. If you downloaded with a browser instead of `curl`, macOS will block the programs because they aren't notarized by Apple. Clear that with:

```bash
xattr -d com.apple.quarantine soqucoind soqucoin-cli
```

### Windows

Download `soqucoin-v2.6.1-windows-x64.zip` and `SHA256SUMS` from the [release page](https://github.com/soqucoin/soqucoin/releases/tag/v2.6.1). In PowerShell, in the folder you saved them to:

```powershell
Get-FileHash .\soqucoin-v2.6.1-windows-x64.zip
Select-String windows SHA256SUMS
```

The two long hashes have to match (PowerShell prints its hash in capitals; that's fine). Unzip it to a folder such as `C:\soqucoin`. In the steps below, use `.\soqucoind.exe` and `.\soqucoin-cli.exe` from that folder in place of `./soqucoind` and `./soqucoin-cli`, and run the node in its own window without `-daemon`.

## Step 2: Start it

No config file is needed. From the folder with the programs:

```bash
./soqucoind -daemon
```

Give it about ten seconds, then:

```bash
./soqucoin-cli getblockchaininfo
```

To stop it later: `./soqucoin-cli stop`.

Check you're running the right release:

```bash
./soqucoind -version
```

It should print `Soqucoin Core Daemon version v2.6.1.0-` followed by the release commit (or just `v2.6.1` if you built it yourself).

Then check that it carries the activation height:

```bash
./soqucoin-cli getblockchaininfo | grep chainid_required_height
```

It should show `"chainid_required_height": 67000` on the line it prints. A node built from the development branch before the 2.6.0 tag prints nothing here and reports version 2.5.3, even when its blocks carry the 2.6.0 release mark: rebuild it from the `v2.6.0` tag, or install the release build.

The node keeps its data and its log (`debug.log`) here:

| System | Data folder |
|---|---|
| Linux | `~/.soqucoin` |
| macOS | `~/Library/Application Support/Soqucoin` |
| Windows | `%APPDATA%\Soqucoin` |

Two things catch people who've run a node before:

- **You ran stagenet.** If `soqucoin.conf` in the data folder has a `stagenet=1` line, your node is on stagenet. `getblockchaininfo` tells you which one: `"chain": "main"` is mainnet and `"chain": "stagenet"` is stagenet. Delete that line and restart.
- **You ran a mainnet node with 2.5.0 or older.** Stop it, rename the data folder (for example to `Soqucoin.old`) and start 2.6.1 fresh. Renaming instead of deleting keeps any wallet that was in it.

## Step 3: What normal looks like

Two commands tell you everything:

```bash
./soqucoin-cli getblockcount
./soqucoin-cli getconnectioncount
```

| When | Blocks | Connections | What it means |
|---|---|---|---|
| Just started | 0 | 0 | Give it a few minutes to find peers |
| Syncing | climbing | more than 0 | Your node is catching up |
| Caught up | about one new block a minute | more than 0 | Done. Now check the hashes (step 4) |

A node that still shows 0 and 0 after ten minutes isn't finding peers. Check that the machine is online and that you run release 2.5.1 or newer. A synced node rejects a block that builds on a fork 288 blocks deep or more, with one exception: a competing chain whose headers it accepted while it was still syncing. A node downloading the chain for the first time doesn't have the protection yet. Both are why step 4 has you check two hashes.

Opening port 33388 on your router or firewall is optional. Your node syncs fine without it. Opening it lets other nodes connect to yours.

## Step 4: Check you're on the real chain

A node syncing for the first time has nothing of its own to compare against. So we publish two block hashes here: block 1, and block 1,502, the height at which the network opened to outside nodes on 14 October 2026. Check yours against both:

```bash
./soqucoin-cli getblockhash 1
./soqucoin-cli getblockhash 1502
```

| Block | Hash |
|---|---|
| 1 | `0f810805571d662db8146f869b3dc6b9fa9212a4cc3c3b11f18f03b856cffee1` |
| 1,502 | `e8820618a5fe88a67681873ba3d3dcf5143d28e3aadb2bde04f60187ec21ec56` |

The block explorer at [explorer.soqu.org](https://explorer.soqu.org) shows the same two blocks; this page and the explorer should agree. If they don't, trust neither and ask in the Telegram channel.

If either hash doesn't match, your node is on the wrong chain. Stop it, and don't send or accept anything with it. Syncing again from scratch won't fix it by itself, because the node can pick up the same wrong chain from the same peers. Check the release page and our official channels for recovery steps (usually a new release with a checkpoint for the right chain) and follow those.

## Building from source

Use this on a Linux release before Ubuntu 22.04 or Debian 12, or to build the programs yourself. These steps are for Ubuntu 24.04:

```bash
sudo apt update
sudo apt install git build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 \
  libssl-dev libevent-dev libboost-all-dev libminiupnpc-dev libzmq3-dev libsqlite3-dev libdb++-dev
git clone --depth 1 --branch v2.6.1 https://github.com/soqucoin/soqucoin.git
cd soqucoin
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j"$(nproc)"
```

The build took under three minutes on 8 cores in our test. A smaller machine takes longer, and if it has less than 4 GB of memory, use `make -j1` so the build doesn't run out of memory. The programs end up in `src/`, so run `src/soqucoind -daemon` and `src/soqucoin-cli ...` from the `soqucoin` folder, then carry on from step 2.

## Mining

SOQ is mined at SOQUPOOL ([soqupool.com](https://soqupool.com)) and at other pools that merge-mine it. If you run a pool, [pool-integration.md](pool-integration.md) is where adding SOQ starts.

Your node doesn't need mining turned on. On a regular node, `getblocktemplate` returns an error. That's on purpose.

## The wallet

The node's built-in wallet works on mainnet and stagenet. If you only need to validate and relay blocks, add `disablewallet=1` to `soqucoin.conf` in the data folder. That takes the wallet out of startup and out of the RPC commands. SoquShield and the SDK give you addresses and signing without the node wallet.

The Linux and Windows builds come with the wallet. The macOS builds are made without it, so wallet commands like `getnewaddress` answer `error code: -32601` there. If you need the node wallet on a Mac, build from source. The wallet is part of a source build. The [source build steps](#building-from-source) on this page cover Linux, and [INSTALL.md](../INSTALL.md) points to the macOS build steps.

## When something goes wrong

**`error while loading shared libraries: libunivalue.so.0`** (or another `.so` file)
The 2.5.1 Linux build needed libraries it did not ship. Download 2.6.1 (step 1), which needs none.

**`error: Could not locate RPC credentials. No authentication cookie could be found...`**
The node isn't running, or it's still starting. Wait a few seconds and try again. If it keeps happening, look at the end of `debug.log` in the data folder. Run `soqucoin-cli` as the same user that started the node.

**`error: incorrect rpcuser or rpcpassword`**
You've put `rpcuser` or `rpcpassword` in `soqucoin.conf` and something doesn't line up. Unless you need them, remove both lines and restart the node.

**macOS says it can't verify the developer, or won't open the program**
Run the `xattr` line from step 1. If macOS says the program needs a newer version, you need macOS 15 or later.

**0 blocks and 0 connections**
Normal for the first few minutes while the node finds peers. If it stays that way, see step 3.

**`"chain": "stagenet"`**
Remove `stagenet=1` from `soqucoin.conf` and restart.

**`getblocktemplate` returns an error**
By design. See Mining.

**Startup sits on `Loading wallet...` for more than a minute**
Keep `debug.log` and tell us in the Telegram channel which release file you downloaded and whether the data folder had a `wallet.dat` from an earlier release.

## Updates in the first weeks

Release 2.6.0 pins the chain's history: a minimum chain work a node must reach before it leaves initial block download, an assumed-valid block, and checkpoints at blocks 1, 1,502 and 2,029 below which a node that holds them accepts no fork. Stay on the current release. Each release's notes name the height by which you need it to stay in sync; for 2.6.0 that height is block 67,000. If a point release moves the height, the release page and our channels carry the new height at least a week before the old one, and every node installs the point release the day it appears.

## Practicing on stagenet

Stagenet is the live test network our own nodes run today. It's a good place to prove your setup before you run a mainnet node. Put this line in `soqucoin.conf` in the data folder:

```ini
stagenet=1
```

Stagenet keeps its data in a `stagenet` folder inside the data folder, and finds peers through `stagenet.soqu.org`. A fresh node syncs in a few minutes on a fast connection. Stagenet addresses start with `ssq1p` and mainnet addresses start with `sq1p`. When you're done practicing, take the `stagenet=1` line back out.

## Getting help

Ask in the Telegram channel ([t.me/officialsoqucoin](https://t.me/officialsoqucoin)) or [open an issue on GitHub](https://github.com/soqucoin/soqucoin/issues). Include your operating system, which release file you downloaded, and the last 50 lines of `debug.log`. Never post your wallet file, a seed phrase or a private key.
