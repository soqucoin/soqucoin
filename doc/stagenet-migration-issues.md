# Stagenet Migration Issues Log

> **Purpose**: Running log of all issues discovered during the testnet3 → stagenet migration.
> These lessons are MANDATORY reading before mainnet launch to prevent repeating mistakes.

---

## Issue #1: Genesis Block Hash Invalidation (CRITICAL)
**Discovered**: 2026-04-27  
**Root Cause**: The USDSOQ commit (`c1bff39a4`) added `nVisibility` and `nAssetType` fields to `CTxOut` serialization. This changed the coinbase transaction hash → merkle root → block hash for ALL genesis blocks across all 4 networks.  
**Impact**: Every existing binary crashes on startup with `Assertion failed: consensus.hashGenesisBlock`.  
**Fix**: Required re-mining all genesis nonces (scrypt PoW) and updating assertions.  
**Mainnet Lesson**: **ANY change to transaction serialization format invalidates ALL genesis blocks.** Before mainnet launch, the genesis block nonces MUST be mined and hardcoded as the FINAL step after all serialization changes are frozen. Genesis parameter freeze must happen BEFORE release tagging.

## Issue #2: Scrypt Genesis Mining is Extremely Slow
**Discovered**: 2026-04-27  
**Root Cause**: Bitcoin Core instantiates ALL chain params classes on startup (CMainParams, CTestNetParams, CStagenetParams, CRegTestParams) regardless of which network is selected. If genesis mining loops are in all constructors, startup takes 10+ minutes.  
**Impact**: Initial approach of mining all 4 genesis blocks at startup was impractical.  
**Fix**: Only mine stagenet (needed now) and regtest (trivial difficulty). Defer mainnet/testnet3 to later.  
**Mainnet Lesson**: Genesis nonces MUST be pre-computed and hardcoded. NEVER ship a binary with runtime genesis mining. Build a standalone genesis miner tool (`contrib/mine_genesis.cpp`) that runs once offline.

## Issue #3: Binary Staleness (146 commits behind)
**Discovered**: 2026-04-27  
**Root Cause**: VPS nodes were running binaries from April 13 commit `66f019b42`, which is 146 commits behind `main`. These binaries lacked stagenet parameters, USDSOQ opcodes, and mining race-condition fixes.  
**Impact**: Cannot transition to stagenet without rebuild. Community nodes with old binaries will be incompatible.  
**Mainnet Lesson**: Establish a **release cadence** — tag releases (v1.0.0-rc1, rc2, etc.) and ensure all nodes upgrade to the SAME tagged release before genesis. CI/CD must produce deterministic binaries that community can verify.

## Issue #4: OOM During Build on 16GB VPS
**Discovered**: 2026-04-27  
**Root Cause**: Parallel build (`make -j8`) on the Services VPS consumed all 16GB RAM during C++ compilation+linking.  
**Fix**: Added 4GB swap file, reduced to `make -j4`.  
**Mainnet Lesson**: Document minimum build requirements (RAM, swap, disk) in BUILDING.md. Consider providing pre-built binaries via GitHub Releases.

## Issue #5: Systemd Auto-Restart Blocks Binary Deployment  
**Discovered**: 2026-04-27  
**Root Cause**: `soqucoind-hot.service` has `Restart=always`. When we stopped the node to deploy a new binary, systemd restarted it immediately, giving "Text file busy" errors when trying to overwrite.  
**Fix**: Must `systemctl disable` AND `systemctl stop` AND `kill -9` before deploying.  
**Mainnet Lesson**: Create a proper deployment script that handles service lifecycle: `deploy_soqucoind.sh stop → backup → copy → start`.

## Issue #6: L7 Pool Config vs Node Config Separation
**Discovered**: 2026-04-27  
**L7 Stratum**: `stratum+tcp://64.23.197.144:3333` (worker: `sq1pr0qql...L7`)  
**Key Insight**: The L7 miner connects to the POOL's stratum port (3333), not the node's P2P port. Changing networks only requires updating the pool software's RPC connection to point to the new stagenet node port (28332). The L7 config stays the same as long as the pool software is on the same IP.  
**Mainnet Lesson**: Document the full data flow: `L7 → Pool:3333 → soqucoind RPC:28332 → P2P:28333`. For mainnet, only the pool's `config.json` and the node's `soqucoin.conf` change. The L7 stratum URL stays the same unless the Mining VPS IP changes.

---

## Issue #7: GetHash() vs GetPoWHash() Confusion (CRITICAL — ROOT CAUSE)
**Discovered**: 2026-04-27  
**Root Cause**: The genesis mining loop used `genesis.GetHash()` (SHA256 double-hash) to check PoW, but `CheckAuxPowProofOfWork()` at line 107 of `soqucoin.cpp` validates against `genesis.GetPoWHash()` (scrypt). The mined nonce produced a SHA256d hash below the target, but the scrypt hash of the same block header was above the target — so the node accepted the genesis during construction but rejected it when reading from disk.  
**Impact**: Node starts, mines genesis, writes to disk, then immediately crashes with `ERROR: CheckAuxPowProofOfWork : non-AUX proof of work failed`. Wasted ~45 minutes debugging.  
**Fix**: Changed mining loop from `UintToArith256(genesis.GetHash())` to `UintToArith256(genesis.GetPoWHash())`.  
**Mainnet Lesson**: **The genesis miner tool MUST use the exact same PoW function as the consensus validation path.** Add a unit test: `BOOST_CHECK(CheckAuxPowProofOfWork(genesis, params))` that runs against the hardcoded genesis block for every network. This test would have caught the bug instantly.

## Issue #8: Scrypt Mining Rate on VPS CPU
**Discovered**: 2026-04-27  
**Observation**: VPS CPU achieves ~2,700 scrypt hashes/sec. At `0x1e0ffff0` difficulty (expected ~65K iterations), genesis mining takes 25-90 seconds. At real mainnet difficulty, it would be impractical at startup.  
**Mainnet Lesson**: Genesis mining MUST be done offline, ideally on the L7 ASIC or via the standalone mining tool. The nonce is then hardcoded. Runtime genesis mining is a development-only shortcut.

## Issue #9: SCP Binary Deployment Deploys Stale Build
**Discovered**: 2026-04-27  
**Root Cause**: After fixing the genesis mining (hardcoding nonce 942423), the Services VPS still had the OLD binary with the runtime mining loop. SCP'd that binary to the Mining VPS, which then had to re-mine genesis from scratch (~6 minutes) instead of starting instantly.  
**Impact**: 6-minute unnecessary startup delay on Mining VPS, plus confusion about which binary version is deployed where.  
**Fix**: Must rebuild on Services VPS BEFORE SCP deployment, or better yet, use a versioned deployment pipeline.  
**Mainnet Lesson**: **NEVER deploy via SCP from a running node.** Always: (1) `git pull` → (2) `make` → (3) copy binary → (4) deploy. Use `soqucoind --version` to verify the deployed binary matches the expected commit hash. Add commit hash to the `--version` output if not already present.

## Issue #10: Firewall Rules Not Updated for New Ports
**Discovered**: 2026-04-27  
**Root Cause**: Both VPS machines had UFW rules for the old testnet3 ports (44555/44556/44557/44558) but NOT for the new stagenet ports (28332/28333/38332). P2P connections silently failed — TCP port was open (soqucoind listening) but UFW dropped all external traffic.  
**Symptoms**: `getpeerinfo` showed 0 peers despite `nc -zv` succeeding (nc connects to localhost, not through UFW). Took `addnode` failing + log inspection to discover.  
**Fix**: `ufw allow 28333/tcp` and `ufw allow 28332/tcp` on both VPS.  
**Mainnet Lesson**: **Firewall port changes are step 1 of ANY network migration, not an afterthought.** Add to the deployment script: verify UFW rules BEFORE starting the node. Script should check: `ufw status | grep <PORT>/tcp || ufw allow <PORT>/tcp`.

## Issue #11: Zombie soqucoind Processes Holding Ports
**Discovered**: 2026-04-27  
**Root Cause**: An old testnet3 soqucoind process (renamed to `soqucoin-shutof` in shutdown state) was still running and holding ports 44556 and 28332. The new stagenet node couldn't bind its RPC port because the zombie's shutdown handler was still active. `pgrep soqucoind` didn't catch it because the process name had changed.  
**Fix**: `kill -9 <PID>` targeting the specific process from `ss -tlnp | grep <PORT>`.  
**Mainnet Lesson**: Before starting ANY node, run `ss -tlnp | grep -E '<ALL_PORTS>'` to verify no stale processes are holding ports. The deployment script must check for AND kill any process bound to the target ports, regardless of process name.

---

## Pre-Mainnet Checklist (derived from issues above)

### Phase 1: Code Freeze & Verification
- [ ] **Serialization Freeze**: All CTxOut/CTxIn format changes finalized — NO changes after this point
- [ ] **Genesis Mining Tool**: Build `contrib/mine_genesis.cpp` — standalone offline miner using `GetPoWHash()` (scrypt)
- [ ] **Genesis Unit Test**: Add `BOOST_CHECK(CheckAuxPowProofOfWork(genesis, params))` for all 4 networks
- [ ] **Genesis Nonce Hardcoding**: Mine all 4 network genesis blocks, hardcode nonces + hashes + merkle roots

### Phase 2: Build & Release
- [ ] **Release Tag**: Tag `v1.0.0` AFTER genesis nonces are hardcoded
- [ ] **CI/CD Binary Artifacts**: Ensure GitHub Actions produces reproducible binaries
- [ ] **Build Documentation**: Update BUILDING.md with RAM/swap/disk requirements
- [ ] **Community Build Test**: At least 2 independent builds from source to verify reproducibility

### Phase 3: Infrastructure & Deployment
- [ ] **Firewall Rules**: Open P2P and RPC ports on ALL nodes BEFORE starting daemons
- [ ] **Deployment Script**: Create `deploy_soqucoind.sh` with proper systemd lifecycle (kill zombies, verify ports)
- [ ] **Node Upgrade Coordination**: All seed nodes must run same tagged release before block 0
- [ ] **Pool Config Template**: Document exact pool config changes needed for mainnet ports
- [ ] **L7/ASIC Docs**: Document full data flow: L7 → Pool:3333 → soqucoind RPC → P2P
- [ ] **Version Verification**: `soqucoind --version` must include commit hash; verify on ALL nodes before launch

### Phase 4: Network Launch
- [ ] **Seed Node Verification**: All 3+ seed nodes return matching `getblockchaininfo` at block 0
- [ ] **Pool Verification**: L7 connects, receives work, submits shares successfully
- [ ] **Block 1 Confirmation**: First block mined and propagated to all peers
- [ ] **SOQ-TEC Relayer**: Relayer successfully reads block data from new mainnet RPC
