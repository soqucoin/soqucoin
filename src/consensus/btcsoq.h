// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BTCSOQ: consensus-native, Bitcoin-backed, post-quantum asset.
// Design Log: design-log/DL-BTCSOQ-CONSENSUS-NATIVE.md
//
// BTCSOQ mirrors the USDSOQ stablecoin consensus layer (consensus/usdsoq.h)
// almost verbatim: a deterministic supply counter and an M-of-N Dilithium
// (ML-DSA-44) issuer authority, replayable on reindex, reversible on reorg.
//
// The one structural difference from USDSOQ: every MINT is bound to a specific
// Bitcoin deposit (txid:vout, sats) carried in the mint payload, and consensus
// tracks the set of already-minted Bitcoin outpoints so no deposit can back two
// mints. In Tier A the authority's signature attests the deposit; a future
// Tier C would replace that attestation with an in-consensus Bitcoin SPV proof.
//
// All operations are BIP9-gated via DEPLOYMENT_BTCSOQ and are NEVER_ACTIVE on
// mainnet at genesis. Stagenet activates for testing; mainnet activates by
// signaled flag height only after the Phase 2 audit. Classification is
// STRUCTURAL (script shape), never via CTxOut extension bytes.

#ifndef SOQUCOIN_CONSENSUS_BTCSOQ_H
#define SOQUCOIN_CONSENSUS_BTCSOQ_H

#include "amount.h"
#include "consensus/usdsoq.h"   // shared ASSET_TYPE_*, DILITHIUM_*, authority limits
#include "serialize.h"
#include "uint256.h"

#include <cstdint>
#include <vector>

class CTransaction;
class COutPoint;
class CScript;

// =========================================================================
// Asset type — extends the shared set defined in usdsoq.h
// =========================================================================
// NOTE (Step 2 integration): also bump ASSET_TYPE_MAX in usdsoq.h to 0x02 and
// add CTxOut::IsBTCSOQ() so structural classification recognizes BTCSOQ. Kept
// out of this header so the standalone module compiles and unit-tests without
// touching the shared classification path.
static constexpr uint8_t ASSET_TYPE_BTCSOQ = 0x02;  // Bitcoin-backed asset

// =========================================================================
// Authority marker and op tags.
//
// The BTCSOQ authority marker output is witness v9: OP_9 <SHA256(concat keys)>.
// It is deliberately a DIFFERENT witness version from the USDSOQ authority
// marker (v5): the marker output is the unforgeable, sighash-covered fact that
// routes a transaction to exactly one asset's enforcement block. Partitioning
// on a witness tag instead would be attacker-malleable (witness data is not
// covered by any signature) and would require tag-conditional routing inside
// the audited USDSOQ path. A transaction carrying BOTH a v5 and a v9 marker
// output is consensus-invalid (bad-txns-dual-authority-marker).
//
// The op tag + payload ride a signed OP_RETURN output (see
// ParseBTCSOQAuthorityOp below), NOT the witness: the authority M-of-N
// signature covers the transaction sighash, so only output-side data is
// authenticated. A witness-side payload could be mutated in flight (e.g.
// rewriting the bound btc_txid:vout of a MINT), desyncing the deposit ledger.
// The witness tag slot [2] still carries a copy of the op tag for cheap
// authority-witness detection; consensus requires it to EQUAL the OP_RETURN
// tag so there is a single source of truth.
// =========================================================================
static constexpr uint8_t BTCSOQ_OP_MINT    = 0x60;  // create supply against a BTC deposit
static constexpr uint8_t BTCSOQ_OP_BURN     = 0x61;  // destroy supply, record release intent
static constexpr uint8_t BTCSOQ_OP_ROTATE   = 0x62;  // rotate issuer authority key set (NOT yet wired — rejected by consensus)
static constexpr uint8_t BTCSOQ_OP_FREEZE   = 0x63;  // add/remove outpoint from frozen set

// =========================================================================
// MINT payload wire format (carried in the authority payload witness slot)
//   [btc_txid:32][btc_vout:4 LE][sats:8 LE][recipient_commitment:32]
// recipient_commitment binds the mint to the intended Soqucoin recipient
// (SHA256 of the receiving ssq script), preventing an authority signature from
// being replayed to a different recipient.
// =========================================================================
static constexpr size_t BTCSOQ_MINT_PAYLOAD_LEN = 32 + 4 + 8 + 32;  // 76 bytes

// =========================================================================
// BURN (redeem) payload wire format
//   [release_scripthash:32][sats:8 LE]
// release_scripthash names the Bitcoin script the gateway must release to;
// sats MUST equal the total BTCSOQ input value burned by the transaction, so
// the signed release intent can never disagree with the consensus burn.
// =========================================================================
static constexpr size_t BTCSOQ_BURN_PAYLOAD_LEN = 32 + 8;  // 40 bytes

// =========================================================================
// CBTCSOQSupply — deterministic supply counter (identical semantics to
// CUSDSOQSupply). Outstanding() = total_minted - total_burned, always >= 0.
// =========================================================================
class CBTCSOQSupply
{
private:
    CAmount total_minted;
    CAmount total_burned;

public:
    CBTCSOQSupply() : total_minted(0), total_burned(0) {}

    CAmount Outstanding() const { return total_minted - total_burned; }
    CAmount TotalMinted() const { return total_minted; }
    CAmount TotalBurned() const { return total_burned; }

    //! Record a mint. Checked arithmetic; false on overflow / out of range.
    bool Mint(CAmount amount);
    //! Record a burn. False on underflow / burning more than outstanding.
    bool Burn(CAmount amount);
    //! Reverse a mint during DisconnectBlock (reorg).
    bool UndoMint(CAmount amount);
    //! Reverse a burn during DisconnectBlock (reorg).
    bool UndoBurn(CAmount amount);
    //! Outstanding() >= 0 and both counters within MoneyRange.
    bool CheckInvariant() const;
    //! Reset to initial state (for -reindex).
    void Reset() { total_minted = 0; total_burned = 0; }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(total_minted);
        READWRITE(total_burned);
    }
};

// =========================================================================
// CBTCSOQAuthority — M-of-N Dilithium issuer authority (the gateway).
// Reuses the shared USDSOQ authority limits and Dilithium sizes.
// =========================================================================
class CBTCSOQAuthority
{
private:
    std::vector<std::vector<uint8_t>> authority_keys;
    uint32_t threshold;

public:
    CBTCSOQAuthority() : threshold(0) {}

    bool Initialize(const std::vector<std::vector<uint8_t>>& keys, uint32_t m);
    bool VerifyAuthoritySignatures(
        const std::vector<uint8_t>& msg,
        const std::vector<std::vector<uint8_t>>& sigs) const;
    bool RotateKeys(const std::vector<std::vector<uint8_t>>& new_keys,
                    uint32_t new_threshold);

    uint32_t GetThreshold() const { return threshold; }
    size_t GetKeyCount() const { return authority_keys.size(); }
    bool IsInitialized() const { return !authority_keys.empty() && threshold > 0; }
    const std::vector<std::vector<uint8_t>>& GetKeys() const { return authority_keys; }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(authority_keys);
        READWRITE(threshold);
    }
};

// =========================================================================
// MINT payload helpers (pure functions, unit-testable)
// =========================================================================

//! Serialize a MINT payload. Returns a BTCSOQ_MINT_PAYLOAD_LEN-byte vector.
std::vector<uint8_t> BuildBTCSOQMintPayload(
    const uint256& btcTxid, uint32_t btcVout, CAmount sats, const uint256& recipient);

//! Parse a MINT payload. Returns false unless the payload is exactly
//! BTCSOQ_MINT_PAYLOAD_LEN bytes and sats is a positive MoneyRange amount.
bool ParseBTCSOQMintPayload(
    const std::vector<uint8_t>& payload,
    uint256& btcTxid, uint32_t& btcVout, CAmount& sats, uint256& recipient);

//! Serialize a BURN payload. Returns a BTCSOQ_BURN_PAYLOAD_LEN-byte vector.
std::vector<uint8_t> BuildBTCSOQBurnPayload(
    const uint256& releaseScriptHash, CAmount sats);

//! Parse a BURN payload. Returns false unless the payload is exactly
//! BTCSOQ_BURN_PAYLOAD_LEN bytes and sats is a positive in-range amount.
bool ParseBTCSOQBurnPayload(
    const std::vector<uint8_t>& payload,
    uint256& releaseScriptHash, CAmount& sats);

// =========================================================================
// Signed OP_RETURN op envelope.
//
// A BTCSOQ authority transaction carries exactly one OP_RETURN output whose
// single data push is [op_tag:1][payload], where op_tag selects the operation
// and the payload length is fixed per op:
//   MINT   (0x60): BTCSOQ_MINT_PAYLOAD_LEN   (76)  → push 77, script 80 bytes
//   BURN   (0x61): BTCSOQ_BURN_PAYLOAD_LEN   (40)  → push 41
//   FREEZE (0x63): FREEZE_OP_PAYLOAD_LEN     (37)  → push 38 (same layout as
//                  the USDSOQ freeze payload: [freeze_op:1][txid:32][vout:4])
// ROTATE (0x62) has no wired semantics yet; a 0x62 push is not recognized, so
// an authority tx carrying one fails the mandatory-op check in ConnectBlock.
// All sizes stay within the 83-byte OP_RETURN relay-standardness budget.
// =========================================================================

//! Scan tx.vout for the BTCSOQ authority op OP_RETURN. Returns true iff
//! exactly one well-formed op is present (mirrors the USDSOQ freeze parser's
//! single-action invariant: a second well-formed op fails the parse).
//! On success fills `tag` and `payload` (payload excludes the tag byte).
//! Pure function — no chain state, safe to unit-test.
bool ParseBTCSOQAuthorityOp(
    const CTransaction& tx, uint8_t& tag, std::vector<uint8_t>& payload);

//! SHA256 of the serialized scriptPubKey bytes of the mint recipient output.
//! This is the 32-byte recipient_commitment carried in the MINT payload; it
//! binds the authority signature to the exact receiving script.
uint256 ComputeBTCSOQRecipientCommitment(const CScript& scriptPubKey);

// =========================================================================
// Anti-replay: the DB key that marks a Bitcoin deposit as already minted.
// ConnectBlock rejects any MINT whose (btc_txid, btc_vout) is already present
// in the DB set DB_BTCSOQ_MINTED_OUTPOINTS. A missed check here is a double
// mint, which is supply inflation, so this is a Phase 2 audit focus.
// =========================================================================
//! Deterministic 36-byte key (txid || vout LE) for the minted-outpoint set.
std::vector<uint8_t> BTCSOQMintedOutpointKey(const uint256& btcTxid, uint32_t btcVout);

// =========================================================================
// Witness helpers (same extended layout as USDSOQ)
//   [0] payout_sig [1] payout_pk [2] tag [3] payload [4..N-2] auth_sigs [N-1] authority_set
// =========================================================================
uint8_t GetBTCSOQWitnessTag(const std::vector<std::vector<uint8_t>>& witnessStack);
std::vector<std::vector<uint8_t>> ExtractBTCSOQWitnessSignatures(
    const std::vector<std::vector<uint8_t>>& witnessStack);

#endif // SOQUCOIN_CONSENSUS_BTCSOQ_H
