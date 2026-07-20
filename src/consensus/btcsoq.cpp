// Copyright (c) 2024-2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// BTCSOQ consensus layer — implementation. See consensus/btcsoq.h and
// design-log/DL-BTCSOQ-CONSENSUS-NATIVE.md. The supply and authority bodies
// are the audited USDSOQ logic; the MINT payload and minted-outpoint helpers
// are the Bitcoin-deposit binding that is new to BTCSOQ.

#include "consensus/btcsoq.h"
#include "amount.h"
#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "script/script.h"
extern "C" {
#include "crypto/dilithium/api.h"
}

#include <cstring>
#include <limits>

// Upper bound on a mint amount: 21,000,000 BTC expressed in satoshis.
// The sat-to-BTCSOQ-base-unit mapping is 1:1 and fixed here; see the design log.
static constexpr CAmount BTCSOQ_MAX_SATS = 2100000000000000LL;

// =========================================================================
// CBTCSOQSupply — checked arithmetic supply counter (mirrors CUSDSOQSupply)
// =========================================================================

bool CBTCSOQSupply::Mint(CAmount amount)
{
    if (amount <= 0) return false;
    if (amount > std::numeric_limits<CAmount>::max() - total_minted) return false;
    CAmount new_minted = total_minted + amount;
    if (!MoneyRange(new_minted)) return false;
    CAmount new_outstanding = new_minted - total_burned;
    if (!MoneyRange(new_outstanding)) return false;
    total_minted = new_minted;
    return true;
}

bool CBTCSOQSupply::Burn(CAmount amount)
{
    if (amount <= 0) return false;
    if (amount > std::numeric_limits<CAmount>::max() - total_burned) return false;
    CAmount new_burned = total_burned + amount;
    if (new_burned > total_minted) return false;   // cannot burn more than minted
    if (!MoneyRange(new_burned)) return false;
    total_burned = new_burned;
    return true;
}

bool CBTCSOQSupply::CheckInvariant() const
{
    if (total_minted < 0 || total_burned < 0) return false;
    if (total_burned > total_minted) return false;
    if (!MoneyRange(total_minted)) return false;
    if (!MoneyRange(total_burned)) return false;
    CAmount outstanding = total_minted - total_burned;
    if (!MoneyRange(outstanding)) return false;
    return true;
}

bool CBTCSOQSupply::UndoMint(CAmount amount)
{
    if (amount <= 0) return false;
    if (amount > total_minted) return false;
    CAmount new_minted = total_minted - amount;
    if (new_minted < total_burned) return false;
    if (!MoneyRange(new_minted)) return false;
    total_minted = new_minted;
    return true;
}

bool CBTCSOQSupply::UndoBurn(CAmount amount)
{
    if (amount <= 0) return false;
    if (amount > total_burned) return false;
    CAmount new_burned = total_burned - amount;
    if (!MoneyRange(new_burned)) return false;
    CAmount new_outstanding = total_minted - new_burned;
    if (!MoneyRange(new_outstanding)) return false;
    total_burned = new_burned;
    return true;
}

// =========================================================================
// CBTCSOQAuthority — M-of-N Dilithium issuer authority (mirrors CUSDSOQAuthority)
// =========================================================================

bool CBTCSOQAuthority::Initialize(
    const std::vector<std::vector<uint8_t>>& keys, uint32_t m)
{
    if (keys.empty()) return false;
    if (keys.size() > USDSOQ_MAX_AUTHORITY_KEYS) return false;
    if (m < USDSOQ_MIN_THRESHOLD) return false;
    if (m > keys.size()) return false;
    for (const auto& key : keys) {
        if (key.size() != DILITHIUM_PUBKEY_SIZE) return false;
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        for (size_t j = i + 1; j < keys.size(); ++j) {
            if (keys[i] == keys[j]) return false;
        }
    }
    authority_keys = keys;
    threshold = m;
    return true;
}

bool CBTCSOQAuthority::VerifyAuthoritySignatures(
    const std::vector<uint8_t>& msg,
    const std::vector<std::vector<uint8_t>>& sigs) const
{
    if (!IsInitialized()) return false;
    if (sigs.empty()) return false;
    if (sigs.size() > authority_keys.size()) return false;
    for (const auto& sig : sigs) {
        if (sig.size() != DILITHIUM_SIG_SIZE) return false;
    }

    std::vector<bool> key_used(authority_keys.size(), false);
    uint32_t valid_count = 0;

    for (const auto& sig : sigs) {
        for (size_t k = 0; k < authority_keys.size(); ++k) {
            if (key_used[k]) continue;
            int result = pqcrystals_dilithium2_ref_verify(
                sig.data(), sig.size(),
                msg.data(), msg.size(),
                nullptr, 0,     // FIPS 204 context string (empty)
                authority_keys[k].data());
            if (result == 0) {  // 0 = success in CRYSTALS-Dilithium
                key_used[k] = true;
                ++valid_count;
                break;
            }
        }
    }
    return valid_count >= threshold;
}

bool CBTCSOQAuthority::RotateKeys(
    const std::vector<std::vector<uint8_t>>& new_keys,
    uint32_t new_threshold)
{
    if (new_keys.empty()) return false;
    if (new_keys.size() > USDSOQ_MAX_AUTHORITY_KEYS) return false;
    if (new_threshold < USDSOQ_MIN_THRESHOLD) return false;
    if (new_threshold > new_keys.size()) return false;
    for (const auto& key : new_keys) {
        if (key.size() != DILITHIUM_PUBKEY_SIZE) return false;
    }
    for (size_t i = 0; i < new_keys.size(); ++i) {
        for (size_t j = i + 1; j < new_keys.size(); ++j) {
            if (new_keys[i] == new_keys[j]) return false;
        }
    }
    // Authorization (M-of-N over the rotation message covering old+new sets) is
    // verified by the ROTATE handler in ConnectBlock before this is called.
    authority_keys = new_keys;
    threshold = new_threshold;
    return true;
}

// =========================================================================
// MINT payload helpers — the Bitcoin-deposit binding new to BTCSOQ
// =========================================================================

static void put_u32_le(std::vector<uint8_t>& v, uint32_t x)
{
    v.push_back((uint8_t)(x & 0xff));
    v.push_back((uint8_t)((x >> 8) & 0xff));
    v.push_back((uint8_t)((x >> 16) & 0xff));
    v.push_back((uint8_t)((x >> 24) & 0xff));
}

static void put_u64_le(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back((uint8_t)((x >> (8 * i)) & 0xff));
}

std::vector<uint8_t> BuildBTCSOQMintPayload(
    const uint256& btcTxid, uint32_t btcVout, CAmount sats, const uint256& recipient)
{
    std::vector<uint8_t> p;
    p.reserve(BTCSOQ_MINT_PAYLOAD_LEN);
    p.insert(p.end(), btcTxid.begin(), btcTxid.end());        // 32
    put_u32_le(p, btcVout);                                   // 4
    put_u64_le(p, (uint64_t)sats);                            // 8
    p.insert(p.end(), recipient.begin(), recipient.end());    // 32
    return p;
}

bool ParseBTCSOQMintPayload(
    const std::vector<uint8_t>& payload,
    uint256& btcTxid, uint32_t& btcVout, CAmount& sats, uint256& recipient)
{
    if (payload.size() != BTCSOQ_MINT_PAYLOAD_LEN) return false;

    memcpy(btcTxid.begin(), &payload[0], 32);

    btcVout = (uint32_t)payload[32]
            | ((uint32_t)payload[33] << 8)
            | ((uint32_t)payload[34] << 16)
            | ((uint32_t)payload[35] << 24);

    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s |= ((uint64_t)payload[36 + i]) << (8 * i);
    // Reject amounts that overflow a signed CAmount or exceed the BTC supply.
    if (s > (uint64_t)BTCSOQ_MAX_SATS) return false;
    sats = (CAmount)s;
    if (sats <= 0) return false;

    memcpy(recipient.begin(), &payload[44], 32);
    return true;
}

std::vector<uint8_t> BuildBTCSOQBurnPayload(
    const uint256& releaseScriptHash, CAmount sats)
{
    std::vector<uint8_t> p;
    p.reserve(BTCSOQ_BURN_PAYLOAD_LEN);
    p.insert(p.end(), releaseScriptHash.begin(), releaseScriptHash.end());  // 32
    put_u64_le(p, (uint64_t)sats);                                          // 8
    return p;
}

bool ParseBTCSOQBurnPayload(
    const std::vector<uint8_t>& payload,
    uint256& releaseScriptHash, CAmount& sats)
{
    if (payload.size() != BTCSOQ_BURN_PAYLOAD_LEN) return false;

    memcpy(releaseScriptHash.begin(), &payload[0], 32);

    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s |= ((uint64_t)payload[32 + i]) << (8 * i);
    if (s > (uint64_t)BTCSOQ_MAX_SATS) return false;
    sats = (CAmount)s;
    if (sats <= 0) return false;
    return true;
}

// =========================================================================
// Signed OP_RETURN op envelope — see the header for the wire format and the
// rationale (the authority sighash covers outputs, not witness data, so the
// op tag and payload MUST live output-side to be authenticated).
// =========================================================================

//! Expected payload length (excluding the tag byte) for a recognized op tag,
//! or 0 if the tag has no wired semantics (0x62 ROTATE, unknown bytes).
static size_t BTCSOQOpPayloadLen(uint8_t tag)
{
    switch (tag) {
    case BTCSOQ_OP_MINT:   return BTCSOQ_MINT_PAYLOAD_LEN;
    case BTCSOQ_OP_BURN:   return BTCSOQ_BURN_PAYLOAD_LEN;
    case BTCSOQ_OP_FREEZE: return FREEZE_OP_PAYLOAD_LEN;
    default:               return 0;
    }
}

bool ParseBTCSOQAuthorityOp(
    const CTransaction& tx, uint8_t& tag, std::vector<uint8_t>& payload)
{
    bool found = false;

    for (const auto& txout : tx.vout) {
        const CScript& script = txout.scriptPubKey;

        if (script.size() < 2 || script[0] != OP_RETURN)
            continue;

        // Strict envelope: OP_RETURN followed by exactly one data push.
        CScript::const_iterator pc = script.begin();
        opcodetype opcode;
        std::vector<uint8_t> push;

        ++pc;  // skip OP_RETURN
        if (!script.GetOp(pc, opcode, push))
            continue;
        if (pc != script.end())
            continue;  // trailing opcodes/pushes — not a BTCSOQ op

        if (push.empty())
            continue;
        const uint8_t candidateTag = push[0];
        const size_t expectedLen = BTCSOQOpPayloadLen(candidateTag);
        if (expectedLen == 0 || push.size() != 1 + expectedLen)
            continue;

        // Single-action invariant: a second well-formed op fails the parse
        // (mirrors ParseUSDSOQFreezeOp — an ambiguous tx must never be
        // interpreted as either op).
        if (found)
            return false;

        tag = candidateTag;
        payload.assign(push.begin() + 1, push.end());
        found = true;
    }

    return found;
}

uint256 ComputeBTCSOQRecipientCommitment(const CScript& scriptPubKey)
{
    uint256 out;
    CSHA256().Write(scriptPubKey.data(), scriptPubKey.size()).Finalize(out.begin());
    return out;
}

std::vector<uint8_t> BTCSOQMintedOutpointKey(const uint256& btcTxid, uint32_t btcVout)
{
    std::vector<uint8_t> key;
    key.reserve(36);
    key.insert(key.end(), btcTxid.begin(), btcTxid.end());
    put_u32_le(key, btcVout);
    return key;
}

// =========================================================================
// Witness helpers — same extended layout as USDSOQ
// =========================================================================

uint8_t GetBTCSOQWitnessTag(const std::vector<std::vector<uint8_t>>& witnessStack)
{
    if (witnessStack.size() < 3 || witnessStack[2].empty()) return 0x00;
    return witnessStack[2][0];
}

std::vector<std::vector<uint8_t>> ExtractBTCSOQWitnessSignatures(
    const std::vector<std::vector<uint8_t>>& witnessStack)
{
    std::vector<std::vector<uint8_t>> sigs;
    if (witnessStack.size() < 6) return sigs;
    for (size_t i = 4; i < witnessStack.size() - 1; ++i) {
        if (witnessStack[i].size() == DILITHIUM_SIG_SIZE) {
            sigs.push_back(witnessStack[i]);
        }
    }
    return sigs;
}
