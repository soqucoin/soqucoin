// Copyright (c) 2026 Soqucoin Foundation
// Distributed under the MIT software license
//
// Lattice-BP++: Stealth Addresses for Privacy
// Stage 3 R&D - One-time Address Generation
//

#ifndef SOQUCOIN_CRYPTO_LATTICEBP_STEALTH_ADDRESS_H
#define SOQUCOIN_CRYPTO_LATTICEBP_STEALTH_ADDRESS_H

#include "commitment.h"
#include "ring_signature.h"
#include <array>
#include <stdint.h>
#include <vector>

namespace latticebp
{

/**
 * Stealth Address System
 *
 * Implements Monero-style stealth addresses adapted for Soqucoin's
 * Dilithium-based key infrastructure.
 *
 * Key derivation:
 *   - Master view key (mvk)     - Can see incoming transactions
 *   - Master spend key (msk)    - Can spend funds
 *   - One-time public key (P)   - Unique per transaction
 *   - One-time private key (x)  - Derived by recipient
 *
 * Protocol:
 *   1. Sender generates random R
 *   2. Sender computes P = H(R || mvk) * G + msk * G
 *   3. Recipient scans: x = H(R || mvk) + msk
 *   4. Only recipient can compute x and spend
 */

/**
 * View Key
 *
 * Allows viewing incoming transactions without spending ability.
 * Used for audit/compliance disclosure.
 */
class ViewKey
{
public:
    RingElement key;

    // Derive from master seed using HKDF
    static ViewKey deriveFromSeed(
        const std::array<uint8_t, 32>& seed,
        const char* domain = "soqucoin.privacy.view.v1");

    // Scan transaction for incoming funds
    bool canView(
        const LatticePublicKey& one_time_pk,
        const RingElement& tx_public_key) const;

    // Serialization
    std::vector<uint8_t> serialize() const;
    static ViewKey deserialize(const std::vector<uint8_t>& data);
};

/**
 * Spend Key
 *
 * Required to spend funds. Never shared.
 */
class SpendKey
{
public:
    RingElement key;

    // Derive from master seed using HKDF
    static SpendKey deriveFromSeed(
        const std::array<uint8_t, 32>& seed,
        const char* domain = "soqucoin.privacy.spend.v1");

    // Derive one-time private key for a specific transaction
    RingElement deriveOneTimeKey(
        const ViewKey& view_key,
        const RingElement& tx_public_key) const;

    // Serialization (encrypted at rest)
    std::vector<uint8_t> serialize() const;
    static SpendKey deserialize(const std::vector<uint8_t>& data);
};

/**
 * Audit Disclosure Key
 *
 * Enhanced view key for compliance. Can prove:
 *   - All incoming transactions
 *   - All outgoing transactions (with key images)
 *   - Account balance at any point in time
 */
class AuditKey
{
public:
    ViewKey view_key;
    std::vector<KeyImage> revealed_key_images; // Outgoing TX proof

    // Generate audit disclosure for a time range
    static AuditKey generateDisclosure(
        const ViewKey& view_key,
        const SpendKey& spend_key,
        const std::vector<RingElement>& spent_outputs);

    // Verify audit disclosure is complete (no hidden spends)
    bool verifyCompleteness(
        const std::vector<LatticePublicKey>& known_outputs) const;

    // Serialization
    std::vector<uint8_t> serialize() const;
    static AuditKey deserialize(const std::vector<uint8_t>& data);
};

/**
 * Stealth Address
 *
 * One-time address for receiving private transactions.
 */
class StealthAddress
{
public:
    LatticePublicKey one_time_pk; // Recipient's one-time public key
    RingElement tx_public_key;    // Sender's random key (R)

    /**
     * Generate stealth address for payment.
     *
     * @param recipient_view_pk  Recipient's public view key
     * @param recipient_spend_pk Recipient's public spend key
     * @return Stealth address + tx_public_key to include in TX
     */
    static StealthAddress generate(
        const LatticePublicKey& recipient_view_pk,
        const LatticePublicKey& recipient_spend_pk);

    /**
     * Scan output to check if it belongs to us.
     *
     * @param view_key Our private view key
     * @param spend_pk Our public spend key
     * @return true if this output is ours
     */
    bool belongsTo(
        const ViewKey& view_key,
        const LatticePublicKey& spend_pk) const;

    /**
     * Recover the one-time private key (only owner can do this).
     */
    RingElement recoverPrivateKey(
        const ViewKey& view_key,
        const SpendKey& spend_key) const;

    // Serialization
    std::vector<uint8_t> serialize() const;
    static StealthAddress deserialize(const std::vector<uint8_t>& data);
};

} // namespace latticebp

#endif // SOQUCOIN_CRYPTO_LATTICEBP_STEALTH_ADDRESS_H
