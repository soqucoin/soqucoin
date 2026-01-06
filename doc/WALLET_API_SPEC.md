# Soqucoin Wallet Library API Specification

> **Version**: 1.0-draft | **Updated**: 2026-01-06
> **Status**: Pre-Implementation Design
> **Audience**: Core Developers, Wallet Integrators, Auditors

---

## Overview

`libsoqucoin-wallet` is the official C++ library for building Soqucoin wallets. It abstracts cryptographic complexity and provides high-level APIs that **automatically optimize for per-proof verification costs**.

### Design Principles (Expert Best Practices)

1. **Secure by Default** — Private keys never exposed; hardware wallet compatible
2. **Aggregation by Default** — PAT and BP++ batching enabled automatically
3. **Minimal Dependencies** — Only libsoqucoin-core required
4. **Auditable** — Clean separation of concerns; well-documented interfaces
5. **Testable** — All functions have deterministic test vectors

---

## Module Structure

```
libsoqucoin-wallet/
├── include/wallet/
│   ├── wallet.h           // Main wallet interface
│   ├── keys.h             // Key management
│   ├── address.h          // Address encoding/decoding
│   ├── transaction.h      // TX construction
│   ├── aggregation.h      // Proof aggregation
│   └── cost.h             // Fee/cost estimation
├── src/
│   ├── wallet.cpp
│   ├── keys.cpp
│   ├── address.cpp
│   ├── transaction.cpp
│   ├── aggregation.cpp
│   └── cost.cpp
└── test/
    ├── wallet_tests.cpp
    └── test_vectors/
```

---

## Core Interfaces

### 1. Key Management (`keys.h`)

```cpp
namespace soqucoin::wallet {

// Key generation using Dilithium ML-DSA-44
class KeyPair {
public:
    // Generate new keypair from entropy
    static KeyPair Generate(const SecureBytes& entropy);
    
    // Derive from BIP-44 style path (m/44'/21329'/account'/change/index)
    static KeyPair DeriveFromSeed(const SecureBytes& seed, const DerivationPath& path);
    
    // Access public key (safe to share)
    const DilithiumPublicKey& GetPublicKey() const;
    
    // Sign message (returns Dilithium signature)
    Signature Sign(const Bytes& message) const;
    
    // Serialize for storage (encrypted)
    SecureBytes Serialize(const SecureBytes& encryptionKey) const;
    
    // Deserialize from storage
    static KeyPair Deserialize(const SecureBytes& data, const SecureBytes& encryptionKey);

private:
    DilithiumSecretKey m_secretKey;  // Never exposed
};

// Secure memory handling
class SecureBytes {
    // Zeroed on destruction, mlock'd in memory
};

} // namespace soqucoin::wallet
```

### 2. Address Encoding (`address.h`)

```cpp
namespace soqucoin::wallet {

enum class AddressType {
    P2PQ,       // Pay-to-Post-Quantum (Dilithium)
    P2PQ_PAT,   // P2PQ with PAT aggregation hint
    P2SH_PQ,    // Script hash (post-quantum)
};

class Address {
public:
    // Encode public key to address string
    static std::string Encode(const DilithiumPublicKey& pubkey, 
                               AddressType type = AddressType::P2PQ,
                               Network network = Network::Mainnet);
    
    // Decode address string to components
    static AddressInfo Decode(const std::string& address);
    
    // Validate address format
    static bool IsValid(const std::string& address);
    
    // Get address type
    AddressType GetType() const;
    
    // Get network (mainnet, testnet, stagenet)
    Network GetNetwork() const;
};

struct AddressInfo {
    AddressType type;
    Network network;
    Bytes hash;        // Hash of public key
    bool valid;
};

} // namespace soqucoin::wallet
```

### 3. Transaction Construction (`transaction.h`)

```cpp
namespace soqucoin::wallet {

class TransactionBuilder {
public:
    TransactionBuilder();
    
    // Add input (UTXO to spend)
    TransactionBuilder& AddInput(const OutPoint& utxo, const KeyPair& key);
    
    // Add output (recipient)
    TransactionBuilder& AddOutput(const Address& recipient, Amount value);
    
    // Add change output (auto-calculated)
    TransactionBuilder& AddChangeOutput(const Address& changeAddr);
    
    // Enable PAT aggregation (default: true when beneficial)
    TransactionBuilder& EnablePATAggregation(bool enable = true);
    
    // Enable BP++ batching for range proofs (default: true)
    TransactionBuilder& EnableBPPPBatching(bool enable = true);
    
    // Set fee rate (SOQ per vbyte)
    TransactionBuilder& SetFeeRate(Amount feePerVByte);
    
    // Estimate verification cost before signing
    VerifyCostEstimate EstimateVerifyCost() const;
    
    // Estimate total fee
    Amount EstimateFee() const;
    
    // Build and sign transaction
    Result<Transaction> Build();

private:
    std::vector<TxInput> m_inputs;
    std::vector<TxOutput> m_outputs;
    bool m_patEnabled = true;
    bool m_bpppBatchingEnabled = true;
    Amount m_feeRate;
};

struct VerifyCostEstimate {
    uint32_t dilithiumCost;    // Signature verification cost
    uint32_t patCost;          // PAT proof cost (0 if not aggregated)
    uint32_t bpppCost;         // Range proof cost
    uint32_t totalCost;        // Sum
    uint32_t savingsFromAggregation;  // Cost saved by aggregation
};

} // namespace soqucoin::wallet
```

### 4. Proof Aggregation (`aggregation.h`)

```cpp
namespace soqucoin::wallet {

// PAT (Proof Aggregation Tree) for signature batching
class PATBuilder {
public:
    // Add signature to aggregation batch
    PATBuilder& AddSignature(const Signature& sig, const DilithiumPublicKey& pubkey);
    
    // Check if aggregation is cost-effective
    bool IsCostEffective() const;  // Returns true if sigs >= 20
    
    // Build aggregated proof
    PATProof Build();
    
    // Get cost comparison
    struct CostComparison {
        uint32_t withoutPAT;
        uint32_t withPAT;
        int32_t savings;
    };
    CostComparison GetCostComparison() const;
};

// BP++ range proof batching
class BPPPBatcher {
public:
    // Add output value to batch
    BPPPBatcher& AddValue(Amount value);
    
    // Build batched range proof
    BPPPRangeProof Build();
    
    // Get estimated cost
    uint32_t EstimateCost() const;
};

// Aggregation thresholds (configurable)
struct AggregationConfig {
    uint32_t patThreshold = 20;   // Min signatures for PAT benefit
    bool autoAggregate = true;    // Auto-detect when to aggregate
};

} // namespace soqucoin::wallet
```

### 5. Cost Estimation (`cost.h`)

```cpp
namespace soqucoin::wallet {

// Verification cost constants (from consensus)
constexpr uint32_t DILITHIUM_VERIFY_COST = 1;
constexpr uint32_t PAT_VERIFY_COST = 20;
constexpr uint32_t BPPP_VERIFY_COST = 50;
constexpr uint32_t LATTICEFOLD_VERIFY_COST = 200;

// Fee recommendation engine
class FeeEstimator {
public:
    // Get current network fee rate
    static Amount GetRecommendedFeeRate();
    
    // Calculate fee for transaction
    static Amount CalculateFee(const Transaction& tx);
    
    // Calculate fee from verify cost estimate
    static Amount CalculateFee(const VerifyCostEstimate& cost, size_t txSize);
};

// Cost optimization advisor
class CostAdvisor {
public:
    // Analyze transaction and suggest optimizations
    static std::vector<CostOptimization> Analyze(const TransactionBuilder& builder);
};

struct CostOptimization {
    std::string description;
    uint32_t potentialSavings;
    bool applied;
};

} // namespace soqucoin::wallet
```

---

## Usage Examples

### Basic Transaction

```cpp
using namespace soqucoin::wallet;

// Create wallet with key
auto keypair = KeyPair::DeriveFromSeed(seed, "m/44'/21329'/0'/0/0");
auto address = Address::Encode(keypair.GetPublicKey());

// Build transaction
TransactionBuilder builder;
auto result = builder
    .AddInput(utxo, keypair)
    .AddOutput(recipientAddress, 1000 * COIN)
    .AddChangeOutput(changeAddress)
    .SetFeeRate(10)  // 10 satoshis per vbyte
    .Build();

if (result.IsOk()) {
    auto tx = result.Unwrap();
    // Broadcast tx
}
```

### Batch Transaction (Exchange Withdrawal)

```cpp
// 100 withdrawals - PAT aggregation automatically applied
TransactionBuilder builder;
builder.AddInput(hotWalletUtxo, hotWalletKey);

for (const auto& withdrawal : withdrawals) {
    builder.AddOutput(withdrawal.address, withdrawal.amount);
}

auto estimate = builder.EstimateVerifyCost();
// estimate.savingsFromAggregation shows ~80% savings

auto tx = builder.Build().Unwrap();
```

---

## Security Considerations

### Auditor Checklist

| Area | Requirement | Implementation |
|------|-------------|----------------|
| Key Storage | Encrypted at rest | AES-256-GCM |
| Memory Safety | Keys zeroed on free | SecureBytes class |
| Side Channels | Constant-time operations | Dilithium reference impl |
| Randomness | CSPRNG only | OS entropy source |
| Input Validation | All inputs validated | Bounds checking throughout |

### Hardware Wallet Compatibility

The API is designed for hardware wallet integration:
- Signing happens in `KeyPair::Sign()` which can be proxied to hardware
- Public keys and addresses can be derived/displayed on hardware
- Transaction preview before signing

---

## Test Vector Requirements

Each function must have test vectors covering:
1. Happy path
2. Edge cases (empty inputs, max values)
3. Error cases (invalid inputs)
4. Deterministic outputs (same seed → same keys)

See: `WALLET_TEST_VECTORS.md`

---

*Wallet API Specification v1.0-draft | January 2026*
