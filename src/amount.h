// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include "serialize.h"

#include <stdlib.h>
#include <string>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

static const CAmount COIN = 100000000;
static const CAmount CENT = 1000000;

extern const std::string CURRENCY_UNIT;

/** No amount larger than this (in shors) is valid.
 *
 * ⛔ ON SOQUCOIN THIS IS A PER-TRANSACTION CEILING, NOT A SUPPLY BOUND, AND IT
 * STRUCTURALLY CANNOT BE ONE. Bitcoin sets MAX_MONEY to its total supply, which
 * makes MoneyRange a loose sanity check no honest value approaches. Neither half
 * of that holds here:
 *
 *   1. THE SUPPLY IS UNBOUNDED. The emission schedule has a perpetual tail of
 *      2,500 SOQ per block (soqucoin.cpp GetSoqucoinBlockSubsidy), roughly
 *      1.31B SOQ a year on top of the ~46.875B head supply. No constant can
 *      bound a supply that grows forever.
 *   2. EVEN THE HEAD SUPPLY WILL NOT FIT. Accumulators ADD BEFORE THEY CHECK,
 *      e.g. validation.cpp:1947 does `nValueIn += ...` and only then calls
 *      MoneyRange. So a sum of two in-range values must not overflow, which
 *      requires 2 * MAX_MONEY <= INT64_MAX, i.e. MAX_MONEY <= ~46.1B coins.
 *      Head supply is 46.875B, already past that line. Raising MAX_MONEY to
 *      "cover the supply" would silently reintroduce the signed-overflow bug
 *      this constant exists to prevent, and the MoneyRange check downstream
 *      would be reading an already-wrapped value.
 *
 * AND A THIRD BOUND EXISTS, DISCOVERED BY TEST WHEN 40B WAS TRIED (FC4,
 * 2026-08-26): CompressAmount/DecompressAmount, the chainstate txout codec,
 * computes roughly 9n + 81 in a uint64, so any amount above
 * ~2,049,638,230,412,172,714 shors (~20.49B coins) with a non-round decimal
 * tail fails to round-trip and would silently corrupt in the UTXO database.
 * serialization_invariance_tests caught 40B * COIN - 1 decompressing to
 * garbage. The static_assert below enforces this bound too.
 *
 * So 20B coins is the cap: 4.5x above the largest consolidation observed to
 * date (the 4.45B the pool consolidation trapped), 80% of first-epoch
 * emission, 2.4% under the codec ceiling, and 4.6x under the int64 additive
 * ceiling. The consequence is real and worth knowing: NO SINGLE TRANSACTION
 * MAY MOVE MORE THAN 20B SOQ on either side; a larger treasury or exchange
 * consolidation must be split. (40B was ratified first, bead iwzf; the codec
 * bound reduced it to 20B. Raising it above ~20.49B requires replacing the
 * amount codec, which is chainstate-format surgery, not a constant bump.)
 *
 * The previous comment here claimed "maximum of 100B coins". That was wrong
 * twice over: the value is 10B, not 100B, and 100B coins in shors is 1e19,
 * which does not fit in an int64 at all. Do not "fix" the value to match a
 * comment. See bead iwzf.
 *
 * As this sanity check is used by consensus-critical validation code, the exact
 * value is consensus critical; changing it after genesis is a hard fork.
 * */
static const CAmount MAX_MONEY = 20000000000 * COIN; // 20B SOQ, a per-TX ceiling

//! The overflow bound argued for above, enforced rather than trusted: every
//! accumulator in the validation path adds two in-range amounts before it calls
//! MoneyRange, so twice MAX_MONEY has to remain representable.
static_assert(MAX_MONEY > 0 && MAX_MONEY <= 2049638230412172714LL,
              "MAX_MONEY must fit the CompressAmount codec (~9n+81 in a uint64, "
              "see the comment above): amounts past ~20.49B coins silently "
              "corrupt in the chainstate. Raising this bound means replacing "
              "the amount codec first.");
static_assert(MAX_MONEY <= 4611686018427387903LL,
              "MAX_MONEY must satisfy 2 * MAX_MONEY <= INT64_MAX: validation "
              "accumulators sum before they range-check, so a larger value makes "
              "the check read an already-overflowed total");

inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

/**
 * Fee rate in satoshis per kilobyte: CAmount / kB
 */
class CFeeRate
{
private:
    CAmount nSatoshisPerK; // unit is satoshis-per-1,000-bytes
public:
    /** Fee rate of 0 satoshis per kB */
    CFeeRate() : nSatoshisPerK(0) { }
    explicit CFeeRate(const CAmount& _nSatoshisPerK): nSatoshisPerK(_nSatoshisPerK) { }
    /** Constructor for a fee rate in satoshis per kB. The size in bytes must not exceed (2^63 - 1)*/
    CFeeRate(const CAmount& nFeePaid, size_t nBytes);
    /**
     * Return the wallet fee in koinus for the given size in bytes.
     */
    CAmount GetFee(size_t nBytes) const;
    /**
     * Return the relay fee in koinus for the given size in bytes.
     */
    CAmount GetRelayFee(size_t nBytes) const;
    /**
     * Return the fee in satoshis for a size of 1000 bytes
     */
    CAmount GetFeePerK() const { return GetFee(1000); }
    friend bool operator<(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK < b.nSatoshisPerK; }
    friend bool operator>(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK > b.nSatoshisPerK; }
    friend bool operator==(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK == b.nSatoshisPerK; }
    friend bool operator<=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK <= b.nSatoshisPerK; }
    friend bool operator>=(const CFeeRate& a, const CFeeRate& b) { return a.nSatoshisPerK >= b.nSatoshisPerK; }
    CFeeRate& operator+=(const CFeeRate& a) { nSatoshisPerK += a.nSatoshisPerK; return *this; }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSatoshisPerK);
    }
};

#endif //  BITCOIN_AMOUNT_H
