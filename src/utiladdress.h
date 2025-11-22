// Copyright (c) 2021-2023 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTILADDRESS_H
#define BITCOIN_UTILADDRESS_H

#include "script/standard.h"
#include <string>

class CPubKey;

/**
 * Encode a Dilithium destination (WitnessV1ScriptHash) as a Bech32m address.
 * @param dest The destination to encode
 * @param hrp The human-readable part (e.g., "sq" for Soqucoin)
 * @return The Bech32m-encoded address
 */
std::string EncodeDestination(const CTxDestination& dest, const std::string& hrp);

/**
 * Decode a Bech32m address into a destination.
 * @param str The address string
 * @param hrp The expected human-readable part
 * @return The decoded destination (or CNoDestination if invalid)
 */
CTxDestination DecodeDestination(const std::string& str, const std::string& hrp);

/**
 * Check if a destination is valid (not CNoDestination).
 * @param dest The destination to check
 * @return true if valid, false otherwise
 */
bool IsValidDestination(const CTxDestination& dest);

/**
 * Check if a destination string is valid.
 * @param str The address string
 * @param hrp The expected human-readable part
 * @return true if valid, false otherwise
 */
bool IsValidDestinationString(const std::string& str, const std::string& hrp);

/**
 * Encode a Dilithium public key as a Bech32m address.
 * @param pubkey The Dilithium public key
 * @param hrp The human-readable part (e.g., "sq" for Soqucoin)
 * @return The Bech32m-encoded address
 */
std::string EncodeDilithiumAddress(const CPubKey& pubkey, const std::string& hrp);

/**
 * Decode a Dilithium Bech32m address.
 * @param addr The address string
 * @param hrp The expected human-readable part
 * @return The decoded destination (or CNoDestination if invalid)
 */
CTxDestination DecodeDilithiumAddress(const std::string& addr, const std::string& hrp);

#endif // BITCOIN_UTILADDRESS_H
