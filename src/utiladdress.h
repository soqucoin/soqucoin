// Copyright (c) 2021-2023 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTILADDRESS_H
#define BITCOIN_UTILADDRESS_H

#include "script/standard.h"
#include <string>
#include <vector>

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

/**
 * Encode a witness version 6 program as a Bech32m address.
 * @param program The 32-byte witness program, in the order its bytes sit in the output script
 * @param hrp The human-readable part
 * @return The Bech32m-encoded address, or an empty string if the program is not 32 bytes
 */
std::string EncodeWitnessV6Address(const std::vector<unsigned char>& program, const std::string& hrp);

/**
 * Decode a witness version 6 Bech32m address.
 * @param str The address string
 * @param hrp The expected human-readable part
 * @param programRet The 32-byte witness program, in the order its bytes sit in the output script;
 *                   written only when the function returns true
 * @return true if str is a witness version 6 address with a 32-byte program for hrp
 */
bool DecodeWitnessV6Address(const std::string& str, const std::string& hrp, std::vector<unsigned char>& programRet);

#endif // BITCOIN_UTILADDRESS_H
