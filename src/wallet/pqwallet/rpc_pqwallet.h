// Copyright (c) 2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOQUCOIN_WALLET_RPC_PQWALLET_H
#define SOQUCOIN_WALLET_RPC_PQWALLET_H

/**
 * @file rpc_pqwallet.h
 * @brief RPC command registration for PQ wallet
 *
 * @see rpc_pqwallet.cpp for implementation
 */

class CRPCTable;

/**
 * @brief Register PQ wallet RPC commands
 *
 * Registers the following commands:
 * - pqgetnewaddress: Generate new Dilithium address
 * - pqvalidateaddress: Validate PQ address
 * - pqestimatefeerate: Estimate verification cost
 * - pqwalletinfo: Get wallet library info
 *
 * @param t RPC table to register commands with
 */
void RegisterPQWalletRPCCommands(CRPCTable& t);

#endif // SOQUCOIN_WALLET_RPC_PQWALLET_H
