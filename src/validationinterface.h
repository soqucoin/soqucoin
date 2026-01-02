// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "validation.h"

#include <functional>
#include <memory>

class CBlockIndex;
struct CBlockLocator;
class CConnman;
class CReserveScript;
class CScheduler;

// Forward declaration
struct MainSignalsInstance;

// These functions dispatch to one or all registered wallets

/** Register the scheduler to use for background signal processing */
void RegisterBackgroundSignalScheduler(CScheduler& scheduler);
/** Unregister the scheduler from the background signal processing */
void UnregisterBackgroundSignalScheduler();
/** Flush any remaining callbacks in the validation interface queue */
void FlushBackgroundCallbacks();

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(class CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(class CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();

/**
 * Pushes a function to call onto the internal callback queue.
 */
void CallFunctionInValidationInterfaceQueue(std::function<void()> func);

/**
 * Blocks until all validation interface callbacks are complete.
 */
void SyncWithValidationInterfaceQueue();

class CValidationInterface
{
public:
    /**
     * Virtual destructor for proper polymorphic destruction
     */
    virtual ~CValidationInterface() = default;

    // Callbacks - all public so MainSignalsInstance can invoke them
    virtual void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) {}
    virtual void SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int posInBlock) {}
    virtual void SetBestChain(const CBlockLocator& locator) {}
    virtual void UpdatedTransaction(const uint256& hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman) {}
    virtual void BlockChecked(const CBlock&, const CValidationState&) {}
    virtual void GetScriptForMining(std::shared_ptr<CReserveScript>&) {}
    virtual void ResetRequestCount(const uint256& hash) {}
    virtual void NewPoWValidBlock(const CBlockIndex* pindex, const std::shared_ptr<const CBlock>& block) {}
};

struct CMainSignals {
    /** Constant for transactions not in a block */
    static const int SYNC_TRANSACTION_NOT_IN_BLOCK = -1;

    /** Internal implementation - handles callback scheduling */
    std::unique_ptr<MainSignalsInstance> m_internals;

    /** Initialize with a scheduler for background processing */
    void RegisterBackgroundSignalScheduler(CScheduler& scheduler);
    void UnregisterBackgroundSignalScheduler();
    void FlushBackgroundCallbacks();
    size_t CallbacksPending();

    // Signal dispatch methods - these queue to the scheduler
    void UpdatedBlockTip(const CBlockIndex*, const CBlockIndex*, bool fInitialDownload);
    void SyncTransaction(const CTransaction&, const CBlockIndex* pindex, int posInBlock);
    void UpdatedTransaction(const uint256&);
    void SetBestChain(const CBlockLocator&);
    void Broadcast(int64_t nBestBlockTime, CConnman* connman);
    void BlockChecked(const CBlock&, const CValidationState&);
    void ScriptForMining(std::shared_ptr<CReserveScript>&);
    void BlockFound(const uint256&);
    void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>&);
};

CMainSignals& GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H
