// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2026 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"
#include "scheduler.h"
#include "sync.h"
#include "util.h"

#include <future>
#include <list>
#include <unordered_map>

/**
 * MainSignalsInstance manages a list of CValidationInterface callbacks.
 * It uses reference counting to safely handle callbacks that are in the
 * process of being executed when they are unregistered.
 */
struct MainSignalsInstance {
private:
    CCriticalSection m_mutex;

    /**
     * List entries consist of a callback pointer and reference count.
     * The count is equal to the number of current executions of that entry,
     * plus 1 if it's registered. It cannot be 0 because that would imply
     * it is unregistered and also not being executed (so shouldn't exist).
     */
    struct ListEntry {
        CValidationInterface* callbacks;
        int count = 1;
    };
    std::list<ListEntry> m_list GUARDED_BY(m_mutex);
    std::unordered_map<CValidationInterface*, std::list<ListEntry>::iterator> m_map GUARDED_BY(m_mutex);

public:
    // Single-threaded scheduler client ensures all callbacks happen in-order
    SingleThreadedSchedulerClient m_schedulerClient;

    explicit MainSignalsInstance(CScheduler* pscheduler) : m_schedulerClient(pscheduler) {}

    void Register(CValidationInterface* callbacks)
    {
        LOCK(m_mutex);
        auto inserted = m_map.emplace(callbacks, m_list.end());
        if (inserted.second) {
            inserted.first->second = m_list.emplace(m_list.end());
        }
        inserted.first->second->callbacks = callbacks;
        inserted.first->second->count = 1;
    }

    void Unregister(CValidationInterface* callbacks)
    {
        LOCK(m_mutex);
        auto it = m_map.find(callbacks);
        if (it != m_map.end()) {
            if (!--it->second->count) {
                m_list.erase(it->second);
            }
            m_map.erase(it);
        }
    }

    /**
     * Clear unregisters every previously registered callback.
     */
    void Clear()
    {
        LOCK(m_mutex);
        for (const auto& entry : m_map) {
            if (!--entry.second->count) {
                m_list.erase(entry.second);
            }
        }
        m_map.clear();
    }

    /**
     * Iterate over all registered callbacks and invoke the given function.
     * Uses reference counting to safely handle concurrent unregistration.
     */
    template <typename F>
    void Iterate(F&& f)
    {
        std::unique_lock<CCriticalSection> lock(m_mutex);
        for (auto it = m_list.begin(); it != m_list.end();) {
            ++it->count;
            CValidationInterface* callbacks = it->callbacks;
            {
                lock.unlock();
                f(callbacks);
                lock.lock();
            }
            it = --it->count ? std::next(it) : m_list.erase(it);
        }
    }
};

static CMainSignals g_signals;

void CMainSignals::RegisterBackgroundSignalScheduler(CScheduler& scheduler)
{
    assert(!m_internals);
    m_internals.reset(new MainSignalsInstance(&scheduler));
}

void CMainSignals::UnregisterBackgroundSignalScheduler()
{
    m_internals.reset(nullptr);
}

void CMainSignals::FlushBackgroundCallbacks()
{
    if (m_internals) {
        m_internals->m_schedulerClient.EmptyQueue();
    }
}

size_t CMainSignals::CallbacksPending()
{
    if (!m_internals) return 0;
    return m_internals->m_schedulerClient.CallbacksPending();
}

CMainSignals& GetMainSignals()
{
    return g_signals;
}

void RegisterBackgroundSignalScheduler(CScheduler& scheduler)
{
    g_signals.RegisterBackgroundSignalScheduler(scheduler);
}

void UnregisterBackgroundSignalScheduler()
{
    g_signals.UnregisterBackgroundSignalScheduler();
}

void FlushBackgroundCallbacks()
{
    g_signals.FlushBackgroundCallbacks();
}

void RegisterValidationInterface(CValidationInterface* pwalletIn)
{
    if (g_signals.m_internals) {
        g_signals.m_internals->Register(pwalletIn);
    }
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn)
{
    if (g_signals.m_internals) {
        g_signals.m_internals->Unregister(pwalletIn);
    }
}

void UnregisterAllValidationInterfaces()
{
    if (g_signals.m_internals) {
        g_signals.m_internals->Clear();
    }
}

void CallFunctionInValidationInterfaceQueue(std::function<void()> func)
{
    if (g_signals.m_internals) {
        g_signals.m_internals->m_schedulerClient.AddToProcessQueue(std::move(func));
    }
}

void SyncWithValidationInterfaceQueue()
{
    // Block until the validation queue drains
    if (!g_signals.m_internals) return;

    std::promise<void> promise;
    CallFunctionInValidationInterfaceQueue([&promise] {
        promise.set_value();
    });
    promise.get_future().wait();
}

// Signal dispatch implementations - SYNCHRONOUS to avoid race conditions during high-frequency mining
// This is simpler and safer than async dispatch for the current use case.

void CMainSignals::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->UpdatedBlockTip(pindexNew, pindexFork, fInitialDownload);
    });
}

void CMainSignals::SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int posInBlock)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->SyncTransaction(tx, pindex, posInBlock);
    });
}

void CMainSignals::UpdatedTransaction(const uint256& hash)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->UpdatedTransaction(hash);
    });
}

void CMainSignals::SetBestChain(const CBlockLocator& locator)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->SetBestChain(locator);
    });
}

void CMainSignals::Broadcast(int64_t nBestBlockTime, CConnman* connman)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->ResendWalletTransactions(nBestBlockTime, connman);
    });
}

void CMainSignals::BlockChecked(const CBlock& block, const CValidationState& state)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->BlockChecked(block, state);
    });
}

void CMainSignals::ScriptForMining(std::shared_ptr<CReserveScript>& coinbaseScript)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->GetScriptForMining(coinbaseScript);
    });
}

void CMainSignals::BlockFound(const uint256& hash)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->ResetRequestCount(hash);
    });
}

void CMainSignals::NewPoWValidBlock(const CBlockIndex* pindex, const std::shared_ptr<const CBlock>& block)
{
    if (!m_internals) return;
    m_internals->Iterate([&](CValidationInterface* callbacks) {
        callbacks->NewPoWValidBlock(pindex, block);
    });
}
