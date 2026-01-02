// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2020-2022 The Soqucoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "scheduler.h"

#include "reverselock.h"

#include <assert.h>
#include <boost/bind/bind.hpp>
#include <utility>

CScheduler::CScheduler() : nThreadsServicingQueue(0), stopRequested(false), stopWhenEmpty(false)
{
}

CScheduler::~CScheduler()
{
    assert(nThreadsServicingQueue == 0);
}


#if BOOST_VERSION < 105000
static boost::system_time toPosixTime(const boost::chrono::system_clock::time_point& t)
{
    return boost::posix_time::from_time_t(boost::chrono::system_clock::to_time_t(t));
}
#endif

void CScheduler::serviceQueue()
{
    boost::unique_lock<boost::mutex> lock(newTaskMutex);
    ++nThreadsServicingQueue;

    // newTaskMutex is locked throughout this loop EXCEPT
    // when the thread is waiting or when the user's function
    // is called.
    while (!shouldStop()) {
        try {
            while (!shouldStop() && taskQueue.empty()) {
                // Wait until there is something to do.
                newTaskScheduled.wait(lock);
            }

            // Wait until either there is a new task, or until
            // the time of the first item on the queue:

// wait_until needs boost 1.50 or later; older versions have timed_wait:
#if BOOST_VERSION < 105000
            while (!shouldStop() && !taskQueue.empty() &&
                   newTaskScheduled.timed_wait(lock, toPosixTime(taskQueue.begin()->first))) {
                // Keep waiting until timeout
            }
#else
            // Some boost versions have a conflicting overload of wait_until that returns void.
            // Explicitly use a template here to avoid hitting that overload.
            while (!shouldStop() && !taskQueue.empty()) {
                boost::chrono::system_clock::time_point timeToWaitFor = taskQueue.begin()->first;
                if (newTaskScheduled.wait_until<>(lock, timeToWaitFor) == boost::cv_status::timeout)
                    break; // Exit loop after timeout, it means we reached the time of the event
            }
#endif
            // If there are multiple threads, the queue can empty while we're waiting (another
            // thread may service the task we were waiting on).
            if (shouldStop() || taskQueue.empty())
                continue;

            Function f = taskQueue.begin()->second;
            taskQueue.erase(taskQueue.begin());

            {
                // Unlock before calling f, so it can reschedule itself or another task
                // without deadlocking:
                reverse_lock<boost::unique_lock<boost::mutex> > rlock(lock);
                f();
            }
        } catch (...) {
            --nThreadsServicingQueue;
            throw;
        }
    }
    --nThreadsServicingQueue;
    newTaskScheduled.notify_one();
}

void CScheduler::stop(bool drain)
{
    {
        boost::unique_lock<boost::mutex> lock(newTaskMutex);
        if (drain)
            stopWhenEmpty = true;
        else
            stopRequested = true;
    }
    newTaskScheduled.notify_all();
}

void CScheduler::schedule(CScheduler::Function f, boost::chrono::system_clock::time_point t)
{
    {
        boost::unique_lock<boost::mutex> lock(newTaskMutex);
        taskQueue.insert(std::make_pair(t, f));
    }
    newTaskScheduled.notify_one();
}

void CScheduler::scheduleFromNow(CScheduler::Function f, int64_t deltaSeconds)
{
    schedule(f, boost::chrono::system_clock::now() + boost::chrono::seconds(deltaSeconds));
}

static void Repeat(CScheduler* s, CScheduler::Function f, int64_t deltaSeconds)
{
    f();
    s->scheduleFromNow(boost::bind(&Repeat, s, f, deltaSeconds), deltaSeconds);
}

void CScheduler::scheduleEvery(CScheduler::Function f, int64_t deltaSeconds)
{
    scheduleFromNow(boost::bind(&Repeat, this, f, deltaSeconds), deltaSeconds);
}

size_t CScheduler::getQueueInfo(boost::chrono::system_clock::time_point& first,
    boost::chrono::system_clock::time_point& last) const
{
    boost::unique_lock<boost::mutex> lock(newTaskMutex);
    size_t result = taskQueue.size();
    if (!taskQueue.empty()) {
        first = taskQueue.begin()->first;
        last = taskQueue.rbegin()->first;
    }
    return result;
}

// SingleThreadedSchedulerClient methods

void SingleThreadedSchedulerClient::MaybeScheduleProcessQueue()
{
    // Called with m_cs_callbacks_pending held
    if (m_are_callbacks_running) return;
    if (m_callbacks_pending.empty()) return;
    m_are_callbacks_running = true;

    m_pscheduler->schedule(std::bind(&SingleThreadedSchedulerClient::ProcessQueue, this),
        boost::chrono::system_clock::now());
}

void SingleThreadedSchedulerClient::ProcessQueue()
{
    std::function<void()> callback;
    {
        boost::unique_lock<boost::mutex> lock(m_cs_callbacks_pending);
        if (m_callbacks_pending.empty()) {
            m_are_callbacks_running = false;
            return;
        }
        callback = std::move(m_callbacks_pending.front());
        m_callbacks_pending.pop_front();
    }

    // Release lock before calling callback - this allows new callbacks to be added
    // while we're processing, which will trigger MaybeScheduleProcessQueue again
    callback();

    // After callback completes, schedule next one if any
    {
        boost::unique_lock<boost::mutex> lock(m_cs_callbacks_pending);
        if (m_callbacks_pending.empty()) {
            m_are_callbacks_running = false;
        } else {
            // Schedule next callback
            m_pscheduler->schedule(std::bind(&SingleThreadedSchedulerClient::ProcessQueue, this),
                boost::chrono::system_clock::now());
        }
    }
}

void SingleThreadedSchedulerClient::AddToProcessQueue(std::function<void()> func)
{
    boost::unique_lock<boost::mutex> lock(m_cs_callbacks_pending);
    m_callbacks_pending.emplace_back(std::move(func));
    MaybeScheduleProcessQueue();
}

void SingleThreadedSchedulerClient::EmptyQueue()
{
    // Process all pending callbacks on the calling thread
    while (true) {
        std::function<void()> callback;
        {
            boost::unique_lock<boost::mutex> lock(m_cs_callbacks_pending);
            if (m_callbacks_pending.empty()) {
                m_are_callbacks_running = false;
                return;
            }
            callback = std::move(m_callbacks_pending.front());
            m_callbacks_pending.pop_front();
        }
        callback();
    }
}

size_t SingleThreadedSchedulerClient::CallbacksPending()
{
    boost::unique_lock<boost::mutex> lock(m_cs_callbacks_pending);
    return m_callbacks_pending.size();
}
