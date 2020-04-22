#pragma once

#include <mutex>
#include <condition_variable>
#include <queue>

template<typename T>
class concurrent_queue {
public:
    void push(T data) {
        std::unique_lock<std::mutex> lockq{mtx};
        m_queue.push(std::move(data));

        lockq.unlock();
        cv.notify_one();
    }

    bool empty() const {
        std::lock_guard<std::mutex> lockg{mtx};
        return m_queue.empty();
    }

    bool try_pop(T &popped) {
        std::unique_lock<std::mutex> lockq{mtx};
        if (m_queue.empty())
            return false;

        try {
            popped = std::move(m_queue.front());
            m_queue.pop();
        } catch (...) {
            return false;
        }

        return true;
    }

    void wait_and_pop(T &popped) {
        std::unique_lock<std::mutex> lockq{mtx};
        while (m_queue.empty())
            cv.wait(lockq);

        try {
            popped = std::move(m_queue.front());
            m_queue.pop();
        } catch (...) {}
    }

private:
    mutable std::mutex mtx;
    mutable std::condition_variable cv;
    std::queue<T> m_queue;

};
