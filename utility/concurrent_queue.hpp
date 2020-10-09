/**
 * @file concurrent_queue.hpp
 * @author M. Sami GÜRPINAR <sami.gurpinar@gmail.com>
 *
 * @brief
 * Implementation of concurrent_queue.
 *
 */

#pragma once

#include <mutex>
#include <condition_variable>
#include <queue>

template<typename T>
class concurrent_queue {
public:
    void push_back(T &&data);
    
    void push_back(const T &data);
    
    bool empty() const;

    bool try_pop(T &popped);

    void wait_and_pop(T &popped);

private:
    template<typename... Args>
    void emplace_back(Args &&... args);

    mutable std::mutex mtx;
    mutable std::condition_variable cv;
    std::queue<T> m_queue;

};

template<typename T>
void concurrent_dequeue<T>::push_back(T &&data) {
    emplace_back(std::move(data));

}

template<typename T>
void concurrent_dequeue<T>::push_back(const T &data) {
    emplace_back(data);
}

template<typename T>
bool concurrent_dequeue<T>::empty() const {
    std::lock_guard<std::mutex> lockg{mtx};
    return m_queue.empty();
}

template<typename T>
bool concurrent_dequeue<T>::try_pop(T &popped) {
    std::unique_lock<std::mutex> lockq{mtx};
    if (m_queue.empty())
        return false;

    try {
        popped = std::move(m_queue.front());
        m_queue.pop_front();
    } catch (...) {
        return false;
    }

    return true;
}

template<typename T>
void concurrent_dequeue<T>::wait_and_pop(T &popped) {
    std::unique_lock<std::mutex> lockq{mtx};
    while (m_queue.empty())
        cv.wait(lockq);

    try {
        popped = std::move(m_queue.front());
        m_queue.pop_front();
    } catch (...) {}
}

template<typename T>
template<typename... Args>
void concurrent_dequeue<T>::emplace_back(Args &&... args) {
    std::unique_lock<std::mutex> lockq{mtx};
    m_queue.emplace_back(std::forward<Args>(args)...);
    cv.notify_one();
}
