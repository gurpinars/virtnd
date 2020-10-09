/**
 * @file concurrent_map.hpp
 * @author M. Sami GÜRPINAR <sami.gurpinar@gmail.com>
 *
 * @brief
 * Implementation of concurrent_map.
 */

#pragma once

#include <map>
#include <mutex>

template<typename K, typename V>
class concurrent_map {
public:
    using const_iterator = typename std::map<K, V>::const_iterator;

    V find(const K &key);

    void insert(const K &key, V &&v);

    void insert(const K &key, const V &v);

    void update(const K &key, V &&v);

    template<typename... Args>
    void emplace(Args &&... args);

    V &operator[](const K &k);

    void erase(const_iterator it);

    void erase(const K &key);

    auto cbegin() const;

    auto cend() const;

    auto rbegin() const;

    auto rend() const;

private:
    mutable std::mutex mtx;
    std::map<K, V> container;

};

template<typename K, typename V>
V concurrent_map<K, V>::find(const K &key) {
    std::lock_guard<std::mutex> lockq{mtx};
    auto found = container.find(key);
    if (found != container.end())
        return found->second;
    return {};
}

template<typename K, typename V>
void concurrent_map<K, V>::insert(const K &key, V &&v) {
    emplace(key, std::move(v));

}

template<typename K, typename V>
void concurrent_map<K, V>::insert(const K &key, const V &v) {
    emplace(key, v);
}


template<typename K, typename V>
void concurrent_map<K, V>::update(const K &key, V &&v) {
    std::lock_guard<std::mutex> lockq{mtx};
    container[key] = std::move(v);
}

template<typename K, typename V>
template<typename... Args>
void concurrent_map<K, V>::emplace(Args &&... args) {
    std::lock_guard<std::mutex> lockq{mtx};
    container.emplace(std::forward<Args>(args)...);

}

template<typename K, typename V>
V &concurrent_map<K, V>::operator[](const K &k) {
    std::lock_guard<std::mutex> lockq{mtx};
    return container[k];
}

template<typename K, typename V>
void concurrent_map<K, V>::erase(const_iterator it) {
    std::lock_guard<std::mutex> lockq{mtx};
    container.erase(it);
}

template<typename K, typename V>
void concurrent_map<K, V>::erase(const K &key) {
    std::lock_guard<std::mutex> lockq{mtx};
    container.erase(key);
}

template<typename K, typename V>
auto concurrent_map<K, V>::cbegin() const {
    std::lock_guard<std::mutex> lockq{mtx};
    return container.cbegin();
}

template<typename K, typename V>
auto concurrent_map<K, V>::cend() const {
    std::lock_guard<std::mutex> lockq{mtx};
    return container.cend();
}

template<typename K, typename V>
auto concurrent_map<K, V>::rbegin() const {
    std::lock_guard<std::mutex> lockq{mtx};
    return container.rbegin();
}

template<typename K, typename V>
auto concurrent_map<K, V>::rend() const {
    std::lock_guard<std::mutex> lockq{mtx};
    return container.rend();
}
