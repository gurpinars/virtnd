#pragma once

#include <map>
#include <mutex>


template<typename _Key, typename _Val, typename const_iterator =typename decltype(std::map<_Key, _Val>{})::const_iterator>
class concurrent_map {
public:
    _Val find(const _Key k) {
        std::lock_guard<std::mutex> lockq{mtx};
        auto found = container.find(k);
        if (found != container.end())
            return found->second;
        return {};
    }

    void insert(const _Key k, _Val &&v) {
        std::lock_guard<std::mutex> lockq{mtx};
        container.insert(std::make_pair(k, std::forward<T>(v)));
    }

    void update(const _Key k, _Val &&v) {
        std::lock_guard<std::mutex> lockq{mtx};
        container[k] = std::forward<T>(v);
    }

    void erase(const_iterator it) {
        std::lock_guard<std::mutex> lockq{mtx};
        container.erase(it);
    }

    auto cbegin() const {
        std::lock_guard<std::mutex> lockq{mtx};
        return container.cbegin();
    }

    auto cend() const {
        std::lock_guard<std::mutex> lockq{mtx};
        return container.cend();
    }


private:
    mutable std::mutex mtx;
    std::map<_Key, _Val> container;

};



