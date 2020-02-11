#ifndef VIRTND_OBSERVER_HPP
#define VIRTND_OBSERVER_HPP
#include <vector>
#include "pk_buff.h"

template <typename T, bool is_rvalue=std::is_rvalue_reference<T>::value>
class Observer {
public:
    using data_t = typename std::conditional<is_rvalue, typename std::decay<T>::type, const T&>::type;
    virtual void update(data_t data) = 0;
};

template <typename T, bool is_rvalue=std::is_rvalue_reference<T>::value>
class Subject {
public:
    using data_t = typename std::conditional<is_rvalue, typename std::decay<T>::type, const T&>::type;
    void attach(Observer<T> *ob) {
        m_observers.push_back(ob);
    }
    
    void notify(data_t data) {
        for (auto &ob:m_observers) {
        ob->update(std::move(data));
        }
    }

private:
    std::vector<Observer<T>*> m_observers;
};





#endif
