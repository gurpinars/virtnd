#ifndef VIRTND_OBSERVER_HPP
#define VIRTND_OBSERVER_HPP
#include <vector>
#include "pk_buff.h"


class Observer {
public:
    virtual void update(pk_buff data) = 0;
};


class Subject {
public:
    void attach(Observer *ob) {
        m_observers.push_back(ob);
    }
    
    void notify(pk_buff data) {
        for (auto &ob:m_observers) {
        ob->update(data);

        }
    }

private:
    std::vector<Observer*> m_observers;
};





#endif
