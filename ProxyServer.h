#ifndef __PROXY_SERVER_H__
#define __PROXY_SERVER_H__

#include <map>
#include <boost/thread.hpp>
#include <boost/utility.hpp>

class ProxyWorker;

class ProxyServer: boost::noncopyable
{
public:
    ProxyServer();
    ~ProxyServer();
    //void Start(unsigned int port);
    void Stop();
    void Run(unsigned int port);
    
private:
    int m_socket;
    bool m_wanna_stop;
    //boost::thread_group m_worker_threads;
    std::map<size_t, ProxyWorker*> m_workers;
};

#endif
