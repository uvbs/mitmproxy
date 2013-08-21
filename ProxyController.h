#ifndef __PROXY_CONTROLLER_H__
#define __PROXY_CONTROLLER_H__

#include <sys/types.h>
#include <boost/thread.hpp>
#include <boost/utility.hpp>

class ProxyServer;

typedef void (*proxy_callback_function)(const char* data, size_t len);

class ProxyController: boost::noncopyable
{
public:
    static ProxyController& GetController();
    ~ProxyController();
    void Start(unsigned int port);
    void Stop();
    void SetRequestCallback(proxy_callback_function f);
    void SetResponseCallback(proxy_callback_function f);
    void CallRequestCallback(const char* data, size_t len);
    void CallResponseCallback(const char* data, size_t len);
private:
    ProxyServer* GetProxyServer();
    ProxyController();
    proxy_callback_function m_request_callback;
    proxy_callback_function m_response_callback;
    boost::thread* m_server_thread;
    bool m_running;
};


#endif