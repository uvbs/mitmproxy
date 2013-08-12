
#ifndef __PROXY_SERVER_H__
#define __PROXY_SERVER_H__

class ProxyServer
{
public:
    ProxyServer();
    ~ProxyServer();
    void Run(int port, unsigned int maxconn = 5);
private:

    int m_socket;
    bool m_wanna_stop;
};

#endif
