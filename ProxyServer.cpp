#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include "ProxyServer.h"
#include "ProxyWorker.h"
#include "ProxyException.h"

ProxyServer::ProxyServer():
m_socket(0)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        throw ProxyException("Create socket failed");

    m_socket = sock;
}

ProxyServer::~ProxyServer()
{
    if (m_socket)
        close(m_socket);
}

void workthread(int clientsock, size_t sn)
{
    ProxyWorker worker(clientsock, sn);
    worker.Run();
}
void ProxyServer::Run(int port, unsigned int maxconn)
{
    signal(SIGPIPE, SIG_IGN);   //避免由于客户端发送Request之后就断开连接而导致的Broken_Pipe错误

    sockaddr_in sa;
    bzero(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);

    if (bind(m_socket, (sockaddr*)&sa, sizeof(sa)) < 0)
    {
        close(m_socket);
        throw ProxyException("Bind failed");
    }

    if (listen(m_socket, maxconn) < 0)
    {
        close(m_socket);
        throw ProxyException("Listen failed");
    }

    ProxyWorker::InitSSLCtx();
    m_wanna_stop = false;
    size_t sn = 1;
    while(!m_wanna_stop)
    {
        boost::this_thread::interruption_point();
        sockaddr clientaddr;
        socklen_t salen = sizeof(clientaddr);
        int clientsock = accept(m_socket, &clientaddr, &salen);
        if (clientsock == 0)
            continue;
        boost::thread t(workthread, clientsock, sn++);
    }
    ProxyWorker::DeleteSSLCtx();
}
