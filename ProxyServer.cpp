#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <boost/bind.hpp>
#include "ProxyServer.h"
#include "ProxyWorker.h"
#include "ProxyException.h"

ProxyServer::ProxyServer():
m_socket(0)
{
    int flag = 1;
    int len = sizeof flag;
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
        throw ProxyException("Create socket failed");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, len) < 0)
    {
        close(sock);
        throw ProxyException("socket error");
    }

    m_socket = sock;
}

ProxyServer::~ProxyServer()
{
    if (m_socket)
        close(m_socket);
}

void ProxyServer::Stop()
{
    m_wanna_stop = true;
    close(m_socket);
}

void WorkerThread(ProxyWorker* worker)
{
    worker->Run();
}

void ProxyServer::Run(unsigned int port)
{
    try
    {
        m_wanna_stop = false;
        signal(SIGPIPE, SIG_IGN);   //避免由于客户端发送Request之后就断开连接而导致的Broken_Pipe错误
        std::map<size_t, ProxyWorker*>::iterator worker_iter;
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

        if (listen(m_socket, 5) < 0)
        {
            close(m_socket);
            throw ProxyException("Listen failed");
        }

        ProxyWorker::InitSSLCtx();
        size_t sn = 1;
        while(!m_wanna_stop)
        {
            sockaddr clientaddr;
            socklen_t salen = sizeof(clientaddr);
            int clientsock = accept(m_socket, &clientaddr, &salen);

            if (m_wanna_stop)
                break;

            //remove terminated worker
            worker_iter = m_workers.begin();
            while(worker_iter != m_workers.end())
            {
                if (worker_iter->second && !worker_iter->second->IsRunning())
                {
                    delete worker_iter->second;
                    worker_iter->second = NULL;
                    m_workers.erase(worker_iter++);
                }
                else
                    ++worker_iter;
            }

            if (clientsock == 0)
                continue;

            ProxyWorker* pw = new ProxyWorker(clientsock, sn);
            boost::thread(&ProxyWorker::Run, pw);
            m_workers[sn] = pw;
            ++sn;
        }

        //关闭所有套接字
        worker_iter = m_workers.begin();
        while(worker_iter != m_workers.end())
        {
            worker_iter->second->ShutDown();
            ++worker_iter;
        }

        //等待所有线程退出，相当于join
        worker_iter = m_workers.begin();
        while(worker_iter != m_workers.end())
        {
            while(worker_iter->second->IsRunning())
                sleep(0);
            delete worker_iter->second;
            m_workers.erase(worker_iter++);
        }

        ProxyWorker::DeleteSSLCtx();
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;

    }
    catch (...)
    {
        std::cout << "unhandled error" << std::endl;
    }
}
