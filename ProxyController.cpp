#include "ProxyController.h"
#include "ProxyServer.h"
#include <stdlib.h>

ProxyController& ProxyController::GetController()
{
    static ProxyController controller;
    return controller;
}

ProxyController::~ProxyController()
{

}

void ProxyController::SetRequestCallback(proxy_callback_function f)
{
    m_request_callback = f;
}

void ProxyController::SetResponseCallback(proxy_callback_function f)
{
    m_response_callback = f;
}

void ProxyController::CallRequestCallback(const char* data, size_t len)
{
    if (m_request_callback)
        m_request_callback(data, len);
}

void ProxyController::CallResponseCallback(const char* data, size_t len)
{
    if (m_response_callback)
        m_response_callback(data, len);
}

void ProxyController::Start(unsigned int port)
{
    if (m_running)
        return;
    m_server_thread = new boost::thread(boost::bind(&ProxyServer::Run, GetProxyServer(), port));
    m_running = true;
}

void ProxyController::Stop()
{
    if (!m_running)
        return;
    m_running = false;
    std::cout << "controller stoped" << std::endl;
    GetProxyServer()->Stop();
    m_server_thread->join();
}

ProxyController::ProxyController():
m_request_callback(NULL),
m_response_callback(NULL),
m_running(false)
{

}

ProxyServer* ProxyController::GetProxyServer()
{
    static ProxyServer s;
    return &s;
}