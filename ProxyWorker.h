#ifndef __PROXY_WORKER_H__
#define __PROXY_WORKER_H__

#include <string>
#include <map>
#include <boost/thread.hpp>

#include "ProxyHeaders.h"
#include "ProxyAutoBuffer.h"

struct ssl_st;
typedef struct ssl_st SSL;
struct ssl_ctx_st;
typedef struct ssl_ctx_st SSL_CTX;

class ProxyWorker: boost::noncopyable
{
public:
    enum PROXY_WOKER_ERROR
    {
        PROXY_WOKER_ERROR_BASE = 100,
        PWE_CONNECTION_SHUT_DOWN,
        PWE_SOCKET_ERROR,
        PWE_SSL_ERROR,
        PWE_RECV_TIMEOUT,
        PWE_DNS_FAILED,
        PWE_HTTP_FORMAT_ERROR,
    };

    enum DIRECTION
    {
        NONE = 0,
        HOST = 1,
        CLIENT = 2
    };

    ProxyWorker(int clientsock);
    ProxyWorker(int clientsock, size_t sn);
    ~ProxyWorker();
    inline bool IsRunning() {return m_running;}
    void ShutDown();
    static void InitSSLCtx();
    static void DeleteSSLCtx();
    void Run();
    inline void operator() () {Run();}
    static void TransferThread(ProxyWorker *me, ProxyWorker::DIRECTION d);

private:
    inline DIRECTION ReverseDirection(DIRECTION d) {return d == NONE ? NONE : (d == HOST ? CLIENT : HOST);}
    size_t RecvFrom(DIRECTION dir, char* buff, size_t sz);
    size_t SSLRecv(SSL* ssl, char* buff, size_t sz);
    size_t SocketRecv(int sock, char* buff, size_t sz);
    void SendTo(DIRECTION dir, const char* buff, size_t len);
    void SSLSend(SSL* ssl, const char* buff, size_t len);
    void SocketSend(int sock, const char* buff, size_t len);
    bool IsKeepAlive();
    void ConnectToHost();
    void CloseConnectionToHost();
    void MethodConnect();
    void RewriteRequest();
    void RecvCompleteRequest();
    void TransferResponse();

    struct RequestHeader m_request;
    struct ResponseHeader m_response;
    bool m_bssl;
    bool m_ssl_inited;
    bool m_running;
    static SSL_CTX* m_ctx;
    static boost::mutex m_ctx_mutex;
    SSL* m_clientssl;
    SSL* m_hostssl;
    int m_clientsock;
    int m_hostsock;
    static const unsigned int INIT_BUFF_SIZE = 4096;
    std::string m_last_connected_host;
    AutoBuffer m_buffer;
    size_t m_sn;
};

#endif
