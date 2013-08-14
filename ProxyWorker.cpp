#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/regex.hpp>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ProxyWorker.h"
#include "ProxyException.h"

static boost::mutex debugmu;
#define sndebug(msg) {debugmu.lock(); std::cout << "#" << m_sn << ": " << msg << std::endl; debugmu.unlock();}
#define debug(msg) {debugmu.lock(); std::cout << msg << std::endl; debugmu.unlock();}
static boost::mutex fdebugmu;
#define fdebug(msg, sn)\
{\
    fdebugmu.lock();\
    std::ofstream fs("log.txt", std::fstream::app);\
    fs << "#" << sn << std::endl << msg << std::endl;\
    fs.close();\
    fdebugmu.unlock();\
}

template<typename T>
T Min(T a, T b)
{
    return a < b ? a : b;
}

template<typename T>
T Max(T a, T b)
{
    return a > b ? a : b;
}

bool SameStringIgnoreCase(const std::string &s1, const std::string &s2)
{
    if (s1.length() != s2.length())
        return false;

    const char offset = 'a' - 'A';
    for (size_t i = 0; i < s1.length(); ++i)
    {
        if (s1[i] != s2[i])
        {
            char bigc = Max(s1[i], s2[i]);
            char smallc = Min(s1[i], s2[i]);
            if ('a' <= bigc && bigc <= 'z' && bigc - offset == smallc)
                continue;
            else
                return false;
        }
    }
    return true;
}

int WorkerCount(int n)
{
    static boost::mutex cntmu;
    static int cnt = 0;
    static int max_cnt = 0;
    cntmu.lock();
    cnt += n;
    max_cnt = max_cnt > cnt ? max_cnt : cnt;
    debug( "Workers " << cnt << "/" << max_cnt)
    cntmu.unlock();
    return cnt;
}

bool IsIpAddr(const std::string &dn)
{
    boost::regex ippattern("^[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}$");
    boost::cmatch result;
    if(regex_match(dn.c_str(), result, ippattern))
        return true;
    return false;
}

char** GetIpAddr(const char * dn)
{
    struct hostent *ph = NULL;
    if( (ph = gethostbyname(dn) ) == NULL )
    {
        return NULL; 
    }
    if (ph->h_addrtype != AF_INET)
    {
        debug("None ipv4 address")
        return NULL;
    }
    return ph->h_addr_list;
}

bool IsChunkEnded(const char* p, int len)
{
    unsigned int proceedcnt = 0;
    unsigned int chunksz;
    while(1)
    {
        if (sscanf(p, "%x", &chunksz) != 1)
            return false;
        if (chunksz == 0)
            return true;

        proceedcnt = strstr(p, "\r\n") + 4 + chunksz - p;
        if (proceedcnt >= len)
            return false;
        p += proceedcnt;
        len -= proceedcnt;
    }
}

bool IsHttpDataCompleted(std::map<std::string, std::string> &header, const char* content, size_t len)
{
    bool bchunked;
    size_t contentlen;
    if (header.find("Transfer-Encoding") != header.end()
            && header["Transfer-Encoding"] == "chunked")
        bchunked = true;
    else if (header.find("Content-Length") != header.end())
        contentlen = atoi(header["Content-Length"].c_str());
    else
        return true;

    if (!bchunked && len >= contentlen)
        return true;

    if (bchunked && IsChunkEnded(content, len))
        return true;

    return false;
}

SSL_CTX* ProxyWorker::m_ctx = NULL;
boost::mutex ProxyWorker::m_ctx_mutex;

ProxyWorker::ProxyWorker(int clientsock):
    m_clientsock(clientsock),
    m_wanna_stop(false),
    m_clientssl(NULL),
    m_hostssl(NULL),
    m_hostsock(0),
    m_ssl_inited(false),
    m_bssl(false),
    m_sn(0),
    m_last_connected_host("")
{
    WorkerCount(1);
}

ProxyWorker::ProxyWorker(int clientsock, size_t sn):
    m_clientsock(clientsock),
    m_wanna_stop(false),
    m_clientssl(NULL),
    m_hostssl(NULL),
    m_hostsock(0),
    m_ssl_inited(false),
    m_bssl(false),
    m_sn(sn),
    m_last_connected_host("")
{
    WorkerCount(1);
}

ProxyWorker::~ProxyWorker()
{
    if (m_clientsock)
        close(m_clientsock);
    if (m_hostsock)
        close(m_hostsock);
    if (m_clientssl)
        SSL_free(m_clientssl);
    if (m_hostssl)
        SSL_free(m_hostssl);
    
    WorkerCount(-1);
}

void ProxyWorker::InitSSLCtx()
{
    if (m_ctx)
        return;

    CRYPTO_malloc_init();
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    ERR_load_ERR_strings();
    ERR_load_crypto_strings(); 

    m_ctx = SSL_CTX_new(SSLv23_method());
    
    if (SSL_CTX_use_certificate_file(m_ctx, "Cert/cert.crt", SSL_FILETYPE_PEM) <= 0)
    {  
        ERR_print_errors_fp(stderr);  
        debug("SSL_CTX_use_certificate_file error.")  
        return;  
    }  
    if (SSL_CTX_use_PrivateKey_file(m_ctx, "Cert/privkey.pem", SSL_FILETYPE_PEM) <= 0)
    {  
        ERR_print_errors_fp(stderr);  
        debug("SSL_CTX_use_PrivateKey_file error.")
        return;  
    }  
  
    if (!SSL_CTX_check_private_key(m_ctx))
    {  
        ERR_print_errors_fp(stderr);  
        debug("SSL_CTX_check_private_key error.")  
        return;  
    }
}

void ProxyWorker::DeleteSSLCtx()
{
    if (m_ctx)
        SSL_CTX_free(m_ctx);
}

size_t ProxyWorker::RecvFrom(DIRECTION d, char* buff, size_t sz)
{
    if (d == NONE)
        throw ProxyException("NONE DIRECTION");
    if (m_bssl)
        return SSLRecv(d == HOST ? m_hostssl : m_clientssl, buff, sz);
    else
        return SocketRecv(d == HOST ? m_hostsock : m_clientsock, buff, sz);
}

size_t ProxyWorker::SSLRecv(SSL* ssl, char* buff, size_t sz)
{
    int nread = SSL_read (ssl, buff, sz);
    if (nread < 0)
    {
        if (errno == EAGAIN)
            throw ProxyException(RECV_TIMEOUT, __FUNCTION__);
        throw ProxyException(SSL_ERROR);
    }
    else if (nread == 0 && sz != 0)
    {
        throw ProxyException(CONNECTION_SHUT_DOWN, __FUNCTION__);
    }
    return nread;
}

size_t ProxyWorker::SocketRecv(int sock, char* buff, size_t sz)
{
    int nread = recv(sock, buff, sz, 0);
    if (nread < 0)
    {
        if (errno == EAGAIN)
            throw ProxyException(RECV_TIMEOUT, __FUNCTION__);
        throw ProxyException(SOCKET_ERROR, __FUNCTION__);
    }
    else if (nread == 0 && sz != 0)
    {
        throw ProxyException(CONNECTION_SHUT_DOWN, __FUNCTION__);
    }
    return nread;
}

void ProxyWorker::SendTo(DIRECTION d, const char* buff, size_t len)
{
    if (d == NONE)
        throw ProxyException("NONE DIRECTION");
    if (m_bssl)
        SSLSend(d == HOST ? m_hostssl : m_clientssl, buff, len);
    else
        SocketSend(d == HOST ? m_hostsock : m_clientsock, buff, len);
}
void ProxyWorker::SSLSend(SSL* ssl, const char* buff, size_t len)
{
    if (SSL_write (ssl, buff, len) < 0 )
        throw ProxyException(SSL_ERROR, __FUNCTION__);
}
void ProxyWorker::SocketSend(int sock, const char* buff, size_t len)
{
    int nsent = send(sock, buff, len, 0);
    if ( nsent < 0)
        throw ProxyException(SOCKET_ERROR,  __FUNCTION__);
    
    if ( nsent == 0)
        throw ProxyException(CONNECTION_SHUT_DOWN, __FUNCTION__);
}

void ProxyWorker::ConnectToHost()
{
    struct sockaddr_in host_addr;
    bzero(&host_addr, sizeof(host_addr));

    int port;
    if (m_request.uri.port)
        port = m_request.uri.port;
    else
        port = m_bssl ? 443 : 80;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        throw ProxyException(SOCKET_ERROR, __FUNCTION__);

    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(port);

    if (IsIpAddr(m_request.uri.absuri.c_str()))
    {
        host_addr.sin_addr.s_addr = inet_addr(m_request.uri.absuri.c_str());
        if (connect (sock, (sockaddr*) &host_addr, sizeof(host_addr)) < 0)
            throw ProxyException("Wrong IP addr");
    }
    else
    {
        char ** ipaddrlist = GetIpAddr(
            m_request.uri.absuri != "" ?
            m_request.uri.absuri.c_str() : m_request.header["Host"].c_str());

        if (!ipaddrlist)
            throw ProxyException(DNS_FAILED);

        for(int i = 0; ; ++i)
        {
            if (ipaddrlist[i] == NULL)
                throw ProxyException(DNS_FAILED);

            host_addr.sin_addr = *(struct in_addr *) ipaddrlist[i];
            if (connect (sock, (sockaddr*) &host_addr, sizeof(host_addr)) == 0)
                break;
        }
    }
    struct timeval timeout = {5, 0}; 
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
    
    m_hostsock = sock;

    if (m_bssl)
    {
        m_ctx_mutex.lock();
        m_hostssl = SSL_new(m_ctx);
        m_ctx_mutex.unlock();

        if ( m_hostssl == NULL)
            throw ProxyException(SSL_ERROR, __FUNCTION__);
        SSL_set_fd (m_hostssl, m_hostsock);  
        if (SSL_connect (m_hostssl) < 0)
            throw ProxyException(SSL_ERROR, __FUNCTION__);  
    }
}

void ProxyWorker::CloseConnectionToHost()
{
    if (m_hostsock)
        close(m_hostsock);
    if (m_hostssl)
        SSL_free(m_hostssl);
}

void ProxyWorker::MethodConnect()
{
    int ret;
    char buff[128];
    sprintf(buff, "HTTP/1.1 200 Connection established\r\n\r\n");
    ret = send(m_clientsock, buff, strlen(buff), 0);
    if (ret < 0)
        throw ProxyException(SOCKET_ERROR, __FUNCTION__);
    else if (ret == 0)
        throw ProxyException(CONNECTION_SHUT_DOWN, __FUNCTION__);

    if(m_bssl)
    {
        m_ctx_mutex.lock();
        m_clientssl = SSL_new(m_ctx);
        m_ctx_mutex.unlock();
        if (m_clientssl == NULL)
            throw ProxyException(SSL_ERROR);
        SSL_set_fd (m_clientssl, m_clientsock);
        ret = SSL_accept(m_clientssl);
        if (ret == 0)
        {
            throw ProxyException( CONNECTION_SHUT_DOWN );
        }
        else if (ret < 0)
        {
            throw ProxyException(SSL_ERROR);
        }
    }
}

void ProxyWorker::RewriteRequest()
{
    AutoBuffer buff;
    buff.CopyFrom(m_buffer);
    if (m_request.header.find("Proxy-Connection") != m_request.header.end())
    {
        if (m_request.header.find("Connection") != m_request.header.end())
            m_request.header["Connection"] = m_request.header["Proxy-Connection"];
        m_request.header.erase("Proxy-Connection");
    }

    if (m_request.header.find("Connection") != m_request.header.end())
    {
        m_request.header.erase("Connection");
    }

    std::string reqh = m_request.ToString();
    m_buffer.Reset();
    m_buffer.Append(reqh.c_str(), reqh.size());
    if (buff.Len() > m_request.header_length)
        m_buffer.Append(buff.Ptr() + m_request.header_length, buff.Len() - m_request.header_length);
}

void ProxyWorker::RecvCompleteRequest()
{
    int nread;
    int parse_ret;
    char buff[2048];
    bool header_ok = false;
    m_buffer.Reset();
    while(1)
    {
        nread = RecvFrom(CLIENT, buff, sizeof buff);
        m_buffer.Append(buff, nread);

        if ( !header_ok )
        {
            parse_ret = m_request.Parse(m_buffer.Ptr(), m_buffer.Len());
            if (parse_ret == PARSE_WRONG_FORMAT)
                throw ProxyException(HTTP_FORMAT_ERROR, __FUNCTION__);
            else if (parse_ret == PARSE_IMCOMPLETE_HEADER)
                continue;

            header_ok = true;
        }
        if (IsHttpDataCompleted(m_request.header, m_buffer.Ptr() + parse_ret, m_buffer.Len() - parse_ret))
            break;
    }
}

void ProxyWorker::TransferResponse()
{
    int nread;
    int parse_ret;
    char buff[2048];
    bool header_ok = false;
    m_buffer.Reset();
    while(1)
    {
        nread = RecvFrom(HOST, buff, sizeof buff);
        SendTo(CLIENT, buff, nread);    //收到内容直接转到客户端，
        m_buffer.Append(buff, nread);     //复制到Buffer中，重组整个Http消息，用于判断是否结束。

        if ( !header_ok )
        {
            parse_ret = m_response.Parse(m_buffer.Ptr(), m_buffer.Len());
            if (parse_ret == PARSE_WRONG_FORMAT)
                throw ProxyException(HTTP_FORMAT_ERROR, __FUNCTION__);
            else if (parse_ret == PARSE_IMCOMPLETE_HEADER)
                continue;

            header_ok = true;
        }

        if (IsHttpDataCompleted(m_response.header, m_buffer.Ptr() + parse_ret, m_buffer.Len() - parse_ret))
            break;
    }
}

bool ProxyWorker::IsKeepAlive()
{
    if (m_request.header.find("Connection") != m_request.header.end()
        && SameStringIgnoreCase(m_request.header["Connection"], "Close"))
    {
        sndebug("    >Connection:" << " " << m_request.header["Connection"])
        return false;
    }

    if (m_request.header.find("Proxy-Connection") != m_request.header.end()
        && SameStringIgnoreCase(m_request.header["Proxy-Connection"], "Close"))
    {
        sndebug("    >Proxy-Connection:" << " " << m_request.header["Proxy-Connection"])
        return false;
    }

    if (m_response.header.find("Connection") != m_response.header.end()
        && SameStringIgnoreCase(m_response.header["Connection"], "Close"))
    {
        sndebug("    <Connection:" << " " << m_response.header["Connection"])
        return false;
    }

    if (m_request.header.find("Connection") == m_request.header.end()
        && m_request.header.find("Proxy-Connection") == m_request.header.end()
        && m_request.version == "HTTP/1.0")
        return false;

    return true;
}

void ProxyWorker::Run()
{
    try
    {
        RecvCompleteRequest();
        sndebug("> " << m_request.method << " " << m_request.uri.ToString(true))
        if (m_request.method == "CONNECT")
        {
            if ( m_request.uri.scheme == "https" || m_request.uri.port == 443 )
                m_bssl = true;
            MethodConnect();
            RecvCompleteRequest();
        }
        ConnectToHost();
        m_last_connected_host = m_request.header["Host"];
        RewriteRequest();
        SendTo(HOST, m_buffer.Ptr(), m_buffer.Len());
        TransferResponse();
        sndebug("< " << m_response.code)
        while(IsKeepAlive())
        {
            RecvCompleteRequest();
            if (m_last_connected_host != m_request.header["Host"])
            {
                sndebug("change host from '" << m_last_connected_host << "'' to '" << m_request.header["Host"] << "'")
                CloseConnectionToHost();
                ConnectToHost();
                m_last_connected_host = m_request.header["Host"];
            }
            sndebug(">> " << m_request.method << " " << m_request.uri.ToString(true))
            RewriteRequest();
            SendTo(HOST, m_buffer.Ptr(), m_buffer.Len());
            TransferResponse();
            sndebug("<< " << m_response.code)
        } 
    }
    catch(ProxyException& e)
    {
        if (e.code() == SSL_ERROR)
        {
            unsigned long ulErr = ERR_get_error();
            char szErrMsg[1024] = {0};
            char *pTmp = NULL;
            pTmp = ERR_error_string(ulErr,szErrMsg);
            sndebug("ssl error: " << " code: " << ulErr << " " << pTmp << " " << e.what())
        }
        else if (e.code() == SOCKET_ERROR)
        {
            sndebug("socket error: " << strerror(errno) << " " << e.what())
        }
        else if (e.code() == CONNECTION_SHUT_DOWN)
        {
            sndebug("connection shut dwon. " << e.what())
        }
        else
        {
            sndebug("error " << e.code() << " " << e.what());
        }
    }
    catch(...)
    {
        sndebug("Unknow Exception")
    }
}
