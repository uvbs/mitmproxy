#ifndef __PROXY_EXCEPTION_H__
#define __PROXY_EXCEPTION_H__

#include <string>
#include <exception>

class ProxyException: public std::exception
{
public:
    inline ProxyException(int code, std::string description): m_code(code), m_description(description) {}
    inline ProxyException(int code): m_code(code), m_description("") {}
    inline ProxyException(std::string description): m_code(0), m_description(description) {}

    inline ~ProxyException() throw() {}

    inline const char* what() const throw() {return m_description.c_str();}
    inline int code() const {return m_code;}
private:
    std::string m_description;
    int m_code;
};


#endif
