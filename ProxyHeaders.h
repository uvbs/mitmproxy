#ifndef __HEADER_H__
#define __HEADER_H__

#include <string>
#include <map>
#include "ProxyUri.h"


#define PARSE_WRONG_FORMAT -1
#define PARSE_IMCOMPLETE_HEADER -2

struct RequestHeader
{
    std::string method;
    Uri uri;
    std::string version;
    std::map<std::string, std::string> header;

    size_t header_length;

    int Parse(const char* data, unsigned int len);
    std::string Dump();
    void Clear();
    RequestHeader();
};

struct ResponseHeader
{
    std::string version;
    unsigned int code;
    std::string reason;
    std::map<std::string, std::string> header;

    size_t header_length;
    
    int Parse(const char* data, unsigned int len);
    std::string Dump();
    void Clear();
    ResponseHeader();
};



#endif //__HEADER_H__