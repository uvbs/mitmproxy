#ifndef __PROXY_URI_H__
#define __PROXY_URI_H__

#include <string>

struct Uri
{
    std::string scheme;
    std::string absuri;
    unsigned int port;
    std::string abspath;

    Uri(std::string uri_string);
    Uri();
    Uri(const Uri &uri);
    Uri& operator= (const Uri& uri);
    std::string Dump(bool dump_abs_uri = false) const;
    std::string GetDomainName() const;
};

#endif
