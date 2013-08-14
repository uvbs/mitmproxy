#include "ProxyUri.h"
#include <sstream>

Uri::Uri(std::string uri_string)
{
    int seg = 0;
    if ( (seg = uri_string.find("://")) != std::string::npos)
    {
        scheme = uri_string.substr(0, seg);
        uri_string = uri_string.substr(seg+3);
    }
    else
        scheme = "";

    port = 0;
    if ( (seg = uri_string.find_first_of("/")) != std::string::npos)
    {
        absuri = uri_string.substr(0, seg);
        abspath = uri_string.substr(seg);
    }
    else
    {
        absuri = uri_string;
        abspath = "";
    }

    if ( (seg = absuri.find_first_of(":")) != std::string::npos)
    {
        port = atoi(absuri.substr(seg+1).c_str());
        absuri = absuri.substr(0, seg);
    }
}

Uri::Uri():
    scheme(""), absuri(""), port(0), abspath("")
{}

Uri::Uri(const Uri &uri)
{
    scheme = uri.scheme;
    absuri = uri.absuri;
    port = uri.port;
    abspath = uri.abspath;
}

Uri& Uri::operator= (const Uri& uri)
{
    scheme = uri.scheme;
    absuri = uri.absuri;
    port = uri.port;
    abspath = uri.abspath;
    return *this;
}

std::string Uri::ToString(bool abs_uri) const
{
    std::ostringstream ostr;
    if (abs_uri)
    {
        if (scheme != "")
            ostr << scheme + "://";

        if (absuri != "")
        {
            ostr << absuri;
            if (port != 0)
                ostr << ":" << port;
        }
    }
    if (abspath != "")
        ostr << abspath;
    return ostr.str();
}

std::string Uri::GetDomainName() const
{
    std::string ostr = "";
    if (scheme != "")
        ostr += scheme + "://";
    if (absuri != "")
        ostr += absuri;
    return ostr;
}
