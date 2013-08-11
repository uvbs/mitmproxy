#include <string>

#ifndef __URI_H__
#define __URI_H__

struct Uri
{
    std::string scheme;
    std::string absuri;
    unsigned int port;
    std::string abspath;

    inline Uri(std::string src)
    {
        int seg = 0;
        if ( (seg = src.find("://")) != std::string::npos)
        {
            scheme = src.substr(0, seg);
            src = src.substr(seg+3);
        }
        else
            scheme = "";

        port = 0;
        if ( (seg = src.find_first_of("/")) != std::string::npos)
        {
            absuri = src.substr(0, seg);
            abspath = src.substr(seg);
        }
        else
        {
            absuri = src;
            abspath = "";
        }

        if ( (seg = absuri.find_first_of(":")) != std::string::npos)
        {
            port = atoi(absuri.substr(seg+1).c_str());
            absuri = absuri.substr(0, seg);
        }
    }

    inline Uri():
        scheme(""), absuri(""), port(0), abspath("")
    {}

    inline Uri(const Uri &uri)
    {
        scheme = uri.scheme;
        absuri = uri.absuri;
        port = uri.port;
        abspath = uri.abspath;
    }

    inline Uri& operator= (const Uri& uri)
    {
        scheme = uri.scheme;
        absuri = uri.absuri;
        port = uri.port;
        abspath = uri.abspath;
        return *this;
    }

    inline std::string Dump(bool dumpdomain = false)
    {
        std::ostringstream ostr;
        if (dumpdomain)
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

    inline std::string GetDomainName()
    {
        std::string ostr = "";
        if (scheme != "")
            ostr += scheme + "://";
        if (absuri != "")
            ostr += absuri;
        return ostr;
    }
};

#endif