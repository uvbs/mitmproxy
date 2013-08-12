#include <sstream>
#include "ProxyHeaders.h"

static void strip(std::string& str)
{
    while(str.length() && str.find_first_of("\r\n ") == 0)
        str.erase(0, 1);

    while(str.length() && str.find_last_of("\r\n ") == str.length() - 1)
        str.erase(str.end()-1);
}

RequestHeader::RequestHeader(){}

int RequestHeader::Parse(const char* data, unsigned int len)
{
    Clear();
    std::istringstream datastream( std::string(data, len));
    std::string line;
    int ln = 0;
    size_t seg = std::string::npos;
    bool bHeaderParsed = false;
    while(std::getline(datastream, line, '\n'))
    {
        strip(line);
        if (ln == 0)    //首行中的:方法、uri、port、version
        {
            if ((seg = line.find_first_of(" ")) == std::string::npos)
            {
                if (datastream.tellg() == len)
                    return PARSE_IMCOMPLETE_HEADER;
                else
                    return PARSE_WRONG_FORMAT;
            }
            method = line.substr(0, seg);
            line.erase(0, seg + 1);

            seg = line.find_first_of(" ");
            if ((seg = line.find_first_of(" ")) == std::string::npos)
            {
                if (datastream.tellg() == len)
                    return PARSE_IMCOMPLETE_HEADER;
                else
                    return PARSE_WRONG_FORMAT;
            }
            std::string struri = line.substr(0, seg);
            uri = Uri(struri);
            
            line.erase(0, seg + 1);
            version = line;
        }
        else //header
        {
            if (line == "")
            {
                header_length = datastream.tellg();
                bHeaderParsed = true;
                break;
            }
            else
            {
                seg = line.find_first_of(":");
                if (seg == std::string::npos)
                {
                    if (datastream.tellg() == len)
                        return PARSE_IMCOMPLETE_HEADER;
                    else
                        return PARSE_WRONG_FORMAT;
                }
                std::string key = line.substr(0, seg);
                line.erase(0, seg + 1);
                strip(line);
                header[key] = line;
            }
        }
        ++ln;
    }

    if (!bHeaderParsed)
    {
        if (datastream.tellg() == len)
            return PARSE_IMCOMPLETE_HEADER;
        else
            return PARSE_WRONG_FORMAT;
    }

    return header_length;
}

std::string RequestHeader::Dump() const
{
    std::ostringstream ostr;
    ostr << method << " "
        << uri.Dump()<< " " 
        << version << "\r\n";

    for (std::map<std::string, std::string>::const_iterator i = header.begin();
        i != header.end();
        ++i)
    {
        ostr << i->first << ": " << i->second << "\r\n";
    }
    ostr << "\r\n";

    return ostr.str();
}

void RequestHeader::Clear()
{
    method = "";
    uri = Uri();
    version = "";
    header.clear();
}

ResponseHeader::ResponseHeader(){}

int ResponseHeader::Parse(const char* data, unsigned int len)
{
    Clear();
    std::istringstream datastream(std::string(data, len));
    std::string line;
    int ln = 0;
    size_t seg = std::string::npos;
    bool bHeaderParsed = false;
    while(std::getline(datastream, line, '\n'))
    {
        strip(line);
        if (ln == 0)
        {
            if ((seg = line.find_first_of(" ")) == std::string::npos)
            {
                if (datastream.tellg() == len)
                    return PARSE_IMCOMPLETE_HEADER;
                else
                    return PARSE_WRONG_FORMAT;
            }
            version = line.substr(0, seg);
            line.erase(0, seg + 1);

            if ((seg = line.find_first_of(" ")) == std::string::npos)
            {
                if (datastream.tellg() == len)
                    return PARSE_IMCOMPLETE_HEADER;
                else
                    return PARSE_WRONG_FORMAT;
            }
            code = atoi(line.substr(0, seg).c_str());
            line.erase(0, seg + 1);

            reason = line;
        }
        else //header
        {
            if (line == "")
            {
                header_length = datastream.tellg();
                bHeaderParsed = true;
                break;
            }
            else
            {
                seg = line.find_first_of(":");
                if (seg == std::string::npos)
                {
                    if (datastream.tellg() == len)
                        return PARSE_IMCOMPLETE_HEADER;
                    else
                        return PARSE_WRONG_FORMAT;
                }
                std::string key = line.substr(0, seg);
                line.erase(0, seg + 1);
                strip(line);
                header[key] = line;
            }
        }
        ++ln;
    }
    if (!bHeaderParsed)
    {
        if (datastream.tellg() == len)
            return PARSE_IMCOMPLETE_HEADER;
        else
            return PARSE_WRONG_FORMAT;
    }

    return header_length;
}

void ResponseHeader::Clear()
{
    version = "";
    code = 0;
    reason = "";
    header.clear();
}
