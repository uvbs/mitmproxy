#ifndef __PROXY_AUTO_BUFFER_H__
#define __PROXY_AUTO_BUFFER_H__

#include <sys/types.h>

class AutoBuffer
{
public:
    AutoBuffer();
    ~AutoBuffer();
    const char* Ptr() {return buf;}
    size_t Len() {return buflen;}
    void Append(const char* data, size_t len);
    void Reset() {buflen = 0;}
    void CopyFrom(AutoBuffer &buffer);
private:
    char* buf;
    size_t bufsz;
    size_t buflen;
};

#endif