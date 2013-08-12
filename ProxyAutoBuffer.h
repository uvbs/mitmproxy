#ifndef __PROXY_AUTO_BUFFER_H__
#define __PROXY_AUTO_BUFFER_H__

#include <sys/types.h>

class AutoBuffer
{
public:
    AutoBuffer();
    ~AutoBuffer();
    inline const char* Ptr() const {return buf;}
    inline size_t Len() const {return buflen;}
    void Append(const char* data, size_t len);
    inline void Reset() {buflen = 0;}
    void CopyFrom(AutoBuffer &buffer);
private:
    char* buf;
    size_t bufsz;
    size_t buflen;
};

#endif
