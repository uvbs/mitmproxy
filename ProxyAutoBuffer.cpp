#include "ProxyAutoBuffer.h"
#include "ProxyException.h"

const size_t INIT_BUFF_SIZE = 4096;

AutoBuffer::AutoBuffer():
    buflen(0),
    bufsz(0),
    buf(NULL)
{
    if ( (buf = (char*) malloc(INIT_BUFF_SIZE)) == NULL)
        throw ProxyException("No memory");
    bufsz = INIT_BUFF_SIZE;
}

AutoBuffer::~AutoBuffer()
{
    if (buf)
        free(buf);
}

void AutoBuffer::Append(const char* data, size_t len)
{
    if (buflen + len > bufsz)
    {
        bufsz = (buflen + len) * 2;
        buf = (char*)realloc(buf, bufsz);
        if (buf == NULL)
            throw ProxyException("No memory");
    }
    memcpy(buf + buflen, data, len);
    buflen += len;
}

void AutoBuffer::CopyFrom(AutoBuffer &buffer)
{
    Reset();
    Append(buffer.Ptr(), buffer.Len());
}
