#include <iostream>
#include "ProxyServer.h"
#include "ProxyException.h"

int main()
{
    try
    {
        std::cout << "Proxy run" << std::endl;
        ProxyServer ps;
        ps.Run(8080);
        return 0;
    }
    catch(ProxyException e)
    {
        std::cout << "Fatal error: " << e.what() << std::endl;
    }
}