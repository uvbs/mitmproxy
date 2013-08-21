#include <iostream>
#include "ProxyException.h"
#include "ProxyController.h"
#include "ProxyHeaders.h"
#include <boost/thread.hpp>

static boost::mutex callback_mu;
void onrequest(const char* data, size_t len)
{
    callback_mu.lock();
    RequestHeader rh;
    rh.Parse(data, len);
    std::cout << "> " << rh.method << " " << rh.uri.ToString(true) << std::endl;
    callback_mu.unlock();
}

void onresponse(const char* data, size_t len)
{
    callback_mu.lock();
    ResponseHeader rh;
    rh.Parse(data, len);
    std::cout << "< " << rh.code << std::endl;
    callback_mu.unlock();
}

int main()
{
    try
    {
        std::cout << "Proxy run" << std::endl;
        ProxyController &pc = ProxyController::GetController();
        pc.SetRequestCallback(&onrequest);
        pc.SetResponseCallback(&onresponse);
        pc.Start(8080);
        std::string input;
        while(input == "")
        {

            std::cin >> input;
        }
        pc.Stop();
        std::cout << "Stoped" << std::endl;
        return 0;
    }
    catch(ProxyException e)
    {
        std::cout << "Fatal error: " << e.what() << std::endl;
    }
    catch(...)
    {
        std::cout << "Other error!" << std::endl;
    }
}
