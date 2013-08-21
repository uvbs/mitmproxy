
objects = proxy.o ProxyServer.o ProxyWorker.o ProxyHeaders.o ProxyAutoBuffer.o ProxyUri.o ProxyController.o

proxy : $(objects) 
	c++ -o proxy $(objects) -L/Users/gao/libboost/ -lboost_thread -lboost_system -lboost_regex\
	 -L/Users/gao/srcs/openssl-1.0.1e/ -lssl -lcrypto -std=c++11

proxy.o: ProxyServer.h ProxyException.h ProxyController.h
ProxyServer.o: ProxyServer.h ProxyWorker.h ProxyException.h
#	c++ -std=c++11 -pthread -c ProxyServer.cpp -o ProxyServer.o
ProxyWorker.o: ProxyWorker.cpp ProxyWorker.h ProxyException.h ProxyHeaders.h ProxyAutoBuffer.h ProxyController.h
	c++ -Wno-deprecated-declarations -pthread -c ProxyWorker.cpp -o ProxyWorker.o
ProxyHeaders.o: ProxyHeaders.h ProxyUri.h
ProxyAutoBuffer.o: ProxyAutoBuffer.h ProxyException.h
ProxyUri.o: ProxyUri.h
ProxyController.o: ProxyController.h ProxyServer.h

.PHONY: clean
clean: 
	-rm proxy $(objects)
