
objects = proxy.o ProxyServer.o ProxyWorker.o ProxyHeaders.o ProxyAutoBuffer.o ProxyUri.o

proxy : $(objects) 
	c++ -o proxy $(objects) -L/Users/gao/libboost/ -lboost_thread -lboost_system -lboost_regex\
	 -L/Users/gao/srcs/openssl-1.0.1e/ -lssl -lcrypto

proxy.o: ProxyServer.h ProxyException.h
ProxyServer.o: ProxyServer.h ProxyWorker.h ProxyException.h
ProxyWorker.o: ProxyWorker.cpp ProxyWorker.h ProxyException.h ProxyHeaders.h ProxyAutoBuffer.h
	c++ -Wno-deprecated-declarations -pthread -c ProxyWorker.cpp -o ProxyWorker.o
ProxyHeaders.o: ProxyHeaders.h ProxyUri.h
ProxyAutoBuffer.o: ProxyAutoBuffer.h ProxyException.h
ProxyUri.o: ProxyUri.h

.PHONY: clean
clean: 
	-rm proxy $(objects)
