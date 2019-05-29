TARGET: netstore-server netstore-client

GCCFLAGS = -std=c++17 -Wall -Wextra -O2
LFLAGS = -lboost_program_options -lstdc++fs -pthread

err.o: err.h err.c
	g++ -c $^

netstore-server: server.cpp cmd.h err.o network-manager.h
	g++ $(GCCFLAGS) $^ $(LFLAGS) -o $@

netstore-client: klient.cpp cmd.h err.o network-manager.h
	g++ $(GCCFLAGS) $^ $(LFLAGS) -o $@

.PHONY: clean TARGET
clean:
	rm -f netstore-server netstore-client err.o