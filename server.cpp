#include <iostream>
#include <boost/program_options.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <unordered_set>
#include <experimental/filesystem>
#include <time.h>

#include "cmd.h"
extern "C" {
	#include "err.h"
}

namespace po = boost::program_options;
namespace fs = std::experimental::filesystem;

class FileManager {
public:
	uint64_t free_space;
	uint64_t max_space;
	std::string path;
    std::unordered_set<std::string> files;

    FileManager(unsigned int set_max_space, std::string set_path) 
    	: free_space(set_max_space), max_space(set_max_space), path(set_path) {
    	for (const auto & entry : fs::directory_iterator(path)) {
            if (fs::is_regular_file(entry.path())) {
                files.insert(entry.path().filename());
                std::cout << entry.path().filename() << std::endl;
                unsigned int k = fs::file_size(entry.path());
                if (k > free_space)
                    free_space = 0;
                else
                    free_space -= k;
            }
        }
    }
};

class Server {
public:
	char *mcast_addr;
	in_port_t cmd_port;
	unsigned int timeout;
	FileManager *fm;
	int udpSock;
	struct sockaddr_in local_address;
	struct ip_mreq ip_mreq;

public: 
	Server(int argc, const char *argv[]) {
		try {
			po::options_description desc{"Parameters"};
            desc.add_options()
                ("help,h", "Help screen.")
                ("MCAST_ADDR,g", po::value<std::string>(), "Multicast address.")
                ("CMD_PORT,p", po::value<in_port_t>(), "UDP port.")
                ("MAX_SPACE,b", po::value<unsigned int>()->default_value(52428800), "The maximum number of bytes "
                                                                                    "of shared disk space.")
                ("SHRD_FLDR,f", po::value<std::string>(), "Path to the dedicated disk folder.")
                ("TIMEOUT,t", po::value<unsigned int>()->default_value(5), "The number of seconds the server can "
                                                                           "wait for connections from clients.")
            ;

            po::variables_map vm;
            store(parse_command_line(argc, argv, desc), vm);
            notify(vm);

            if (argc == 1 || vm.count("help")) {
                std::cout << desc << std::endl;
                exit(0);
            }

            if (vm.count("help")) {
            	std::cout << desc << "\n";
            	exit(0);
            }

            if (!vm.count("MCAST_ADDR"))
            	syserr("MCAST_ADDR is required.");
            if (!vm.count("CMD_PORT")) {
            	syserr("CMD_PORT is required.");
            }
	        if (!vm.count("SHRD_FLDR"))
	            syserr("SHRD_FLDR is required.");
	        std::string ma = vm["MCAST_ADDR"].as<std::string>();
	        mcast_addr = new char[ma.length() + 1];
	        for (int i = 0; i < (int)ma.size(); ++i)
	        	mcast_addr[i] = ma[i];
	        mcast_addr[ma.size()] = 0;
	        cmd_port = vm["CMD_PORT"].as<in_port_t>();
	        std::string shrd_fldr = vm["SHRD_FLDR"].as<std::string>();
	        timeout = vm["TIMEOUT"].as<unsigned int>();
	        if (timeout == 0)
	            syserr("TIMEOUT must have positive value.");
	        if (timeout > 300)
	            syserr("TIMEOUT max value is 300.");
	        unsigned int max_space = vm["MAX_SPACE"].as<unsigned int>();
	        fm = new FileManager(max_space, shrd_fldr);
		} catch (const po::error &e) {
			syserr(e.what());
		}
	}

	~Server() {
		delete[] mcast_addr;
		delete fm;
	}

	void setUDPSock() {
		udpSock = socket(AF_INET, SOCK_DGRAM, 0);
	    if (udpSock < 0)
	        syserr("socket");
	    u_int yes = 1;
		if (setsockopt(udpSock, SOL_SOCKET, SO_REUSEADDR, (char*) &yes, sizeof(yes)) < 0)
			syserr("Reusing ADDR failed");
		ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (inet_aton(mcast_addr, &ip_mreq.imr_multiaddr) == 0)
		    syserr("inet_aton");
		if (setsockopt(udpSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0)
		    syserr("setsockopt");
		struct timeval t;
	    t.tv_sec = timeout;
	    t.tv_usec = 0;
	    if (setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, (void*)&t, sizeof t)) {
	        syserr("setsockopt timeout");
	    }
		local_address.sin_family = AF_INET;
		local_address.sin_addr.s_addr = htonl(INADDR_ANY);
		local_address.sin_port = htons(cmd_port);
		if (bind(udpSock, (struct sockaddr *)&local_address, sizeof local_address) < 0)
		    syserr("bind");
	}

	void receiveHello() {
		struct sockaddr_in Sender_addr;
		socklen_t socklen = sizeof(struct sockaddr);
		struct simpl_cmd *recvbuff = (struct simpl_cmd*)malloc(sizeof(struct simpl_cmd));
		ssize_t recvlen = recvfrom(udpSock, (struct simpl_cmd*)recvbuff, sizeof(*recvbuff), 0, (struct sockaddr *)&Sender_addr, &socklen);
		if (recvlen < 0) {
			std::cout << "timeout" << std::endl;
			return;
		}
		std::cout << recvbuff->cmd << std::endl;
		std::cout << recvbuff->cmd_seq << std::endl;

		struct cmplx_cmd *buffer = (struct cmplx_cmd*)malloc(sizeof(struct cmplx_cmd));
		strcpy(buffer->cmd, "GOOD DAY");
		buffer->cmd[8] = 0;
		buffer->cmd_seq = htobe64(recvbuff->cmd_seq);
		buffer->param = htobe64(fm->free_space);
		buffer->cmd_seq = htonl(buffer->cmd_seq);
		buffer->param = htonl(buffer->param);

		std::cout << buffer->cmd << " " << buffer->cmd_seq << " " << buffer->param << std::endl;
		ssize_t length = sizeof(*buffer);
		std::cout << Sender_addr.sin_port << " " << Sender_addr.sin_addr.s_addr << std::endl;

	    if (sendto(udpSock, (const char*)buffer, sizeof(*buffer), 0, (struct sockaddr *)&Sender_addr, sizeof(Sender_addr)) != length) 
	    	syserr("sendto");

	    std::cout << "send " <<  length << std::endl;
	}
};

int main(int argc, const char *argv[]) {
	Server server(argc, argv);
	server.setUDPSock();
	while (true) {
		server.receiveHello();
	}
}