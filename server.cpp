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

#define MAX_UDP_SIZE 512000
#define CMD_SIZE 10
#define SIMPL_STRUCT 0
#define CMPLX_STRUCT 1
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
    	std::cout << "wielkość " << max_space << std::endl;
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
        std::cout << free_space << std::endl;
    }
};

char *buffer;
int calcSize(int type) {
	if (type == SIMPL_STRUCT) {
		return sizeof(struct simpl_cmd);
	} else {
		return sizeof(struct cmplx_cmd);
	}
}

class Server {
public:
	std::vector<std::string> cmplx = {"ADD"};
	std::vector<std::string> simpl = {"HELLO", "LIST", "GET", "DEL"};
	char *mcast_addr;
	in_port_t cmd_port;
	unsigned int timeout;
	FileManager *fm;
	struct sockaddr_in local_address;
	int udpSock;

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
	        udpSock = getUDPSock();
		} catch (const po::error &e) {
			syserr(e.what());
		}
	}

	~Server() {
		delete[] mcast_addr;
		delete fm;
	}

	int getUDPSock() {
		int udpSock = socket(AF_INET, SOCK_DGRAM, 0);
	    if (udpSock < 0)
	        syserr("socket");

	    ip_mreq ip_mreq{};
	    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	    if (inet_aton(mcast_addr, &ip_mreq.imr_multiaddr) == 0) {
	    	syserr("inet_aton 118");
	    }
		if (setsockopt(udpSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq, sizeof ip_mreq) < 0) {
		    syserr("setsockopt");
		}
	    u_int yes = 1;
		if (setsockopt(udpSock, SOL_SOCKET, SO_REUSEADDR, (char*) &yes, sizeof(yes)) < 0)
			syserr("Reusing ADDR failed");

		struct timeval t;
	    t.tv_sec = timeout;
	    t.tv_usec = 0;
	    if (setsockopt(udpSock, SOL_SOCKET, SO_SNDTIMEO, (void*)&t, sizeof t)) {
	        syserr("setsockopt timeout");
	    }
		local_address.sin_family = AF_INET;
		local_address.sin_addr.s_addr = htonl(INADDR_ANY);
		local_address.sin_port = htons(cmd_port);
		if (bind(udpSock, (struct sockaddr *)&local_address, sizeof local_address) < 0)
		    syserr("bind");
		return udpSock;
	}

	struct simpl_cmd *getSimplCmd() {
		int size = calcSize(SIMPL_STRUCT);
		struct simpl_cmd *ret = (struct simpl_cmd*)malloc(size);
		std::cout << "w " << sizeof(*ret) << std::endl;
		memcpy(ret, (struct simpl_cmd*)buffer, sizeof(*ret));
		for (int i = 0; i < size; ++i)
			buffer[i] = 0;
		ret->cmd_seq = be64toh(ret->cmd_seq);
		std::cout << ret->cmd << " " << ret->cmd_seq << std::endl;
		return ret;
	}

	void handleCmd(std::string cmd, struct sockaddr_in Sender_addr) {
		if (cmd == "ADD") {
			// struct simpl_cmd *dg = getSimplCmd(); 
			// handleAdd
			// return;
		}

		struct simpl_cmd *dg = getSimplCmd(); 
		receiveHello(dg, Sender_addr);
		return;
	}

	void receiveHello(struct simpl_cmd *dg, struct sockaddr_in Sender_addr) {
		struct cmplx_cmd *buffer = (struct cmplx_cmd*)malloc(sizeof(struct cmplx_cmd));
		strcpy(buffer->cmd, "GOOD DAY");
		buffer->cmd[8] = 0;
		buffer->cmd_seq = htobe64(dg->cmd_seq);
		buffer->param = htobe64(fm->free_space);

		ssize_t length = sizeof(*buffer);

	    if (sendto(udpSock, (const char*)buffer, sizeof(*buffer), 0, (struct sockaddr *)&Sender_addr, sizeof(Sender_addr)) != length) 
	    	syserr("sendto");

	    std::cout << "send " <<  length << std::endl;
	}
};

int main(int argc, const char *argv[]) {
	Server server(argc, argv);
	int sock = server.udpSock;
	buffer = (char*)malloc(MAX_UDP_SIZE);
	while (true) {
		struct sockaddr_in Sender_addr;
		socklen_t socklen = sizeof(struct sockaddr);
		std::cout << "sdsad " << sizeof(*buffer) << std::endl;
		if (recvfrom(sock, (char*)buffer, MAX_UDP_SIZE, 0, (struct sockaddr *)&Sender_addr, &socklen) < 0)
			syserr("recvfrom 182");

		std::string cmd = "";
		for (int i = 0; i < CMD_SIZE; ++i)
			cmd += buffer[i];

		server.handleCmd(cmd, Sender_addr);
	}
}