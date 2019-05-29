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
#include <thread>
#include <csignal>

#include "cmd.h"
#include "network-manager.h"

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
        std::cout << free_space << std::endl;
    }

    void removeFile(std::string s) {
    	for (const auto &entry : fs::directory_iterator(path)) {
    		if (fs::is_regular_file(entry.path()) && entry.path().filename() == s) {
    			free_space += fs::file_size(entry.path());
    			files.erase(entry.path().filename());
    			fs::remove(entry.path());
    		}
    	}
    }
};

void interrupted(int signal) {
	std::cout << "Ktoś mi wykurwił bombe" << std::endl;
	exit(0);
}

char *buffer;
class Server {
public:
	std::vector<std::string> simpl = {"HELLO", "LIST", "DEL"};
	std::string mcast_addr;
	in_port_t cmd_port;
	unsigned int timeout;
	FileManager *fm;
	NetworkManager *nm;
	struct sockaddr_in local_address;

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
	        mcast_addr = vm["MCAST_ADDR"].as<std::string>();
	        cmd_port = vm["CMD_PORT"].as<in_port_t>();
	        std::string shrd_fldr = vm["SHRD_FLDR"].as<std::string>();
	        timeout = vm["TIMEOUT"].as<unsigned int>();
	        if (timeout == 0)
	            syserr("TIMEOUT must have positive value.");
	        if (timeout > 300)
	            syserr("TIMEOUT max value is 300.");
	        unsigned int max_space = vm["MAX_SPACE"].as<unsigned int>();
	        fm = new FileManager(max_space, shrd_fldr);
	        nm = new NetworkManager(getUDPSock());
		} catch (const po::error &e) {
			syserr(e.what());
		}
	}

	~Server() {
		delete fm;
		delete nm;
	}

	int getUDPSock() {
		int udpSock = socket(AF_INET, SOCK_DGRAM, 0);
	    if (udpSock < 0)
	        syserr("socket");

	    ip_mreq ip_mreq{};
	    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	    if (inet_aton(mcast_addr.c_str(), &ip_mreq.imr_multiaddr) == 0) {
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

	void handleCmd(std::string cmd, struct sockaddr_in Sender_addr, int len) {
		if (cmd == "ADD") {
			
		}
		bool isOk = false;
		for (auto s : simpl) {
			if (cmd == s)
				isOk = true;
		}
		std::cout << "Dostałem taką komende " << cmd << std::endl;
		if (!isOk) {
			std::string ip = nm->getIpFromAddress(Sender_addr);
			std::cout << "[PCKG ERROR] Skipping invalid package from " << ip << ":" << Sender_addr.sin_port << ". Bad cmd argument." << std::endl;
			return;
		}
		struct simpl_cmd *dg = nm->getSimplCmd(buffer, len);
		for (int i = 0; i < len; ++i)
			buffer[i] = 0;
		if (cmd == "HELLO")
			receiveHello(dg, Sender_addr);
		else if (cmd == "LIST")
			receiveList(dg, Sender_addr);
		else if (cmd == "DEL") {
			receiveDel(dg);
		}
		return;
	}

	void receiveHello(struct simpl_cmd *dg, struct sockaddr_in Sender_addr) {
		std::string data(dg->data);
		if (data.size() != 0) {
			std::string ip = nm->getIpFromAddress(Sender_addr);
			std::cout << "[PCKG ERROR]  Skipping invalid package from " << ip << ":" << Sender_addr.sin_port << std::endl;
			return;
		}
		struct cmplx_cmd *buffer = nm->generateCmplxCmd("GOOD_DAY", dg->cmd_seq, fm->free_space, mcast_addr);
		ssize_t length = nm->getSizeWithData(CMPLX_STRUCT, mcast_addr.size());
		std::cout << "hello " << length << " " << sizeof(struct cmplx_cmd) << " " << mcast_addr.size() << std::endl;
	    nm->sendCmd((const char *)buffer, length, Sender_addr);
	    delete dg;
	    delete buffer;
	}

	void receiveList(struct simpl_cmd *dg, struct sockaddr_in Sender_addr) {
		std::string fileList = "";
		std::string toFind(dg->data);
		struct simpl_cmd *buffer;
		for (auto file : fm->files) {
			if (file.find(toFind) != std::string::npos) {
				if (fileList.size() + file.size() + 1 > MAX_UDP_SIZE - 20) {
					buffer = nm->generateSimplCmd("MY_LIST", dg->cmd_seq, fileList);
					ssize_t length = nm->getSizeWithData(SIMPL_STRUCT, fileList.size());
					nm->sendCmd((const char*)buffer, length, Sender_addr);
				    delete buffer;
				    fileList = "";
				}
				if (fileList.size() == 0)
					fileList = file;
				else
					fileList += '\n' + file;
			}
		}

		if (fileList.size() != 0) {
			buffer = nm->generateSimplCmd("MY_LIST", dg->cmd_seq, fileList);
			std::cout << "WYSYŁAM " << fileList << std::endl;
			std::string ip = nm->getIpFromAddress(Sender_addr);
			std::cout << "IP :: " << ip << std::endl;
			ssize_t length = nm->getSizeWithData(SIMPL_STRUCT, fileList.size());
			std::cout << "wysłany pakiet ma " << length << std::endl;
			nm->sendCmd((const char*)buffer, length, Sender_addr);
			delete buffer;
		}
		delete dg;
	}

	void receiveDel(struct simpl_cmd *dg) {
		std::cout << dg->cmd << " " << dg->data << std::endl;
		std::string file(dg->data);
		fm->removeFile(file);
	}
};

int main(int argc, const char *argv[]) {
	std::signal(SIGINT, interrupted);
	Server server(argc, argv);
	int sock = server.nm->udpSock;
	buffer = (char*)malloc(MAX_UDP_SIZE);
	while (true) {
		struct sockaddr_in Sender_addr;
		socklen_t socklen = sizeof(struct sockaddr);
		int len = recvfrom(sock, (char*)buffer, MAX_UDP_SIZE, 0, (struct sockaddr *)&Sender_addr, &socklen);
		if (len < 0)
			syserr("recvfrom 182");

		std::string cmd = "";
		for (int i = 0; i < CMD_SIZE; ++i) {
			if (buffer[i] == 0)
				break;
			cmd += buffer[i];
		}

		server.handleCmd(cmd, Sender_addr, len);
	}
	delete buffer;
}