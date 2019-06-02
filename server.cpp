#include <iostream>
#include <boost/program_options.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <unordered_set>
#include <time.h>
#include <thread>
#include <csignal>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>


#include "cmd.h"
#include "network-manager.h"

namespace po = boost::program_options;

#define QUEUE_LENGTH     5

std::vector<std::thread> threadPool;
char *buffer;

class Server {
public:
	std::vector<std::string> simpl = {"HELLO", "LIST", "DEL", "GET"};
	std::string mcast_addr;
	in_port_t cmd_port;
	unsigned int timeout;
	FileManager *fm;
	NetworkManager *nm;
	struct sockaddr_in local_address;
	Logger logger;

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

	int getTcpSock(uint64_t *port) {
		int sock = socket(PF_INET, SOCK_STREAM, 0);
		if (sock < 0)
			syserr("socket");

		struct timeval t;
	    t.tv_sec = timeout;
	    t.tv_usec = 0;
		if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,(struct timeval *)&t,sizeof(struct timeval)) < 0) 
			syserr("setsockopt");
		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&t,sizeof(struct timeval)) < 0) 
			syserr("setsockopt");
		struct sockaddr_in server_address;
		server_address.sin_family = AF_INET;
		server_address.sin_addr.s_addr = htonl(INADDR_ANY);
		server_address.sin_port = 0;
		if (bind(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
		    syserr("bind");
		if (listen(sock, QUEUE_LENGTH) < 0)
		    syserr("listen");
		socklen_t len = sizeof(server_address);
		if (getsockname(sock, (struct sockaddr*)&server_address, &len) < 0)
			syserr("getsockname");
		*port = (uint64_t)ntohs(server_address.sin_port);
		return sock;
	}

	void handleCmd(std::string cmd, struct sockaddr_in Sender_addr, int len) {
		uint64_t port = (uint64_t)ntohs(Sender_addr.sin_port);
		std::string ip = nm->getIpFromAddress(Sender_addr);
		if (cmd == "ADD") {
			struct cmplx_cmd *toSend = nm->getCmplxCmd(buffer, len);
			receiveAdd(toSend, Sender_addr);
			free(toSend);
			return;
		}
		bool isOk = false;
		for (auto s : simpl) {
			if (cmd == s)
				isOk = true;
		}
		if (!isOk) {
			std::string ip = nm->getIpFromAddress(Sender_addr);
			std::cout << "[PCKG ERROR] Skipping invalid package from " << ip << ":" << Sender_addr.sin_port << ". Bad cmd argument." << std::endl;
			return;
		}
		struct simpl_cmd *dg = nm->getSimplCmd(buffer, len);
		for (int i = 0; i < len; ++i)
			buffer[i] = 0;
		if (cmd == "HELLO") {
			if (!nm->checkSimplCmd(&logger, ip, port, dg, "HELLO", dg->cmd_seq, "")) {
				free(dg);
				return;
			}
			receiveHello(dg, Sender_addr);
		}
		else if (cmd == "LIST") {
			if (!nm->checkSimplCmd(&logger, ip, port, dg, "LIST", dg->cmd_seq, "STH")) {
				free(dg);
				return;
			}
			receiveList(dg, Sender_addr);
		}
		else if (cmd == "DEL") {
			if (!nm->checkSimplCmd(&logger, ip, port, dg, "DEL", dg->cmd_seq, "STH")) {
				free(dg);
				return;
			}
			receiveDel(dg);
		}
		else if (cmd == "GET") {
			if (!nm->checkSimplCmd(&logger, ip, port, dg, "GET", dg->cmd_seq, "STH")) {
				free(dg);
				return;
			}
			receiveGet(dg, Sender_addr); 
		}
		else {
			// use it to log bad cmd, i know GET is not in this dg
			nm->checkSimplCmd(&logger, ip, port, dg, "GET", 0, "");
		}
		free(dg);
		return;
	}

	void receiveHello(struct simpl_cmd *dg, struct sockaddr_in Sender_addr) {
		std::string data(dg->data);
		struct cmplx_cmd *buffer = nm->generateCmplxCmd("GOOD_DAY", dg->cmd_seq, fm->free_space, mcast_addr);
		ssize_t length = nm->getSizeWithData(CMPLX_STRUCT, mcast_addr.size());
	    nm->sendCmd((const char *)buffer, length, Sender_addr);
	    free(buffer);
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
				    free(buffer);
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
			std::string ip = nm->getIpFromAddress(Sender_addr);
			ssize_t length = nm->getSizeWithData(SIMPL_STRUCT, fileList.size());
			nm->sendCmd((const char*)buffer, length, Sender_addr);
			free(buffer);
		}
	}

	void receiveDel(struct simpl_cmd *dg) {
		std::string file(dg->data);
		fm->removeFile(file);
	}

	void receiveGet(struct simpl_cmd *dg, struct sockaddr_in Sender_addr) {
		bool found = false;
		std::string toGet(dg->data);
		for (auto i : fm->files) {
			if (toGet == i) {
				fm->isBusy[toGet] = true;
				found = true;
			}
		}
		if (found == false) {
			// log it TODO
			std::string toLog("Server doesn't have file " + toGet + ".");
			std::string ip = nm->getIpFromAddress(Sender_addr);
			uint64_t port = (uint64_t)ntohs(Sender_addr.sin_port);
			logger.logError(ip, port, toLog);
			return;
		}
		uint64_t port;
		int sock = getTcpSock(&port);
		struct cmplx_cmd *buffer = nm->generateCmplxCmd("CONNECT_ME", dg->cmd_seq, port, toGet);
		ssize_t length = nm->getSizeWithData(CMPLX_STRUCT, toGet.size());
		std::string path = getPathToFile(toGet);
		nm->sendCmd((const char*)buffer, length, Sender_addr);
		free(buffer);
		threadPool.push_back(std::thread(&Server::sendFileTcp, this, sock, path));
	}

	void receiveAdd(struct cmplx_cmd *dg, struct sockaddr_in Sender_addr) {
		std::string file(dg->data);
		bool isOkName = true;
		for (auto c : file) {
			if (c == '/')
				isOkName = false;
		}
		if (!isOkName || fm->free_space < dg->param || fm->exists(dg->data)) {
			struct simpl_cmd *buffer2 = nm->generateSimplCmd("NO_WAY", dg->cmd_seq, file);
			ssize_t length = nm->getSizeWithData(SIMPL_STRUCT, file.size());
			nm->sendCmd((const char*)buffer2, length, Sender_addr);
			free(buffer2);
			std::string ip = nm->getIpFromAddress(Sender_addr);
			uint64_t port = (uint64_t)ntohs(Sender_addr.sin_port);
			if (!isOkName) {
				logger.logError(ip, port, "File name contains \"/\" char.");
				return;
			}
			if (fm->free_space < (dg->param)) {
				logger.logError(ip, port, "Not enough free space.");
				return;
			}
			if (fm->exists(dg->data)) {
				logger.logError(ip, port, "Server already contains that data.");
				return;
			}
			return;
		}

		fm->free_space -= dg->param;
		uint64_t port;
		int sock = getTcpSock(&port);
		struct cmplx_cmd *buff = nm->generateCmplxCmd("CAN_ADD", dg->cmd_seq, port, "");
		ssize_t length = nm->getSizeWithData(CMPLX_STRUCT, 0);
		std::string path = fm->path + "/" + file;
		nm->sendCmd((const char*)buff, length, Sender_addr);
		threadPool.push_back(std::thread(&Server::receiveFileTcp, this, sock, path, file, (uint64_t)dg->param));
		free(buff);
	}

	std::string getPathToFile(std::string file) {
		for (const auto & entry : fs::directory_iterator(fm->path)) {
            if (fs::is_regular_file(entry.path()) && file == entry.path().filename()) {
                return entry.path();
            }
        }

        return "";
	}

	void sendFileTcp(int sock, std::string path) {

		struct sockaddr_in clientAddress;
		socklen_t clientAddressLen = sizeof(clientAddress);
		int msgSock = accept(sock, (struct sockaddr*)&clientAddress, &clientAddressLen);
	
		std::string err = nm->sendFile(msgSock, path);

		fm->isBusy[path] = false;
		close(msgSock);
		close(sock);
	}

	void receiveFileTcp(int sock, std::string path, std::string file, uint64_t size) {

		struct sockaddr_in clientAddress;
		socklen_t clientAddressLen = sizeof(clientAddress);
		int msgSock = accept(sock, (struct sockaddr*)&clientAddress, &clientAddressLen);
		
		if (nm->receiveFile(msgSock, path) == "") {
			fm->files.insert(file);
		} else {
			fm->free_space += size;
		}

		close(msgSock);
		close(sock);
	}
};

Server *server;
void interrupted(int signal) {
	server->logger.log("Got signal " + std::to_string(signal));
	server->logger.log("Exiting. Waiting for all connections to end.");
	for (int i = 0; i < (int)threadPool.size(); ++i) 
		threadPool[i].join();
	free(buffer);
	delete server;
	exit(1);
}

int main(int argc, const char *argv[]) {
	// Server server(argc, argv);
	server = new Server(argc, argv);
	std::signal(SIGINT, interrupted);
	int sock = server->nm->udpSock;
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
		server->handleCmd(cmd, Sender_addr, len);
	}
	for (int i = 0; i < (int)threadPool.size(); ++i) 
		threadPool[i].join();
	free(buffer);
}