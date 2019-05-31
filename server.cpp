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

void interrupted(int signal) {
	std::cout << "Ktoś mi wykurwił bombe" << std::endl;
	exit(0);
}

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
			receiveAdd(nm->getCmplxCmd(buffer, len), Sender_addr);
			return;
		}
		bool isOk = false;
		for (auto s : simpl) {
			if (cmd == s)
				isOk = true;
		}
		std::cout << "Dostałem taką komende2 " << cmd << std::endl;
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
		else if (cmd == "DEL")
			receiveDel(dg);
		else if (cmd == "GET")
			receiveGet(dg, Sender_addr); 
		else {
			//log it
			std::cout << "Zły cmd" << std::endl;
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

	void receiveGet(struct simpl_cmd *dg, struct sockaddr_in Sender_addr) {
		std::cout << dg->cmd << " " << dg->data << std::endl;
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
			return;
		}
		uint64_t port;
		int sock = getTcpSock(&port);
		struct cmplx_cmd *buffer = nm->generateCmplxCmd("CONNECT_ME", dg->cmd_seq, port, toGet);
		ssize_t length = nm->getSizeWithData(CMPLX_STRUCT, toGet.size());
		std::string path = getPathToFile(toGet);
		nm->sendCmd((const char*)buffer, length, Sender_addr);
		delete buffer;
		std::thread t1(&Server::sendFileTcp, this, sock, path);
		t1.join();

	}

	void receiveAdd(struct cmplx_cmd *dg, struct sockaddr_in Sender_addr) {
		// sprawdz poprawność tej komendy
		std::string file(dg->data);
		bool isOkName = true;
		for (auto c : file) {
			if (c == '/')
				isOkName = false;
		}
		if (!isOkName || file.size() == 0 || fm->free_space < dg->param || fm->exists(dg->data)) {
			struct simpl_cmd *buffer = nm->generateSimplCmd("NO_WAY", dg->cmd_seq, file);
			ssize_t length = nm->getSizeWithData(CMPLX_STRUCT, file.size());
			nm->sendCmd((const char*)buffer, length, Sender_addr);
			delete buffer;
			delete dg;
			return;
		}

		fm->free_space -= dg->param;
		uint64_t port;
		int sock = getTcpSock(&port);
		struct cmplx_cmd *buff = nm->generateCmplxCmd("CAN_ADD", dg->cmd_seq, port, "");
		ssize_t length = nm->getSizeWithData(CMPLX_STRUCT, 0);
		std::string path = fm->path + "/" + file;
		nm->sendCmd((const char*)buff, length, Sender_addr);
		delete buff;
		std::thread t1(&Server::receiveFileTcp, this, sock, path, file, (uint64_t)dg->param);
		t1.join();
	}

	std::string getPathToFile(std::string file) {
		for (const auto & entry : fs::directory_iterator(fm->path)) {
            if (fs::is_regular_file(entry.path()) && file == entry.path().filename()) {
                std::cout << entry.path() << std::endl;
                return entry.path();
            }
        }

        return "";
	}

	void sendFileTcp(int sock, std::string path) {
		std::cout << "Send file " << std::endl;

		socklen_t clientAddressLen;
		struct sockaddr_in clientAddress;
		int msgSock = accept(sock, (struct sockaddr*)&clientAddress, &clientAddressLen);
	
		nm->sendFile(msgSock, path);

		fm->isBusy[path] = false;
		close(msgSock);
		close(sock);
		std::cout << "wyslalem" << std::endl;
	}

	void receiveFileTcp(int sock, std::string path, std::string file, uint64_t size) {
		std::cout << "Receive file " << path << std::endl;

		socklen_t clientAddressLen;
		struct sockaddr_in clientAddress;
		int msgSock = accept(sock, (struct sockaddr*)&clientAddress, &clientAddressLen);
	
		if (nm->receiveFile(msgSock, path) == "") {
			fm->files.insert(file);
		} else {
			fm->free_space += size;
		}

		close(msgSock);
		close(sock);
		std::cout << "wyslalem" << std::endl;
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
		std::cout << "Otworzony tcp socket na porcie " << ntohs(server_address.sin_port) << std::endl;
		*port = (uint64_t)ntohs(server_address.sin_port);
		return sock;
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
		std::cout << "Dostałem " << cmd << " handling" << std::endl;
		server.handleCmd(cmd, Sender_addr, len);
	}
	delete buffer;
}