	#include <iostream>
#include <boost/program_options.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string>
#include <unordered_set>
#include <time.h>
#include <thread>

#include "network-manager.h"
#include "cmd.h"

namespace po = boost::program_options;

#define TTL_VALUE		4

std::vector<std::thread> threadPool;

class Client {
public:
	std::string mcast_addr;
	in_port_t cmd_port;
	std::string out_fldr;
	unsigned int timeout;
	uint64_t cmd_seq;
	std::unordered_set<std::string> fetch_files;
	std::set<unsigned int> activeCmdSeq;
	struct sockaddr_in remote_address;
	std::vector<std::pair<std::string, std::string>> serversFiles;
	NetworkManager *nm;
	FileManager *fm;
	Logger logger;

public: 
	Client(int argc, const char *argv[]) : cmd_seq(0) {
		try {
			po::options_description desc{"Parameters"};
			desc.add_options()
				("help,h", "Help screen.")
				("MCAST_ADDR,g", po::value<std::string>(), "Multicast address.")
				("CMD_PORT,p", po::value<in_port_t>(), "UDP port.")
                ("OUT_FLDR,o", po::value<std::string>(), "Folder path for saving files.")
                ("TIMEOUT,t", po::value<unsigned int>()->default_value(5), "The number of seconds the client can "
                                                                               "wait for answers.")
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
            if (!vm.count("CMD_PORT"))
            	syserr("CMD_PORT is required.");
            if (!vm.count("OUT_FLDR"))
	            syserr("OUT_FLDR is required.");
	        mcast_addr = vm["MCAST_ADDR"].as<std::string>();
	        cmd_port = vm["CMD_PORT"].as<in_port_t>();
	        out_fldr = vm["OUT_FLDR"].as<std::string>();
	        timeout = vm["TIMEOUT"].as<unsigned int>();
	        if (timeout == 0)
	            syserr("TIMEOUT must have positive value.");
	        if (timeout > 300)
	            syserr("TIMEOUT max value is 300.");
	        nm = new NetworkManager(getUDPSock());
	        fm = new FileManager(0, out_fldr);
		} catch (const po::error &e) {
			syserr(e.what());
		}
	}

	~Client() {
		delete nm;
		delete fm;
	}

	int getUDPSock() {
		int udpSock = socket(AF_INET, SOCK_DGRAM, 0);
	    if (udpSock < 0)
	        syserr("socket");
	    int optval = 1;
	    if (setsockopt(udpSock, SOL_SOCKET, SO_BROADCAST, (void*)&optval, sizeof optval) < 0)
		    syserr("setsockopt broadcast");
		optval = TTL_VALUE;
		if (setsockopt(udpSock, IPPROTO_IP, IP_MULTICAST_TTL, (void*)&optval, sizeof optval) < 0)
			syserr("setsockopt multicast ttl");
	    struct timeval t;
	    t.tv_sec = timeout;
	    t.tv_usec = 0;
	    if (setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, (void*)&t, sizeof t)) {
	        syserr("setsockopt timeout");
	    }
	    if (setsockopt(udpSock, SOL_SOCKET, SO_SNDTIMEO, (void*)&t, sizeof t)) {
	        syserr("setsockopt timeout");
	    }
		remote_address.sin_family = AF_INET;
		remote_address.sin_port = htons(cmd_port);
		if (inet_aton(mcast_addr.c_str(), &remote_address.sin_addr) == 0)
		    syserr("inet_aton");
		return udpSock;
	}

	int getTcpOnPort(std::string host, uint64_t port) {
		struct addrinfo addr_hints;
		struct addrinfo *addr_result;
		memset(&addr_hints, 0, sizeof(struct addrinfo));
		addr_hints.ai_family = AF_INET;
		addr_hints.ai_socktype = SOCK_STREAM;
		addr_hints.ai_protocol = IPPROTO_TCP;
		int err = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &addr_hints, &addr_result);
		if (err == EAI_SYSTEM)
			syserr("getaddrinfo: %s", gai_strerror(err));
		else if (err != 0)
			fatal("getaddrinfo: %s", gai_strerror(err));
		int sock = socket(addr_result->ai_family, addr_result->ai_socktype, addr_result->ai_protocol);
		if (sock < 0)
		    syserr("socket");
		struct timeval t;
	    t.tv_sec = timeout;
	    t.tv_usec = 0;
		if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,(struct timeval *)&t,sizeof(struct timeval)) < 0) 
			syserr("setsockopt");
		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&t,sizeof(struct timeval)) < 0) 
			syserr("setsockopt");
		if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
		    syserr("connect tu problem");
		freeaddrinfo(addr_result);

		return sock;
	}

	std::vector<std::pair<uint64_t, std::string>> discover(bool ouput) {
		std::vector<std::pair<uint64_t, std::string>> ret;
		struct simpl_cmd *buffer = nm->generateSimplCmd("HELLO", getCmdSeq(), "");
		uint64_t myCmdSeq = be64toh(buffer->cmd_seq);
		int length = nm->getSizeWithData(SIMPL_STRUCT, 0);
		nm->sendCmd((const char*)buffer, length, remote_address);
		free(buffer);

		char *buff = (char*)malloc(MAX_UDP_SIZE + 1);
		struct sockaddr_in Sender_addr;
		auto packets = nm->recvCmplxCmd(&logger, MAX_UDP_SIZE, &Sender_addr, buff, timeout, "GOOD_DAY", myCmdSeq, "STH");
		free(buff);
		for (auto packet : packets) {
			struct cmplx_cmd *recvbuff = packet.first;
			std::string ip = packet.second;
			if (ouput) {
				std::string toLog("Found " + ip + " (" + std::string(recvbuff->data) + ") with free space " 
					+ std::to_string(recvbuff->param));
				logger.log(toLog);
			}
			ret.push_back({(uint64_t)recvbuff->param, ip});
	    }
	    for (auto packet : packets)
	    	free(packet.first);
	    return ret;
	}

	void fetch(std::string s) {
		if (s.size() == 0 || s.size() == 1) 
			return;
		if (s[0] == ' ')
			s.erase(0, 1);
		else {
			logger.log("[CL ERROR] Unknown command.");
			return;
		}

		int found = -1;
		for (int i = 0; i < (int)serversFiles.size(); ++i) {
			if (serversFiles[i].first == s) 
				found = i;
		}
		if (found == -1) {
			logger.log("File " + s + " not found in last search.");
			return;
		}

		struct simpl_cmd *buffer = nm->generateSimplCmd("GET", getCmdSeq(), serversFiles[found].first);
		uint64_t orgCmdSeq = be64toh(buffer->cmd_seq);
		int length = nm->getSizeWithData(SIMPL_STRUCT, s.size());
		struct sockaddr_in address;
		address.sin_family = AF_INET;
		address.sin_port = htons(cmd_port);
		if (inet_aton(serversFiles[found].second.c_str(), &address.sin_addr) == 0)
		    syserr("inet_aton");
		nm->sendCmd((const char*)buffer, length, address);
		free(buffer);

		char *buff = (char*)malloc(MAX_UDP_SIZE + 1);
		struct cmplx_cmd *recvbuff = NULL;
		struct sockaddr_in Sender_addr;
		socklen_t slen = sizeof(struct sockaddr);
		ssize_t rcv_len = recvfrom(nm->udpSock, buff, MAX_UDP_SIZE, 0, (struct sockaddr *)&Sender_addr, &slen);
		if (rcv_len < 0) {
			free(buff);
			return;
		} else {
			buff[rcv_len] = 0;
			recvbuff = (struct cmplx_cmd*)buff;
			recvbuff->cmd_seq = be64toh(recvbuff->cmd_seq);
			if (!nm->checkCmplxCmd(&logger, nm->getIpFromAddress(Sender_addr), (uint64_t)ntohs(Sender_addr.sin_port), recvbuff, "CONNECT_ME", orgCmdSeq, s)) {
				free(buff);
				return;
			}
		}

		// add thread
		threadPool.push_back(std::thread(&Client::getFile, this, serversFiles[found].second, be64toh(recvbuff->param), s));
		free(buff);
	}

	void getFile(std::string host, uint64_t port, std::string file) {
		int sock = getTcpOnPort(host, port);
		std::string err = nm->receiveFile(sock, out_fldr + "/" + file);
		if (err == "")
			logger.log("File " + file + " downloaded (" + host + ":" + std::to_string(port) + ")");
		else 
			logger.log("File " + file + " downloading failed (" + host + ":" + std::to_string(port) + ") " + err);
		close(sock);
	}

	void sendFile(std::string host, uint64_t port, std::string file) {
		int sock = getTcpOnPort(host, port);
		std::string err = nm->sendFile(sock, file);
		if (err == "") {
			logger.log("File " + fm->getFileName(file) + " uploaded (" + host + ":" + std::to_string(port) + ")");
		} else {
			logger.log("File " + fm->getFileName(file) + "uploading failed (" + host + ":" + std::to_string(port) + ")");
		}
		close(sock);
	}

	void search(std::string s) {
		serversFiles.clear();
		if (s.size() > 0 && s[0] == ' ')
			s.erase(0, 1);
		struct simpl_cmd *buffer = nm->generateSimplCmd("LIST", getCmdSeq(), s);
		uint64_t orgCmdSeq = be64toh(buffer->cmd_seq);
		int length = nm->getSizeWithData(SIMPL_STRUCT, s.size());
		nm->sendCmd((const char*)buffer, length, remote_address);
		free(buffer);

		char *buff = (char*)malloc(MAX_UDP_SIZE + 1);
		struct sockaddr_in Sender_addr;
		auto packets = nm->recvSimplCmd(&logger, MAX_UDP_SIZE, &Sender_addr, buff, timeout, "MY_LIST", orgCmdSeq, "STH");
		free(buff);
        for (auto packet : packets) {
        	struct simpl_cmd *recvbuff = packet.first;
        	std::string ip = nm->getIpFromAddress(Sender_addr);
			std::string file = "";
			std::string nextFile = "";
			for (int i = 0; i < MAX_UDP_SIZE; ++i) {
				if (recvbuff->data[i] == 0) 
					break;
				if (recvbuff->data[i] == '\n') {
					serversFiles.push_back({file, ip});
					logger.log(file + " (" + ip + ")");
					file = "";
				}
				else {
					file += recvbuff->data[i];
					if (recvbuff->data[i + 1] == 0) {
						serversFiles.push_back({file, ip});
						logger.log(file + " (" + ip + ")");
						file = "";
						break;
					}
				}
			}
        }
        for (auto packet : packets)
        	free(packet.first);
	}

	void upload(std::string path) {
		if (path.size() == 0 || path.size() == 1)
			return;
		if (path[0] == ' ')
			path.erase(0, 1);
		FILE *file = fopen(path.c_str(), "r");
		if (file == NULL) {
			logger.log("File " + path + " does not exist");
			return;
		}

		std::vector<std::pair<uint64_t, std::string>> servers = discover(false);
		bool sent = false;
		char *buff = (char*)malloc(MAX_UDP_SIZE + 1);
		uint64_t fileSize = (uint64_t)getFileSize(file);
		fclose(file);
		for (int i = 0; i < (int)servers.size(); ++i) {
			if (fileSize > servers[i].first) {
				logger.log("File " + path + " too big");
				break;
			}
			struct cmplx_cmd *buffer = nm->generateCmplxCmd("ADD", getCmdSeq(), fileSize, fm->getFileName(path));
			uint64_t orgCmdSeq = be64toh(buffer->cmd_seq);
			int length = nm->getSizeWithData(CMPLX_STRUCT, path.size());
			struct sockaddr_in address;
			address.sin_family = AF_INET;
			address.sin_port = htons(cmd_port);
			if (inet_aton(servers[i].second.c_str(), &address.sin_addr) == 0)
			    syserr("inet_aton");
			nm->sendCmd((const char*)buffer, length, address);
			free(buffer);
			struct sockaddr_in Sender_addr;
			socklen_t slen = sizeof(struct sockaddr);
			ssize_t rcv_len = recvfrom(nm->udpSock, buff, MAX_UDP_SIZE, 0, (struct sockaddr*)&Sender_addr, &slen);
			buff[rcv_len] = 0;
			std::string ip = nm->getIpFromAddress(Sender_addr);
			if (rcv_len < 0)
				continue;
			std::string cmd = "";
			for (int i = 0; i < 10; ++i) {
				if (buff[i] == 0)
					break;
				cmd += buff[i];
			}
			if (cmd == "NO_WAY") {
				// check corectness
				struct simpl_cmd *recvStruct = (struct simpl_cmd*)buff;
				recvStruct->cmd_seq = be64toh(recvStruct->cmd_seq);
				nm->checkSimplCmd(&logger, ip, (uint64_t)ntohs(Sender_addr.sin_port), recvStruct, "NO_WAY", orgCmdSeq, fm->getFileName(path));
				continue;
			} else if (cmd == "CAN_ADD") {
				// check corectness
				struct cmplx_cmd *recvStruct = (struct cmplx_cmd*)buff;
				recvStruct->cmd_seq = be64toh(recvStruct->cmd_seq);
				if (!nm->checkCmplxCmd(&logger, ip, (uint64_t)ntohs(Sender_addr.sin_port), recvStruct, "CAN_ADD", orgCmdSeq, ""))
					continue;
				sent = true;
				threadPool.push_back(std::thread(&Client::sendFile, this, ip, be64toh(recvStruct->param), path));
				break;
			} else {
				logger.logError(ip, (uint64_t)ntohs(Sender_addr.sin_port), "Wrong cmd.");
				continue;
			}
		}

		if (!sent) {
		}

		free(buff);
	}

	void remove(std::string s) {
		if (s.size() == 0 || s.size() == 1)
			return;
		if (s[0] == ' ')
			s.erase(0, 1);

		struct simpl_cmd *buffer = nm->generateSimplCmd("DEL", 0, s);
		int length = nm->getSizeWithData(SIMPL_STRUCT, s.size());
		nm->sendCmd((const char*)buffer, length, remote_address);
		free(buffer);
	}

private:
	uint64_t getCmdSeq() {
		// może być mutex śmierdzący
		uint64_t ret = cmd_seq;
		cmd_seq++;
		return ret;
	}
};

int main(int argc, const char *argv[]) {
	Client client(argc, argv);

	std::string command, search_str("search"), fetch_str("fetch"), upload_str("upload"), remove_str("remove");
	while (true) {
		std::getline(std::cin, command);
		if (command == "exit") {
			client.logger.log("Got exiting command.");
			break;
		}
		if (command == "discover") {
			client.discover(true);
			continue;
		}
		if ((int)command.size() >= 5) {
			if (fetch_str == command.substr(0, 5)) {
                    client.fetch(command.substr(5));
                    continue;
            }
            if (command.length() >= 6) {
            	std::string command_substr = command.substr(0, 6);
                if (search_str == command_substr) {
                	if (command.size() >= 7 && command[6] != ' ') {
                		client.logger.log("[CL ERROR] Unknown command.");
                		continue;
                	}
                    client.search(command.substr(6));
                    continue;
                }

                if (upload_str == command_substr) {
                	if (command.size() >= 7 && command[6] != ' ') {
                		client.logger.log("[CL ERROR] Unknown command.");
                		continue;
                	}
                    client.upload(command.substr(6));
                    continue;
                }

                if (remove_str == command_substr) {
                	if (command.size() >= 7 && command[6] != ' ') {
                		client.logger.log("[CL ERROR] Unknown command.");
                		continue;
                	}
                    client.remove(command.substr(6));
                    continue;
                }
            }
		}
		client.logger.log("[CL ERROR] Unknown command.");
	}
	client.logger.log("Exiting. Waiting for all connections to end.");
	for (int i = 0; i < (int)threadPool.size(); ++i)
		threadPool[i].join();
}