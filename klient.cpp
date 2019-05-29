#include <iostream>
#include <boost/program_options.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <unordered_set>
#include <time.h>

#include "network-manager.h"
#include "cmd.h"

namespace po = boost::program_options;

#define TTL_VALUE		4

class Client {
public:
	char *mcast_addr;
	in_port_t cmd_port;
	std::string out_fldr;
	unsigned int timeout;
	uint64_t cmd_seq;
	std::unordered_set<std::string> fetch_files;
	std::set<unsigned int> activeCmdSeq;
	struct sockaddr_in remote_address;
	std::vector<std::pair<std::string, std::string>> serversFiles;
	NetworkManager *nm;

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
	        std::string ma = vm["MCAST_ADDR"].as<std::string>();
	        mcast_addr = new char[ma.length() + 1];
	        for (int i = 0; i < (int)ma.size(); ++i)
	        	mcast_addr[i] = ma[i];
	        mcast_addr[ma.size()] = 0;
	        cmd_port = vm["CMD_PORT"].as<in_port_t>();
	        out_fldr = vm["OUT_FLDR"].as<std::string>();
	        timeout = vm["TIMEOUT"].as<unsigned int>();
	        if (timeout == 0)
	            syserr("TIMEOUT must have positive value.");
	        if (timeout > 300)
	            syserr("TIMEOUT max value is 300.");
	        nm = new NetworkManager(getUDPSock());

		} catch (const po::error &e) {
			syserr(e.what());
		}
	}

	~Client() {
		delete[] mcast_addr;
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
		if (inet_aton(mcast_addr, &remote_address.sin_addr) == 0)
		    syserr("inet_aton");
		return udpSock;
	}

	void discover() {
		std::cout << "discover" << std::endl;
		struct simpl_cmd *buffer = nm->generateSimplCmd("HELLO", getCmdSeq(), "");
		uint64_t orgCmdSeq = buffer->cmd_seq;
		std::cout << "SEND HELLO " << nm->getSizeWithData(SIMPL_STRUCT, 0) << " " << sizeof(buffer) << std::endl;
		int length = nm->getSizeWithData(SIMPL_STRUCT, 0);
		nm->sendCmd((const char*)buffer, length, remote_address);
		delete buffer;

		char *buff = (char*)malloc(sizeof(struct cmplx_cmd) + INET_ADDRSTRLEN + 1);
		while (true) {
			struct sockaddr_in Sender_addr;
			socklen_t slen = sizeof(struct sockaddr);
			ssize_t rcv_len = recvfrom(nm->udpSock, buff, sizeof(struct cmplx_cmd) + INET_ADDRSTRLEN, 0, (struct sockaddr *)&Sender_addr, &slen);
	        if (rcv_len < 0) {
	        	break;
	        } else {
	        	buff[rcv_len] = 0;
				struct cmplx_cmd *recvbuff = (struct cmplx_cmd*)buff;
				assert(orgCmdSeq == recvbuff->cmd_seq);
				// dodaj handlowanie błędami
				std::string ip = nm->getIpFromAddress(Sender_addr);
				std::cout << recvbuff->cmd << " Found " << ip << " (" << recvbuff->data << ") with free space " << be64toh(recvbuff->param) << std::endl;
	        }
	    }
	    delete buff;
	}

	void fetch(std::string s) {
		// if (s.size() == 0 || s.size() == 1)
		// 	return;
		// if (s[0] == ' ')
		// 	s.erase(0, 1);

		// std::cout << "fetch" << std::endl;
		// int found = -1;
		// for (int i = 0; i < (int)serversFiles.size(); ++i) {
		// 	if (serversFiles[i].first == s) 
		// 		found = i;
		// }
		// if (found == -1) {
		// 	std::cout << "File not found in last search." << std::endl;
		// 	return;
		// }

		// struct simpl_cmd *buffer = nm->generateSimplCmd("GET", getCmdSeq(), serversFiles[found].first);
		// int length = nm->getSizeWithData(SIMPL_STRUCT, s.size());
		// std::cout << "size " << length << std::endl;
		// socklen_t slen = sizeof(struct sockaddr);

		// if (sendto(sock, (const char*)buffer, length, 0, (struct sockaddr *)&remote_address, slen) != length) {
		// 	syserr("sendto");
		// }
		// delete buffer;
	}

	void search(std::string s) {
		serversFiles.clear();
		if (s.size() > 0 && s[0] == ' ')
			s.erase(0, 1);
		std::cout << "search " << s << ";" << std::endl;
		struct simpl_cmd *buffer = nm->generateSimplCmd("LIST", getCmdSeq(), s);
		uint64_t orgCmdSeq = buffer->cmd_seq;
		int length = nm->getSizeWithData(SIMPL_STRUCT, s.size());
		std::cout << "size " << length << std::endl;
		nm->sendCmd((const char*)buffer, length, remote_address);
		delete buffer;

		char *buff = (char*)malloc(MAX_UDP_SIZE);
		while (true) {
			struct sockaddr_in Sender_addr;
			socklen_t slen = sizeof(struct sockaddr);
			ssize_t rcv_len = recvfrom(nm->udpSock, buff, MAX_UDP_SIZE, 0, (struct sockaddr *)&Sender_addr, &slen);
	        if (rcv_len < 0) {
	        	break;
	        } else {
				buff[rcv_len] = 0;
	        	struct simpl_cmd *recvbuff = (struct simpl_cmd*)buff;
	        	std::cout << recvbuff->cmd << " " << be64toh(recvbuff->cmd_seq) << std::endl;
	        	assert(recvbuff->cmd_seq == orgCmdSeq);
				std::string ip = nm->getIpFromAddress(Sender_addr);
				std::string file = "";
				for (int i = 0; i < MAX_UDP_SIZE; ++i) {
					if (recvbuff->data[i] == 0) 
						break;
					if (recvbuff->data[i] == '\n') 
						std::cout << " (" << ip << ")" << std::endl;
					else {
						std::cout << recvbuff->data[i];
						if (recvbuff->data[i + 1] == 0) {
							file = "";
							serversFiles.push_back({file, std::string(ip)});
							std::cout << " (" << ip << ")" << std::endl;
							break;
						}
					}
				}
	        }
		}
	}

	void upload(std::string s) {
		std::cout << "upload" << std::endl;
	}

	void remove(std::string s) {
		std::cout << "remove" << std::endl;
		if (s.size() == 0 || s.size() == 1)
			return;
		if (s[0] == ' ')
			s.erase(0, 1);

		struct simpl_cmd *buffer = nm->generateSimplCmd("DEL", 0, s);
		int length = nm->getSizeWithData(SIMPL_STRUCT, s.size());
		nm->sendCmd((const char*)buffer, length, remote_address);
		delete buffer;
	}

private:
	uint64_t getCmdSeq() {
		// może być mutex śmierdzący
		uint64_t ret = cmd_seq;
		std::cout << "biore " << ret << std::endl;
		cmd_seq++;
		return ret;
	}
};

int main(int argc, const char *argv[]) {
	Client client(argc, argv);
	std::cout << client.mcast_addr << std::endl;
	std::cout << client.cmd_port << std::endl;
	std::cout << client.out_fldr << std::endl;
	std::cout << client.timeout << std::endl;

	std::string command, search_str("search"), fetch_str("fetch"), upload_str("upload"), remove_str("remove");
	while (true) {
		std::getline(std::cin, command);
		if (command == "exit") {
			std::cout << "exiting program\n";
			return 0;
		}
		if (command == "discover") {
			client.discover();
			continue;
		}
		if ((int)command.size() >= 5) {
			if (fetch_str.compare(0, 5, command) == 0) {
                    client.fetch(command.substr(5));
                    continue;
            }
            if (command.length() >= 6) {
            	std::string command_substr = command.substr(0, 6);
                if (search_str == command_substr) {
                    client.search(command.substr(6));
                    continue;
                }

                if (upload_str == command_substr) {
                    client.upload(command.substr(6));
                    continue;
                }

                if (remove_str == command_substr) {
                    client.remove(command.substr(6));
                }
            }
		}
	}
}