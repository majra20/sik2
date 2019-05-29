#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <unordered_set>
#include <time.h>
#include <thread>
#include <csignal>
#include <cstring>

#include "cmd.h"
extern "C" {
	#include "err.h"
}

#define MAX_UDP_SIZE 512000
#define CMD_SIZE 10
#define SIMPL_STRUCT 0
#define CMPLX_STRUCT 1

class NetworkManager {
public:
	int udpSock;

	NetworkManager(int set_sock) : udpSock(set_sock) {}

	int getSizeWithData(int type, int len) {
		int size = (type == SIMPL_STRUCT ? sizeof(struct simpl_cmd) : sizeof(struct cmplx_cmd));
		if (len == 0)
			return size;
		size += len;
		return size;
	}

	struct simpl_cmd *getSimplCmd(char* buffer, int len) {
		std::cout << "deklaruje size " << len << " " << sizeof(struct simpl_cmd) << std::endl;
		struct simpl_cmd *ret = (struct simpl_cmd*)malloc(len + 1);
		memcpy(ret, (struct simpl_cmd*)buffer, len);
		for (int i = 0; i < len; ++i)
			buffer[i] = 0;
		ret->data[len - sizeof(struct simpl_cmd)] = 0;
		ret->cmd_seq = be64toh(ret->cmd_seq);
		std::cout << ret->cmd << " " << ret->cmd_seq << " " << ret->data << std::endl;
		return ret;
	}

	struct cmplx_cmd *generateCmplxCmd(std::string cmd, uint64_t cmd_seq, uint64_t param, std::string data) {
		int size = getSizeWithData(CMPLX_STRUCT, data.size());
		struct cmplx_cmd *ret = (struct cmplx_cmd*)malloc(size);
		strcpy(ret->cmd, cmd.c_str());
		for (int i = cmd.size(); i < 10; ++i)
			ret->cmd[i] = 0;
		ret->cmd_seq = htobe64(cmd_seq);
		ret->param = htobe64(param);
		if (data.size() != 0) 
			memcpy(ret->data, data.c_str(), data.size());
		return ret;
	}

	struct simpl_cmd *generateSimplCmd(std::string cmd, uint64_t cmd_seq, std::string data) {
		std::cout << "seq " << cmd_seq << std::endl;
		int size = getSizeWithData(SIMPL_STRUCT, data.size());
		struct simpl_cmd *ret = (struct simpl_cmd*)malloc(size);
		strcpy(ret->cmd, cmd.c_str());
		for (int i = cmd.size(); i < 10; ++i)
			ret->cmd[i] = 0;
		ret->cmd_seq = htobe64(cmd_seq);
		if (data.size() != 0) 
			memcpy(ret->data, data.c_str(), data.size());
		return ret;
	}

	void sendCmd(const char *buffer, ssize_t length, struct sockaddr_in addr) {
		std::cout << "Sending cmd " << buffer << " " << length << std::endl;
		socklen_t slen = sizeof(struct sockaddr);
	    if (sendto(udpSock, (const char*)buffer, length, 0, (struct sockaddr *)&addr, slen) != length) 
	    	syserr("sendto");
	}

	std::string getIpFromAddress(struct sockaddr_in addr) {
		char ip[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN) == 0)
			syserr("inet_ntop 162");
		return std::string(ip);
	}
};