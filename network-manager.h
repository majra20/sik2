#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <unordered_set>
#include <time.h>
#include <thread>
#include <experimental/filesystem>
#include <csignal>
#include <cstring>
#include <map>

#include "cmd.h"
#include "err.h"

#define MAX_UDP_SIZE 			512000
#define CMD_SIZE 				10
#define SIMPL_STRUCT 			0
#define CMPLX_STRUCT 			1
#define FILE_PACKET_SIZE		512000

namespace fs = std::experimental::filesystem;

long getFileSize(FILE *file) {
	fseek(file, 0, SEEK_END); // seek to end of file
	long size = ftell(file); // get current file pointer
	fseek(file, 0, SEEK_SET);
	return size; 
}

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
		std::cout << "Sending cmd: " << buffer << " : length : " << length << std::endl;
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

	void sendFile(int sock, std::string path) {
		FILE *file = fopen(path.c_str(), "r");
		long sendLen = getFileSize(file);		
		char buf[FILE_PACKET_SIZE];
		int actPos = 0;
	  	for (uint32_t i = 0; i < sendLen; ++i) {
	  		buf[actPos++] = fgetc(file);
	  		if (actPos + 1 == FILE_PACKET_SIZE) {
	  			int len = sizeof(buf);
			  	if (write(sock, buf, len) != len)
			  		syserr("partial / failed write");
			  	actPos = 0;
	  		} else if (i + (uint32_t)1 == sendLen) {
			  	if (write(sock, buf, sizeof(char) * actPos) != (ssize_t)(sizeof(char) * actPos))
			  		syserr("partial / failed write");
	  		}
	  	}
	  	fclose(file);
	}

	void receivePacket(int sock, char fileContent[], ssize_t sizeToRecv) {
		size_t prevLen = 0;
		ssize_t len;
		do {
			ssize_t remains = sizeToRecv - prevLen; // number of bytes to be read
			len = read(sock, ((char*)fileContent) + prevLen, remains);
			if (len < 0)
				syserr("reading from client socket");
			else if (len > 0) {
				prevLen += len;
				if ((ssize_t)prevLen == sizeToRecv) {
					prevLen = 0;
					break;
				}
			}
		} while (len > 0);
	}

	void receiveFile(int sock, std::string path) {
		FILE *file = fopen(path.c_str(), "r+");
		if (file == NULL)
			file = fopen(path.c_str(), "w");

		char fileContent[FILE_PACKET_SIZE];
		ssize_t len;
		while (true) {
			len = read(sock, (char*)fileContent, FILE_PACKET_SIZE);
			if (len == 0)
				break;
			if (len < 0)
				syserr("reading from socket");
			for (int i = 0; i < len; ++i) {
				fputc(fileContent[i], file);
				fileContent[i] = 0;
			}
		}
		fclose(file);
	}
};

class FileManager {
public:
	uint64_t free_space;
	uint64_t max_space;
	std::string path;
    std::unordered_set<std::string> files;
    std::map<std::string, bool> isBusy;

    FileManager(unsigned int set_max_space, std::string set_path) 
    	: free_space(set_max_space), max_space(set_max_space), path(set_path) {
    	for (const auto & entry : fs::directory_iterator(path)) {
            if (fs::is_regular_file(entry.path())) {
                files.insert(entry.path().filename());
                isBusy[entry.path().filename()] = false;
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
