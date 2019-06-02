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
#include <algorithm>
#include <csignal>
#include <cstring>
#include <mutex>
#include <atomic>
#include <map>
#include <ctime>

#include "cmd.h"
#include "err.h"

#define MAX_UDP_SIZE 			64000
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

class Logger {
public:
	std::mutex m;

	Logger() {}

	void logError(std::string ip, uint64_t port, std::string err) {
		std::lock_guard<std::mutex> lg(m);
		std::cout << "[PCKG ERROR] Skipping invalid package from " << ip << ":" 
			<< port << ". " << err << std::endl;

		return;
	}

	void log(std::string s) {
		std::lock_guard<std::mutex> lg(m);
		std::cout << s << std::endl;
	}
};

class NetworkManager {
public:
	int udpSock;

	NetworkManager(int set_sock) : udpSock(set_sock) {}

	~NetworkManager() {
		close(udpSock);
	}

	int getSizeWithData(int type, int len) {
		int size = (type == SIMPL_STRUCT ? sizeof(struct simpl_cmd) : sizeof(struct cmplx_cmd));
		if (len == 0)
			return size;
		size += len;
		return size;
	}

	struct simpl_cmd *getSimplCmd(char* buffer, int len) {
		struct simpl_cmd *ret = (struct simpl_cmd*)malloc(len + 1);
		memcpy(ret, (struct simpl_cmd*)buffer, len);
		ret->data[len - sizeof(struct simpl_cmd)] = 0;
		ret->cmd_seq = be64toh(ret->cmd_seq);
		return ret;
	}

	struct cmplx_cmd *getCmplxCmd(char* buffer, int len) {
		struct cmplx_cmd *ret = (struct cmplx_cmd*)malloc(len + 1);
		memcpy(ret, (struct cmplx_cmd*)buffer, len);
		ret->data[len - sizeof(struct cmplx_cmd)] = 0;
		ret->cmd_seq = be64toh(ret->cmd_seq);
		ret->param = be64toh(ret->param);
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
		std::string cmd = "";
		for (int i = 0; i < 10; ++i)
			cmd += (char)buffer[i];
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

	std::string sendFile(int sock, std::string path) {
		FILE *file = fopen(path.c_str(), "r");
		long sendLen = getFileSize(file);		
		char buf[FILE_PACKET_SIZE];
		for (int i = 0; i < FILE_PACKET_SIZE; ++i)
			buf[i] = 0;
		int actPos = 0;
	  	for (uint32_t i = 0; i < sendLen; ++i) {
	  		buf[actPos++] = fgetc(file);
	  		if (actPos + 1 == FILE_PACKET_SIZE) {
	  			int len = sizeof(buf);
			  	if (write(sock, (char*)buf, len) != len) {
		  			fclose(file);
		  			return "Lost connection.";
			  	}
			  	actPos = 0;
	  		} else if (i + (uint32_t)1 == sendLen) {
			  	if (write(sock, buf, sizeof(char) * actPos) != (ssize_t)(sizeof(char) * actPos)) {
		  			fclose(file);
		  			return "Lost connection.";
			  	}
	  		}
	  	}
	  	fclose(file);
	  	return "";
	}

	std::string receiveFile(int sock, std::string path) {
		FILE *file = fopen(path.c_str(), "r+");
		if (file == NULL)
			file = fopen(path.c_str(), "w");

		char fileContent[FILE_PACKET_SIZE];
		ssize_t len;
		while (true) {
			len = read(sock, (char*)fileContent, FILE_PACKET_SIZE);
			if (len == 0)
				break;
			if (len < 0) {
				return "Lost connection.";
			}
			for (int i = 0; i < len; ++i) {
				fputc(fileContent[i], file);
				fileContent[i] = 0;
			}
		}
		fclose(file);
		return "";
	}

	bool checkSimplCmd(Logger *logger, std::string ip, uint64_t port, struct simpl_cmd *dg, std::string cmd, uint64_t cmd_seq, std::string data) {
		std::string dgCmd(dg->cmd);
		if (dgCmd != cmd) {
			logger->logError(ip, port, "Wrong cmd.");
			return false;
		}
		
		if (dg->cmd_seq != cmd_seq) {
			logger->logError(ip, port, "Wrong cmd_seq.");
			return false;
		}
		std::string dgData(dg->data);
		if (data == "" && dgData.size() != 0) {
			logger->logError(ip, port, "Data should be empty.");
			return false;
		}
		else if (data == "STH" && dgData.size() == 0) {
			if (dgCmd != "LIST") {
				logger->logError(ip, port, "Data should contain something.");
				return false;
			}
		}
		else if (data != "STH" && data != "" && data != dgData) {
			logger->logError(ip, port, "Data have invalid content.");
			return false;
		}

		return true;
	}

	bool checkCmplxCmd(Logger *logger, std::string ip, uint64_t port, struct cmplx_cmd *dg, std::string cmd, uint64_t cmd_seq, std::string data) {
		std::string dgCmd = "";
		for (int i = 0; i < 10; ++i) {
			if (dg->cmd[i] == 0)
				break;
			dgCmd += dg->cmd[i];
		}
		if (dgCmd != cmd) {
			logger->logError(ip, port, "Wrong cmd.");
			return false;
		}
		if (dg->cmd_seq != cmd_seq) {
			logger->logError(ip, port, "Wrong cmd_seq.");
			return false;
		}

		std::string dgData(dg->data);
		if (data == "" && dgData.size() != 0) {
			logger->logError(ip, port, "Data should be empty.");
			return false;
		}
		else if (data == "STH" && dgData.size() == 0) {
			logger->logError(ip, port, "Data should contain something.");
			return false;
		}
		else if (data != "STH" && data != "" && data != dgData) {
			logger->logError(ip, port, "Data have invalid content.");
			return false;
		}

		return true;
	}

	void setTimeout(unsigned int timeout) {
		struct timeval t;
	    t.tv_sec = timeout;
	    t.tv_usec = 0;
	    if (setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, (void*)&t, sizeof t)) {
	        syserr("setsockopt timeout");
	    }
	    if (setsockopt(udpSock, SOL_SOCKET, SO_SNDTIMEO, (void*)&t, sizeof t)) {
	        syserr("setsockopt timeout");
	    }
	}

	std::vector<std::pair<struct simpl_cmd*, std::string>> recvSimplCmd(Logger *logger, int toRecv, struct sockaddr_in* addr, char* buff, unsigned int timeout, std::string toCheck1, uint64_t orgCmdSeq, std::string toCheck2) {
		std::vector<std::pair<struct simpl_cmd*, std::string>> ret;
		time_t start;
		time(&start);
		time_t end = start + timeout;
		while (true) {
			time_t now;
			time(&now);
			if (now >= end)
				break;
			setTimeout(difftime(end, now));
			socklen_t slen = sizeof(struct sockaddr);
			ssize_t rcv_len = recvfrom(udpSock, buff, toRecv, 0, (struct sockaddr *)addr, &slen);
			if (rcv_len < 0) {
	        	return ret;
	        } else {
				std::string ip = getIpFromAddress(*addr);
	        	struct simpl_cmd *recvbuff = getSimplCmd(buff, rcv_len);
	        	if (!checkSimplCmd(logger, ip, (uint64_t)ntohs(addr->sin_port), recvbuff, toCheck1, orgCmdSeq, toCheck2)) {
	        		free(recvbuff);
	        		continue;
	        	}
	        	ret.push_back({recvbuff, ip});
	        }
		}
		time(&end);
		setTimeout(timeout);
		return ret;
	}

	std::vector<std::pair<struct cmplx_cmd*, std::string>> recvCmplxCmd(Logger *logger, int toRecv, struct sockaddr_in* addr, char* buff, unsigned int timeout, std::string toCheck1, uint64_t orgCmdSeq, std::string toCheck2) {
		std::vector<std::pair<struct cmplx_cmd*, std::string>> ret;
		time_t start;
		time(&start);
		time_t end = start + timeout;
		while (true) {
			time_t now;
			time(&now);
			if (now >= end)
				break;
			setTimeout(difftime(end, now));
			socklen_t slen = sizeof(struct sockaddr);
			ssize_t rcv_len = recvfrom(udpSock, buff, toRecv, 0, (struct sockaddr *)addr, &slen);
			if (rcv_len < 0) {
	        	return ret;
	        } else {
				std::string ip = getIpFromAddress(*addr);
	        	struct cmplx_cmd *recvbuff = getCmplxCmd(buff, rcv_len);
	        	if (!checkCmplxCmd(logger, ip, (uint64_t)ntohs(addr->sin_port), recvbuff, toCheck1, orgCmdSeq, toCheck2)) {
	        		free(recvbuff);
	        		continue;
	        	}
	        	ret.push_back({recvbuff, ip});
	        }
		}
		time(&end);
		setTimeout(timeout);
		return ret;
	}
};

class FileManager {
public:
	std::atomic<uint64_t> free_space;
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
                unsigned int k = fs::file_size(entry.path());
                if (k > free_space)
                    free_space = 0;
                else
                    free_space -= k;
            }
        }
    }

    void removeFile(std::string s) {
    	for (const auto &entry : fs::directory_iterator(path)) {
    		std::string actName = entry.path().filename();
    		if (fs::is_regular_file(entry.path()) && entry.path().filename() == s && !isBusy[s]) {
    			free_space += fs::file_size(entry.path());
    			files.erase(s);
    			fs::remove(entry.path());
    		}
    	}
    }

    void addFile(std::string s) {
    	files.insert(s);
    	isBusy[s] = false;
    }

	std::string getFileName(std::string path) {
		std::string ret = "";
		for (int i = (int)path.size() - 1; i >= 0; --i) {
			if (path[i] == '/')
				break;
			ret += path[i];
		}
		std::reverse(ret.begin(), ret.end());
		return ret;
	}

	bool exists(std::string file) {
		if (files.find(file) == files.end())
			return false;
		return true;
	}
};