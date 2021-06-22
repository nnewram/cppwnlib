#pragma once
#include "basic.hpp"
#include "context.hpp"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <sys/poll.h>

namespace pwn {

enum RemoteFlags {
	nonblocking = 1
};

namespace detail {

bool socket_has_input(int sockid, int timeout) {
	pollfd fds[1] = {
		{
			.fd = sockid,
			.events = POLLIN
		}
	};

	int status = poll(fds, 1, timeout);

	if (status == -1)
		throw std::runtime_error(pwn::format("Could not poll sockid: {}", sockid));

	return fds[0].revents & POLLIN;
}

template<int flags = 0>
class SocketBuffer {
private:
	int timeout = 100;
	int sockid;
	std::string buffer;

	std::string impl_readb(std::size_t n = 1024) {
		if (buffer.length() < n) {
			char *partial_buffer = static_cast<char *>(calloc(n, 1));
			::read(sockid, partial_buffer, n - buffer.length() - 1);
			buffer += std::string(partial_buffer);
			free(partial_buffer);
		}

		std::string part = buffer.substr(0, n);
		buffer.erase(0, n);

		return part;
	}

	std::string impl_readnb(std::size_t n = 1024) {
		if (!socket_has_input(sockid, timeout))
			return "";
		
		if ((buffer.length() < n)) {
			char *partial_buffer = static_cast<char *>(calloc(n, 1));

			::read(sockid, partial_buffer, n - buffer.length() - 1);
			buffer += partial_buffer;

			free(partial_buffer);
		}

		std::string part = buffer.substr(0, n);
		buffer.erase(0, std::min(buffer.length(), n));

		return part;
	}
public:
	SocketBuffer() {}
	SocketBuffer(int sockid) : sockid(sockid), buffer("") {}

	std::string read(std::size_t n = 1024) {
		constexpr bool is_nonblocking = flags & nonblocking;
		if (is_nonblocking) {
			return impl_readnb(n);
		}
		else {
			return impl_readb(n);
		}
	}

	void unread(std::string what) {
		buffer = what + buffer;
	}

	void write(std::string what, const std::size_t length) {
		::write(sockid, what.c_str(), length);
	}

	const std::size_t length() {
		return buffer.length();
	}

	void set_timeout(int milliseconds) {
		timeout = milliseconds;
	}
};

bool is_ip(const std::string &s) {
	std::string::const_iterator itr = s.begin();
	
	for (int i = 0; i < 4; i++) {
		std::string::const_iterator itr2 = itr;
		
		while (itr != s.end() && std::isdigit(*itr))
			itr++;

		if ((itr == itr2) || (*itr++ != '.'))
			return false;
	}

	return true;
}

}

template<int flags = 0>
class remote {
private:
	int sockid;
	context ctx;
	std::string ip;
	int port;

	detail::SocketBuffer<flags> sb;
public:
	remote() {}

	remote(const std::string ip, int port) : ctx(), sb(), port(port) {
		sockid = socket(AF_INET, SOCK_STREAM, 0);
		if (sockid < 0) {
			throw std::runtime_error(pwn::format("Failed to establish a socket to {}:{}", ip, port));
		}

		sockaddr_in server;
		server.sin_family = AF_INET;
		server.sin_port = htons(port);

		if (detail::is_ip(ip)) {
			if (inet_pton(AF_INET, ip.c_str(), &server.sin_addr) < 1) {
				throw std::runtime_error(pwn::format("Invalid ip: {}", ip));
			}

			this->ip = ip;
		}
		else {
			hostent *hent;
			in_addr **ip_list;
			
			if (!(hent = gethostbyname(ip.c_str()))) {
				throw std::runtime_error(pwn::format("Could not get host {} by name", ip));
			}

			ip_list = reinterpret_cast<in_addr **>(hent->h_addr_list);
			
			char *real_ip = inet_ntoa(*ip_list[0]);

			if (!real_ip) {
				throw std::runtime_error(pwn::format("Could not deduce ip from {}", ip));
			}

			if (inet_pton(AF_INET, real_ip, &server.sin_addr) < 1) {
				throw std::runtime_error(pwn::format("Invalid ip: {}", ip));
			}

			this->ip = std::string(real_ip);
		}

		if (connect(sockid, reinterpret_cast<sockaddr *>(&server), sizeof(server)) < 0) {
			throw std::runtime_error(pwn::format("Could not connect to {}:{}", this->ip, port));
		}

		sb = detail::SocketBuffer<flags>(sockid);
	}

	std::string recv(const std::size_t length = 1024) {
		return sb.read(length);
	}

	std::string recvline(const std::size_t buffsize = 1024) {
		std::string buffer("");
		std::string new_part;
		
		while (true) {
			new_part = sb.read(buffsize);
			auto endline = new_part.find('\n');
		
			if (endline != std::string::npos) {
				if (endline < new_part.length()) {
					sb.unread(new_part.substr(endline + 1, new_part.length()));
					new_part.erase(endline + 1, new_part.length());

				}
				break;
			}

			if ((new_part == "") && (flags & nonblocking))
				break;
			
			buffer += new_part;
		}

		buffer += new_part;
		return buffer;
	}

	void send(const std::string what, const std::size_t length = 0) {
		sb.write(what, length ? length : what.length());
	}

	void sendline(const std::string what) {
		send(what + '\n');
	}

	void setTimeout(int milliseconds) {
		if (!(flags & nonblocking))
			throw std::runtime_error("Only possible to set timeout on non-blocking remotes. Use pwn::nonblocking as a flag.");
		
		sb.set_timeout(milliseconds);
	}

	/*
		Q: why the fck is cyclic here?
		A: this allows us to generate unique cyclic data all the time for the specific remote instance 
	*/
	std::string cyclic(std::size_t amount) {
		return ctx.cyclic(amount);
	}

	std::size_t cyclic_find(std::string pattern) {
		return ctx.cyclic_find(pattern);
	}
};

}