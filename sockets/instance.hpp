#pragma once
#include <cppwnlib/basic/config.hpp>
#include <cppwnlib/basic/context.hpp>
#include <cppwnlib/sockets/socketbuffer.hpp>

#include <atomic>
#include <thread>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <sys/poll.h>
#include <sys/ptrace.h>

namespace pwn {
template<int flags = 0>
class instance;

namespace detail {

constexpr int read = 0;
constexpr int write = 1;
constexpr int stdin = 0;
constexpr int stdout = 1;
constexpr int stderr = 2;

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

template<int flags>
class instance {
private:
	context ctx;
	std::string ip;
	int port;

	detail::SocketBuffer<flags> sb;
public:
	instance() {}
	// why tf doesn't sfinae work on constructors?

	template<typename ...Args>
	instance(std::string pathorip, Args&& ...args): ctx(flags & (pwn::bit64 | pwn::bit32)), sb() {
		constexpr bool is_remote = pwnflag::remote & flags;
		constexpr bool is_local = pwnflag::local & flags;
		if constexpr (is_remote) {
			_instance_remote(pathorip, std::get<0>(std::forward_as_tuple(args ...)));
		}
		else if constexpr (is_local) {
			_instance_local(pathorip, std::forward<Args>(args) ...);
		}
		else {
			throw std::runtime_error("Incorrect flag for instance, please use either pwnflag::remote or pwnflag::local");
		}
	}

private:
	void _instance_remote(std::string ip, int port) {
		int sockid = socket(AF_INET, SOCK_STREAM, 0);
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

			this->ip = std::move(ip);
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

	template<typename ...Args>
	void _instance_local(std::string path, Args&& ...args) {

		std::vector<std::string> argv {path, pwn::detail::stringify(std::forward<Args>(args)) ...};

		int input_socket[2] = {0};
		int output_socket[2] = {0};
		pipe(input_socket);
		pipe(output_socket);

		int pid = fork();

		auto pargv = new char *[argv.size() + 1]();
		for (int i = 0; i < argv.size(); i++)
			pargv[i] = const_cast<char *>(argv[i].c_str());

		if (pid == 0) {
    			/*
			 * Make the program socket create duplicates to map to stdin, stdout, stderr.
			 * Close the actual socket in the fork for clean-up.
			*/
			dup2(input_socket[detail::read], detail::stdin);
 			dup2(output_socket[detail::write], detail::stdout);
			//dup2(program_socket[detail::write], detail::stderr);

			close(input_socket[detail::read]);
			close(input_socket[detail::write]);
			close(output_socket[detail::read]);
			close(output_socket[detail::write]);

			/*
			 * Construct an array for argv, nullptr terminated.
			 * */

//			ptrace(PTRACE_TRACEME, pid, nullptr, nullptr); // PTRACE for debugging.
			execvp(pargv[0], &pargv[0]);

			exit(0);
		}
		else {
			close(input_socket[detail::read]);
			close(output_socket[detail::write]);

			sb = detail::SocketBuffer<flags>(output_socket[detail::read], input_socket[detail::write]);
		}
	
	}

public:
	~instance() {
		if (sb.get_readsock() == sb.get_writesock()) {
			close(sb.get_readsock());
		}
		else {
			close(sb.get_readsock());
			close(sb.get_writesock());
		}
	}

	std::string recv(const std::size_t length = 1024) {
		return sb.read(length);
	}

	std::string recvuntil(const std::string &what, const std::size_t buffsize = 1024) {
		std::string buffer("");
		std::string new_part;
		
		while (true) {
			new_part = sb.read(buffsize);
			auto endline = new_part.find(what);
		
			if (endline != std::string::npos) {
				if (endline < new_part.length()) {
					sb.unread(new_part.substr(endline + what.length(), new_part.length()));
					new_part.erase(endline + what.length(), new_part.length());

				}
				break;
			}

			if ((new_part == "") && (flags & noblocking))
				break;
			
			buffer += new_part;
		}

		buffer += new_part;
		return buffer;
	}

	std::string recvline(const std::size_t buffsize = 1024) {
		return recvuntil("\n", buffsize);
	}

	void send(const std::string &what, const std::size_t length = 0) {
		sb.write(what, length ? length : what.length());
	}

	void sendline(const std::string &what) {
		send(what + '\n');
	}

	void set_timeout(const int ms) {
		if (!(flags & noblocking))
			throw std::runtime_error("Only possible to set timeout on non-blocking remotes. Use pwn::nonblocking as a flag.");
		
		sb.set_timeout(ms);
	}

private:
	static void _input_loop(std::atomic<bool> &loop, instance<flags> *that) {
		std::string linebuffer;
	
		while (loop.load()) {
			std::getline(std::cin, linebuffer);
			if (linebuffer == "quit") {
				loop = false;
				break;
			}

			that->sendline(linebuffer);
		}
	}
public:
	void interactive() {
		std::atomic<bool> loop(true);
		
		std::thread input_thread(_input_loop, std::ref(loop), this);

		while (loop.load()) {
			std::string s = recvline();
			std::cout << s;
		}
	}

	/*
		Q: why the fck is cyclic here?
		A: this allows us to generate unique cyclic data all the time for the specific remote instance 
	*/
	std::string cyclic(const std::size_t amount) {
		return ctx.cyclic(amount);
	}

	std::size_t cyclic_find(const std::string pattern) {
		return ctx.cyclic_find(pattern);
	}
};

}
