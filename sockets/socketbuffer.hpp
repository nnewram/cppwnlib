#include <string>
#include <sys/poll.h>
#include <cppwnlib/basic/config.hpp>
#include <unistd.h>

namespace pwn {
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
	int readsock, writesock;
	std::string buffer;

	std::string impl_readb(const std::size_t n = 1024) {
		if (buffer.length() < n) {
			auto partial_buffer = new char[n]();
			
			::read(readsock, partial_buffer, n - buffer.length() - 1);
			buffer += std::string(partial_buffer);
			free(partial_buffer);
		}

		std::string part = buffer.substr(0, n);
		buffer.erase(0, std::min(buffer.length(), n));

		return part;
	}
	
public:
	SocketBuffer() {}
	SocketBuffer(int sockid): readsock(sockid), writesock(sockid), buffer("") {}
	SocketBuffer(int readid, int writeid): readsock(readid), writesock(writeid), buffer("") {}

	std::string read(std::size_t n = 1024) {
		 bool is_nonblocking = flags & noblocking;
		if (is_nonblocking && !socket_has_input(readsock, timeout))
				return "";
	
		return impl_readb(n);
	}

	void unread(const std::string &what) {
		buffer = what + buffer;
	}

	void write(const std::string &what, const std::size_t length) {
		::write(writesock, what.c_str(), length);
	}

	const std::size_t length() {
		return buffer.length();
	}

	void set_timeout(const int ms) {
		timeout = ms;
	}

	int get_readsock() { return readsock; }
	int get_writesock() { return writesock; }
};

}
}
