#include "remote.hpp"

int main() {
	std::string ip("www.google.se");
	auto r = pwn::remote<pwn::nonblocking>(ip, 80);
	std::string s;

	r.setTimeout(100);
	r.sendline("HTTP");

	for (int i = 0; i < 50; i++) {
		s = r.recvline();
		std::cout << s;
	}
}
