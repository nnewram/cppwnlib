#include "remote.hpp"

int main() {
	auto r = pwn::remote<pwn::nonblocking>("www.google.se", 80);
	std::string s;

	r.setTimeout(100);
	r.sendline("HTTP");

	for (int i = 0; i < 50; i++) {
		s = r.recvline();
		std::cout << s;
	}
}
