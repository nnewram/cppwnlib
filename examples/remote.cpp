#include <cppwnlib/pwn.hpp>

int main() {
	std::string s("www.google.se");
	auto r = pwn::instance<pwn::pwnflag::remote>(s, 80);

	std::string http("HTTP");

//	r.set_timeout(100);
	r.sendline(http);

	for (int i = 0; i < 50; i++) {
		s = r.recvline();
		std::cout << s;
	}
}
