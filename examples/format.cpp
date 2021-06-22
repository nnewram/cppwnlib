#include "basic.hpp"
#include "remote.hpp"
#include <iostream>

int main() {

	std::cout << pwn::format("lol {}, {}\\{\\} {}", 123, "why are we here", 0.123f) << std::endl;

	std::cout << pwn::p64(0x4142434445464748) << std::endl;
	std::cout << pwn::p32(0x31323334) << std::endl;


	pwn::remote r("123", 123);

	std::cout << r.cyclic(3) << std::endl;
}