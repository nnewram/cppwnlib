#include "basic.hpp"
#include "remote.hpp"
#include <iostream>

int main() {

	std::cout << pwn::format("lol {}, {} \\{\\} {}", 123, "why is it that", 0.123f) << std::endl;

	std::cout << pwn::p64(0x4142434445464748) << std::endl;
	std::cout << pwn::p32(0x31323334) << std::endl;


	pwn::remote<> r("www.google.se", 80);

	std::cout << r.cyclic(100) << std::endl;

	std::cout << r.cyclic(50) << std::endl;


	std::cout << pwn::format("Abaa: {}", r.cyclic_find("Abaa")) << std::endl;
	std::cout << pwn::format("aaBb: {}", r.cyclic_find("aaBb")) << std::endl;
}