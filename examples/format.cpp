#include "basic.hpp"
#include "cyclic.hpp"
#include "remote.hpp"
#include <iostream>

int main() {

	std::cout << pwn::format("lol {}, {} \\{\\} {}", 123, "why is it that", 0.123f) << std::endl;

	std::cout << pwn::p64(0x4142434445464748) << std::endl;
	std::cout << pwn::p32(0x31323334) << std::endl;


	pwn::remote<pwn::noblocking | pwn::bit64> r("www.google.se", 80);

	std::string s1 = r.cyclic(100);
	std::string s2 = r.cyclic(100);

	std::cout << s1.length() << " "<< s1 << std::endl;

	std::cout << s2.length() << " "<< s2 << std::endl;


	std::cout << pwn::format("Aaaaaaaa: {}", r.cyclic_find("Aaaaaaaa")) << std::endl;
	std::cout << pwn::format("aaBbaaaa: {}", r.cyclic_find("aaBbaaaa")) << std::endl;


	pwn::cyclic cc(pwn::bit32);

	std::cout << cc.get_sequence(100) << std::endl;
	std::cout << cc.get_sequence(100) << std::endl;
}