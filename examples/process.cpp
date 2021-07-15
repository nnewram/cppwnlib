#include <cppwnlib/pwn.hpp>
#include <iostream>

int main() {
	auto p = pwn::instance<pwn::local>("/home/nnew/programming/cppwnlib/examples/example_process");

	std::cout << "Did i fuck up stdout?" << std::endl;

	while (1)
		std::cout << "content2: " << p.recv() << std::endl;
}
