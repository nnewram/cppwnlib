#include "elf.hpp"

int main() {
	pwn::elf<pwn::bit64> e("a.out");

	for (auto &a : e.segments)
		std::cout << a.flags << std::endl;
}