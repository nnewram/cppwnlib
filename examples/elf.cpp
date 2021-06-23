#include "elf.hpp"

int main() {
	pwn::elf<pwn::bit64> e("a.out");

	for (auto &a : e.symbols)
		std::cout << a.name << std::endl;
}