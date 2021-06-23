#include "elf.hpp"

int main() {
	pwn::elf<pwn::bit32> e("a.out");

	std::cout << e.get_symbols().size() << std::endl;

	for (auto &a : e.get_symbols())
		std::cout << pwn::format("symbol {} with type {}", pwn::demanglecpp(a.name), a.get_type()) << std::endl;
}