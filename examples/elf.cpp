#include "elf.hpp"

int main() {
	pwn::elf<pwn::bit32> e("a.out");

	std::cout << e.get_relocations().size() << std::endl;

	for (auto &a : e.get_relocations())
		std::cout << pwn::format("relocation {} with type {}", a.symbol_name, a.type) << std::endl;
}