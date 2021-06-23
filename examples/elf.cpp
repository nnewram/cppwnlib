#include "elf.hpp"

void win() {}

void foo() {
	std::cout << "foo" << std::endl;
}

int main() {
	pwn::elf<pwn::bit64> e("a.out");

	std::cout << e.get_symbols().size() << std::endl;

	for (auto &a : e.get_symbols())
		std::cout << pwn::format("symbol {} with type {}", pwn::demanglecpp(a.name), a.get_type()) << std::endl;

	std::cout << pwn::format("{}::foo() = {}", e.get_symbol("foo").size, e.get_symbol("foo").value) << std::endl;
}