#include "elf.hpp"

void win() {
	
}

void foo() {
	std::cout << "foo" << std::endl;
}

int main() {
	pwn::elf<pwn::bit64> e("a.out");

	std::cout << e.get_symbols().size() << std::endl;

	for (auto &a : e.get_symbols())
		std::cout << pwn::format("symbol {} with type {}", pwn::demanglecpp(a.name), a.get_type()) << std::endl;
	
	auto fun = e.get_function("_Z3foov");

	std::cout << pwn::format("main = {}", fun.get_address()) << std::endl;
	fun.call<void()>();
}