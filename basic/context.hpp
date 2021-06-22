#pragma once
#include <string>
#include <vector>

#include "cyclic.hpp"

namespace pwn {

class context {
private:
	pwn::cyclic cyclic_context;
public:
	context(std::size_t bitwidth) : cyclic_context(bitwidth) {}

	std::string cyclic(std::size_t amount) {
		std::string seq = cyclic_context.get_sequence(amount);
		cyclic_context.walk(amount);
		
		return seq;
	}

	std::uint64_t cyclic_find(std::string pattern) {
		return cyclic_context.inverse(pattern);
	}
};

}