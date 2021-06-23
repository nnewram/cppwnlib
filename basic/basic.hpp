#pragma once
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>
#include <iostream>

#include <cxxabi.h>
#include <new>

namespace pwn {

namespace detail {
	template <typename T>
	typename std::enable_if<
		not std::is_convertible<T, std::string>::value,
	std::string>::type stringify(T const &val) {
		return std::to_string(val);
	}

	std::string stringify(std::string const &val) {
		return val;
	}
}

template<typename ...Args>
std::string format(std::string format, Args ...arglist) {
	enum State {
		NORMAL = 0,
		ESCAPE,
		BEGIN,
	};

	State state = NORMAL;

	std::string s2(format);
	std::vector<std::string> formatted {detail::stringify(arglist) ...};

	int argid = 0;
	std::size_t position = 0;
	for (auto itr = format.begin(); itr != format.end(); itr++, position++) {
		switch (*itr) {
			case '\\':
				state = ESCAPE;
				s2.erase(position--, 1);
				break;
			case '{':
				if (state != ESCAPE)
					state = BEGIN;
				break;
			case '}':
				if (state == BEGIN) {
					s2.erase(position - 1, 2);
					s2.insert(position - 1, formatted[argid]);
					position += formatted[argid].length() - 2;
					argid++;
				}
			default:
				state = NORMAL;
		}
	}
	return s2;
}

std::string p64(std::uint64_t value) {
	std::string s("");
	s.resize(8);

	for (char i = 0; i < 8; i++) {
		s += static_cast<unsigned char>(value >> (8 * i) & 0xff);
	}

	return s;
}

std::string p32(std::uint32_t value) {
	std::string s("");
	s.resize(4);


	for (char i = 0; i < 4; i++) {
		s += static_cast<unsigned char>(value >> (8 * i) & 0xff);
	}

	return s;
}

std::string demanglecpp(std::string identifier) {
	const char *demangled = abi::__cxa_demangle(identifier.c_str(), nullptr, nullptr, nullptr);

	if (!demangled)
		return identifier;
	
	std::string s(identifier);
	free(const_cast<char *>(demangled));

	return s;
}

}