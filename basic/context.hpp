#pragma once
#include <string>
#include <vector>

namespace pwn {

namespace detail {
	template<typename T>
	std::vector<T> between(std::vector<T> vec, std::size_t pos0, std::size_t pos1) {
		std::vector<T> new_vec(pos1 - pos0);
		
		for (std::size_t i = pos0; i < pos1; i++) {
			new_vec.push_back(vec[i]);
		}

		return new_vec;
	}
}

class cyclicg {
private:
	std::string alphabet;
	std::size_t position;
	std::size_t width;
	std::vector<int> buffer;
	std::string yielded;
public:
	cyclicg(std::string &&alphabet, std::size_t width) : alphabet(alphabet), position(0), width(width), buffer(alphabet.length()) {}

	std::vector<int> debruijn(std::size_t amount, int t, int p) {
		if (t > amount) {
			return detail::between(buffer, 1, p + 1);
		}

		buffer[t] = buffer[t - p];

		std::vector<int> partial = debruijn(amount, t + 1, p);

		for (std::size_t i = buffer[t - p] + 1; i < alphabet.length(); i++) {
			buffer[t] = i;
			std::vector<int> partial2 = debruijn(amount, t + 1, p);
			partial.reserve(partial.size() + partial2.size());
			partial.insert(partial.end(), partial2.begin(), partial2.end());
		}

		return partial;
	}

	std::string get(std::size_t amount) {
		std::string buf("");
		std::vector<int> generated = debruijn(amount, 1, 1);
	
		for (int a : generated) {
			buf += 'A' + a;
		}

		return buf;
	}
};

class context {
private:
	cyclicg cyclic_context;
	std::size_t width;
public:
	context() : cyclic_context("ab", 8) {}

	std::string cyclic(std::size_t amount) {
		return cyclic_context.get(amount);
	}
};

}