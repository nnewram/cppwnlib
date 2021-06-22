#pragma once
#include <vector>
#include <string>
#include <cmath>
#include <algorithm>

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

	std::size_t roundup(std::size_t number, std::size_t multiple) {
		return ((number + multiple - 1) / multiple) * multiple;
	}
}

class cyclic {
private:
	std::size_t width;
	std::vector<std::size_t> history;
public:
	cyclic(std::size_t width) : width(width), history({0}) {}

	std::string get(std::size_t pos) {
		std::string pattern("");

		pattern += 'A' + pos % 26;
		std::size_t num = pos / 26;
		for (std::size_t i = 1; i < width; i++) {
			pattern += 'a' + num % 26;
			num /= 26;
		}

		return pattern;
	}

	std::string get_sequence(std::size_t len) {
		std::string seq("");
		for (std::size_t i = 0; i < len/width + 1; i++) {
			seq += get(get_pos()/width + i);
		}

		seq.erase(len);

		return seq;
	}

	// courtesy of Gabriel Ericson
	std::uint64_t inverse(std::string pattern) {
		std::size_t offset = 0;

		// find the anchor uppercase letter to adjust for the offset
		for (std::size_t i = 0; i < width; i++) {
			if (pattern[i] < 'a') {
				offset = i;
				break;
			}
		}

		std::string part_lo = pattern.substr(0, offset);
		std::string part_hi = pattern.substr(offset, pattern.length());

		std::uint64_t out_lo = 0;
		std::uint64_t out_hi = 0;

		for (std::size_t i = offset - 1; i > -1; i--) {
			out_lo = part_lo[i] - 'a' + 26 * out_lo;
		}

		bool all_a = true;

		/*
			offset 0: [a + 26b + 26²c + 26³d]
			offset 1: [26b + 26²c + 26³d, (a+1)]
			offset 2: [26²c + 26³d, a + 26b + 1]
			offset 3: [26³d, a + 26b + 26²c + 1]
		*/

		for (std::size_t i = 0; i < part_hi.length(); i++) {
			if (std::tolower(part_hi[i]) != 'a') {
				all_a = false;
				break;
			}
		}

		if (offset && all_a) {
			out_lo++;
		}

		out_lo *= std::pow(26, width - offset);
		
		for (std::size_t i = width - offset - 1; i > 0; i--) {
			out_hi = part_hi[i] - 'a' + 26 * out_hi;
		}

		out_hi = part_hi[0] - 'A' + 26 * out_hi;

		std::uint64_t out = out_lo + out_hi;
		std::uint64_t pos = (out * width - offset);

		std::size_t i = 0;
		bool found = false;
		for (; i < history.size() - 1; i++) {
			if (pos >= history[i] && pos <= history[i + 1]) {
				found = true;
				break;
			}
		}

		if (!found)
			i = history.size() - 1;
		return pos - history[i];
	}

	/*
		walk the position forwards in order to generate unique numbers in the future
		note that the inverse will take the history of positions in to account
		to generate a relative position.
	*/
	void walk(std::size_t number) {
		history.push_back(detail::roundup(history[history.size() - 1] + number, get_width()));
	}

	std::size_t get_width() const {
		return width;
	}

	std::size_t get_pos() const {
		return history[history.size() - 1];
	}
};

}