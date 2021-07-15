#pragma once
#include <bits/c++config.h>
namespace pwn {
enum pwnflag : std::size_t {
	invalid = -1,
	standard = 0,
	noblocking = 1,
	bit32 = 4,
	bit64 = 8,
	remote = 2,
	local = 16,
};
}
