#include <dlfcn.h>
#include <iostream>

void foo() {
	std::cout << "bruh" << std::endl;
}

int main() {
	void *a = dlopen("a.out", RTLD_LAZY);

	dlerror();

	void (*foo)() = reinterpret_cast<void(*)()>(dlsym(a, "foo"));

	foo();
}