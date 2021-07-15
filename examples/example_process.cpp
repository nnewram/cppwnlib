#include <iostream>

int main(int argc, char **argv) {
	std::string in;
	std::cout << "A" << std::endl;
 	std::cout << "B" << std::endl;

	std::cout << "Argv: ";
	for (int i = 0; i < argc; i++)
    		std::cout << argv[i] << " ";
	std::cout << std::endl;

	std::cin >> in;
	std::cout << "C" << std::endl;
	std::cout << "D" << std::endl;
}
