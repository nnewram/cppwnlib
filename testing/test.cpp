#include <atomic>
#include <thread>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <sys/poll.h>
#include <sys/ptrace.h>
#include <iostream>


constexpr int READ = 0;
constexpr int WRITE = 1;
constexpr int STDIN = 0;
constexpr int STDOUT = 1;
constexpr int STDERR = 2;

int main() {
	int input[2];
	int output[2];

	pipe(input);
	pipe(output);

	int pid = fork();

	if (pid == 0) {
		dup2(input[READ], STDIN);
		dup2(output[WRITE], STDOUT);
		close(input[READ]);
		close(input[WRITE]);

		close(output[READ]);
		close(output[WRITE]);

		execlp("/home/nnew/programming/cppwnlib/examples/example_process", "/home/nnew/programming/cppwnlib/examples/example_process", nullptr);
		exit(1);
	}

	char buff[256] = {0};

	while (1) {
		read(output[READ], &buff, 256);
		if (*buff) {
			std::cout << "content: " << buff << std::endl;
			break;
		}
	}
}

