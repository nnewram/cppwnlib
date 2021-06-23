# cppwnlib
C++ Pwn Library

## Header Only C++ Pwn Library
To use it, simply include it!\
the goal of the library is simplicity and to maximize the readablity of the code\
which is produced when using the library. To use it, include as such.
```cpp
#include "pwn.hpp"

int main() {
  auto r = pwn::remote<pwn::nonblocking>("www.google.com", 80); // non-blocking reading, this is of course optional
  
  std::string buf = "HTTP" + r.cyclic(20) + pwn::p32(0xdeadbeef) + pwn::p64(0x4141414142424242);
  
  r.sendline(buf);
  
  std::cout << pwn::format("recieved {} from google.com", r.recvline());
}
```

## Remote and Process
the most commonly used pwntools functionality is remote and process, \
process is currently WIP and will offer gdb integration. \
However, remote is a easy to use tool similar to that of the pwntools remote but with one twist. \
Instead of having a global cyclic tool, each remote has its own cyclic context which guarantees that each time cyclic is called, \
new data will be generated. Don't worry! This data will still be findable with r.cyclic_find :)

## ELF
Elf parsing is available with `pwn::elf<pwn::bit64 / pwn::bit32>` but will be improved upon in order to create functionality to that of pwntools. \
The goal with the ELF parsing is to be able to do fun things such as
```cpp
#include "pwn.hpp"

int main() {
  pwn::elf<pwn::bit64> binary("challenge");
  
  std::cout << pwn::format("win function at {}", binary.functions["win"].address) << std::endl;
  
  // also since we are in a compiled binary
  
  std::cout << binary.functions["foo"]("test-password") << std::endl;
}
```
