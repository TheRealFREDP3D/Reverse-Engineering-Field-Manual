# Compiling C Programs for Practice

A crucial part of learning binary exploitation is having binaries to practice on. Compiling your own simple, vulnerable programs is the best way to start. This allows you to understand the connection between source code and the resulting assembly, and to control the security protections in place.

We'll use `gcc` (the GNU Compiler Collection), which should be installed with `build-essential` or is available on most Linux systems.

### Basic Compilation

Here's a simple "Hello, World!" program (`hello.c`):

```c
// File: hello.c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

To compile it, use the following command:

```bash
gcc -o hello hello.c
```

This creates an executable file named `hello`.

### Compiling for Exploitation Practice

Modern compilers enable security protections by default. For learning basic buffer overflows, it's helpful to disable them.

```bash
# Compile a 64-bit binary with protections disabled
gcc -m64 -fno-stack-protector -z execstack -no-pie -o vulnerable vulnerable.c
```

- **`-fno-stack-protector`**: Disables stack canaries, which are designed to detect stack buffer overflows.
- **`-z execstack`**: Makes the stack executable. This is necessary for shellcode injection but is generally disabled by modern security practices.
- **`-no-pie`**: Disables Position-Independent Executable. This ensures the binary's code is loaded at a fixed address, making it easier to predict function and gadget addresses without needing an information leak.
- **`-m64`**: Explicitly compile for a 64-bit architecture.
