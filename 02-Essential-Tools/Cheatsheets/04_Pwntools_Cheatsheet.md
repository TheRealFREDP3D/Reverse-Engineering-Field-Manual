# Python pwntools Cheatsheet

```python
# File: pwntools_cheatsheet.py

"""
=== PWNTOOLS ESSENTIAL FUNCTIONS ===
"""

from pwn import *

# === CONNECTION ===
p = process('./binary')              # Local process
p = remote('host', port)             # Remote connection
p = ssh('user', 'host', password='pass').process('./binary')  # SSH

# === CONTEXT ===
context.arch = 'amd64'               # Set architecture
context.os = 'linux'                 # Set OS
context.log_level = 'debug'          # Set logging level
context.binary = './binary'          # Set binary context

# === PACKING/UNPACKING ===
p32(0x41414141)                      # Pack 32-bit value
p64(0x4141414141414141)              # Pack 64-bit value
u32(b'AAAA')                         # Unpack 32-bit value
u64(b'AAAABBBB')                     # Unpack 64-bit value

# === PATTERNS ===
cyclic(200)                          # Generate cyclic pattern
cyclic_find(0x61616175)              # Find offset in pattern
cyclic_find(b'uaaa')                 # Find offset by bytes

# === SHELLCODE ===
asm('mov eax, 1')                    # Assemble instruction
shellcraft.sh()                      # Generate shell shellcode
shellcraft.amd64.linux.sh()         # Platform-specific shellcode

# === COMMUNICATION ===
p.recv(1024)                         # Receive up to 1024 bytes
p.recvline()                         # Receive one line
p.recvuntil(b'Enter name: ')         # Receive until pattern
p.send(b'data')                      # Send data
p.sendline(b'data')                  # Send data with newline
p.interactive()                      # Interactive shell mode

# === UTILITY ===
log.info('Message')                  # Info logging
log.success('Success!')              # Success logging
log.warning('Warning!')              # Warning logging
log.error('Error!')                  # Error logging
pause()                              # Pause execution for debugging

# === ELF ANALYSIS ===
elf = ELF('./binary')
elf.address                          # Base address
elf.symbols['main']                  # Symbol address
elf.got['puts']                      # GOT entry
elf.plt['puts']                      # PLT entry
elf.search(b'/bin/sh')              # Search for bytes

# === ROP ===
rop = ROP(elf)
rop.call('system', ['/bin/sh'])      # Call system('/bin/sh')
rop.raw('A' * 8)                     # Add raw data
str(rop)                             # Get ROP chain bytes
```
