# GDB Quick Reference

```bash
# File: gdb_cheatsheet.txt

=== GDB ESSENTIAL COMMANDS ===

STARTING/STOPPING:
gdb <binary>                 # Start GDB with binary
(gdb) run [args]            # Run program with arguments
(gdb) kill                  # Kill running program
(gdb) quit                  # Exit GDB

BREAKPOINTS:
(gdb) break main            # Break at main function
(gdb) break *0x401234       # Break at specific address
(gdb) break filename.c:10   # Break at line 10 in file
(gdb) info breakpoints      # List all breakpoints
(gdb) delete 1              # Delete breakpoint 1
(gdb) disable 1             # Disable breakpoint 1

EXECUTION CONTROL:
(gdb) continue              # Continue execution
(gdb) step                  # Step into function calls
(gdb) next                  # Step over function calls
(gdb) finish                # Run until function returns
(gdb) until                 # Run until next line

EXAMINING DATA:
(gdb) info registers        # Show all registers
(gdb) print $rax           # Show register value
(gdb) x/10x $rsp           # Examine 10 hex words at RSP
(gdb) x/s 0x401234         # Examine string at address
(gdb) disas main           # Disassemble function
(gdb) bt                   # Show backtrace

MEMORY EXAMINATION:
x/[count][format][size] <address>
Formats: x(hex), d(decimal), s(string), i(instruction)
Sizes: b(byte), h(halfword), w(word), g(giant/8bytes)

Examples:
x/20x $rsp                 # 20 hex words from stack
x/5i $rip                  # 5 instructions from current
x/s 0x401000              # String at address

GEF/PEDA ADDITIONS (if installed):
(gdb) checksec             # Show binary protections
(gdb) vmmap                # Show memory mappings
(gdb) pattern create 200   # Create cyclic pattern
(gdb) pattern offset $rsp  # Find offset in pattern
(gdb) rop                  # Find ROP gadgets
```
