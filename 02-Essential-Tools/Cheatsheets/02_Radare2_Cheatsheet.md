# Radare2 Quick Reference

```bash
# File: radare2_cheatsheet.txt

=== RADARE2 ESSENTIAL COMMANDS ===

BASIC USAGE:
r2 <binary>                # Open binary in radare2
r2 -d <binary>             # Open in debug mode
r2 -A <binary>             # Auto-analyze binary

ANALYSIS:
aa                         # Analyze all
aaa                        # Analyze all (more thorough)
afl                        # List all functions
afn <new_name> <old_name>  # Rename function
afi                        # Show current function info

NAVIGATION:
s main                     # Seek to main function
s 0x401234                 # Seek to address
pdf                        # Print disassembly of function
pd 20                      # Print 20 disassembly lines

STRINGS AND DATA:
iz                         # List strings in data sections
izz                        # List all strings
iS                         # List sections
ie                         # List entry points

SEARCHING:
/ string                   # Search for string
/x 4142434445             # Search for hex bytes
/r <regex>                 # Search with regex

VISUAL MODE:
V                          # Enter visual mode
VV                         # Enter visual graph mode
p                          # Cycle through visual modes
hjkl                       # Navigation (vim-like)

DEBUG MODE:
db 0x401234               # Set breakpoint
dc                        # Continue execution
ds                        # Step instruction
dr                        # Show registers
```
