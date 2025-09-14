# Dynamic Analysis Tools

### GDB (GNU Debugger)
**Purpose**: Debug and analyze running programs
- **Pros**: Powerful, flexible, well-documented
- **Cons**: Command-line interface can be intimidating
- **Best for**: Understanding program execution, finding vulnerabilities

### GDB with GEF/PEDA
**Purpose**: Enhanced GDB with better interface
- **Pros**: Colored output, additional commands, exploit-focused
- **Cons**: Additional dependencies
- **Best for**: Exploit development, visual debugging

### strace / ltrace
**Purpose**: Trace system calls and library calls
```bash
strace ./binary_name        # System calls
ltrace ./binary_name        # Library calls
```
