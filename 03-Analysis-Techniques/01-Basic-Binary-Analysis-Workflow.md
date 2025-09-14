# Basic Binary Analysis Workflow

### Step 1: Initial Reconnaissance

```bash
# File: basic_analysis.sh
#!/bin/bash

BINARY=$1

echo "=== Basic Binary Analysis ==="
echo "File: $BINARY"
echo

echo "1. File Type Analysis:"
file $BINARY
echo

echo "2. Binary Properties:"
readelf -h $BINARY 2>/dev/null || echo "Not an ELF file"
echo

echo "3. String Analysis:"
echo "Interesting strings:"
strings $BINARY | grep -E "(flag|password|secret|admin|root|key)" | head -10
echo

echo "4. Function Symbols:"
if readelf -s $BINARY 2>/dev/null | grep -q "FUNC"; then
    echo "Functions found:"
    readelf -s $BINARY | grep "FUNC" | head -10
else
    echo "Binary appears to be stripped"
fi
echo

echo "5. Security Protections:"
if command -v checksec >/dev/null; then
    checksec --file=$BINARY
else
    echo "Install checksec for security analysis"
fi
```

### Step 2: Static Analysis Deep Dive

#### Using Ghidra

1. **Launch Ghidra**: `ghidra`
2. **Create New Project**: File → New Project
3. **Import Binary**: File → Import File
4. **Auto-Analyze**: When prompted, accept default analysis options
5. **Navigate Code**: Use the Symbol Tree to find main() function

#### Key Areas to Examine:

```python
# File: analysis_checklist.py
#!/usr/bin/env python3

"""
Static Analysis Checklist for CTF Binaries
"""

checklist = {
    "entry_points": [
        "main() function",
        "_start function",
        "entry point from header"
    ],

    "interesting_functions": [
        "Functions with 'win', 'flag', 'secret' in name",
        "Functions that call system()",
        "Functions that read files",
        "Unused or 'dead' code"
    ],

    "data_sections": [
        "String literals",
        "Hardcoded values",
        "Global variables",
        "Embedded data"
    ],

    "potential_vulnerabilities": [
        "Buffer overflow opportunities",
        "Format string vulnerabilities",
        "Integer overflows",
        "Use after free"
    ]
}

def print_checklist():
    for category, items in checklist.items():
        print(f"\n{category.upper().replace('_', ' ')}:")
        for item in items:
            print(f"  □ {item}")

if __name__ == "__main__":
    print("=== CTF Binary Analysis Checklist ===")
    print_checklist()
```

### Step 3: Dynamic Analysis

#### Basic GDB Usage

```bash
# File: gdb_basics.sh
#!/bin/bash

# Basic GDB commands for binary analysis

echo "=== GDB Basic Commands ==="
echo
echo "Starting GDB:"
echo "  gdb ./binary_name"
echo
echo "Essential Commands:"
echo "  (gdb) run                    # Execute the program"
echo "  (gdb) break main             # Set breakpoint at main"
echo "  (gdb) break *0x401234        # Set breakpoint at address"
echo "  (gdb) continue               # Continue execution"
echo "  (gdb) step                   # Step into function calls"
echo "  (gdb) next                   # Step over function calls"
echo "  (gdb) info registers         # Show register values"
echo "  (gdb) x/20x \$rsp             # Examine stack memory"
echo "  (gdb) disas main             # Disassemble main function"
echo "  (gdb) print variable_name    # Print variable value"
echo "  (gdb) backtrace              # Show call stack"
echo "  (gdb) quit                   # Exit GDB"
```
