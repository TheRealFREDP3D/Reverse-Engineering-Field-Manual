# Practical Exercises

### Exercise 1: Basic String Analysis

Create a simple binary analysis script:

```python
# File: exercise1_string_analysis.py
#!/usr/bin/env python3

"""
Exercise 1: String Analysis Challenge

Task: Create a script that analyzes a binary and finds:
1. All strings containing "flag"
2. All strings that look like passwords (8+ chars, mixed case)
3. All URLs or file paths
4. Potential function names
"""

import re
import sys

def analyze_strings(binary_path):
    """Your implementation here"""
    pass

def find_flags(strings):
    """Find potential flag strings"""
    # TODO: Implement flag detection logic
    pass

def find_passwords(strings):
    """Find potential password strings"""
    # TODO: Implement password pattern matching
    pass

def find_paths(strings):
    """Find file paths and URLs"""
    # TODO: Implement path detection
    pass

# Your code here...
```

### Exercise 2: GDB Automation

```python
# File: exercise2_gdb_automation.py
#!/usr/bin/env python3

"""
Exercise 2: GDB Automation

Task: Create a script that uses GDB to:
1. Set breakpoints on all functions
2. Run the binary with test input
3. Collect information about each function call
4. Generate a report of the program flow
"""

import subprocess
import tempfile

def create_gdb_script(binary_path):
    """Create GDB script for automation"""
    script = f"""
    file {binary_path}
    set confirm off
    set pagination off

    # Your GDB commands here
    """
    return script

def run_gdb_analysis(binary_path):
    """Run automated GDB analysis"""
    # TODO: Implement GDB automation
    pass

# Your implementation here...
```
