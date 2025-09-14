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
