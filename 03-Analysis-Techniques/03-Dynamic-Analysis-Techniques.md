# Dynamic Analysis Techniques

### Finding Crash Points

```python
# File: crash_finder.py
#!/usr/bin/env python3

"""
Simple script to find crash points in binaries using pattern generation
"""

from pwn import *
import string

def generate_pattern(length):
    """Generate a cyclic pattern for overflow testing"""
    pattern = cyclic(length)
    return pattern

def test_crash(binary_path, pattern_length):
    """Test if binary crashes with given pattern length"""
    try:
        # Start the process
        p = process(binary_path)

        # Generate pattern
        pattern = generate_pattern(pattern_length)

        # Send pattern
        p.sendline(pattern)

        # Wait for process to finish
        p.wait()

        # Check return code
        if p.returncode < 0:  # Negative return code indicates crash
            log.success(f"Crash found with {pattern_length} bytes!")
            return True
        else:
            log.info(f"No crash with {pattern_length} bytes")
            return False

    except Exception as e:
        log.error(f"Error testing {pattern_length} bytes: {e}")
        return False

def find_crash_point(binary_path, start=50, end=200, step=10):
    """Find the approximate point where binary starts crashing"""
    log.info(f"Testing crash points for {binary_path}")

    for length in range(start, end, step):
        if test_crash(binary_path, length):
            return length

    log.warning("No crash point found in tested range")
    return None

# Example usage
if __name__ == "__main__":
    binary = "./vulnerable_binary"
    crash_point = find_crash_point(binary)

    if crash_point:
        log.success(f"Binary crashes at approximately {crash_point} bytes")

        # Generate pattern for detailed analysis
        pattern = generate_pattern(crash_point)
        with open("crash_pattern.txt", "wb") as f:
            f.write(pattern)

        log.info("Crash pattern saved to crash_pattern.txt")
        log.info("Use this pattern with GDB to find exact offset")
```

### Precise Offset Finding

```bash
# File: find_offset.sh
#!/bin/bash

BINARY=$1
PATTERN_FILE="crash_pattern.txt"

echo "=== Finding Exact Offset ==="
echo "1. Start GDB with pattern"
echo "   gdb $BINARY"
echo
echo "2. In GDB, run with pattern:"
echo "   (gdb) run < $PATTERN_FILE"
echo
echo "3. After crash, check RSP:"
echo "   (gdb) info registers"
echo "   (gdb) x/gx \$rsp"
echo
echo "4. Find pattern offset:"
echo "   Take the value from RSP and use:"
echo "   python3 -c \"from pwn import *; print(cyclic_find(0x<VALUE>))\""
echo
echo "5. Verify offset:"
echo "   Create payload: 'A' * offset + 'BBBBBBBB'"
echo "   RSP should contain 0x4242424242424242"
```
