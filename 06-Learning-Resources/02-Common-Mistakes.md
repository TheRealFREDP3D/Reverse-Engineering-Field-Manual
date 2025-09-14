# Common Mistakes and How to Avoid Them

### Analysis Phase Mistakes

```python
# File: common_mistakes.py
#!/usr/bin/env python3

"""
Common Reverse Engineering Mistakes and Solutions
"""

common_mistakes = {
    "analysis_phase": [
        {
            "mistake": "Not checking file type and architecture first",
            "solution": "Always run 'file binary_name' first",
            "consequence": "Wrong tools/techniques for architecture"
        },
        {
            "mistake": "Ignoring security protections",
            "solution": "Use checksec or similar tools",
            "consequence": "Exploitation attempts fail unexpectedly"
        },
        {
            "mistake": "Not examining all functions in binary",
            "solution": "Use objdump -t or Ghidra symbol tree",
            "consequence": "Missing hidden functionality"
        }
    ],

    "debugging_phase": [
        {
            "mistake": "Not setting appropriate breakpoints",
            "solution": "Break at main, critical functions, and suspected vuln points",
            "consequence": "Missing important program behavior"
        },
        {
            "mistake": "Ignoring program arguments and environment",
            "solution": "Test with various inputs and command line args",
            "consequence": "Missing alternative code paths"
        }
    ],

    "exploitation_phase": [
        {
            "mistake": "Incorrect endianness in payloads",
            "solution": "Use p32()/p64() from pwntools",
            "consequence": "Addresses don't work as expected"
        },
        {
            "mistake": "Not accounting for null bytes in payload",
            "solution": "Check for null bytes, use encoding if necessary",
            "consequence": "Payload gets truncated"
        },
        {
            "mistake": "Wrong offset calculations",
            "solution": "Use cyclic patterns and verify with debugger",
            "consequence": "Exploit doesn't work reliably"
        }
    ]
}

def print_mistakes_guide():
    """Print formatted guide of common mistakes"""
    for phase, mistakes in common_mistakes.items():
        print(f"\n{phase.upper().replace('_', ' ')} MISTAKES:")
        print("=" * 50)

        for i, mistake in enumerate(mistakes, 1):
            print(f"{i}. MISTAKE: {mistake['mistake']}")
            print(f"   SOLUTION: {mistake['solution']}")
            print(f"   CONSEQUENCE: {mistake['consequence']}")
            print()

if __name__ == "__main__":
    print_mistakes_guide()
```

### Debugging Tips

```bash
# File: debugging_tips.sh
#!/bin/bash

echo "=== DEBUGGING TIPS FOR REVERSE ENGINEERING ==="
echo
echo "1. ALWAYS SAVE YOUR WORK:"
echo "   - Document interesting findings immediately"
echo "   - Save GDB sessions: (gdb) set logging on"
echo "   - Screenshot important discoveries"
echo
echo "2. SYSTEMATIC APPROACH:"
echo "   - Follow the same analysis workflow every time"
echo "   - Don't skip steps even for 'simple' binaries"
echo "   - Keep notes of what you've tried"
echo
echo "3. VERIFICATION:"
echo "   - Always test your findings"
echo "   - Verify offsets with different patterns"
echo "   - Test exploits multiple times"
echo
echo "4. LEARNING FROM FAILURES:"
echo "   - Analyze why exploits don't work"
echo "   - Check assumptions about memory layout"
echo "   - Verify target environment matches test environment"
```
