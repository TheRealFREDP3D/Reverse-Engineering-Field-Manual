# File Analysis Tools

### `file` Command
**Purpose**: Identify file types and basic properties
```bash
file binary_name
# Output: ELF 64-bit LSB executable, x86-64, dynamically linked
```

### `strings` Command
**Purpose**: Extract printable strings from binaries
```bash
strings binary_name | grep -i "flag\|pass\|secret"
```

### `hexdump` / `xxd`
**Purpose**: View binary content in hexadecimal format
```bash
hexdump -C binary_name | head -20
xxd binary_name | less
```
