# Setting Up Your Environment

### Recommended Setup

For beginners, I recommend starting with a Linux environment (Ubuntu/Kali Linux) either native or in a virtual machine.

```bash
# File: setup_environment.sh
#!/bin/bash

# Update system
sudo apt update && sudo apt upgrade -y

# Install essential tools
sudo apt install -y \
    gdb \
    radare2 \
    binutils \
    strace \
    ltrace \
    hexdump \
    python3 \
    python3-pip \
    git \
    vim \
    curl \
    wget

# Install pwntools for Python
pip3 install pwntools

# Install additional useful tools
sudo apt install -y \
    ghidra \
    ida-free \
    objdump \
    readelf \
    file \
    strings

echo "Environment setup complete!"
```

### Environment Variables Setup

Create a `.env` file for your workspace:

```bash
# File: .env
# Workspace configuration
WORKSPACE_DIR="$HOME/ctf-reversing"
TOOLS_DIR="$HOME/tools"
BINARIES_DIR="$HOME/ctf-reversing/binaries"
EXPLOITS_DIR="$HOME/ctf-reversing/exploits"

# Default settings
DEFAULT_ARCH="amd64"
DEFAULT_OS="linux"
```
