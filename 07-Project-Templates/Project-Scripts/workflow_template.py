#!/usr/bin/env python3

"""
Standard CTF Reverse Engineering Workflow Template
"""

import os
import sys
from datetime import datetime
from pathlib import Path

class CTFProject:
    def __init__(self, project_name, binary_path):
        self.project_name = project_name
        self.binary_path = Path(binary_path)
        self.project_dir = Path(f"./ctf-{project_name}")
        self.setup_project_structure()

    def setup_project_structure(self):
        """Create standard project directory structure"""
        directories = [
            'binaries', 'analysis', 'exploits',
            'notes', 'tools', 'analysis/ghidra_project'
        ]

        self.project_dir.mkdir(exist_ok=True)

        for dir_name in directories:
            (self.project_dir / dir_name).mkdir(parents=True, exist_ok=True)

        # Copy binary to project
        if self.binary_path.exists():
            import shutil
            shutil.copy2(self.binary_path, self.project_dir / 'binaries')

        # Create initial files
        self.create_initial_files()

    def create_initial_files(self):
        """Create initial project files"""
        # README.md
        readme_content = f"""# CTF Project: {self.project_name}

## Binary Information
- **File**: {self.binary_path.name}
- **Started**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Analysis Progress
- [ ] Initial reconnaissance
- [ ] Static analysis
- [ ] Dynamic analysis
- [ ] Vulnerability identification
- [ ] Exploit development
- [ ] Documentation

## Notes
Add your analysis notes here...

## Exploitation Status
- **Status**: In Progress
- **Vulnerabilities Found**: TBD
- **Exploit Success**: TBD
"""

        with open(self.project_dir / 'README.md', 'w') as f:
            f.write(readme_content)

        # .env file
        env_content = f"""# Project: {self.project_name}
BINARY_NAME={self.binary_path.name}
BINARY_PATH=./binaries/{self.binary_path.name}
PROJECT_DIR={self.project_dir}

# Target information (update as needed)
TARGET_HOST=localhost
TARGET_PORT=1337

# Analysis settings
DEFAULT_ARCH=amd64
DEFAULT_OS=linux
"""

        with open(self.project_dir / '.env', 'w') as f:
            f.write(env_content)

        # requirements.txt
        requirements = """pwntools>=4.7.0
requests>=2.25.0
python-dotenv>=0.19.0
"""

        with open(self.project_dir / 'requirements.txt', 'w') as f:
            f.write(requirements)

        # .gitignore
        gitignore = """.env
__pycache__/
*.pyc
*.pyo
.DS_Store
.vscode/
.idea/
core
*.core
peda-session-*
.gdb_history
"""

        with open(self.project_dir / '.gitignore', 'w') as f:
            f.write(gitignore)

    def create_analysis_template(self):
        """Create analysis script template"""
        template = f'''#!/usr/bin/env python3

"""
Analysis script for {self.project_name}
Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

from pwn import *
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Configuration
BINARY_PATH = os.getenv('BINARY_PATH', './binaries/{self.binary_path.name}')
context.arch = os.getenv('DEFAULT_ARCH', 'amd64')
context.os = os.getenv('DEFAULT_OS', 'linux')

def initial_analysis():
    """Perform initial binary analysis"""
    log.info("Starting initial analysis...")

    # Load binary
    elf = ELF(BINARY_PATH)

    # Basic information
    log.info(f"Architecture: {elf.arch}")
    log.info(f"Bits: {elf.bits}")
    log.info(f"Endianness: {elf.endian}")

    # Security protections
    log.info("Security protections:")
    log.info(f"  NX: {elf.nx}")
    log.info(f"  PIE: {elf.pie}")
    log.info(f"  Canary: {elf.canary}")
    log.info(f"  RELRO: {elf.relro}")

    # Functions
    log.info("Available functions:")
    for func in elf.symbols:
        if elf.symbols[func] != 0:
            log.info(f"  {{func}}: {{hex(elf.symbols[func])}}")

def static_analysis():
    """Perform static analysis"""
    log.info("Performing static analysis...")

    # String analysis
    import subprocess
    result = subprocess.run(['strings', BINARY_PATH],
                          capture_output=True, text=True)

    interesting_strings = []
    for line in result.stdout.splitlines():
        if any(keyword in line.lower() for keyword in
               ['flag', 'password', 'secret', 'admin', 'root']):
            interesting_strings.append(line)

    if interesting_strings:
        log.success("Interesting strings found:")
        for s in interesting_strings:
            log.info(f"  {s}")

def dynamic_analysis():
    """Perform dynamic analysis"""
    log.info("Starting dynamic analysis...")

    # Test basic execution
    try:
        p = process(BINARY_PATH)
        p.sendline(b"test")
        response = p.recv(timeout=2)
        p.close()

        log.info(f"Basic execution response: {response}")

    except Exception as e:
        log.error(f"Error during basic execution: {e}")

if __name__ == "__main__":
    log.info(f"Analyzing {{BINARY_PATH}}")

    initial_analysis()
    static_analysis()
    dynamic_analysis()

    log.success("Analysis complete!")
'''

        with open(self.project_dir / 'analysis' / 'analyze.py', 'w') as f:
            f.write(template)

        # Make executable
        os.chmod(self.project_dir / 'analysis' / 'analyze.py', 0o755)

# Usage example:
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <project_name> <binary_path>")
        sys.exit(1)

    project_name = sys.argv[1]
    binary_path = sys.argv[2]

    project = CTFProject(project_name, binary_path)
    project.create_analysis_template()

    print(f"Project '{project_name}' created successfully!")
    print(f"Project directory: {project.project_dir}")
    print(f"Next steps:")
    print(f"  1. cd {project.project_dir}")
    print(f"  2. python3 -m pip install -r requirements.txt")
    print(f"  3. python3 analysis/analyze.py")
```
