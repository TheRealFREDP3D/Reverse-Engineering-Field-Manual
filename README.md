# Reverse Engineering CTF Field Manual

A comprehensive, community-sourced collection of reverse engineering resources, guides, and exploit examples for CTF (Capture The Flag) competitions and security research. This repository is structured for easy navigation and is managed using Obsidian.

---

## 📖 Table of Contents

### [▶️ 00-Introduction](./00-Introduction/01-Introduction.md)
-   [Introduction to Reverse Engineering](./00-Introduction/01-Introduction.md)
-   [About and Final Thoughts](./00-Introduction/02-About.md)

### [▶️ 01-Getting-Started](./01-Getting-Started/01-Setting-Up-Your-Environment.md)
-   [Setting Up Your Environment](./01-Getting-Started/01-Setting-Up-Your-Environment.md)
-   [Compiling C Programs for Practice](./01-Getting-Started/02-Compiling-C-Programs.md)

### [▶️ 02-Essential-Tools](./02-Essential-Tools/01-File-Analysis-Tools.md)
-   [File Analysis Tools](./02-Essential-Tools/01-File-Analysis-Tools.md)
-   [Static Analysis Tools](./02-Essential-Tools/02-Static-Analysis-Tools.md)
-   [Dynamic Analysis Tools](./02-Essential-Tools/03-Dynamic-Analysis-Tools.md)
-   **Cheatsheets:**
    -   [GDB Cheatsheet](./02-Essential-Tools/Cheatsheets/01_GDB_Cheatsheet.md)
    -   [Radare2 Cheatsheet](./02-Essential-Tools/Cheatsheets/02_Radare2_Cheatsheet.md)
    -   [Ghidra Cheatsheet](./02-Essential-Tools/Cheatsheets/03_Ghidra_Cheatsheet.md)
    -   [Pwntools Cheatsheet](./02-Essential-Tools/Cheatsheets/04_Pwntools_Cheatsheet.md)

### [▶️ 03-Analysis-Techniques](./03-Analysis-Techniques/01-Basic-Binary-Analysis-Workflow.md)
-   [Basic Binary Analysis Workflow](./03-Analysis-Techniques/01-Basic-Binary-Analysis-Workflow.md)
-   [Static Analysis Fundamentals](./03-Analysis-Techniques/02-Static-Analysis-Fundamentals.md)
-   [Dynamic Analysis Techniques](./03-Analysis-Techniques/03-Dynamic-Analysis-Techniques.md)

### [▶️ 04-Vulnerabilities-and-Exploitation](./04-Vulnerabilities-and-Exploitation/01-Common-Vulnerability-Types.md)
-   [Common Vulnerability Types](./04-Vulnerabilities-and-Exploitation/01-Common-Vulnerability-Types.md)
-   [Exploitation Basics](./04-Vulnerabilities-and-Exploitation/02-Exploitation-Basics.md)
-   [Advanced Topics](./04-Vulnerabilities-and-Exploitation/03-Advanced-Topics.md)
-   [Security Protections and Bypasses](./04-Vulnerabilities-and-Exploitation/04-Security-Protections-and-Bypasses.md)

### [▶️ 05-Practical-Walkthroughs](./05-Practical-Walkthroughs/01-Full-Walkthrough.md)
-   [Full Walkthrough: From C Code to Exploit](./05-Practical-Walkthroughs/01-Full-Walkthrough.md)
-   **Exploit Examples:**
    -   [`vulnerable.c`](./05-Practical-Walkthroughs/Exploit-Examples/vulnerable.c)
    -   [`exploit.py`](./05-Practical-Walkthroughs/Exploit-Examples/exploit.py)
    -   [`basic_buffer_overflow_exploit.py`](./05-Practical-Walkthroughs/Exploit-Examples/basic_buffer_overflow_exploit.py)

### [▶️ 06-Learning-Resources](./06-Learning-Resources/01-Learning-Resources.md)
-   [Additional Learning Resources](./06-Learning-Resources/01-Learning-Resources.md)
-   [Common Mistakes and How to Avoid Them](./06-Learning-Resources/02-Common-Mistakes.md)

### [▶️ 07-Project-Templates](./07-Project-Templates/01-Practical-Exercises.md)
-   [Practical Exercises](./07-Project-Templates/01-Practical-Exercises.md)
-   [Practice Projects](./07-Project-Templates/02-Practice-Projects.md)
-   [Project Template and Workflow](./07-Project-Templates/03-Project-Template-and-Workflow.md)
-   **Project Scripts:**
    -   [`exercise1_string_analysis.py`](./07-Project-Templates/Project-Scripts/exercise1_string_analysis.py)
    -   [`exercise2_gdb_automation.py`](./07-Project-Templates/Project-Scripts/exercise2_gdb_automation.py)
    -   [`project1_password_cracker.py`](./07-Project-Templates/Project-Scripts/project1_password_cracker.py)
    -   [`project2_buffer_overflow_detector.py`](./07-Project-Templates/Project-Scripts/project2_buffer_overflow_detector.py)
    -   [`workflow_template.py`](./07-Project-Templates/Project-Scripts/workflow_template.py)

### [▶️ 99-Assets](./99-Assets/)
- This directory contains media assets used throughout the guide.

---

## 🤝 Contributing

Contributions are welcome! If you have additional guides, examples, or improvements, please feel free to submit a pull request or open an issue.

## ⚠️ Disclaimer

This repository contains educational materials for security research and CTF competitions. All content is provided for educational purposes only. Do not use these techniques for malicious activities.

## 📄 License

This project is licensed under the MIT License.
