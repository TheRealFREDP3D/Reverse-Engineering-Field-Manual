# Static Analysis Fundamentals

### Understanding Assembly Basics

#### x86-64 Registers
```
General Purpose Registers:
RAX - Accumulator (return values)
RBX - Base register
RCX - Counter register
RDX - Data register
RSI - Source index (function args)
RDI - Destination index (function args)
RSP - Stack pointer
RBP - Base pointer (frame pointer)

Key Instructions:
MOV - Move data
PUSH/POP - Stack operations
CALL/RET - Function calls
JMP/JE/JNE - Jumps and conditionals
CMP - Compare values
ADD/SUB - Arithmetic
```

#### Common Patterns to Look For

```assembly
# Password checking pattern
cmp    $0x1337, %eax    ; Compare input with expected value
je     success_function  ; Jump if equal to success

# Buffer overflow vulnerability
lea    -0x20(%rbp), %rax ; Load buffer address (32 bytes)
mov    %rax, %rdi        ; Set as destination
call   gets              ; Dangerous function - no bounds checking!

# Hidden functionality
call   system            ; Execute shell command
.string "/bin/sh"        ; Shell command string
```

### Identifying Vulnerabilities

#### Buffer Overflow Indicators

```c
// File: vulnerability_patterns.c
// Common vulnerable patterns to look for in decompiled code

// 1. Dangerous functions
gets(buffer);                    // No bounds checking
strcpy(dest, source);           // No length validation
strcat(dest, source);           // Can exceed buffer
sprintf(buffer, format, ...);    // Format string + overflow

// 2. Fixed-size buffers with user input
char buffer[64];
fgets(buffer, 1000, stdin);     // Reading more than buffer size!

// 3. Missing bounds checks
int index;
scanf("%d", &index);
array[index] = value;           // No validation of index

// 4. Integer overflows
int size;
scanf("%d", &size);
char* buffer = malloc(size);    // What if size is negative?
```
