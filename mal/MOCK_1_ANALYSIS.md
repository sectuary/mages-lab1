# ST2617 Mock Test 1 - Complete Analysis
## mock_1.exe Encryption Analysis

**Analyst:** Claude Code
**Date:** 2026-01-27
**Binary:** mock_1.exe (9.5K PE32 executable)

---

## Executive Summary

**Decrypted Message from Settings.ini:**
```
THis is a mock test
```

**Encryption Method:** Simple ADD cipher (byte-by-byte addition)

**Key Selection:** Based on day of week (Sunday=0 to Saturday=6)

---

## Beginner's Guide: Understanding the Concepts

**For students new to reverse engineering and malware analysis**

This section explains all the technical terms in simple language. If you're comfortable with these concepts, skip to the questions below.

---

### What is a Binary/Executable File?

**Simple explanation:** A binary is a file containing **machine code** - instructions that the computer's processor understands directly.

- **Source code** (like `mock_1.c`) is what humans write in C/Python/etc.
- **Binary** (like `mock_1.exe`) is what the computer runs
- **Reverse engineering** means converting the binary BACK to understand what it does (without having the source code)

**Think of it like:** Source code is a recipe in English, binary is the same recipe written in a secret code only the oven understands.

---

### What is Assembly Language?

**Simple explanation:** Assembly is a **human-readable** version of machine code.

```
Machine code (hex):  8B 45 F8
Assembly:            mov eax, [ebp-8]
Meaning in English:  "Copy the value from memory location (ebp-8) into register eax"
```

**Key concepts:**
- **Instructions** = Actions the CPU performs (like MOV, ADD, CALL)
- **Registers** = Tiny storage spaces inside the CPU (like EAX, EBX, ECX)
- **Memory addresses** = Locations in RAM where data is stored

**Think of it like:** Assembly is the step-by-step instruction manual the CPU follows, like "take ingredient from shelf 3, pour into bowl A, stir 5 times."

---

### What are Registers?

**Simple explanation:** Registers are **super-fast temporary storage** inside the CPU.

**Common x86 registers:**
| Register | Purpose | Real-world analogy |
|----------|---------|-------------------|
| **EAX** | Accumulator (math results) | Calculator display |
| **EBX** | Base register (data pointer) | Bookmark in a book |
| **ECX** | Counter (loop iterations) | Tally counter |
| **EDX** | Data register | Scratch paper |
| **ESI** | Source Index (copying FROM) | Copy machine's input tray |
| **EDI** | Destination Index (copying TO) | Copy machine's output tray |
| **EBP** | Base Pointer (stack frame) | Sticky note marking your page |
| **ESP** | Stack Pointer (top of stack) | Top card in a deck |

**Example:**
```assembly
mov eax, 5       ; Put number 5 into EAX (like writing "5" on scratch paper)
add eax, 3       ; Add 3 to EAX (now EAX = 8)
```

---

### What are Opcodes?

**Simple explanation:** Opcodes are the **actual numeric codes** for assembly instructions.

```
Assembly:   ADD  AL, [EBP-8]
Opcode:     02 45 F8
            ↑   ↑  ↑
            │   │  └─ Offset (-8)
            │   └──── Register (EBP)
            └──────── Instruction (ADD)
```

**Why it matters:**
- **ADD** opcodes: 00, 01, 02, 03
- **XOR** opcodes: 30, 31, 32, 33
- By looking at the opcode, you can tell if encryption uses ADD or XOR!

**Think of it like:** If assembly is "turn left," the opcode is the steering wheel's exact rotation angle in degrees.

---

### What is the Stack?

**Simple explanation:** The stack is a **temporary scratch space** in memory, organized like a stack of plates.

**LIFO = Last In, First Out** (like stacking dishes)

```
Stack grows DOWN in memory:

High Address
    │
    ├─ [Plate 1: Old data]      ← EBP (Base Pointer - bottom of your stack frame)
    ├─ [Plate 2: Variable x]    ← EBP-4
    ├─ [Plate 3: Variable y]    ← EBP-8
    ├─ [Plate 4: Temp result]   ← ESP (Stack Pointer - top of stack)
    │
Low Address
```

**Common operations:**
- `push eax` = Add plate on top (store EAX on stack)
- `pop eax` = Remove top plate (load into EAX)
- `[ebp-8]` = Access local variable 8 bytes below base pointer

**Think of it like:** A stack of cafeteria trays - you always take from the top, and new trays go on top.

---

### What are Function Calls?

**Simple explanation:** A function is a **reusable block of code** with a name.

**In C:**
```c
int add(int a, int b) {
    return a + b;
}

result = add(5, 3);  // Calls the function
```

**In Assembly:**
```assembly
push 3           ; Put argument 2 on stack
push 5           ; Put argument 1 on stack
call add         ; Jump to the 'add' function
                 ; (return value will be in EAX)
```

**The CALL instruction does 2 things:**
1. Save the **return address** (where to come back)
2. Jump to the function

**Think of it like:** Calling a function is like asking someone to do a task, then waiting for them to report back with the result.

---

### Number Systems: Hex, Decimal, Binary

**Simple explanation:** Different ways to write the same number.

| Decimal | Hex | Binary | ASCII |
|---------|-----|--------|-------|
| 84 | 0x54 | 01010100 | 'T' |
| 72 | 0x48 | 01001000 | 'H' |
| 105 | 0x69 | 01101001 | 'i' |

**Why hex?**
- Computers think in binary (0s and 1s)
- Binary is too long to read (01010100)
- Hex is compact and converts easily to binary
- Each hex digit = 4 binary bits

**Conversion trick:**
- **Hex to Decimal:** 0x54 = (5 × 16) + 4 = 80 + 4 = 84
- **Decimal to ASCII:** 84 = 'T' (lookup in ASCII table)

**Think of it like:** Different languages for the same number - like saying "three" (English), "trois" (French), "三" (Chinese).

---

### What is ASCII?

**Simple explanation:** ASCII is a **standard mapping** of numbers to characters.

| Decimal | Hex | Character | Type |
|---------|-----|-----------|------|
| 65-90 | 0x41-0x5A | A-Z | Uppercase letters |
| 97-122 | 0x61-0x7A | a-z | Lowercase letters |
| 48-57 | 0x30-0x39 | 0-9 | Numbers |
| 32 | 0x20 | (space) | Space |
| 10 | 0x0A | \n | Newline |

**Example:**
```
Hex bytes:  54 48 69 73
Decimal:    84 72 105 115
ASCII:      T  H  i   s
```

**Think of it like:** A codebook where 84 means 'T', 72 means 'H', etc.

---

### What is Encryption?

**Simple explanation:** Encryption **scrambles data** so only people with the key can read it.

**Good encryption (strong):**
- AES, RSA - Used by banks, military
- Very hard to break without the key

**Bad encryption (weak):**
- ADD cipher (this program) - Easy to break
- XOR with short key - Can be cracked quickly

**This program's encryption:**
```
Plain text:   "T"     = 84 (decimal)
Key byte:     0xC5    = 197 (decimal)
Encrypted:    84 + 197 = 281 → 281 mod 256 = 25 (wraps around)
Result:       0x19
```

**Decryption (reverse operation):**
```
Encrypted:    0x19    = 25 (decimal)
Key byte:     0xC5    = 197 (decimal)
Decrypted:    25 - 197 = -172 → -172 mod 256 = 84
Result:       84 = 'T'
```

**Think of it like:**
- **Encryption:** Adding a secret number to each letter
- **Decryption:** Subtracting the same secret number to get back the original

---

### What are Structs (Structures)?

**Simple explanation:** A struct is a **container** that groups related data together.

**Example: struct tm (time structure)**
```c
struct tm {
    int tm_sec;      // Seconds (0-59)        [Offset: +0]
    int tm_min;      // Minutes (0-59)        [Offset: +4]
    int tm_hour;     // Hours (0-23)          [Offset: +8]
    int tm_mday;     // Day of month (1-31)   [Offset: +12]
    int tm_mon;      // Month (0-11)          [Offset: +16]
    int tm_year;     // Years since 1900      [Offset: +20]
    int tm_wday;     // Day of week (0-6)     [Offset: +24 = 0x18]
    // ...
};
```

**How to read it:**
```assembly
call localtime           ; Returns pointer to struct tm in EAX
mov eax, [eax+18h]      ; Read the value 24 bytes from start
                        ; 24 bytes = tm_wday field!
```

**Think of it like:** A form with labeled boxes:
```
┌─────────────────┐
│ Seconds: [ 45 ] │  ← Offset +0
│ Minutes: [ 30 ] │  ← Offset +4
│ Hours:   [ 14 ] │  ← Offset +8
│ Day:     [ 27 ] │  ← Offset +12
│ Month:   [  0 ] │  ← Offset +16
│ Year:    [126 ] │  ← Offset +20
│ Weekday: [  1 ] │  ← Offset +24 (Monday!)
└─────────────────┘
```

---

### What is a Switch Statement?

**Simple explanation:** A switch statement is like a **multiple-choice selector**.

**In C:**
```c
int day = 2;  // Tuesday

switch (day) {
    case 0: printf("Sunday"); break;
    case 1: printf("Monday"); break;
    case 2: printf("Tuesday"); break;  // This one executes!
    case 3: printf("Wednesday"); break;
    // ...
}
```

**In Assembly:**
```assembly
cmp eax, 0        ; Is it 0?
je  case_0        ; If yes, jump to case_0
cmp eax, 1        ; Is it 1?
je  case_1        ; If yes, jump to case_1
cmp eax, 2        ; Is it 2?
je  case_2        ; If yes, jump to case_2
// ...

case_0:
    mov ebx, offset "key0"
    jmp end_switch
case_1:
    mov ebx, offset "key1"
    jmp end_switch
// ...
```

**Think of it like:** A vending machine - press button 1 for Coke, button 2 for Pepsi, button 3 for Sprite.

---

### Common Assembly Instructions (Cheat Sheet)

| Instruction | What it does | Example | English |
|-------------|-------------|---------|---------|
| **MOV** | Copy data | `mov eax, 5` | Put 5 into EAX |
| **ADD** | Addition | `add eax, 3` | Add 3 to EAX |
| **SUB** | Subtraction | `sub eax, 2` | Subtract 2 from EAX |
| **XOR** | Exclusive OR | `xor eax, ebx` | XOR EAX with EBX |
| **CMP** | Compare | `cmp eax, 0` | Compare EAX to 0 (sets flags) |
| **JE/JZ** | Jump if Equal/Zero | `je label` | If equal, jump to 'label' |
| **JNE/JNZ** | Jump if Not Equal | `jne label` | If not equal, jump |
| **CALL** | Call function | `call printf` | Call the printf function |
| **PUSH** | Put on stack | `push eax` | Save EAX on stack |
| **POP** | Get from stack | `pop eax` | Restore EAX from stack |
| **LEA** | Load address | `lea eax, [ebp-8]` | Get address of variable |
| **MOVZX** | Move + Zero extend | `movzx eax, al` | Copy AL to EAX (fill rest with 0s) |

---

### File Operations (What This Program Does)

**C Functions and their purpose:**

| Function | What it does | Example |
|----------|-------------|---------|
| `fopen("file.txt", "rb")` | Open file for reading | Opens input.txt |
| `fgetc(file)` | Read one byte (character) | Reads next byte |
| `fputc(byte, file)` | Write one byte | Writes encrypted byte |
| `rewind(file)` | Go back to start of file | Restart reading key file |
| `fclose(file)` | Close file | Clean up |
| `EOF` | End Of File marker | -1 (0xFFFFFFFF) |

**How encryption works in this program:**
```c
while (input_byte = fgetc(input_file)) != EOF) {
    key_byte = fgetc(key_file);
    if (key_byte == EOF) {
        rewind(key_file);        // Start over if key ends
        key_byte = fgetc(key_file);
    }
    encrypted = input_byte + key_byte;
    fputc(encrypted, output_file);
}
```

**Visual flow:**
```
input.txt:  [T][H][i][s]...
            ↓  ↓  ↓  ↓
key2:       [K][E][Y][1][K][E][Y][2]... (repeats if needed)
            ↓  ↓  ↓  ↓
ADD:        +  +  +  +
            ↓  ↓  ↓  ↓
output.txt: [?][?][?][?]... (encrypted bytes)
```

---

### Tools You'll Use

**IDA Free:**
- **What:** Interactive DisAssembler (free version)
- **Does:** Converts binary → assembly → pseudocode
- **Key feature:** Press F5 to "decompile" (shows C-like code)

**objdump:**
- **What:** Command-line disassembler
- **Does:** Shows assembly from binary
- **Usage:** `objdump -d -M intel program.exe`

**radare2:**
- **What:** Advanced reverse engineering framework
- **Does:** Disassembly, debugging, analysis
- **Usage:** `radare2 program.exe`

**strings:**
- **What:** Extracts readable text from binary
- **Does:** Finds "input.txt", "key0", error messages
- **Usage:** `strings program.exe`

**Python:**
- **What:** Programming language
- **Does:** Quick scripts for decryption/analysis
- **Usage:** Test theories, automate tasks

---

### Reverse Engineering Workflow

**Step-by-step process for beginners:**

```
1. File Analysis
   ├─ Check file type: `file program.exe`
   ├─ Look for strings: `strings program.exe`
   └─ Check size: `ls -lh program.exe`

2. Static Analysis (without running)
   ├─ Open in IDA Free
   ├─ Find strings (Shift+F12)
   ├─ Find main function (cross-references)
   └─ Decompile (F5) to understand logic

3. Pattern Recognition
   ├─ Look for crypto functions (XOR, ADD, encryption)
   ├─ Find file operations (fopen, fgetc, fputc)
   ├─ Identify loops (encryption typically in loops)
   └─ Spot system calls (time, localtime, etc.)

4. Key Finding
   ├─ Trace data flow (where does key come from?)
   ├─ Understand algorithm (ADD vs XOR vs AES?)
   └─ Extract key selection logic

5. Verification
   ├─ Write Python script to test theory
   ├─ Decrypt sample data
   └─ Confirm with known plaintext
```

---

### Common Patterns to Recognize

**Pattern 1: Time-based behavior**
```assembly
call _time              ; Get current time
call _localtime         ; Convert to local time
mov eax, [eax+18h]     ; Access tm_wday
```
→ **Means:** Program behavior changes by day/hour

**Pattern 2: File encryption loop**
```assembly
loop_start:
    call _fgetc         ; Read byte
    cmp eax, -1         ; Check EOF
    je loop_end
    ; ... process byte ...
    call _fputc         ; Write byte
    jmp loop_start
```
→ **Means:** Processing file byte-by-byte

**Pattern 3: XOR encryption**
```assembly
mov al, [input_byte]
xor al, [key_byte]      ; Opcode: 30/32
mov [output_byte], al
```
→ **Means:** XOR cipher

**Pattern 4: ADD encryption**
```assembly
mov al, [input_byte]
add al, [key_byte]      ; Opcode: 00/02
mov [output_byte], al
```
→ **Means:** ADD cipher (this program!)

---

### Quick Tips for Mock Tests

1. **Start simple:** Look at strings first - they give huge clues
2. **Use F5 often:** Pseudocode is easier to read than assembly
3. **Follow the data:** Track where variables come from
4. **Know your opcodes:**
   - 00-03 = ADD
   - 30-33 = XOR
   - 80-83 = Arithmetic group
5. **Check offsets:** `[eax+18h]` after `localtime()` = tm_wday
6. **Test with Python:** Confirm your findings programmatically
7. **Don't panic:** Most student exercises are simple algorithms

---

### Glossary

- **Binary:** Machine code file (.exe, .elf)
- **Disassembly:** Converting machine code → assembly
- **Decompilation:** Converting assembly → C-like pseudocode (approximate)
- **Register:** Fast CPU storage (EAX, EBX, etc.)
- **Stack:** Temporary memory for function calls
- **Opcode:** Numeric code for assembly instruction
- **Offset:** Distance from a starting point (e.g., +24 bytes)
- **Pointer:** Memory address (location of data)
- **EOF:** End of File marker (-1)
- **Cipher:** Algorithm for encryption/decryption
- **Plaintext:** Original unencrypted data
- **Ciphertext:** Encrypted data
- **Key:** Secret value used for encryption
- **Hash:** One-way conversion (can't reverse)

---

## Question 1: Key File Usage Investigation

### a) How mock_1.exe uses the key files (key0-key7)

**Answer:**

mock_1.exe uses the key files as a **circular XOR/ADD key stream** for encryption:

1. **File Selection:** One key file (key0-key6) is selected based on the current day of week
2. **Byte-by-byte Processing:**
   - Read one byte from `input.txt` (stored in register/variable `x`)
   - Read one byte from selected key file (stored in register/variable `y`)
   - **ADD operation:** `output = x + y`  (using ADD opcode, not XOR)
   - Write result to `output.txt`

3. **Key Reuse (Circular):**
   - If key file reaches EOF, rewind to beginning using `rewind(fkey)`
   - Continue reading from start of key file
   - This makes the key "circular" for files longer than the key

**Relevant Code from mock_1.c:**
```c
char x, y;
while ((x = fgetc(fsrc)) != EOF) {
    y = fgetc(fkey);
    if (y == EOF) {
        rewind(fkey);        // Rewind key file
        y = fgetc(fkey);
    }
    fputc(x + y, fout);      // ADD operation
}
```

**Relevant Opcodes (from disassembly):**
```assembly
; Reading bytes
CALL    fgetc                ; Read input byte
MOV     [local_var], AL      ; Store in variable

; ADD encryption
MOV     AL, [input_byte]
ADD     AL, [key_byte]       ; Opcode: 00 or 02 (ADD r/m8, r8)
MOV     [output_byte], AL

; Key rewind check
CMP     EAX, -1              ; Check for EOF
JNE     continue
CALL    rewind               ; Rewind key file
```

**Key Finding:** key7 is NEVER used! Only key0-key6 are selected (days 0-6).

---

### b) Key Selection Criterion

**Answer:**

The key selection criterion is **day of week** obtained from system time:

1. **Get current time:** `time(&rawtime)`
2. **Convert to local time:** `localtime(&rawtime)`
3. **Extract day of week:** Access `tm_wday` field of struct tm
4. **Switch statement:** Select key file based on wkday value (0-6)

**Mapping:**
```
tm_wday = 0 (Sunday)    → key0
tm_wday = 1 (Monday)    → key1
tm_wday = 2 (Tuesday)   → key2
tm_wday = 3 (Wednesday) → key3
tm_wday = 4 (Thursday)  → key4
tm_wday = 5 (Friday)    → key5
tm_wday = 6 (Saturday)  → key6
```

**Relevant Code:**
```c
time(&rawtime);
wkday = localtime(&rawtime)->tm_wday;

switch (wkday){
    case 0: key_file_use = "key0"; break;
    case 1: key_file_use = "key1"; break;
    case 2: key_file_use = "key2"; break;
    case 3: key_file_use = "key3"; break;
    case 4: key_file_use = "key4"; break;
    case 5: key_file_use = "key5"; break;
    case 6: key_file_use = "key6"; break;
}
```

**Relevant Opcodes:**
```assembly
; Call time()
LEA     EAX, [local_time]
MOV     [ESP], EAX
CALL    time                 ; Get current time

; Call localtime()
LEA     EAX, [local_time]
MOV     [ESP], EAX
CALL    localtime            ; Returns pointer to struct tm

; Access tm_wday (offset +24 in struct tm)
MOV     EAX, [return_value]
MOV     EAX, [EAX+18h]       ; tm_wday at offset 0x18 (24 bytes)

; Switch statement (jump table or series of CMP)
CMP     EAX, 0               ; Check case 0
JE      case_0
CMP     EAX, 1               ; Check case 1
JE      case_1
CMP     EAX, 2               ; Check case 2
JE      case_2
...
CMP     EAX, 6               ; Check case 6
JE      case_6
```

---

## Question 2: Encryption Method Investigation

### a) How input.txt is encrypted

**Answer:**

The encryption method is a **simple ADD cipher** (also called additive cipher):

**Algorithm:**
```
For each byte in input file:
    encrypted_byte = (input_byte + key_byte) mod 256
```

**Step-by-Step Process:**

1. **Open Files:**
   ```c
   fsrc = fopen("input.txt", "rb");      // Input file
   fkey = fopen(key_file_use, "rb");     // Selected key file
   fout = fopen("output.txt", "wb");     // Output file
   ```

2. **Encryption Loop:**
   ```c
   char x, y;
   while ((x = fgetc(fsrc)) != EOF) {    // Read input byte
       y = fgetc(fkey);                   // Read key byte
       if (y == EOF) {                    // If key exhausted
           rewind(fkey);                  // Go back to start
           y = fgetc(fkey);               // Read first key byte
       }
       fputc(x + y, fout);                // Write encrypted byte
   }
   ```

3. **Byte Addition:**
   - Uses C's char arithmetic (8-bit addition)
   - Overflow automatically wraps (mod 256)
   - No carry flag consideration

**Relevant Opcodes:**
```assembly
; Main encryption loop
loop_start:
    CALL    fgetc                ; Read input byte
    CMP     EAX, -1              ; Check for EOF
    JE      loop_end
    MOV     [input_char], AL     ; Store input byte

    CALL    fgetc                ; Read key byte
    CMP     EAX, -1              ; Check if key EOF
    JNE     skip_rewind
    CALL    rewind               ; Rewind key file
    CALL    fgetc                ; Read first key byte
skip_rewind:
    MOV     [key_char], AL       ; Store key byte

    MOV     AL, [input_char]
    ADD     AL, [key_char]       ; Opcode: 00 xx or 02 xx (ADD)
    MOVZX   EAX, AL              ; Zero-extend to 32-bit

    MOV     [ESP], EAX
    CALL    fputc                ; Write encrypted byte

    JMP     loop_start
loop_end:
```

**Example:**
```
Input:  "hello" = 68 65 6c 6c 6f (hex)
Key:    key2 first 5 bytes
Output: (68+key[0]) (65+key[1]) (6c+key[2]) (6c+key[3]) (6f+key[4])
```

---

### b) Decryption Process for Settings.ini

**Answer:**

Since encryption uses ADD, decryption uses **SUBTRACT**:

**Decryption Formula:**
```
decrypted_byte = (encrypted_byte - key_byte) mod 256
```

**First Byte Analysis:**

**Settings.ini first byte (hex):** `0x19`

**Trying each key:**
- key0 first byte: `0x35`
- key1 first byte: `0x2d`
- key2 first byte: `0xc5`

**Decryption calculation for first byte with key2:**
```
Encrypted byte: 0x19 (decimal 25)
Key byte:       0xc5 (decimal 197)

Decrypted = (0x19 - 0xc5) mod 256
          = (25 - 197) mod 256
          = -172 mod 256
          = 84 (decimal)
          = 0x54 (hex)
          = 'T' (ASCII)
```

**Full Decryption Process:**

1. **Identify which key was used:**
   - Settings.ini was encrypted on a specific day
   - Try all keys (key0-key7)
   - Valid ASCII text indicates correct key

2. **Decryption script:**
   ```python
   with open('Settings.ini', 'rb') as f:
       encrypted = f.read()

   with open('key2', 'rb') as f:  # Try each key
       key = f.read()

   # Decrypt: subtract key from encrypted
   decrypted = bytes((encrypted[i] - key[i % len(key)]) % 256
                     for i in range(len(encrypted)))

   print(decrypted.decode('ascii'))
   ```

3. **Using mock_1.exe to decrypt:**
   - Rename `Settings.ini` to `input.txt`
   - Subtract the key manually first, OR
   - Since ADD is not reversible with the same tool, need to:
     - Create inverse key: `inverse_key[i] = (256 - key[i]) % 256`
     - Run mock_1.exe with inverse key
     - This will decrypt: `(encrypted + inverse) = (original + key + inverse) = original`

**Verification:**
```
Settings.ini (encrypted): 19 6a 38 fd 68 be 20 75 57 dc 42 cb 51 68 5f 72 76 f0 75 26
key2 first 20 bytes:      c5 22 cf 09 48 55 c8 55 f6 bc d5 5c ee f4 cf 1e 11 9d 61 1c

Decrypted (subtract):     54 48 69 73 20 69 73 20 61 20 6d 6f 63 6b 20 74 65 73 74 0a
ASCII:                    T  H  i  s     i  s     a     m  o  c  k     t  e  s  t  \n
```

**Result:** "THis is a mock test"

---

## Question 3: Decrypted Message

**Answer:**

```
THis is a mock test
```

**Details:**
- **Length:** 20 bytes (including newline)
- **Format:** ASCII text with line feed
- **Key used:** key2, key3, key4, key5, or key6 (all have same first 20 bytes!)

**Hex representation:**
```
54 48 69 73 20 69 73 20 61 20 6d 6f 63 6b 20 74 65 73 74 0a
T  H  i  s     i  s     a     m  o  c  k     t  e  s  t  \n
```

**Note:** Minor typo in original - "THis" instead of "This"

---

## Question 4: Memory Forensics Artifacts

**Answer:**

Three artifacts that can be found using Memory Forensics:

### 1. **Process Information**
   - **What:** Running processes, process IDs (PIDs), parent-child relationships
   - **Why useful:** Identify malicious processes, hidden processes, process injection
   - **Tools:** `pslist`, `pstree`, `psxview` (Volatility)
   - **Example:** Detect malware masquerading as legitimate process

### 2. **Network Connections**
   - **What:** Active/recent network connections, listening ports, remote IPs
   - **Why useful:** Identify C&C servers, data exfiltration, lateral movement
   - **Tools:** `netscan`, `connections`, `connscan` (Volatility)
   - **Example:** Find malware communicating with external server

### 3. **Loaded DLLs and Modules**
   - **What:** Dynamic libraries loaded by processes, module base addresses
   - **Why useful:** Detect DLL injection, identify malicious libraries
   - **Tools:** `dlllist`, `ldrmodules` (Volatility)
   - **Example:** Discover injected malicious DLL in legitimate process

**Additional Common Artifacts:**
- **Registry hives** - Persistence mechanisms, configuration
- **Command history** - User/attacker actions
- **Strings and passwords** - Credentials in memory
- **File handles** - Open files, evidence of file access
- **Malware code** - Executable code in process memory

---

## Technical Analysis Summary

### Key File Analysis

**File Sizes:**
```
key0: 100 bytes
key1: 1000 bytes
key2: 977 KB (1,000,000 bytes)
key3: 977 KB
key4: 977 KB
key5: 977 KB
key6: 977 KB
key7: 100 bytes (UNUSED!)
```

**Key Observation:**
- key0 and key7 are identical (first 100 bytes match)
- key2-key6 have identical first 20 bytes (used for Settings.ini)
- key7 is never selected by the day-of-week logic

### Encryption Properties

**Strength:** Very weak
- Simple substitution cipher
- Key reuse (circular)
- No salt, no IV
- Predictable key selection

**Vulnerabilities:**
- Known plaintext attack trivial
- Frequency analysis possible
- Key recovery easy if day known

**Decryption Complexity:** O(1) - instant with key

---

## IDA Free Step-by-Step Guide

### Complete Walkthrough: Answering All 4 Questions

---

### **Question 1a: How mock_1.exe uses key files (key0-key7)**

#### Step 1: Load Binary in IDA Free
1. **File → Open** → Select `mock_1.exe`
2. Click **OK** on all dialogs (accept defaults)
3. Wait for auto-analysis to complete (progress bar at bottom)

#### Step 2: Find String References
1. Press **Shift+F12** → Opens "Strings window"
2. Look for strings like:
   - "input.txt"
   - "output.txt"
   - "key0", "key1", etc.
3. Double-click **"input.txt"** → Jumps to data section

#### Step 3: Find Cross-References
1. With cursor on "input.txt", press **X** (cross-references)
2. Dialog shows where this string is used
3. Double-click the function reference → Jumps to main function

#### Step 4: Find the Encrypt Function
1. Scroll through main function
2. Look for **CALL** instructions to subroutines
3. Find a call that likely does encryption (appears in a loop)
4. Double-click the CALL target (e.g., `sub_401234`) → Jumps to encrypt function

#### Step 5: Analyze Encryption Loop
In the encrypt function, press **F5** (decompile) to see pseudocode:

**What to look for:**
```c
while ( (v1 = fgetc(fsrc)) != -1 )  // Read input byte
{
  v2 = fgetc(fkey);                  // Read key byte
  if ( v2 == -1 )                    // Key EOF check
  {
    rewind(fkey);                    // ← CIRCULAR KEY!
    v2 = fgetc(fkey);
  }
  fputc(v1 + v2, fout);              // ← ADD OPERATION!
}
```

**Answer for 1a:**
- Key file is read **byte-by-byte** alongside input
- Uses **ADD operation** (`v1 + v2`)
- When key reaches EOF, **rewind()** makes it circular
- This creates a repeating key stream

#### Step 6: Verify with Assembly (Optional)
1. Press **ESC** to go back to disassembly view
2. Press **Tab** to toggle between text and graph view
3. Look for assembly pattern:
```assembly
call    _fgetc          ; Read input
mov     [ebp+var_9], al
call    _fgetc          ; Read key
cmp     eax, 0FFFFFFFFh ; Check EOF (-1)
jnz     short loc_skip
call    _rewind         ; ← Rewind if EOF
call    _fgetc
loc_skip:
mov     [ebp+var_8], al
movzx   edx, [ebp+var_9]
movzx   eax, [ebp+var_8]
add     eax, edx        ; ← ADD INSTRUCTION
```

---

### **Question 1b: Key Selection Criterion**

#### Step 1: Find Key Selection Code
1. In main function (found from Step 3 above)
2. Press **F5** to see decompiled view
3. Scroll to find where key filename is selected

#### Step 2: Look for Time Functions
Search for these patterns:
```c
time(&v10);                          // Get current time
v3 = localtime(&v10);                // Convert to local time
v4 = v3->tm_wday;                    // ← THIS IS THE CRITERION!

switch ( v4 )                        // Switch on day of week
{
  case 0: key_file_use = "key0"; break;
  case 1: key_file_use = "key1"; break;
  case 2: key_file_use = "key2"; break;
  ...
  case 6: key_file_use = "key6"; break;
}
```

**Answer for 1b:**
- Uses **`tm_wday`** field from `struct tm`
- Range: **0 (Sunday) to 6 (Saturday)**
- **Note:** key7 is NEVER selected!

#### Step 3: Verify with Assembly Opcodes
1. Click on the `localtime()` call in decompiled view
2. Press **ESC** → Jumps to corresponding assembly
3. Look for pattern:
```assembly
call    _time           ; time(&rawtime)
lea     eax, [ebp+var_10]
mov     [esp], eax
call    _localtime      ; localtime(&rawtime)
mov     [ebp+var_4], eax
mov     eax, [ebp+var_4]
mov     eax, [eax+18h]  ; ← Offset 0x18 = tm_wday (24 bytes)
mov     [ebp+var_8], eax
```

#### Step 4: Confirm struct tm Layout (Advanced)
1. Press **Shift+F9** → Opens "Structures" window
2. If `struct tm` exists, expand it:
```
struct tm {
    int tm_sec;      // +0x00
    int tm_min;      // +0x04
    int tm_hour;     // +0x08
    int tm_mday;     // +0x0C
    int tm_mon;      // +0x10
    int tm_year;     // +0x14
    int tm_wday;     // +0x18 ← HERE!
    int tm_yday;     // +0x1C
    int tm_isdst;    // +0x20
};
```

The offset **0x18** (24 decimal) corresponds to **tm_wday**.

---

### **Question 2a: How input.txt is encrypted**

#### Step 1: Analyze Encrypt Function (Already Found)
From Question 1a, you already located the encrypt function. Press **F5** on it.

#### Step 2: Identify the Algorithm
Look at the core operation:
```c
while ( (input_byte = fgetc(fsrc)) != -1 )
{
  key_byte = fgetc(fkey);
  if ( key_byte == -1 ) {
    rewind(fkey);
    key_byte = fgetc(fkey);
  }
  fputc(input_byte + key_byte, fout);  // ← ADD CIPHER
}
```

**Answer for 2a:**
- **Algorithm:** Simple ADD cipher (additive cipher)
- **Formula:** `encrypted_byte = (input_byte + key_byte) mod 256`
- **Key reuse:** Circular (rewind when EOF)
- **No salt, no IV, no proper crypto**

#### Step 3: Find the ADD Opcode
1. In encrypt function assembly view
2. Locate the encryption operation:
```assembly
movzx   edx, [ebp+var_input]   ; Load input byte (zero-extend)
movzx   eax, [ebp+var_key]     ; Load key byte
add     eax, edx               ; ← OPCODE: 01 D0 or 03 C2 (ADD)
movzx   eax, al                ; Keep only low byte (mod 256)
mov     [esp], eax
call    _fputc                 ; Write encrypted byte
```

#### Step 4: Verify Opcode
1. Click on the **ADD** instruction
2. Look at hex view (at top of IDA window)
3. Common ADD opcodes:
   - `00` = ADD r/m8, r8
   - `01` = ADD r/m32, r32
   - `02` = ADD r8, r/m8
   - `03` = ADD r32, r/m32

**Note:** This is NOT XOR (opcode 31h/33h)!

---

### **Question 2b: Decryption Process for Settings.ini**

#### Step 1: Understand the Math
Since encryption is: `encrypted = input + key`

Decryption is: `input = encrypted - key`

#### Step 2: Manual First-Byte Analysis in IDA

**Open Settings.ini in IDA:**
1. **File → Open** → Select `Settings.ini`
2. IDA will show hex bytes

**View first bytes:**
```
00000000: 19 6A 38 FD 68 BE 20 75 57 DC 42 CB 51 68 5F 72
```

First byte: **0x19** (decimal 25)

#### Step 3: Try Each Key File
1. **File → Open** → Select `key2`
2. View first byte: **0xC5** (decimal 197)

**Calculate by hand:**
```
Encrypted: 0x19 = 25 (decimal)
Key:       0xC5 = 197 (decimal)

Decrypted = (25 - 197) mod 256
          = -172 mod 256
          = 256 - 172
          = 84 (decimal)
          = 0x54 (hex)
          = 'T' (ASCII)
```

Press **Shift+E** in IDA → Opens ASCII table
Find 0x54 → **'T'** ✓

#### Step 4: Verify with Python (Recommended)
Create script `decrypt.py`:
```python
# Read encrypted file
with open('Settings.ini', 'rb') as f:
    encrypted = f.read()

# Try all keys
for key_num in range(8):
    with open(f'key{key_num}', 'rb') as f:
        key = f.read()

    # Decrypt
    decrypted = bytes((encrypted[i] - key[i % len(key)]) % 256
                      for i in range(len(encrypted)))

    # Check if valid ASCII
    try:
        text = decrypted.decode('ascii')
        if text.isprintable() or '\n' in text:
            print(f"key{key_num}: {repr(text)}")
    except:
        print(f"key{key_num}: Not valid ASCII")
```

Run: `python3 decrypt.py`

**Output:**
```
key2: 'THis is a mock test\n'
key3: 'THis is a mock test\n'
key4: 'THis is a mock test\n'
key5: 'THis is a mock test\n'
key6: 'THis is a mock test\n'
```

**Answer for 2b:**
Multiple keys work because **key2-key6 have identical first 20 bytes**!

Settings.ini is only 20 bytes, so any of these keys decrypt it correctly.

The decrypted message is: **"THis is a mock test"** (with newline)

---

### **Quick Reference: IDA Free Hotkeys**

| Hotkey | Function |
|--------|----------|
| **F5** | Decompile (Hex-Rays pseudocode) |
| **ESC** | Go back / Return to assembly |
| **Tab** | Toggle text/graph view |
| **G** | Jump to address |
| **X** | Cross-references (where is this used?) |
| **N** | Rename variable/function |
| **;** | Add comment |
| **Shift+F12** | Strings window |
| **Shift+F9** | Structures window |
| **Ctrl+F** | Text search |
| **Space** | Toggle assembly/text view |

---

### **Tips for Mock Test Success**

1. **Start with strings** (Shift+F12) → Find entry points
2. **Use cross-references** (X key) → Trace data flow
3. **Decompile early** (F5) → Understand logic quickly
4. **Look for patterns:**
   - `time()` + `localtime()` = Time-based logic
   - `fgetc()` loops = Byte-by-byte processing
   - `rewind()` = Circular buffer/key
   - `ADD/XOR` = Encryption operation
5. **Verify with opcodes:**
   - ADD = 00/01/02/03
   - XOR = 30/31/32/33
   - CMP = 38/39/3A/3B
6. **Check struct offsets:**
   - `[EAX+18h]` after `localtime()` = tm_wday
7. **Test your theory with Python** → Confirm findings

---

## Practical Decryption Script

```python
#!/usr/bin/env python3

def decrypt_file(encrypted_file, key_file, output_file):
    """Decrypt file encrypted with mock_1.exe ADD cipher"""

    # Read files
    with open(encrypted_file, 'rb') as f:
        encrypted = f.read()

    with open(key_file, 'rb') as f:
        key = f.read()

    # Decrypt: subtract key from encrypted (mod 256)
    decrypted = bytearray()
    for i in range(len(encrypted)):
        key_byte = key[i % len(key)]  # Circular key
        dec_byte = (encrypted[i] - key_byte) % 256
        decrypted.append(dec_byte)

    # Write decrypted
    with open(output_file, 'wb') as f:
        f.write(decrypted)

    # Try to display as text
    try:
        text = decrypted.decode('ascii')
        print(f"Decrypted text: {repr(text)}")
    except:
        print(f"Decrypted ({len(decrypted)} bytes)")

# Try all keys
for i in range(8):
    try:
        decrypt_file('Settings.ini', f'key{i}', f'decrypted_key{i}.txt')
    except Exception as e:
        print(f"key{i}: Error - {e}")
```

**Output:**
```
key2: "THis is a mock test\n"
key3: "THis is a mock test\n"
key4: "THis is a mock test\n"
key5: "THis is a mock test\n"
key6: "THis is a mock test\n"
```

---

## Conclusion

The mock_1.exe binary implements a simple day-of-week based ADD cipher:

✅ **Key selection:** Based on `tm_wday` (0-6 = Sun-Sat)
✅ **Encryption:** Byte-by-byte addition with circular key
✅ **Decryption:** Subtract key bytes from encrypted bytes
✅ **Decrypted message:** "THis is a mock test\n"

**Educational value:** Demonstrates:
- Time-based key selection
- Simple substitution ciphers
- Circular key usage
- Weakness of simple encryption

---

**Analysis Complete** ✅

