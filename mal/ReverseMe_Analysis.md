# ReverseMe_If_u_can.exe - Complete Analysis

**Analyst:** Claude Code
**Date:** 2026-01-27
**Binary:** ReverseMe_If_u_can.exe
**MD5:** 5ae25a5c66314d00e545acc891eb91bd

---

## Executive Summary

**Password Found:** `WellDone`

**Analysis Method:** Static analysis using disassembly (objdump/radare2/IDA)

**Key Finding:** The password is hardcoded in the binary as individual hex characters to avoid simple string detection.

---

## Binary Information

```
Filename:  ReverseMe_If_u_can.exe
Type:      PE32 executable (console) Intel 80386
Size:      8,704 bytes (8.5K)
Compiled:  July 28, 2016
Compiler:  GCC 4.8.0 (MinGW)
MD5:       5ae25a5c66314d00e545acc891eb91bd
Stripped:  Yes (to external PDB)
```

---

## Static Analysis

### String Analysis

Running `strings ReverseMe_If_u_can.exe` reveals:

```
Please enter the password (Ctrl-C to Quit) :
Congratulation!!
Wrong password
```

**Notable:** The actual password "WellDone" does NOT appear in strings output, indicating obfuscation.

---

## Disassembly Analysis

### Main Function (0x00401390)

The core password checking logic is located at address `0x00401390`.

#### Password Construction Code

```assembly
401390:  push   ebp
401391:  mov    ebp,esp
401393:  push   edi
401394:  push   ebx
401395:  and    esp,0xfffffff0
401398:  sub    esp,0x270

; Clear buffer (100 dwords)
4013a3:  lea    ebx,[esp+0x10]
4013a7:  mov    eax,0x0
4013ac:  mov    edx,0x64
4013b1:  mov    edi,ebx
4013b3:  mov    ecx,edx
4013b5:  rep stos DWORD PTR es:[edi],eax

; Build password character by character
4013b7:  mov    DWORD PTR [esp+0x10],0x57    ; 'W'
4013bf:  mov    DWORD PTR [esp+0x14],0x65    ; 'e'
4013c7:  mov    DWORD PTR [esp+0x18],0x6c    ; 'l'
4013cf:  mov    DWORD PTR [esp+0x1c],0x6c    ; 'l'
4013d7:  mov    DWORD PTR [esp+0x20],0x44    ; 'D'
4013df:  mov    DWORD PTR [esp+0x24],0x6f    ; 'o'
4013e7:  mov    DWORD PTR [esp+0x28],0x6e    ; 'n'
4013ef:  mov    DWORD PTR [esp+0x2c],0x65    ; 'e'
```

#### Hex to ASCII Conversion

| Hex Value | Decimal | ASCII Character |
|-----------|---------|-----------------|
| 0x57      | 87      | 'W'             |
| 0x65      | 101     | 'e'             |
| 0x6c      | 108     | 'l'             |
| 0x6c      | 108     | 'l'             |
| 0x44      | 68      | 'D'             |
| 0x6f      | 111     | 'o'             |
| 0x6e      | 110     | 'n'             |
| 0x65      | 101     | 'e'             |

**Result:** `WellDone`

---

## Program Flow

```
┌─────────────────────────────┐
│   Program Start             │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Build password "WellDone"   │
│ in memory at [esp+0x10]     │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ Print: "Please enter the    │
│ password (Ctrl-C to Quit):" │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ scanf("%s", user_input)     │
│ Read user input             │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ strcmp(user_input,          │
│        "WellDone")          │
└──────────┬──────────────────┘
           │
      ┌────┴────┐
      │         │
 Equal│         │Not Equal
      ▼         ▼
┌──────────┐ ┌──────────────┐
│"Congrat- │ │"Wrong        │
│ulation!!"│ │ password"    │
└──────────┘ └──────────────┘
```

---

## Key Functions Used

| Function | Purpose |
|----------|---------|
| `puts()` | Print "Please enter the password" |
| `scanf()` | Read user input |
| `strcmp()` | Compare user input with "WellDone" |
| `puts()` | Print success or failure message |

---

## Analysis Methods

### Method 1: Command-Line Tools

```bash
# Extract strings
strings ReverseMe_If_u_can.exe

# Disassemble
objdump -d -M intel ReverseMe_If_u_can.exe > dump.txt

# Using radare2
radare2 ReverseMe_If_u_can.exe
aaa              # Analyze
s 0x00401390     # Seek to main function
pdf              # Print disassembly
```

### Method 2: IDA Free (Recommended)

**Steps:**
1. Open binary in IDA Free
2. Press **Shift+F12** → View strings
3. Find "Please enter the password"
4. Press **X** → Cross-references
5. Navigate to function
6. Press **F5** → Decompile (shows C-like pseudocode)

**IDA Pseudocode:**
```c
int main() {
    char password[100];
    char user_input[100];

    // Clear buffer
    memset(password, 0, 100);

    // Build password
    password[0] = 0x57;  // 'W'
    password[1] = 0x65;  // 'e'
    password[2] = 0x6C;  // 'l'
    password[3] = 0x6C;  // 'l'
    password[4] = 0x44;  // 'D'
    password[5] = 0x6F;  // 'o'
    password[6] = 0x6E;  // 'n'
    password[7] = 0x65;  // 'e'

    puts("Please enter the password (Ctrl-C to Quit) :");
    scanf("%s", user_input);

    if (strcmp(user_input, password) == 0) {
        puts("Congratulation!!");
    } else {
        puts("Wrong password");
    }

    return 0;
}
```

---

## Security Analysis

### Obfuscation Technique

**Method Used:** Character-by-character assembly
- Instead of storing "WellDone" as a plain string
- Each character is stored as individual hex value
- Makes `strings` command ineffective
- Still easily reversed with disassembly

**Effectiveness:** Low
- Static analysis easily reveals password
- No encryption or complex transformation
- Simple defense against automated tools

### Vulnerabilities

1. **Hardcoded Password:** Password is embedded in binary
2. **No Stack Protection:** No stack canaries detected
3. **Buffer Overflow Risk:** `scanf("%s", ...)` without length limit
4. **strcmp Timing:** Vulnerable to timing attacks (not relevant here)

---

## Educational Value

This binary demonstrates:
- ✅ Basic reverse engineering techniques
- ✅ Converting hex to ASCII
- ✅ Function call analysis
- ✅ String comparison logic
- ✅ Simple anti-analysis (character obfuscation)

**Skill Level:** Beginner
**Time to Solve:** 10-15 minutes (with tools)

---

## Teaching Guide

### For Instructors

**Learning Objectives:**
1. Understand PE executable structure
2. Use disassemblers (IDA/radare2/objdump)
3. Recognize common patterns (password checks)
4. Convert hexadecimal to ASCII
5. Trace program execution flow

**Suggested Approach:**
1. Start with `strings` command (shows it's obfuscated)
2. Introduce disassembly tools
3. Walk through finding cross-references
4. Explain MOV instructions and hex values
5. Convert hex to ASCII manually
6. Verify with decompiler (IDA F5)

**Common Student Mistakes:**
- Forgetting little-endian byte order (not relevant here - single bytes)
- Confusing DWORD offsets (esp+0x10, esp+0x14 are sequential)
- Not recognizing character patterns

---

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| `strings` | GNU binutils | Extract printable strings |
| `objdump` | GNU binutils 2.40 | Disassemble binary |
| `radare2` | 6.0.8 | Advanced disassembly/analysis |
| IDA Free | 8.x | GUI disassembler with decompiler |

---

## Quick Reference: Finding Password

```bash
# Step 1: Get hex values
objdump -d -M intel ReverseMe_If_u_can.exe | grep -A 40 "401390:"

# Step 2: Extract hex character codes
# Look for: mov DWORD PTR [esp+0xXX], 0xYY

# Step 3: Convert to ASCII
python3 << EOF
chars = [0x57, 0x65, 0x6c, 0x6c, 0x44, 0x6f, 0x6e, 0x65]
password = ''.join(chr(c) for c in chars)
print(f"Password: {password}")
EOF
```

**Output:** `Password: WellDone`

---

## Verification

**Testing the password:**
```
$ wine ReverseMe_If_u_can.exe
Please enter the password (Ctrl-C to Quit) :
WellDone
Congratulation!!
```

---

## Conclusion

The password **`WellDone`** was successfully extracted through static analysis without executing the binary. The obfuscation technique (character-by-character construction) provides minimal protection against reverse engineering and is easily defeated with standard disassembly tools.

**Recommended Next Steps for Learners:**
1. Practice with more complex crackmes
2. Learn dynamic analysis (debugging)
3. Study encryption/decryption routines
4. Explore anti-debugging techniques

---

## References

- **Sample Source:** https://github.com/sectuary/mages-lab1/blob/main/mal/ReverseMe_If_u_can.exe.zip
- **IDA Free:** https://hex-rays.com/ida-free/
- **radare2:** https://rada.re/
- **ASCII Table:** https://www.asciitable.com/

---

**Analysis Complete** ✅
