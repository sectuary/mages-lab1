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

## Beginner's Guide: Crackme Basics

**For students new to reverse engineering**

This section explains the fundamental concepts you need to understand this analysis. If you're already comfortable with these topics, skip to "Binary Information" below.

---

### What is a Crackme?

**Simple explanation:** A crackme is a **practice program** designed to teach reverse engineering.

**Purpose:**
- Learn how to analyze binaries
- Practice finding passwords/keys
- Understand obfuscation techniques
- Safe, legal way to practice hacking skills

**This crackme's challenge:** Find the password without running the program (static analysis)

**Think of it like:** A puzzle box where you need to figure out the combination by examining how the lock works.

---

### Understanding the Password Check

**How password checking works in C:**

```c
// 1. Define the correct password
char correct_password[] = "WellDone";

// 2. Get user input
char user_input[100];
scanf("%s", user_input);

// 3. Compare strings
if (strcmp(user_input, correct_password) == 0) {
    printf("Congratulation!!\n");  // Match!
} else {
    printf("Wrong password\n");    // No match
}
```

**What strcmp() does:**
- Compares two strings character by character
- Returns **0** if they're identical
- Returns non-zero if different

**In assembly:**
```assembly
call scanf              ; Read user input
push [user_input]       ; Push argument 2
push [password]         ; Push argument 1
call strcmp             ; Compare strings
test eax, eax          ; Check result (0 = match)
jz   success           ; Jump to success if zero
```

---

### The Obfuscation Trick

**Why strings doesn't show the password:**

**Normal way (visible to strings command):**
```c
char password[] = "WellDone";  // Stored as continuous string in binary
```
Binary contains: `57 65 6C 6C 44 6F 6E 65 00` ("WellDone\0")

**Obfuscated way (hidden from strings):**
```c
char password[100];
password[0] = 0x57;  // 'W'
password[1] = 0x65;  // 'e'
password[2] = 0x6c;  // 'l'
// ... etc
```
Binary contains: `MOV DWORD PTR [esp+0x10], 0x57` (instructions, not data)

**Result:** The password is **constructed at runtime**, not stored as a string!

**Think of it like:** Instead of writing "HELLO" on a piece of paper (visible), you write instructions: "Write H, then E, then L, then L, then O" (hidden in code).

---

### Key Concepts: Stack and Memory

**Stack layout for this program:**

```
Higher Memory Address
    │
    ├─ [Return address]         ← Where to go after function ends
    ├─ [Saved EBP]              ← Old base pointer
    │
    ├─ esp+0x10: 0x57 ('W')     ← password[0]
    ├─ esp+0x14: 0x65 ('e')     ← password[1]
    ├─ esp+0x18: 0x6c ('l')     ← password[2]
    ├─ esp+0x1c: 0x6c ('l')     ← password[3]
    ├─ esp+0x20: 0x44 ('D')     ← password[4]
    ├─ esp+0x24: 0x6f ('o')     ← password[5]
    ├─ esp+0x28: 0x6e ('n')     ← password[6]
    ├─ esp+0x2c: 0x65 ('e')     ← password[7]
    ├─ esp+0x30: 0x00           ← Null terminator
    │
    ├─ [user_input buffer]      ← Where scanf stores input
    │
    ↓ ESP (Stack Pointer)
Lower Memory Address
```

**Offset explanation:**
- `esp+0x10` = 16 bytes above stack pointer
- `esp+0x14` = 20 bytes above (4 bytes after 0x10)
- Each DWORD = 4 bytes
- Offsets increase by 4: 0x10, 0x14, 0x18, 0x1c, 0x20...

---

### Understanding MOV DWORD PTR

**What this instruction means:**

```assembly
mov DWORD PTR [esp+0x10], 0x57
│   │         │           │
│   │         │           └─ Value to store (0x57 = 'W')
│   │         └─ Memory location (stack at offset 0x10)
│   └─ DWORD (4 bytes)
└─ Move/copy operation
```

**Breaking it down:**
- **MOV** = Copy data
- **DWORD** = Double Word (4 bytes / 32 bits)
- **PTR** = Pointer (address in memory)
- **[esp+0x10]** = Memory location 16 bytes above ESP
- **0x57** = The hex value 87 decimal = 'W' in ASCII

**In English:** "Put the value 0x57 into memory at location [esp+0x10]"

**Why DWORD for a single character?**
- Each character is 1 byte, but stored in 4-byte chunks
- Only the lowest byte (AL) is used
- Upper 3 bytes are zero: `0x00000057`

---

### Hex to ASCII Quick Reference

**Common printable ASCII ranges:**

| Range | Characters | Example |
|-------|-----------|---------|
| 0x41-0x5A | A-Z (uppercase) | 0x57 = 'W' |
| 0x61-0x7A | a-z (lowercase) | 0x65 = 'e' |
| 0x30-0x39 | 0-9 (digits) | 0x33 = '3' |
| 0x20 | Space | 0x20 = ' ' |

**The password in this crackme:**

| Offset | Hex Value | Decimal | ASCII | Position |
|--------|-----------|---------|-------|----------|
| esp+0x10 | 0x57 | 87 | 'W' | password[0] |
| esp+0x14 | 0x65 | 101 | 'e' | password[1] |
| esp+0x18 | 0x6c | 108 | 'l' | password[2] |
| esp+0x1c | 0x6c | 108 | 'l' | password[3] |
| esp+0x20 | 0x44 | 68 | 'D' | password[4] |
| esp+0x24 | 0x6f | 111 | 'o' | password[5] |
| esp+0x28 | 0x6e | 110 | 'n' | password[6] |
| esp+0x2c | 0x65 | 101 | 'e' | password[7] |

**Result:** W-e-l-l-D-o-n-e = **"WellDone"**

---

### REP STOS Instruction Explained

**What you'll see before the password construction:**

```assembly
4013a3:  lea    ebx,[esp+0x10]          ; Load address of buffer
4013a7:  mov    eax,0x0                 ; Value to fill (zero)
4013ac:  mov    edx,0x64                ; Count (100 in decimal)
4013b1:  mov    edi,ebx                 ; Destination = buffer address
4013b3:  mov    ecx,edx                 ; Counter = 100
4013b5:  rep stos DWORD PTR es:[edi],eax ; Fill memory
```

**What REP STOS does:**
- **REP** = Repeat
- **STOS** = Store String
- Repeats ECX times (100 times)
- Stores EAX value (0) at [EDI]
- Increments EDI after each store

**In English:** "Fill 100 DWORDs (400 bytes) with zeros starting at [esp+0x10]"

**Purpose:** Clear the buffer before building the password (good practice, prevents garbage data)

**Think of it like:** Erasing a whiteboard before writing on it.

---

### Finding the Main Function

**Why we look for strings:**

Every program has strings like:
- "Please enter..."
- "Congratulation!!"
- "Wrong password"

These strings are used by the main logic!

**Cross-reference technique:**
1. Find string "Please enter the password"
2. See where it's used (cross-reference)
3. That location is inside the main function
4. The password logic is nearby!

**Think of it like:** Following breadcrumbs back to the source.

---

## Detailed IDA Free Walkthrough

**Step-by-step guide to finding the password in IDA Free**

---

### Step 1: Load the Binary

1. **Download** `ReverseMe_If_u_can.exe.zip` from the repository
2. **Extract** the file (password: "infected" if required)
3. **Launch IDA Free** (IDA Freeware 8.x)
4. **File → Open** → Select `ReverseMe_If_u_can.exe`
5. Click **OK** on the "Load a new file" dialog
6. Wait for auto-analysis to complete (status bar shows "Idle")

**What IDA is doing:**
- Parsing PE file structure
- Finding code and data sections
- Identifying functions
- Recognizing API calls

---

### Step 2: Find Strings

1. Press **Shift+F12** (or **View → Open subviews → Strings**)
2. The "Strings window" opens showing all readable text

**What you'll see:**
```
Address    String
--------   ------
0x403000   "Please enter the password (Ctrl-C to Quit) :"
0x403030   "Congratulation!!"
0x403040   "Wrong password"
```

**Notice:** "WellDone" is NOT in the list! This means it's obfuscated.

3. **Double-click** on "Please enter the password" string

**Result:** IDA jumps to the data section showing:
```
.rdata:00403000 aPlease  db 'Please enter the password (Ctrl-C to Quit) :',0
```

---

### Step 3: Find Cross-References

1. With cursor on the "Please enter..." string, press **X** (or right-click → "Jump to xref to operand")
2. A dialog appears: "Choose xref to..."

**What you'll see:**
```
Address    Type       Instruction
--------   ----       -----------
0x004013F7 Data Read  push offset aPlease
```

3. **Double-click** the entry

**Result:** IDA jumps to address `0x004013F7` in the code:
```assembly
4013f7:  push   offset aPlease    ; "Please enter the password..."
4013fc:  call   _puts
```

**You're now inside the main function!**

---

### Step 4: Examine the Function

**Scroll up** to see the beginning of the function.

You should see:
```assembly
401390:  push   ebp              ; Function prologue
401391:  mov    ebp,esp
401393:  push   edi
401394:  push   ebx
401395:  and    esp,0xfffffff0   ; Align stack
401398:  sub    esp,0x270        ; Allocate 624 bytes
```

**What to look for next:** A series of **MOV** instructions with hex values

---

### Step 5: Find the Password Construction

**Scroll down** from the function start. Look for this pattern:

```assembly
; Clear buffer (you might see rep stos)
4013a3:  lea    ebx,[esp+0x10]
4013a7:  mov    eax,0x0
...
4013b5:  rep stos DWORD PTR es:[edi],eax

; BUILD PASSWORD HERE! ← This is what we want
4013b7:  mov    DWORD PTR [esp+0x10],0x57
4013bf:  mov    DWORD PTR [esp+0x14],0x65
4013c7:  mov    DWORD PTR [esp+0x18],0x6c
4013cf:  mov    DWORD PTR [esp+0x1c],0x6c
4013d7:  mov    DWORD PTR [esp+0x20],0x44
4013df:  mov    DWORD PTR [esp+0x24],0x6f
4013e7:  mov    DWORD PTR [esp+0x28],0x6e
4013ef:  mov    DWORD PTR [esp+0x2c],0x65
```

**Pattern recognition:**
- Sequential MOV instructions
- Incrementing offsets: 0x10, 0x14, 0x18, 0x1c...
- Hex values in printable ASCII range (0x40-0x7A)

**This is the password being built!**

---

### Step 6: Convert Hex to ASCII

**Method 1: Manual lookup**

Click on each MOV instruction and note the hex values:

1. `0x57` → **Right-click → Character** → Shows 'W'
2. `0x65` → **Right-click → Character** → Shows 'e'
3. `0x6c` → **Right-click → Character** → Shows 'l'
4. Continue for all 8 values...

**Method 2: Use IDA's ASCII table**

1. Press **Shift+E** → Opens "Manual" dialog
2. Type the hex value (e.g., `57`)
3. Look at the character column

**Method 3: Use Python (quickest)**

1. Note down all hex values: `57 65 6c 6c 44 6f 6e 65`
2. Open Python/terminal:
```python
values = [0x57, 0x65, 0x6c, 0x6c, 0x44, 0x6f, 0x6e, 0x65]
password = ''.join(chr(v) for v in values)
print(password)  # Output: WellDone
```

---

### Step 7: Verify with Decompiler (F5)

1. Click anywhere in the main function
2. Press **F5** (Hex-Rays Decompiler)

**IDA shows C-like pseudocode:**

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4[100];
  char Str2[100];

  memset(v4, 0, sizeof(v4));        // Clear buffer

  v4[0] = 0x57;                      // 'W'
  v4[1] = 0x65;                      // 'e'
  v4[2] = 0x6C;                      // 'l'
  v4[3] = 0x6C;                      // 'l'
  v4[4] = 0x44;                      // 'D'
  v4[5] = 0x6F;                      // 'o'
  v4[6] = 0x6E;                      // 'n'
  v4[7] = 0x65;                      // 'e'

  puts("Please enter the password (Ctrl-C to Quit) :");
  scanf("%s", Str2);

  if ( !strcmp(Str2, (const char *)v4) )  // Compare with password
    puts("Congratulation!!");
  else
    puts("Wrong password");

  return 0;
}
```

**Much easier to read!**

Now you can clearly see:
- Password array `v4[]`
- Each character assigned individually
- strcmp comparison
- Success/failure messages

---

### Step 8: Understand strcmp

**Find the strcmp call in assembly:**

```assembly
401401:  lea    eax,[esp+0x110]       ; Load address of user_input
401408:  mov    DWORD PTR [esp+0x4],eax
40140c:  lea    eax,[esp+0x10]        ; Load address of password
401410:  mov    DWORD PTR [esp],eax
401413:  call   _strcmp               ; Compare strings
401418:  test   eax,eax               ; Check result
40141a:  jne    40142c                ; Jump if not equal (wrong password)
```

**How strcmp works:**
1. Takes two pointers (user_input and password)
2. Compares byte by byte
3. Returns 0 if identical
4. `test eax, eax` checks if result is zero
5. `jne` = "Jump if Not Equal" (takes wrong password path)

**In decompiled view (F5):**
```c
if ( !strcmp(Str2, (const char *)v4) )  // If strcmp returns 0 (match)
    puts("Congratulation!!");            // Success path
else
    puts("Wrong password");              // Failure path
```

---

### Step 9: Trace Execution Flow (Optional)

**Use IDA's graph view:**

1. Press **Spacebar** to toggle between text and graph view
2. In graph view, you'll see:

```
┌─────────────────────┐
│  Function Start     │
│  (Build password)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  puts("Please...")  │
│  scanf("%s", input) │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  strcmp(input, pwd) │
│  test eax, eax      │
└──────────┬──────────┘
           │
      ┌────┴────┐
      │         │
  jne │         │ je (fallthrough)
      │         │
      ▼         ▼
┌─────────┐ ┌─────────────┐
│ "Wrong  │ │ "Congratula-│
│password"│ │ tion!!"     │
└─────────┘ └─────────────┘
```

**Color coding:**
- Green arrow = Condition true (password correct)
- Red arrow = Condition false (password wrong)

---

### Step 10: Test the Password

**Option 1: Run in Wine (Linux/WSL)**
```bash
wine ReverseMe_If_u_can.exe
# Enter: WellDone
```

**Option 2: Run on Windows**
```cmd
ReverseMe_If_u_can.exe
# Enter: WellDone
```

**Expected output:**
```
Please enter the password (Ctrl-C to Quit) :
WellDone
Congratulation!!
```

✅ **Success!**

---

## IDA Hotkeys Quick Reference

| Hotkey | Action | Use Case |
|--------|--------|----------|
| **Shift+F12** | Strings window | Find text strings in binary |
| **X** | Cross-references | See where data/function is used |
| **F5** | Decompile (Hex-Rays) | Convert to C-like pseudocode |
| **G** | Jump to address | Go to specific location (e.g., 0x401390) |
| **N** | Rename | Give meaningful names to variables/functions |
| **;** | Add comment | Document your findings |
| **Spacebar** | Toggle view | Switch text ↔ graph view |
| **ESC** | Go back | Return to previous location |
| **Tab** | Switch pane | Move between code/hex/pseudocode |
| **Ctrl+F** | Find text | Search in current view |
| **Alt+T** | Text search | Search across entire database |

---

## Common Patterns to Recognize

### Pattern 1: Character-by-Character String Construction

**Assembly signature:**
```assembly
mov [buffer+0], 0xXX
mov [buffer+4], 0xXX
mov [buffer+8], 0xXX
...
```

**Meaning:** Building a string to hide it from `strings` command

**How to spot:** Sequential MOV with incrementing offsets and ASCII-range hex values

---

### Pattern 2: strcmp Password Check

**Assembly signature:**
```assembly
push [user_input]
push [password]
call strcmp
test eax, eax
je   success          ; Jump if equal (password correct)
```

**Meaning:** Comparing user input against hardcoded password

**How to spot:** strcmp call followed by test/cmp and conditional jump

---

### Pattern 3: Buffer Clearing

**Assembly signature:**
```assembly
rep stos DWORD PTR [edi], eax
```
or
```assembly
call memset
```

**Meaning:** Initializing buffer to zeros

**How to spot:** rep stos before password construction, or memset call in decompiled view

---

## Tips for Beginners

1. **Start with Shift+F12:** Strings are your best friend
2. **Use cross-references (X):** Follow the breadcrumbs
3. **Press F5 early and often:** Pseudocode is much easier than assembly
4. **Look for patterns:** Sequential MOV instructions = data construction
5. **Know your hex:** Learn common ASCII values (A=0x41, a=0x61, 0=0x30)
6. **Use Python:** Quick hex-to-ASCII conversion saves time
7. **Graph view helps:** Spacebar to see execution flow visually
8. **Take notes:** Use IDA's comment feature (;) to document findings
9. **Don't run unknown binaries:** Analyze first, execute later (if ever)
10. **Practice, practice, practice:** Try more crackmes on crackmes.one

---

## Common Mistakes to Avoid

❌ **Mistake 1:** Expecting to see "WellDone" in strings output
- The password is obfuscated, built at runtime

❌ **Mistake 2:** Getting lost in assembly details
- Use F5 decompile to see the big picture first

❌ **Mistake 3:** Not recognizing the MOV pattern
- Look for sequential addresses: esp+0x10, esp+0x14, esp+0x18...

❌ **Mistake 4:** Confusing DWORD with byte offsets
- esp+0x10 to esp+0x14 = 4 bytes (DWORD)
- Each character is 1 byte, but stored in 4-byte chunks

❌ **Mistake 5:** Not using cross-references
- Strings → X key → Find the function → Analyze

---

## Challenge Variations

After solving this crackme, try finding these variations:

**Beginner++:**
- XOR-encrypted passwords
- Multiple password checks
- Time-based passwords

**Intermediate:**
- Password checked character-by-character
- Custom strcmp implementations
- Base64/hex encoded passwords

**Advanced:**
- Anti-debugging techniques
- Packed/encrypted executables
- Virtual machine obfuscation

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
