
# LockBit Black Analysis - Dropper & Shellcode
> This section is not the formal technical writeup. What follows is my cleaned-up internal monologue while reversing — the actual sequence of observations, assumptions, dead ends, corrections, and pivots as they happened. The goal is to make it feel like you are sitting in my head while I’m working, without the noise, repetition, or sloppy phrasing of raw notes. A concise technical summary is provided at the end.

## Tooling & Environment
**Static Analysis**
- [Kali Linux VM](https://www.kali.org/) ([VirtualBox](https://www.virtualbox.org/))
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) (DIE)
- [Sublime Text Build 4200](https://www.sublimetext.com/)
**Dynamic Analysis**
- [Windows 10 Home VM](https://www.microsoft.com/en-us/software-download/windows10) ([VirtualBox](https://www.virtualbox.org/))
- [x32dbg / x64dbg](https://x64dbg.com/)
- [ScyllaHide](https://github.com/x64dbg/ScyllaHide)

## Sample source
Obtained from ANY.RUN task: [96df65a8-c9d4-4863-bddc-3c66617f0538](https://app.any.run/tasks/96df65a8-c9d4-4863-bddc-3c66617f0538)

# Stage 0 – First Contact

**Filename:** 
> ((((((지원서_240305 누구보다 열심히하는 그런 인재입니다))))).exe
**Initial Triage (what immediately caught my eye)**
DIE reports:
- **Compiler:** PureBasic
- **Linker:** Microsoft Linker
Entropy immediately feels wrong:
- `.text`: **7.71** -> basically screaming "packed"
- `.rdata`: **5.32** -> this is unusual and bothers me


![DIE of stage 0](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/DIE_stage0.png)

Imports are empty / meaningless.
**Immediate working assumptions (not conclusions):**
- Heavy obfuscation
- Runtime import resolution
- Probably not virtualized, but I’m not committing to that yet

# Reversing Stage 0 - Following the Weirdness

## Step 1: Strings (low effort, high signal)
I always start with strings, this usually gives away key details about the program. I see some oddities such as keyboard spam but nothing else. 

`LoadLibraryA` is sitting there in plaintext.
That tells me two things mentally, either:
- **1.** Imports are hidden
- **2.** Something is resolving APIs manually

Follow the reference -> lands at `0x00401224`.

This function looks extremely odd, loading `kernel32.dll`, calling `GetProcAddress`, and calling the resolved address with the parameters passed to the function.

## Step 2: “Why is GetProcAddress taking an integer?”
Inside that function:
- `LoadLibraryA("kernel32.dll")`
- `GetProcAddress` with what looks like an integer

At first glance it looks nonsensical.
But the integer feels like encoded characters.
I decode it manually -> 
> Voterpliart�tcu

![IAT Hiding](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/IAT_hiding_stage0.png)

That’s garbage… but structured garbage. Looking closer, the character addresses are out of order.
Reorder them by index ->
> VirtualProtect
This is how the binary hides its imports. I now know exactly what this function is doing.
> 
![Correct IAT](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/IAT_corrected_stage0.png)

## Step 3: Okay, so what is it VirtualProtect-ing?
Now that I know the resolved API, the behavior snaps into place.

This function:
- Calls `VirtualProtect`
- Uses `PAGE_EXECUTE_READWRITE (0x40)`
- Saves the old protection
So the real question becomes:
> What memory region is being made executable?

Tracing backward.
## Step 4: Something is being allocated… strangely

I backtrack to the caller of the suspicious import function. I see a lot of comparisons against a dword that are checking against a hard coded value. These if statements are FULL of what appears to be junk.
I find a global value used as a size. I rename it:
> globalAllocSize

Memory is allocated with `GlobalAlloc`.

Then something odd happens:
- One pointer is set to another
- It looks wrong at first

I stop myself here, this looks suspicious, but I don’t have proof yet.
I keep tracing.

Eventually it lines up:
- The size passed to `VirtualProtect` == allocation size
- The pointer matches the allocated region

I Renamed the previous function to `VirtualProtectRegion`.

**Correction:** That pointer swap was intentional.
Renamed:
- `payloadBase`
- `executableRegion`

![Payload Allocation](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/payload_allocation_stage0.png)

This is clearly staging memory. And it shows, The next lines copy payloadBase + `0x1134b` to executableRegion
![Payload Copying](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/payload_writing_stage0.png)

## Step 5: This doesn’t look like a PE loader
At this point I step back and sanity check the design.

Things I don’t see:
- No PE header parsing
- No relocations
- No import rebuilding
- No CRT repair

That’s important, it tells me that:
> This is not a reflective PE loader. This is a shellcode loader.

that changes what matters next.
## Step 6: Focus shifts to decryption
I find a function that:
- Runs 32 rounds
- Uses a delta constant
- Uses Feistel-style mixing

I don't need to see the excact constants yet. This screams **TEA/TEAX family crypto.**
Conclusion in my head:
- Payload is encrypted
- Decrypted into heap memory
- Executed directly

![Block Decryption](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/payload_decryption_stage0.png)

## Static Picture (as it now exists in my head)
Rough execution flow:
- **1.** Allocate Memory
- **2.** Call hidden `VirtualProtect`
- **3.** Copy encrypted shellcode
- **4.** Decrypt
- **5.** Jump

Static analysis is now giving diminishing returns.

Time to go dynamic.

# Dynamic Reversing – Stage 0
## Environment discipline
Fresh Windows 10 VM:
- No network
- No 3D acceleration
- Snapshot taken
---
## Runtime tracing
- Break on entry
- Break before detonation (LoadLibraryA @ 00401579)

![Dynamic Reversing at breakpoints](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/dynamic_reversing_1_stage0.png)

Everything matches static expectations.

Key value discovered:
> executableRegion = 0x01BAD5B8

Marked as **Heap 0.**

Dump the memory.

## Dumping headaches (and a lucky mistake)
Static analysis of raw shellcode in Ghidra is useless.

Switch tactics:
- x32dbg + ScyllaHide
- Full memory dump
I accidentally let it run.

Nothing detonates.

Instead, Windows asks what program to open a .bin file with.

That’s important.

Renaming the dropper to .bin unintentionally killed execution.

I use that to get a clean exit dump.

# Stage 1 – New Payload, New Problems
## First impressions**
DIE says:
- 32-bit
- No compiler signature
- Entry-point NOP
Entropy is still high:
- Overall: **7.17**
- `.data`: **7.89**
![DIE Stage 1 Payload](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/DIE_stage1.png)

This *feels* like an affiliate payload, but I don’t assert that yet.
---
## Entry point insanity

Entry function:
- ~89 parameters
- Mostly junk

![Entry of stage 1](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/entry_stage1.png)

First call returns immediately.

Second call matters.

## Step 1: Import resolution déjà vu
I see PEB walking patterns immediately.

This is dynamic import resolution. ( hypothesis )

Key signs in the function assist that hypothesis, There's a lot of what appears to be function hashes. 

![Dynamic Importing of stage 1](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/dynamic_importing_stage1.png)

Using x32dbg to step through:
- Skip NOP crash
- Watch hash resolution
Recovered:
- `-0x7f0e718` = `RtlCreateHeap`
- `0x6e6047db` = `RtlAllocateHeap`

Confirmed via parameter matching and heap propagation.
# Step 2: Why the hell are calls XORing themselves?

From taking a browse at the function calls after the dynamic importing: I assumed that each import is set to a pointer. All of the imports are called as a pointer with the parameters passed to that pointer.

Following call sites dynamically:
- Function pointer
- XOR
- Jump

![Table Import Function Call](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/dynamic_importing_tables_stage1.png)

Eventually it clicks.

Imports aren’t functions.

They’re **heap resident shellcode stubs.**


Each stub:
- Is randomly selected (0–4 variants)
- Uses different XOR/key strategies
- Ultimately jumps to the resolved API
Heap base around:
> 0x00C27408

This is runtime polymorphism.
![Runtime Polymorphism](https://raw.githubusercontent.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/refs/heads/main/import_polymorphism_stage1.png)

## Step 3: Strings (thankfully weak)
String protection is laughably simple. Each string is encoded as an array and passed to `FUN_00C01228`. 

Function `00C01228`:
- XOR with `0x47063fc8`
- Bitwise NOT

Simply recreating the decoder in c++, it was easy to decode all of the strings. Looking at the XREF, I could find all of the strings.

Some strings stay non-printable, kept as hex, but all of the strings can be accessed [here](https://github.com/VeryCuteLookingCat/Lockbit-Black-Loader-Analysis/blob/main/strings.txt).

## To Be Continued.
