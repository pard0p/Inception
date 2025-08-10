<div align="center">
  <img width="200px" src="./assets/logo.png" />
  <h1>INCEPTION</h1>
  <br/>
  <p><i>Inception is a ROP gadget-based sleep obfuscation technique designed to evade detection mechanisms and protect C2 implant code by chaining contexts to encrypt executable memory during idle periods.</i></p>
  <p><i>Created by <a href="https://github.com/pard0p">@pard0p</a>.</i></p>
  <br />
</div>

## 📖 Overview

**Inception** is a proof-of-concept ROP gadget-based sleep obfuscation technique that uses Return-Oriented Programming (ROP) chains to encrypt and protect implant's code.

The technique chains multiple `CONTEXT` structures in a ROP chain, each performing a specific task in the obfuscation cycle. When the process needs to sleep, instead of simply waiting, it encrypts its own code section and only decrypts it when ready to continue execution.

## 🏗️ Architecture

The system operates through seven chained execution contexts:

### Context Flow

```
CONTEXT 0 → NtProtectVirtualMemory (PAGE_READWRITE)
    ↓
CONTEXT 1 → SystemFunction032 (Encrypt)
    ↓
CONTEXT 2 → NtWaitForSingleObject (Sleep)
    ↓
CONTEXT 3 → SystemFunction032 (Decrypt)
    ↓
CONTEXT 4 → NtProtectVirtualMemory (PAGE_EXECUTE_READ)
    ↓
CONTEXT 5 → NtSetEvent (Synchronization)
    ↓
CONTEXT 6 → NtTerminateThread (Cleanup)
```

## 🔨 Windows API

| Function | Module | Purpose |
|----------|--------|---------|
| `NtContinue` | ntdll.dll | Context switching between ROP chains |
| `NtProtectVirtualMemory` | ntdll.dll | Change memory protection (RW ↔ RX) |
| `NtWaitForSingleObject` | ntdll.dll | Sleep with timeout during obfuscation |
| `NtSetEvent` | ntdll.dll | Signal completion of obfuscation cycle |
| `NtTerminateThread` | ntdll.dll | Clean thread termination |
| `SystemFunction032` | advapi32.dll | RC4 encryption/decryption |

### Sample Output
```
[*] Initializing INCEPTION...
    [*] Extracting .text section from current process...
    [+] Found .text section: Base=0x00007FF7C2A01000, Size=0x5A3C
    [*] Searching for gadget ADD RSP, XX; POP RCX; RET...

[+] INCEPTION INITIALIZATION COMPLETED

[*] Starting INCEPTION main loop...

[+] INCEPTION START (Iteration 1)
    Base context captured: RIP=0x00007FFB2E6D2340, RSP=0x000000A8B0CFFBC0
    Configuring INCEPTION's ROP contexts...
        Context 0: NtProtectVirtualMemory RW
        Context 1: SystemFunction032 Encrypt
        Context 2: NtWaitForSingleObject
        Context 3: SystemFunction032 Decrypt
        Context 4: NtProtectVirtualMemory RX
        Context 5: NtSetEvent
        Context 6: NtTerminateThread
    Starting INCEPTION's obfuscation...
[+] INCEPTION END (Iteration 1)
```

## ⚠️ Proof of Concept

This is a **proof-of-concept implementation** designed for educational and research purposes. It demonstrates:

- Advanced ROP chaining techniques
- Sleep obfuscation methodologies
- Windows internals manipulation

## 📚 References

- [Ekko](https://github.com/Cracked5pider/Ekko)
- [Foliage](https://github.com/y11en/FOLIAGE)

<img src="./assets/deeper.jpg" />