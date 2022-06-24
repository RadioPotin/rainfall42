# rainfall42 

[PDF](https://linx.zapashcanon.fr/wwpgbqo1.pdf)


## exploiting binaries

This project is essentially a CTF.

Each level has a binary that we must find ways to exploit in order to find our way to next level.

In order to find our way to the next level, we have to expose the hash contained in the `.pass` file in the home directory of the user of the next level.

There are 9 exercises and 4 bonuses.

Each exercise in the final repository must obey the following structure:

```shell-session
├── levelX
│   ├── pass
│   ├── pseudocode.c
│   ├── README.md
│   └── Ressources
│       └── automate_exploit.py
```

1. The `pass` file is the flag found in the `.pass` file in the home directory of `level(X + 1)` this is our target for each exercise.
2. The pseudocode file can obey any langage's syntax, it does not need to compile.
3. README.md must explain the whole logical process.
4. The automation script is optionnal and any other scripting langage is authorised.

## the VM

```shell-session
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level1/level1
```

Everytime we log into the remote machine, we see this promt show up. This basically tells us how tailored for security vulnerabilities exploitation the image really is.

- GR Security is an extensive security enhancement to the Linux kernel that defends against a wide range of security threats through intelligent access control, memory corruption-based exploit prevention, and a host of other system hardening that generally require no configuration.

- ASLR -> Address Space Layout Randomization (ASLR) is a memory-protection process for operating systems (OSes) that guards against buffer-overflow attacks by randomizing the location where system executables are loaded into memory.

- RELRO -> Read Only Rellocation

- Stack Canary-> Stack canaries or security cookies are tell-tale values added to binaries during compilation to protect critical stack values like the Return Pointer against buffer overflow attacks.

- NX -> This option is also referred to as Data Execution Prevention (DEP) or No-Execute (NX). When this option is enabled, it works with the processor to help prevent buffer overflow attacks by blocking code execution from memory that is marked as non-executable.

- PIE -> Position Independant Executable. When activated, the executable's symbols have offsets to which addresses are referenced, instead of absolute addresses

- RPATH -> In computing, rpath designates the run-time search path hard-coded in an executable file or library. Dynamic linking loaders use the rpath to find required libraries. Specifically, it encodes a path to shared libraries into the header of an executable (or another shared library).

-

## ssh

```shell-session
$ ssh levelX@<IP> -p 4242
```

`X`->the current level in the CTF

`IP`->the IP display as a prompt of the VM

## scp

```shell-session
$ scp -p4242 scp://levelX@<IP>/<sourcepath> /path/to/destination
```

## Ressources

MUST HAVE:
- gdb, GNU debugger
- [asm documentation](https://beta.hackndo.com/assembly-basics/)
- [Understanding Buffer Overflow attacks](https://itandsecuritystuffs.wordpress.com/2014/03/18/understanding-buffer-overflows-attacks-part-1/)
- [Buffer Overflow generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/)
- Whats a [shellcode](https://fr.wikipedia.org/wiki/Shellcode) and [where](http://shell-storm.org/shellcode/) to find some.
- GOD TIER DOCUMENTATION FOR INTRUCTIONS: [amd](https://www.amd.com/system/files/TechDocs/24594.pdf)
- DEMI-GOD TIER DOCUMENTATION FOR INSTRUCTIONS: [gladir](https://www.gladir.com/CODER/ASM8086/)
- KING OF ALL SANDBOXES ASM: [godbolt](https://godbolt.org/)
- [peda](https://github.com/longld/peda):
  > level0@RainFall:/tmp$ mkdir peda
  >
  > level0@RainFall:/tmp$ chmod ugo+rwx /tmp/peda
  >
  > scp -P 4242 -r peda/ level0@IP:/tmp/
  >
  > chmod +rwx ~; echo "source /tmp/peda/peda.py" > ~/.gdbinit
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) to reverse binaries
