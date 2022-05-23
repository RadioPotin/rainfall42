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
