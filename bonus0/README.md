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
0x080483c0  __gmon_start__
0x080483c0  __gmon_start__@plt
0x080483d0  strchr
0x080483d0  strchr@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  strncpy
0x080483f0  strncpy@plt
0x08048400  _start
0x08048430  __do_global_dtors_aux
0x08048490  frame_dummy
0x080484b4  p
0x0804851e  pp
0x080485a4  main
0x080485d0  __libc_csu_init
0x08048640  __libc_csu_fini
0x08048642  __i686.get_pc_thunk.bx
0x08048650  __do_global_ctors_aux
0x0804867c  _fini
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
   0x080485aa <+6>:	sub    esp,0x40                             <--|Alignement of a pointer char *s[54] bytes
   0x080485ad <+9>:	lea    eax,[esp+0x16]                       <--|
   0x080485b1 <+13>:	mov    DWORD PTR [esp],eax
   0x080485b4 <+16>:	call   0x804851e <pp>                   <-- Call to pp(s)
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
   0x08048523 <+5>:	sub    esp,0x50                             <-- Space of 80 bytes to align 76 bytes of the stack frame (2 pointer char of 20 bytes and 1 pointer of 12 bytes)
   0x08048526 <+8>:	mov    DWORD PTR [esp+0x4],0x80486a0        <-- Loading char *dash
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
