# bonus2

## Hint

When we log into the machine as `bonus2`, we notice a binary:

```shell-session
bonus2@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus3 users 5664 Mar  6  2016 bonus2
```

We notice that the guid bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

After some playing around we can see we can make the binary crash with a long enough input:

```shell-session
bonus2@RainFall:~$ ./bonus2 lol
bonus2@RainFall:~$ ./bonus2 bonjour bonjour
Hello bonjour
bonus2@RainFall:~$ ./bonus2 euh bonjour
Hello euh
bonus2@RainFall:~$ ./bonus2 HELLOABCDEFGHIJKLMNOPFQRSTUVXYZ0123456789 HELLLOOOOOOOOOOOOOOOOOO>
Hello HELLOABCDEFGHIJKLMNOPFQRSTUVXYZ012345678HELLLOOOOOOOOOOOOOOOOOOOOOOOOOOO
Segmentation fault (core dumped)
bonus2@RainFall:~$ ./bonus2 HELLOABCDEFGHIJKLMNOPFQRSTUVXYZ0123456789 HELLABCDEFGHIJKLMNOPQRSTU
Hello HELLOABCDEFGHIJKLMNOPFQRSTUVXYZ012345678HELLABCDEFGHIJKLMNOPQRSTU
bonus2@RainFall:~$ ./bonus2 HELLOABCDEFGHIJKLMNOPFQRSTUVXYZ0123456789 HELLOABCDEFGHIJKLMNOPQRSTU
Hello HELLOABCDEFGHIJKLMNOPFQRSTUVXYZ012345678HELLOABCDEFGHIJKLMNOPQRSTU
Segmentation fault (core dumped)
```

## gdb

### available symbols

There are only two custom symbols we can see with the `info` gdb cli:

Otherwise, we can notice calls to:
- `strcat`
- `memcmp`
- `getenv`
- `strncpy`

```gdb
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x08048318  _init
0x08048360  memcmp
0x08048360  memcmp@plt
0x08048370  strcat
0x08048370  strcat@plt
0x08048380  getenv
0x08048380  getenv@plt
0x08048390  puts
0x08048390  puts@plt
0x080483a0  __gmon_start__
0x080483a0  __gmon_start__@plt
0x080483b0  __libc_start_main
0x080483b0  __libc_start_main@plt
0x080483c0  strncpy
0x080483c0  strncpy@plt
0x080483d0  _start
0x08048400  __do_global_dtors_aux
0x08048460  frame_dummy
0x08048484  greetuser                  <-- custom function
0x08048529  main
0x08048640  __libc_csu_init
0x080486b0  __libc_csu_fini
0x080486b2  __i686.get_pc_thunk.bx
0x080486c0  __do_global_ctors_aux
0x080486ec  _fini
gdb-peda$ info variable
All defined variables:

Non-debugging symbols:
0x08048708  _fp_hw
0x0804870c  _IO_stdin_used
0x0804886c  __FRAME_END__
0x08049870  __CTOR_LIST__
0x08049870  __init_array_end
0x08049870  __init_array_start
0x08049874  __CTOR_END__
0x08049878  __DTOR_LIST__
0x0804987c  __DTOR_END__
0x08049880  __JCR_END__
0x08049880  __JCR_LIST__
0x08049884  _DYNAMIC
0x08049950  _GLOBAL_OFFSET_TABLE_
0x08049978  __data_start
0x08049978  data_start
0x0804997c  __dso_handle
0x08049980  completed.6159
0x08049984  dtor_idx.6161
0x08049988  language                   <-- custom var 
```

### disas main

Lets analyse what the main does:

```shell-session
bonus2@RainFall:~$ ltrace ./bonus2 wtf1 wtf2
__libc_start_main(0x8048529, 3, 0xbffffcf4, 0x8048640, 0x80486b0 <unfinished ...>
strncpy(0xbffffbf0, "wtf1", 40)                            = 0xbffffbf0
strncpy(0xbffffc18, "wtf2", 32)                            = 0xbffffc18
getenv("LANG")                                             = "en_US.UTF-8"
memcmp(0xbfffff16, 0x804873d, 2, 0xb7fff918, 0)            = -1
memcmp(0xbfffff16, 0x8048740, 2, 0xb7fff918, 0)            = -1
strcat("Hello ", "wtf1")                                   = "Hello wtf1"
puts("Hello wtf1"Hello wtf1
)                                         = 11
+++ exited (status 11) +++
```

`ltrace` tells us what are the arguments to the binary used for: calls to `strncpy` as well as `strcat`... This is probably indicative of a buffer overflow attack opportunity.
Also, we see the first call to `strncpy` consistently gets a copy of `40 bytes` to the destination buffer, while the second gets one of `32`.


It also tells us which env variable is `getenv` asking for from inside the binary: `LANG`


```gdb
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048529 <+0>:	push   ebp
   0x0804852a <+1>:	mov    ebp,esp
   0x0804852c <+3>:	push   edi
   0x0804852d <+4>:	push   esi
   0x0804852e <+5>:	push   ebx
   0x0804852f <+6>:	and    esp,0xfffffff0
   0x08048532 <+9>:	sub    esp,0xa0                   <-- Allocating 170 bytes on main
   0x08048538 <+15>:	cmp    DWORD PTR [ebp+0x8],0x3
   0x0804853c <+19>:	je     0x8048548 <main+31>
   0x0804853e <+21>:	mov    eax,0x1
   0x08048543 <+26>:	jmp    0x8048630 <main+263>
   0x08048548 <+31>:	lea    ebx,[esp+0x50]
   0x0804854c <+35>:	mov    eax,0x0
   0x08048551 <+40>:	mov    edx,0x13
   0x08048556 <+45>:	mov    edi,ebx
   0x08048558 <+47>:	mov    ecx,edx
   0x0804855a <+49>:	rep stos DWORD PTR es:[edi],eax
   0x0804855c <+51>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804855f <+54>:	add    eax,0x4
   0x08048562 <+57>:	mov    eax,DWORD PTR [eax]
   0x08048564 <+59>:	mov    DWORD PTR [esp+0x8],0x28
   0x0804856c <+67>:	mov    DWORD PTR [esp+0x4],eax
   0x08048570 <+71>:	lea    eax,[esp+0x50]
   0x08048574 <+75>:	mov    DWORD PTR [esp],eax
   0x08048577 <+78>:	call   0x80483c0 <strncpy@plt>
   0x0804857c <+83>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804857f <+86>:	add    eax,0x8
   0x08048582 <+89>:	mov    eax,DWORD PTR [eax]
   0x08048584 <+91>:	mov    DWORD PTR [esp+0x8],0x20
   0x0804858c <+99>:	mov    DWORD PTR [esp+0x4],eax
   0x08048590 <+103>:	lea    eax,[esp+0x50]
   0x08048594 <+107>:	add    eax,0x28
   0x08048597 <+110>:	mov    DWORD PTR [esp],eax
   0x0804859a <+113>:	call   0x80483c0 <strncpy@plt>
   0x0804859f <+118>:	mov    DWORD PTR [esp],0x8048738
   0x080485a6 <+125>:	call   0x8048380 <getenv@plt>
   0x080485ab <+130>:	mov    DWORD PTR [esp+0x9c],eax
   0x080485b2 <+137>:	cmp    DWORD PTR [esp+0x9c],0x0
   0x080485ba <+145>:	je     0x8048618 <main+239>
   0x080485bc <+147>:	mov    DWORD PTR [esp+0x8],0x2
   0x080485c4 <+155>:	mov    DWORD PTR [esp+0x4],0x804873d
   0x080485cc <+163>:	mov    eax,DWORD PTR [esp+0x9c]
   0x080485d3 <+170>:	mov    DWORD PTR [esp],eax
   0x080485d6 <+173>:	call   0x8048360 <memcmp@plt>
   0x080485db <+178>:	test   eax,eax
   0x080485dd <+180>:	jne    0x80485eb <main+194>
   0x080485df <+182>:	mov    DWORD PTR ds:0x8049988,0x1
   0x080485e9 <+192>:	jmp    0x8048618 <main+239>
   0x080485eb <+194>:	mov    DWORD PTR [esp+0x8],0x2
   0x080485f3 <+202>:	mov    DWORD PTR [esp+0x4],0x8048740
   0x080485fb <+210>:	mov    eax,DWORD PTR [esp+0x9c]
   0x08048602 <+217>:	mov    DWORD PTR [esp],eax
   0x08048605 <+220>:	call   0x8048360 <memcmp@plt>
   0x0804860a <+225>:	test   eax,eax
   0x0804860c <+227>:	jne    0x8048618 <main+239>
   0x0804860e <+229>:	mov    DWORD PTR ds:0x8049988,0x2
   0x08048618 <+239>:	mov    edx,esp
   0x0804861a <+241>:	lea    ebx,[esp+0x50]
   0x0804861e <+245>:	mov    eax,0x13
   0x08048623 <+250>:	mov    edi,edx
   0x08048625 <+252>:	mov    esi,ebx
   0x08048627 <+254>:	mov    ecx,eax
   0x08048629 <+256>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0x0804862b <+258>:	call   0x8048484 <greetuser>
   0x08048630 <+263>:	lea    esp,[ebp-0xc]
   0x08048633 <+266>:	pop    ebx
   0x08048634 <+267>:	pop    esi
   0x08048635 <+268>:	pop    edi
   0x08048636 <+269>:	pop    ebp
   0x08048637 <+270>:	ret
End of assembler dump.
```

### disas greetuser
