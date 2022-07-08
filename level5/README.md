# level5

## Hint

When we log into the machine as `level5`, we notice a binary:

```shell-session
level5@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level6 users 5385 Mar  6  2016 level5
level5@RainFall:~$
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

## gdb

First, we'll need to see all available global symbols

```shell-session
gdb-peda$ info variables
All defined variables:

Non-debugging symbols:
0x080485e8  _fp_hw
0x080485ec  _IO_stdin_used
0x08048734  __FRAME_END__
0x08049738  __CTOR_LIST__
0x08049738  __init_array_end
0x08049738  __init_array_start
0x0804973c  __CTOR_END__
0x08049740  __DTOR_LIST__
0x08049744  __DTOR_END__
0x08049748  __JCR_END__
0x08049748  __JCR_LIST__
0x0804974c  _DYNAMIC
0x08049818  _GLOBAL_OFFSET_TABLE_
0x08049840  __data_start
0x08049840  data_start
0x08049844  __dso_handle
0x08049848  stdin@@GLIBC_2.0
0x0804984c  completed.6159
0x08049850  dtor_idx.6161
0x08049854  m                                                   <-- Variable `m`
```

We can see that there is a global variable `m` like in the previous level. Let's see if it is in the .bss section aswell.

```shell-session
level5@RainFall:~$ objdump -x level5
[...]
080483f0 g     F .text	00000000              _start
080485e8 g     O .rodata	00000004              _fp_hw
080484a4 g     F .text	0000001e              o
08049854 g     O .bss	00000004              m                 <-- `m` is a global uninitialised
08049848 g       *ABS*	00000000              __bss_start
08048504 g     F .text	0000000d              main
[...]
```

Yes ! So we have `m` a global uninitialised variable in the .bss section.

Let's look now at the binary.

```shell-session
level5@RainFall:~$ gdb -q ./level5
Reading symbols from /home/user/level4/level4...(no debugging symbols found)...done.
gdb-peda$ pdisas main
Dump of assembler code for function main:
   0x08048504 <+0>:	push   ebp
   0x08048505 <+1>:	mov    ebp,esp
   0x08048507 <+3>:	and    esp,0xfffffff0
   0x0804850a <+6>:	call   0x80484c2 <n>                        <-- Call to function `n`
   0x0804850f <+11>:	leave
   0x08048510 <+12>:	ret
End of assembler dump.
```

Let's look at `n`.

```shell-session
gdb-peda$ disas n
Dump of assembler code for function n:
   0x080484c2 <+0>:	push   ebp
   0x080484c3 <+1>:	mov    ebp,esp
   0x080484c5 <+3>:	sub    esp,0x218
   0x080484cb <+9>:	mov    eax,ds:0x8049848
   0x080484d0 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484d4 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484dc <+26>:	lea    eax,[ebp-0x208]
   0x080484e2 <+32>:	mov    DWORD PTR [esp],eax
   0x080484e5 <+35>:	call   0x80483a0 <fgets@plt>            <-- Call to fget into esp
   0x080484ea <+40>:	lea    eax,[ebp-0x208]
   0x080484f0 <+46>:	mov    DWORD PTR [esp],eax
   0x080484f3 <+49>:	call   0x8048380 <printf@plt>           <-- Call to printf with esp as conv string (?)
   0x080484f8 <+54>:	mov    DWORD PTR [esp],0x1
   0x080484ff <+61>:	call   0x80483d0 <exit@plt>
End of assembler dump.
```

So we don't see any system() call here. Maybe there is an other function ?

```shell-session
gdb-peda$ info function
All defined functions:

Non-debugging symbols:
0x08048334  _init
0x08048380  printf
0x08048380  printf@plt
0x08048390  _exit
0x08048390  _exit@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  system
0x080483b0  system@plt
0x080483c0  __gmon_start__
0x080483c0  __gmon_start__@plt
0x080483d0  exit
0x080483d0  exit@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  o                                                   <-- An other function ! `o`
0x080484c2  n
0x08048504  main
0x08048520  __libc_csu_init
0x08048590  __libc_csu_fini
0x08048592  __i686.get_pc_thunk.bx
0x080485a0  __do_global_ctors_aux
0x080485cc  _fini
```

Yes ! There it is. `o` not referenced in the control flow.

Let's see what's `o` tells us.

```
gdb-peda$ disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:	push   ebp
   0x080484a5 <+1>:	mov    ebp,esp
   0x080484a7 <+3>:	sub    esp,0x18
   0x080484aa <+6>:	mov    DWORD PTR [esp],0x80485f0
   0x080484b1 <+13>:	call   0x80483b0 <system@plt>           <-- Call to system() with a shell-code : "\377%0\230\004\bh\030"
   0x080484b6 <+18>:	mov    DWORD PTR [esp],0x1
   0x080484bd <+25>:	call   0x8048390 <_exit@plt>
End of assembler dump
```

Ok now we have our call to system().

What's system() calls ?

```shell-session
gdb-peda$ x/s 0x80483b0
0x80483b0 <system@plt>:	 "\377%0\230\004\bh\030"
```

A shell code !
