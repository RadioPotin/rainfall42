# level6

## Hint

When we log into the machine as `level7`, we notice a binary:

```shell-session
level7@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level8 users 5648 Mar  9  2016 level7
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

The program is crashing (Segmentation Fault) when we try to run it with 1 or less arguments.

```shell-session
level7@RainFall:~$ ./level7
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 a
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 a b
~~
```

## gdb and ltrace

So let's look inside the binary and try to understand what is going on.

First, as always, lets look at available functions and symbols and denote their addresses.

```gdb
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x0804836c  _init
0x080483b0  printf
0x080483b0  printf@plt
0x080483c0  fgets
0x080483c0  fgets@plt
0x080483d0  time
0x080483d0  time@plt
0x080483e0  strcpy
0x080483e0  strcpy@plt
0x080483f0  malloc
0x080483f0  malloc@plt
0x08048400  puts
0x08048400  puts@plt
[...]
0x08048430  fopen
0x08048430  fopen@plt
[...]
0x080484f4  m
0x08048521  main
[...]
gdb-peda$ info variables
All defined variables:

Non-debugging symbols:
[...]
0x0804993c  __dso_handle
0x08049940  completed.6159
0x08049944  dtor_idx.6161
0x08049960  c
```

We have cut out some noise in the output but we can see the following relevant information:

- Some user-defined functions

```gdb
0x080484f4  m
0x08048521  main
```

- Some global variable

```gdb
0x08049960  c
```

Furthermore, we can easily get what allocated addresses `malloc` returns by asking `ltrace` to wrap our binary:

```shell-session
level7@RainFall:~$ ltrace ./level7 ayooooo ayoooooooooooo
__libc_start_main(0x8048521, 3, 0xbffffce4, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                 = 0x0804a008
malloc(8)                                                 = 0x0804a018
malloc(8)                                                 = 0x0804a028
malloc(8)                                                 = 0x0804a038
strcpy(0x0804a018, "ayooooo")                             = 0x0804a018
strcpy(0x0804a038, "ayoooooooooooo")                      = 0x0804a038
fopen("/home/user/level8/.pass", "r")                     = 0
fgets( <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

### disas main

Disassembling main function gives us quite a big output.

Let's proceed with an overview first:

```gdb
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048521 <+0>:	push   ebp
   0x08048522 <+1>:	mov    ebp,esp
   0x08048524 <+3>:	and    esp,0xfffffff0
   0x08048527 <+6>:	sub    esp,0x20                  <--- Room allocated on the stack for two pointers
   0x0804852a <+9>:	mov    DWORD PTR [esp],0x8       <--- put argument to malloc in esp 
   0x08048531 <+16>:	call   0x80483f0 <malloc@plt>    <--- Call to malloc(8) 
   0x08048536 <+21>:	mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:	mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:	mov    DWORD PTR [eax],0x1       <--- Put value 1 at address in eax
   0x08048544 <+35>:	mov    DWORD PTR [esp],0x8       <--- put argument to malloc in esp
   0x0804854b <+42>:	call   0x80483f0 <malloc@plt>    <--- Call to malloc(8)
   0x08048550 <+47>:	mov    edx,eax
   0x08048552 <+49>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:	mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:	mov    DWORD PTR [esp],0x8       <--- put argument to malloc in esp
   0x08048560 <+63>:	call   0x80483f0 <malloc@plt>    <--- Call to malloc(8)
   0x08048565 <+68>:	mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:	mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:	mov    DWORD PTR [eax],0x2       <--- Put value 2 at address in eax
   0x08048573 <+82>:	mov    DWORD PTR [esp],0x8       <--- put argument to malloc in esp
   0x0804857a <+89>:	call   0x80483f0 <malloc@plt>    <--- Call to malloc(8)
   0x0804857f <+94>:	mov    edx,eax
   0x08048581 <+96>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:	mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:	add    eax,0x4
   0x0804858e <+109>:	mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:	mov    edx,eax
   0x08048592 <+113>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:	mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:	mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:	mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>    <--- Call to strcpy
   0x080485a5 <+132>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080485a8 <+135>:	add    eax,0x8
   0x080485ab <+138>:	mov    eax,DWORD PTR [eax]
   0x080485ad <+140>:	mov    edx,eax
   0x080485af <+142>:	mov    eax,DWORD PTR [esp+0x18]
   0x080485b3 <+146>:	mov    eax,DWORD PTR [eax+0x4]
   0x080485b6 <+149>:	mov    DWORD PTR [esp+0x4],edx
   0x080485ba <+153>:	mov    DWORD PTR [esp],eax
   0x080485bd <+156>:	call   0x80483e0 <strcpy@plt>    <--- Call to strcpy
   0x080485c2 <+161>:	mov    edx,0x80486e9             <--- "r"
   0x080485c7 <+166>:	mov    eax,0x80486eb             <--- "/home/user/level8/.pass"
   0x080485cc <+171>:	mov    DWORD PTR [esp+0x4],edx
   0x080485d0 <+175>:	mov    DWORD PTR [esp],eax
   0x080485d3 <+178>:	call   0x8048430 <fopen@plt>
   0x080485d8 <+183>:	mov    DWORD PTR [esp+0x8],eax   <--- FILE * returned by fopen
   0x080485dc <+187>:	mov    DWORD PTR [esp+0x4],0x44  <--- 68 bytes
   0x080485e4 <+195>:	mov    DWORD PTR [esp],0x8049960 <--- Call writing to address of global variable c 
   0x080485eb <+202>:	call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:	mov    DWORD PTR [esp],0x8048703   <--- "~~"
   0x080485f7 <+214>:	call   0x8048400 <puts@plt>
   0x080485fc <+219>:	mov    eax,0x0
   0x08048601 <+224>:	leave
   0x08048602 <+225>:	ret
End of assembler dump.
```

To sum up:

The `main()` function does several calls to `malloc()` and `strcpy()`, then opens the objective of the current exploit level (`/home/user/level8/.pass`) and write 68 bytes of that file to the global variable `c`.
And to finish, before `return(0)`, there is a call to the `puts()` with the static string `~~`.

So, keeping in mind our available symbols, there are no mention of `m()` in main...

So lets look inside `m()`.

Reminder: `0x08049960 c`

```gdb
gdb-peda$ disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:	push   ebp
   0x080484f5 <+1>:	mov    ebp,esp
   0x080484f7 <+3>:	sub    esp,0x18                         <--- Allocating 24 bits for 1 time_t var + alignment on 16 for call to time
   0x080484fa <+6>:	mov    DWORD PTR [esp],0x0              <--- feeding value 0 to function time()
   0x08048501 <+13>:	call   0x80483d0 <time@plt>
   0x08048506 <+18>:	mov    edx,0x80486e0                    <--- "%s - %d\n" format string
   0x0804850b <+23>:	mov    DWORD PTR [esp+0x8],eax		<--- Value returned by the call to time() 
   0x0804850f <+27>:	mov    DWORD PTR [esp+0x4],0x8049960    <--- global variable c
   0x08048517 <+35>:	mov    DWORD PTR [esp],edx              <--- format string
   0x0804851a <+38>:	call   0x80483b0 <printf@plt>
   0x0804851f <+43>:	leave
   0x08048520 <+44>:	ret
End of assembler dump.
```

So it's clear now that we need to manage to call the `m()` function in order to get to that call to printf that will display the pass we are looking for to `stdout`.


