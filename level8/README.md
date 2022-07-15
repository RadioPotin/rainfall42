# level8

## Hint

When we log into the machine as `level8`, we notice a binary:

```shell-session
level8@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level9 users 6057 Mar  6  2016 level8
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

We we start the program with or without arguments, it prints the following:

```shell-session
level8@RainFall:~$ ./level8
(nil), (nil)
```

The program wait for input. We can try to feed it with the following:

```shell-session
level8@RainFall:~$ ./level8
(nil), (nil)
..............................................................................................................................
(nil), (nil)
```

It print again `(nil), (nil)` and wait for input.

But if we add one more character, it prints:

```shell-session
level8@RainFall:~$ ./level8
(nil), (nil)
...............................................................................................................................
(nil), (nil)
(nil), (nil)
```

It's seems like if we put more `n * 126` characters, it will print  `n` * `(nil), (nil)`.

Exemple with `126 * 3` characters:

```shell-session
level8@RainFall:~$ ./level8
(nil), (nil)
..........................................................................................................................................................................................................................................................................................................................................................................................
(nil), (nil)
(nil), (nil)
(nil), (nil)
```

The program doesn't seems to crash. So lets dig with `gdb`.

## gdb

Ok let's wrap up our gdb session. At first, we need to list all the functions.

```gdb
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x080483c4  _init
0x08048410  printf
0x08048410  printf@plt
0x08048420  free
0x08048420  free@plt
0x08048430  strdup
0x08048430  strdup@plt
0x08048440  fgets
0x08048440  fgets@plt
0x08048450  fwrite
0x08048450  fwrite@plt
0x08048460  strcpy
0x08048460  strcpy@plt
0x08048470  malloc
0x08048470  malloc@plt
0x08048480  system
0x08048480  system@plt
0x08048490  __gmon_start__
0x08048490  __gmon_start__@plt
0x080484a0  __libc_start_main
0x080484a0  __libc_start_main@plt
0x080484b0  _start
0x080484e0  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048564  main
0x08048740  __libc_csu_init
0x080487b0  __libc_csu_fini
0x080487b2  __i686.get_pc_thunk.bx
0x080487c0  __do_global_ctors_aux
0x080487ec  _fini
```

And now variables.

```gdb
gdb-peda$ info variables
All defined variables:

Non-debugging symbols:
0x08048808  _fp_hw
0x0804880c  _IO_stdin_used
0x08048948  __FRAME_END__
0x0804994c  __CTOR_LIST__
0x0804994c  __init_array_end
0x0804994c  __init_array_start
0x08049950  __CTOR_END__
0x08049954  __DTOR_LIST__
0x08049958  __DTOR_END__
0x0804995c  __JCR_END__
0x0804995c  __JCR_LIST__
0x08049960  _DYNAMIC
0x08049a2c  _GLOBAL_OFFSET_TABLE_
0x08049a60  __data_start
0x08049a60  data_start
0x08049a64  __dso_handle
0x08049a80  stdin@@GLIBC_2.0
0x08049aa0  stdout@@GLIBC_2.0
0x08049aa4  completed.6159
0x08049aa8  dtor_idx.6161
0x08049aac  auth
0x08049ab0  service
```

Look's like that we only have the `main` function. But two variables are interesting: `auth` and `service`.

Let's see where does variables are stored.

```shell-session
level8@RainFall:~$ objdump -x level8 | grep "auth"
08049aac g     O .bss	00000004              auth
```

```shell-session
level8@RainFall:~$ objdump -x level8 | grep "service"
08049ab0 g     O .bss	00000004              service
```

There are both global and in the .bss section.

### disas main

```gdb
gdb-peda$ pdisas main
Dump of assembler code for function main:
   0x08048564 <+0>:	push   ebp
   0x08048565 <+1>:	mov    ebp,esp
   0x08048567 <+3>:	push   edi
   0x08048568 <+4>:	push   esi
   0x08048569 <+5>:	and    esp,0xfffffff0
   0x0804856c <+8>:	sub    esp, 0x10                                            <-- Room alocated stack for 1 pointer (char *s)
   0x08048572 <+14>:	jmp    0x8048575 <main+17>                              <-- Jump to main+17
   0x08048574 <+16>:	nop
   0x08048575 <+17>:	mov    ecx,DWORD PTR ds:0x8049ab0                       <-- Put pointer of 0x8049ab0 in ecx (global service)
   0x0804857b <+23>:	mov    edx,DWORD PTR ds:0x8049aac                       <-- Put pointer of 0x8049aac in edx (global auth)
   0x08048581 <+29>:	mov    eax,0x8048810                                    <-- Fed ""%p, %p \n" in eax (const char *format)
   0x08048586 <+34>:	mov    DWORD PTR [esp+0x8],ecx                          <-- Put address of ecx in esp+0x8 (3rd argument = service)
   0x0804858a <+38>:	mov    DWORD PTR [esp+0x4],edx                          <-- Put address of edx in esp+0x4 (2nd argument = auth)
   0x0804858e <+42>:	mov    DWORD PTR [esp],eax                              <-- Put eax as argument to printf in esp (1st argument = const *char *format)
   0x08048591 <+45>:	call   0x8048410 <printf@plt>                           <-- Call printf@plt with esp as arguments
   0x08048596 <+50>:	mov    eax,ds:0x8049a80                                 <-- Put address of stdin in eax (stdin)
   0x0804859b <+55>:	mov    DWORD PTR [esp+0x8],eax                          <-- Put eax in esp+0x8 (3rd argument = stdin)
   0x0804859f <+59>:	mov    DWORD PTR [esp+0x4],0x80                         <-- Put 0x80 in esp+0x4 (2nd argument = 128 in decimal)
   0x080485a7 <+67>:	lea    eax,[esp+0x20]                                   <-- Put address of esp+0x20 in eax (1st argument = char *s)
   0x080485ab <+71>:	mov    DWORD PTR [esp],eax                              <-- Put eax as argument to fgets in esp
   0x080485ae <+74>:	call   0x8048440 <fgets@plt>                            <-- Call fgets@plt with eax as arguments
   0x080485b3 <+79>:	test   eax,eax                                          <-- Test if fgets returned NULL
   0x080485b5 <+81>:	je     0x804872c <main+456>                             <-- If it is, jump to main+456 (goto END:)
   0x080485bb <+87>:	lea    eax,[esp+0x20]                                   <-- Fetch address of esp+0x20 in eax (char *s)
   0x080485bf <+91>:	mov    edx,eax                                          <-- Put eax in edx (char *s)
   0x080485c1 <+93>:	mov    eax,0x8048819                                    <-- Fed "auth " in eax
   0x080485c6 <+98>:	mov    ecx,0x5                                          <-- Put '5' in ecx (Counter operator)
   0x080485cb <+103>:	mov    esi,edx                                          <-- Put edx in esi (char *s)
   0x080485cd <+105>:	mov    edi,eax                                          <-- Put eax in edi ("auth ")
   0x080485cf <+107>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]           <-- Begin of optimized inline code of strncmp: (repz means repeat if equal)
   0x080485d1 <+109>:	seta   dl                                               <-- Set flag dl to 1 if esi[i] < edi[i]
   0x080485d4 <+112>:	setb   al                                               <-- Set flag al to 1 if esi[i] > edi[i]
   0x080485d7 <+115>:	mov    ecx,edx                                          <-- Puts edx in ecx (char *s) (Counter)
   0x080485d9 <+117>:	sub    cl,al                                            <-- Generate return value
   0x080485db <+119>:	mov    eax,ecx                                          <-- Put ecx in eax (Counter)
   0x080485dd <+121>:	movsx  eax,al                                           <-- Convert al to signed int (en strncmp)
   0x080485e0 <+124>:	test   eax,eax                                          <-- Test if optimized inline strcnmp equal to 0
   0x080485e2 <+126>:	jne    0x8048642 <main+222>                             <-- If it's not equal, jump to main+222
   0x080485e4 <+128>:	mov    DWORD PTR [esp],0x4                              <-- Else continue, put 4 in esp for malloc
   0x080485eb <+135>:	call   0x8048470 <malloc@plt>                           <-- Call malloc@plt with esp as argument
   0x080485f0 <+140>:	mov    ds:0x8049aac,eax                                 <-- Return of malloc in ds:0x8049aac (global auth)
   0x080485f5 <+145>:	mov    eax,ds:0x8049aac                                 <-- Put address of auth in eax (global auth)
   0x080485fa <+150>:	mov    DWORD PTR [eax],0x0                              <-- Set auth to NULL
   0x08048600 <+156>:	lea    eax,[esp+0x20]                                   <-- Fetch address of esp+0x20 in eax (char *s)
   0x08048604 <+160>:	add    eax,0x5                                          <-- Add 5 to eax (char *s) -> eax = char *s + 5
   0x08048607 <+163>:	mov    DWORD PTR [esp+0x1c],0xffffffff                  <-- Put 0xffffffff in esp+0x1c (3rd argument = -1)
   0x0804860f <+171>:	mov    edx,eax                                          <-- Put eax in edx (char *s) Save original
   0x08048611 <+173>:	mov    eax,0x0                                          <-- Put 0 in eax (Counter)
   0x08048616 <+178>:	mov    ecx,DWORD PTR [esp+0x1c]                         <-- Put 3rd argument in ecx (3rd argument = -1)
   0x0804861a <+182>:	mov    edi,edx                                          <-- Put edx in edi (char *s)
   0x0804861c <+184>:	repnz scas al,BYTE PTR es:[edi]                         <-- Begin of optimized inline code of strlen: (repnz means repeat if not equal)
   0x0804861e <+186>:	mov    eax,ecx                                          <-- Put ecx in eax (Counter)
   0x08048620 <+188>:	not    eax                                              <-- Invert eax (Counter)
   0x08048622 <+190>:	sub    eax,0x1                                          <-- Subtract 1 from eax (Counter)
   0x08048625 <+193>:	cmp    eax,0x1e                                         <-- Compare eax with 0x1e (Counter)
   0x08048628 <+196>:	ja     0x8048642 <main+222>                             <-- If eax is greater than 0x1e (30 decimal), jump to main+222 (goto MAIN_222:)
   0x0804862a <+198>:	lea    eax,[esp+0x20]                                   <-- Fetch address of esp+0x20 in eax (char *s)
   0x0804862e <+202>:	lea    edx,[eax+0x5]                                    <-- Fetch address of eax+0x5 in edx (char *s + 5)
   0x08048631 <+205>:	mov    eax,ds:0x8049aac                                 <-- Put address of auth in eax (global auth)
   0x08048636 <+210>:	mov    DWORD PTR [esp+0x4],edx                          <-- Put edx in esp+0x4 (2nd argument)
   0x0804863a <+214>:	mov    DWORD PTR [esp],eax                              <-- Put eax in esp (1st argument)
   0x0804863d <+217>:	call   0x8048460 <strcpy@plt>                           <-- Call strcpy@plt with esp as arguments
   0x08048642 <+222>:	lea    eax,[esp+0x20]                                   <-- Fetch address of esp+0x20 in eax (char *s)
   0x08048646 <+226>:	mov    edx,eax                                          <-- Put eax in edx (char *s)
   0x08048648 <+228>:	mov    eax,0x804881f                                    <-- Put "reset" in eax
   0x0804864d <+233>:	mov    ecx,0x5                                          <-- Put 5 in ecx (Counter operator)
   0x08048652 <+238>:	mov    esi,edx                                          <-- Put edx in esi (char *s)
   0x08048654 <+240>:	mov    edi,eax                                          <-- Put eax in edi "reset"
   0x08048656 <+242>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]           <-- Begin of optimized inline code of strncmp: (repz means repeat if equal)
   0x08048658 <+244>:	seta   dl                                               <-- Set flag dl to 1 if esi[i] == edi[i]
   0x0804865b <+247>:	setb   al                                               <-- Set flag al to 1 if esi[i] > edi[i]
   0x0804865e <+250>:	mov    ecx,edx                                          <-- Put edx in ecx (char *s) (Counter)
   0x08048660 <+252>:	sub    cl,al                                            <-- Generate return value (Counter - al)
   0x08048662 <+254>:	mov    eax,ecx                                          <-- Put ecx in eax (Counter)
   0x08048664 <+256>:	movsx  eax,al                                           <-- Convert signed byte to signed int (Counter)
   0x08048667 <+259>:	test   eax,eax                                          <-- Test if optimized strncmp is equal to 0
   0x08048669 <+261>:	jne    0x8048678 <main+276>                             <-- If not equal, jump to main+276 (goto MAIN_276:)
   0x0804866b <+263>:	mov    eax,ds:0x8049aac
   0x08048670 <+268>:	mov    DWORD PTR [esp],eax
   0x08048673 <+271>:	call   0x8048420 <free@plt>
   0x08048678 <+276>:	lea    eax,[esp+0x20]
   0x0804867c <+280>:	mov    edx,eax
   0x0804867e <+282>:	mov    eax,0x8048825
   0x08048683 <+287>:	mov    ecx,0x6
   0x08048688 <+292>:	mov    esi,edx
   0x0804868a <+294>:	mov    edi,eax
   0x0804868c <+296>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x0804868e <+298>:	seta   dl
   0x08048691 <+301>:	setb   al
   0x08048694 <+304>:	mov    ecx,edx
   0x08048696 <+306>:	sub    cl,al
   0x08048698 <+308>:	mov    eax,ecx
   0x0804869a <+310>:	movsx  eax,al
   0x0804869d <+313>:	test   eax,eax
   0x0804869f <+315>:	jne    0x80486b5 <main+337>
   0x080486a1 <+317>:	lea    eax,[esp+0x20]
   0x080486a5 <+321>:	add    eax,0x7
   0x080486a8 <+324>:	mov    DWORD PTR [esp],eax
   0x080486ab <+327>:	call   0x8048430 <strdup@plt>
   0x080486b0 <+332>:	mov    ds:0x8049ab0,eax
   0x080486b5 <+337>:	lea    eax,[esp+0x20]
   0x080486b9 <+341>:	mov    edx,eax
   0x080486bb <+343>:	mov    eax,0x804882d
   0x080486c0 <+348>:	mov    ecx,0x5
   0x080486c5 <+353>:	mov    esi,edx
   0x080486c7 <+355>:	mov    edi,eax
   0x080486c9 <+357>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x080486cb <+359>:	seta   dl
   0x080486ce <+362>:	setb   al
   0x080486d1 <+365>:	mov    ecx,edx
   0x080486d3 <+367>:	sub    cl,al
   0x080486d5 <+369>:	mov    eax,ecx
   0x080486d7 <+371>:	movsx  eax,al
   0x080486da <+374>:	test   eax,eax
   0x080486dc <+376>:	jne    0x8048574 <main+16>
   0x080486e2 <+382>:	mov    eax,ds:0x8049aac
   0x080486e7 <+387>:	mov    eax,DWORD PTR [eax+0x20]
   0x080486ea <+390>:	test   eax,eax
   0x080486ec <+392>:	je     0x80486ff <main+411>
   0x080486ee <+394>:	mov    DWORD PTR [esp],0x8048833
   0x080486f5 <+401>:	call   0x8048480 <system@plt>
   0x080486fa <+406>:	jmp    0x8048574 <main+16>
   0x080486ff <+411>:	mov    eax,ds:0x8049aa0
   0x08048704 <+416>:	mov    edx,eax
   0x08048706 <+418>:	mov    eax,0x804883b
   0x0804870b <+423>:	mov    DWORD PTR [esp+0xc],edx
   0x0804870f <+427>:	mov    DWORD PTR [esp+0x8],0xa
   0x08048717 <+435>:	mov    DWORD PTR [esp+0x4],0x1
   0x0804871f <+443>:	mov    DWORD PTR [esp],eax
   0x08048722 <+446>:	call   0x8048450 <fwrite@plt>
   0x08048727 <+451>:	jmp    0x8048574 <main+16>
   0x0804872c <+456>:	nop
   0x0804872d <+457>:	mov    eax,0x0
   0x08048732 <+462>:	lea    esp,[ebp-0x8]
   0x08048735 <+465>:	pop    esi
   0x08048736 <+466>:	pop    edi
   0x08048737 <+467>:	pop    ebp
   0x08048738 <+468>:	ret
End of assembler dump.
```
