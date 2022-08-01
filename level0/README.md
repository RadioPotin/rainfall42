# level0

## Hint

When we log into the machine as `level0`, we notice a binary that segfaults when we run it without a parameter:

```shell-session
level0@RainFall:~$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
level0@RainFall:~$ ./level0
Segmentation fault (core dumped)
level0@RainFall:~$ ./level0 lol
No !
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it is awaiting.

## gdb

```gdb
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048ec0 <+0>:	push   ebp
   0x08048ec1 <+1>:	mov    ebp,esp
   0x08048ec3 <+3>:	and    esp,0xfffffff0
   0x08048ec6 <+6>:	sub    esp,0x20                        <-- Space of 32 bytes is allocated on the stack
   0x08048ec9 <+9>:	mov    eax,DWORD PTR [ebp+0xc]         <-- Load char *argv[0] into eax
   0x08048ecc <+12>:	add    eax,0x4                         <-- Set argv[1]
   0x08048ecf <+15>:	mov    eax,DWORD PTR [eax]             <-- Load argv[1] into eax
   0x08048ed1 <+17>:	mov    DWORD PTR [esp],eax             <-- Pass argv[1] to atoi()
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    eax,0x1a7                       <-- Check atoi(argv[1]) == 423
   0x08048ede <+30>:	jne    0x8048f58 <main+152>            <-- If not, jump to main+152
   0x08048ee0 <+32>:	mov    DWORD PTR [esp],0x80c5348       <-- Pass "/bin/sh" to strdup()
   0x08048ee7 <+39>:	call   0x8050bf0 <strdup>
   0x08048eec <+44>:	mov    DWORD PTR [esp+0x10],eax        <-- Set execv_arg[0] = strdup("/bin/sh")
   0x08048ef0 <+48>:	mov    DWORD PTR [esp+0x14],0x0        <-- Set execv_arg[1] = NULL
   0x08048ef8 <+56>:	call   0x8054680 <getegid>             <-- gid = getegid()
   0x08048efd <+61>:	mov    DWORD PTR [esp+0x1c],eax
   0x08048f01 <+65>:	call   0x8054670 <geteuid>             <-- uid = geteuid()
   0x08048f06 <+70>:	mov    DWORD PTR [esp+0x18],eax
   0x08048f0a <+74>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f0e <+78>:	mov    DWORD PTR [esp+0x8],eax
   0x08048f12 <+82>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f16 <+86>:	mov    DWORD PTR [esp+0x4],eax
   0x08048f1a <+90>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f1e <+94>:	mov    DWORD PTR [esp],eax
   0x08048f21 <+97>:	call   0x8054700 <setresgid>           <-- setresgid(gid, gid, gid)
   0x08048f26 <+102>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f2a <+106>:	mov    DWORD PTR [esp+0x8],eax
   0x08048f2e <+110>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f32 <+114>:	mov    DWORD PTR [esp+0x4],eax
   0x08048f36 <+118>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f3a <+122>:	mov    DWORD PTR [esp],eax
   0x08048f3d <+125>:	call   0x8054690 <setresuid>        <-- setresuid(uid, uid, uid)
   0x08048f42 <+130>:	lea    eax,[esp+0x10]               <-- Address of execv_arg
   0x08048f46 <+134>:	mov    DWORD PTR [esp+0x4],eax      <-- Set address of execv_arg as 2nd arguments
   0x08048f4a <+138>:	mov    DWORD PTR [esp],0x80c5348    <-- Set "/bin/sh" as the first argument
   0x08048f51 <+145>:	call   0x8054640 <execv>            <-- execv("/bin/sh", &execv_arg)
   0x08048f56 <+150>:	jmp    0x8048f80 <main+192>
   0x08048f58 <+152>:	mov    eax,ds:0x80ee170             <-- Load stderr
   0x08048f5d <+157>:	mov    edx,eax
   0x08048f5f <+159>:	mov    eax,0x80c5350                <-- Load "No !\n"
   0x08048f64 <+164>:	mov    DWORD PTR [esp+0xc],edx      <-- Set stderr as 4th argument
   0x08048f68 <+168>:	mov    DWORD PTR [esp+0x8],0x5      <-- Set 5 as 3rd argument
   0x08048f70 <+176>:	mov    DWORD PTR [esp+0x4],0x1      <-- Set 1 as 2nd argument
   0x08048f78 <+184>:	mov    DWORD PTR [esp],eax          <-- Set address of "No !\n" as 1st argument
   0x08048f7b <+187>:	call   0x804a230 <fwrite>           <-- fwrite("No !\n", 1, 5, stderr)
   0x08048f80 <+192>:	mov    eax,0x0
   0x08048f85 <+197>:	leave
   0x08048f86 <+198>:	ret
End of assembler dump.
```

Once we've established a breakpoint at the first instruction of `main` and moved down instructions one by one, we end with a crash at address `0x08048ed4 <+20>`.

If we provide a parameter to the main function, as seen before, the program will no longer crash which, with gdb, will allow us to further inspect what input the program is awaiting.

```gdb
level0@RainFall:~$ gdb -q level0
Reading symbols from /home/user/level0/level0...(no debugging symbols found)...done.
(gdb) b *0x08048ed4
Breakpoint 1 at 0x8048ed4
(gdb) run 1
Starting program: /home/user/level0/level0 1

Breakpoint 1, 0x08048ed4 in main ()
(gdb) disas
Dump of assembler code for function main:
   0x08048ec0 <+0>:	push   ebp
   0x08048ec1 <+1>:	mov    ebp,esp
   0x08048ec3 <+3>:	and    esp,0xfffffff0
   0x08048ec6 <+6>:	sub    esp,0x20                        <-- Space of 32 bytes is allocated on the stack
   0x08048ec9 <+9>:	mov    eax,DWORD PTR [ebp+0xc]         <-- Load char *argv[0] into eax
   0x08048ecc <+12>:	add    eax,0x4                         <-- Set argv[1]
   0x08048ecf <+15>:	mov    eax,DWORD PTR [eax]             <-- Load argv[1] into eax
   0x08048ed1 <+17>:	mov    DWORD PTR [esp],eax             <-- Pass argv[1] to atoi()
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    eax,0x1a7                       <-- Check atoi(argv[1]) == 423
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
   [...]
   (gdb) ni
   0x08048ed9 in main ()
   (gdb) disas
   [...]
   0x08048ed9 <+25>:	cmp    eax,0x1a7
   (gdb) p 0x1a7
   $4 = 423
   (gdb) p $eax
   $6 = 1
   (gdb) set $eax=423
```

Indeed, after we've passed the call to `atoi`, that crashed when we didn't give a parameter to main, we can see a `cmp` instruction comparing what `atoi` has returned in `eax` with the static value `423` which is used for a conditionnal jump.

Conclusion: we know what the program is awaiting the string `423`.

So if we use gdb to insert `423` in eax before this instruction is executed, then we may skip that conditionnal jump. And get more information about what's passed to the next functions.

```gdb
[...]
(gdb) ni
0x08048ede in main ()
(gdb) disas
Dump of assembler code for function main:
   0x08048ec0 <+0>:	push   ebp
   0x08048ec1 <+1>:	mov    ebp,esp
   0x08048ec3 <+3>:	and    esp,0xfffffff0
   0x08048ec6 <+6>:	sub    esp,0x20                        <-- Space of 32 bytes is allocated on the stack
   0x08048ec9 <+9>:	mov    eax,DWORD PTR [ebp+0xc]         <-- Load char *argv[0] into eax
   0x08048ecc <+12>:	add    eax,0x4                         <-- Set argv[1]
   0x08048ecf <+15>:	mov    eax,DWORD PTR [eax]             <-- Load argv[1] into eax
   0x08048ed1 <+17>:	mov    DWORD PTR [esp],eax             <-- Pass argv[1] to atoi()
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    eax,0x1a7                       <-- Check atoi(argv[1]) == 423
   0x08048ede <+30>:	jne    0x8048f58 <main+152>
   [...]
(gdb) ni
0x08048ee0 in main ()
(gdb) disas
Dump of assembler code for function main:
   0x08048ec0 <+0>:	push   ebp
   0x08048ec1 <+1>:	mov    ebp,esp
   0x08048ec3 <+3>:	and    esp,0xfffffff0
   0x08048ec6 <+6>:	sub    esp,0x20                        <-- Space of 32 bytes is allocated on the stack
   0x08048ec9 <+9>:	mov    eax,DWORD PTR [ebp+0xc]         <-- Load char *argv[0] into eax
   0x08048ecc <+12>:	add    eax,0x4                         <-- Set argv[1]
   0x08048ecf <+15>:	mov    eax,DWORD PTR [eax]             <-- Load argv[1] into eax
   0x08048ed1 <+17>:	mov    DWORD PTR [esp],eax             <-- Pass argv[1] to atoi()
   0x08048ed4 <+20>:	call   0x8049710 <atoi>
   0x08048ed9 <+25>:	cmp    eax,0x1a7                       <-- Check atoi(argv[1]) == 423
   0x08048ede <+30>:	jne    0x8048f58 <main+152>            <-- If not, jump to main+152
   0x08048ee0 <+32>:	mov    DWORD PTR [esp],0x80c5348       <-- Pass "/bin/sh" to strdup()
   0x08048ee7 <+39>:	call   0x8050bf0 <strdup>
   0x08048eec <+44>:	mov    DWORD PTR [esp+0x10],eax        <-- Set execv_arg[0] = strdup("/bin/sh")
   0x08048ef0 <+48>:	mov    DWORD PTR [esp+0x14],0x0        <-- Set execv_arg[1] = NULL
   0x08048ef8 <+56>:	call   0x8054680 <getegid>             <-- gid = getegid()
   0x08048efd <+61>:	mov    DWORD PTR [esp+0x1c],eax
   0x08048f01 <+65>:	call   0x8054670 <geteuid>             <-- uid = geteuid()
   [...]
(gdb) x/s 0x80c5348
0x80c5348:	 "/bin/sh"
[...]
```

The first thing we can see after passing that jump is the parameter passed to `strdup` (`/bin/sh`) as well as the subsequent calls to `getegid` and `geteuid`.

Next is some very similar register preparations for calls to both `setresgid` and `setresuid`:

```gdb
[...]
   0x08048f06 <+70>:	mov    DWORD PTR [esp+0x18],eax
   0x08048f0a <+74>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f0e <+78>:	mov    DWORD PTR [esp+0x8],eax
   0x08048f12 <+82>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f16 <+86>:	mov    DWORD PTR [esp+0x4],eax
   0x08048f1a <+90>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048f1e <+94>:	mov    DWORD PTR [esp],eax
   0x08048f21 <+97>:	call   0x8054700 <setresgid>           <-- setresgid(gid, gid, gid)
   0x08048f26 <+102>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f2a <+106>:	mov    DWORD PTR [esp+0x8],eax
   0x08048f2e <+110>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f32 <+114>:	mov    DWORD PTR [esp+0x4],eax
   0x08048f36 <+118>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048f3a <+122>:	mov    DWORD PTR [esp],eax
   0x08048f3d <+125>:	call   0x8054690 <setresuid>        <-- setresuid(uid, uid, uid)
   [...]
(gdb)
```

## execv

Eventually, instruction after instruction, we get to the call of the function `execv` that seems to receive as a parameter the same pointer to a string we saw earlier `0x80c5348` (`/bin/sh`), that means that once that instruction is executed we will have a shell we may have full rights to...

```gdb
   0x08048f42 <+130>:	lea    eax,[esp+0x10]               <-- Address of execv_arg
   0x08048f46 <+134>:	mov    DWORD PTR [esp+0x4],eax      <-- Set address of execv_arg as 2nd arguments
   0x08048f4a <+138>:	mov    DWORD PTR [esp],0x80c5348    <-- Set "/bin/sh" as the first argument
   0x08048f51 <+145>:	call   0x8054640 <execv>            <-- execv("/bin/sh", &execv_arg)
(gdb) ni
process 2842 is executing new program: /bin/dash
$ ls
level0
$ ./level0
Segmentation fault (core dumped)
$ level0 423
$ pwd
/home/user/level0
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

That's what we're looking for ! :)

We may log in as level1 now that we have his pass.

```shell-session
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
level0@RainFall:~$ su level1
Password:
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level1/level1
```
