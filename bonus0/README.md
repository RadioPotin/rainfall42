# bonus0

## Hint

When we log into the machine as `bonus0`, we notice a binary:

```shell-session
bonus0@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 bonus1 users 5566 Mar  6  2016 bonus0
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level.

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

After a simple execution of the binary the program prints:

```shell-session
bonus0@RainFall:~$ ./bonus0
 -
```

It seems that th e program is waiting for two inputs on `stdin` and prints them.

```shell-session
bonus0@RainFall:~$ ./bonus0
 -
a
 -
b
a b
```

It seems that after a long enough input it began to print the second input, then the second input.
It seems that there are two buffer overflows in this program.

```shell-session
bonus0@RainFall:~$ ./bonus0
 -
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 -
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb�� bbbbbbbbbbbbbbbbbbbb��
Segmentation fault (core dumped)
```

Ok let's disas this binary before going further.

## gdb

### functions

```gdb

```
