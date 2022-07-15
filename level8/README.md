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
