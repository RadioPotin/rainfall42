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

That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.

## gdb
That being said, it seems we need to look into the binary in order to try to understand what input it's awaiting.


