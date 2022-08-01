#include <stdio.h>
#include <stdlib.h>

// asm _exit
// {
//    0x080483d0 <+0>:  jmp    DWORD PTR ds:0x8049838
//    0x080483d6 <+6>:  push   0x28
//    0x080483db <+11>: jmp    0x8048370
// }

void    o(void)
{
    system("/bin/sh");
    exit(1);
}

void    n(void)
{
    char buffer[520];

    fgets(buffer, 0x200, stdin);
    printf(buffer);

    exit(1);
}

int     main(void)
{
    n();
    return (0);
}
