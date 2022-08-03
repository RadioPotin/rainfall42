#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void    (*f)(void);

void    m(void)
{
    puts("Nope");
}

void    n(void)
{
    system("/bin/cat /home/user/level7/.pass");
}


int     main(int argc, char *argv[])
{
    char    *a;
    f       *b;

    a = (char *)malloc(64);
    b = (f *)malloc(4);

    *b = m;

    strcpy(a, argv[1]);

    (**b)();

    return (0);
}
