
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void    p(void)
{
    int     memory;
    char    buffer[76];

    fflush(stdout);

    gets(buffer);

    if (memory & 0xb0000000)
    {
        printf("(%p)\n", &memory);
        exit(1);
    }

    puts(buffer);
    strdup(buffer);
}

int     main(void)
{
    p();
    return (0);
}
