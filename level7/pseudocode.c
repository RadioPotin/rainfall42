#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

char c[128];

void    m(void)
{
    printf("%s - %d\n", c, (int)time(0));
}

int     main(int argc, char *argv[])
{
    char **a;
    char **b;

    a       = malloc(8);
    a[0]    = (char *)1;
    a[1]    = malloc(8);

    b       = malloc(8);
    b[0]    = (char *)2;
    b[1]    = malloc(8);

    strcpy(a[1], argv[1]);
    strcpy(b[1], argv[2]);

    fgets(c, 68, fopen("/home/user/level7/.pass", "r"));
    puts("~~");

    return (0);
}
