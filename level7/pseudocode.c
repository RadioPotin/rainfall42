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
    unsigned int **a;
    unsigned int **b;

    a       = malloc(8);
    a[0]    = (unsigned int *)1;
    a[1]    = malloc(8);

    b       = malloc(8);
    b[0]    = (unsigned int *)2;
    b[1]    = malloc(8);

    strcpy((char *)a[1], argv[1]);
    strcpy((char *)b[1], argv[2]);

    fgets(c, 68, fopen("/home/user/level8/.pass","r"));
    puts("~~");

    return (0);
}
