#include <string.h>
#include <stdio.h>
#include <unistd.h>

void    p(char *input, const char *dash)
{
    char    *ptr;
    char    tmp[4104];

    puts(dash);

    read(0, tmp, 4096);

    *strchr(tmp, '\n') = '\0';

    strncpy(input, tmp, 20);
}

void    pp(char *buffer)
{
    char    input_1[20];
    char    input_2[20];

    p(input_1, " - ");
    p(input_2, " - ");

    strcpy(buffer, input_1);

    buffer[strlen(buffer)] = ' ';

    strcat(buffer, input_2);
}

int     main(void)
{
    char    buffer[54];

    pp(buffer);
    puts(buffer);

    return (0);
}
