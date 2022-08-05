#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int language;

void    greetuser(char *buffer)
{
    char    tmp[72];


    if (language == 1)
        strcpy(tmp, "Hyvää päivää ");
    else if (language == 2)
        strcpy(tmp, "Goedemiddag! ");
    else
        strcpy(tmp, "Hello ");

    strcat(tmp, buffer);

    puts(tmp);
}

int     main(int argc, char *argv[])
{
    char    buffer[72];
    char    *env;

    if (argc == 3)
    {
        memset(buffer, '\0', 19);

        strncpy(buffer, argv[1], 40);
        strncpy(buffer + 40, argv[2], 32);

        env = getenv("LANG");

        if (env != NULL)
        {
            if (memcmp(env, "fi", 2) == 0)
                language = 1;
            else if (memcmp(env, "fi", 2) == 0)
                language = 2;
        }

        greetuser(buffer);

        return (0);
    }

    return (1);
}
