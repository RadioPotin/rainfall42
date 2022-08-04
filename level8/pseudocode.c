#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

char *service;
char *auth;

int main(void)
{
    char buffer[8];

    while (true)
    {
        printf("%p, %p \n", auth, service);

        if (fgets(buffer, 128, stdin) == NULL)
            break ;

        if (!strncmp(buffer, "auth ", 5))
        {
            auth = malloc(4);
            auth = NULL;

            if (strlen(buffer + 5) < 31)
                strcpy(auth, buffer + 5);
        }

        if (!strncmp(buffer, "reset", 5))
            free(auth);

        if (!strncmp(buffer, "service", 6))
            service = strdup(buffer + 7);

        if (!strncmp(buffer, "login", 5))
        {
            if (auth[8] != '\0')
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }

    return (0);
}
