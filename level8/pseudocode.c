#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *auth;
char *service;

int main(void)
{
  char *s;

  printf("%p, %p \n", auth, service);

  if (fget(s, 128, stdin) == NULL)
    goto END;

  if (strncmp(s, "auth ", 5) == 0)
  {
      auth = malloc(4);
      auth = NULL;

      if (strlen(s + 5) > 30)
        goto MAIN_222;

      strcpy(auth, s + 5);
  }

MAIN_222:
  if (strncmp(s, "reset", 5) == 0)
  {

  }

MAIN_2276:

END:
  return (0);
}
