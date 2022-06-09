#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void run(void)
{
  fwrite("Good... Wait what?\n", 19, 1, stdout);
  system("/bin/sh");
  return;
}

int main(void)
{
  static char input[76];
  gets(input);
  return 0;
}
