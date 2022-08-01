#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  int     nb;
  char    *execv_arg[2];
  uid_t   uid;
  gid_t   gid;

  nb = atoi(argv[1]);

  if (nb == 423)
  {
    execv_arg[0] = strdup("/bin/bash");
    execv_arg[1] = NULL;

    gid = getegid();
    uid = geteuid();
    setresgid(gid, gid, gid);
    setresuid(uid, uid, uid);
    execv("/bin/sh", execv_arg);
  }
  else
    fwrite("No !\n", 1, 5, stderr);
}
