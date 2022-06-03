#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#define _GNU_SOURCE
#include <unistd.h>
int main(int argc, char **argv)
{
  int     nb;
  char    *arg[2];
  gid_t   gid;
  uid_t   uid;

  nb = atoi(argv[1]);
  if (nb != 423) {
    fwrite("No !\n", 5, 1, stderr);
  } else {

    gid = getegid();
    uid = geteuid();
    setresgid(gid, gid, gid);
		setresuid(uid, uid, uid);
    execv("/bin/sh", arg);

  }
  return (0);
}
